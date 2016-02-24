/*
	Linux Awareness extension target (Linux Kernel Debugger)

	Copyright 2010-2013 STMicroelectronics.

	The Linux Awareness layer allows GDB to debug a Linux kernel
  through a H/W link (presumably a JTAG) as if it were a normal
  executable. One major issue with debugging the kernel through a
  JTAG link is the handling of virtual memory.

  Virtual memory raises some issues while debugging through the JTAG
  because the processor needs to have been correctly setup to be able
  to access such memory. Usually, the TLB needs to be loaded with the
  correct virtual memory translation so that the debugger may access
  it. When some code running above (or inside) Linuux accesses virtual
  memory, the processor raises an exception that will trigger
  handlers in the kernel that in turn will setup everything needed
  for the access to succeed. When the user wants to access such
  memory from the debugger, the processor is basically 'stalled'. No
  handlers will be called in case of exception and the access will
  (sometimes silently) fail. This means the debugger has to setup
  everything correctly *before* trying any virtual memory access.

  Once the debugger knows how to handle virtual memory, it can try to
  debug modules. In most Linux ports, kernel modules are loaded in
  kernel virtual memory (as returned by vmalloc()). This layer tries
  to expose kernel modules as shared libraries to the rest of
  GDB. This is done by registering a 'struct target_so_ops' that
  implements a shared library handling that know how to deal with
  kernel modules. Indeed, kernel modules are different from shared
  libraries in some fundamental ways. First, the kernel module binary
  files are relocatable files, they haven't undergone a link
  step. This means eg. that the files might contain multiple sections
  at the same address. This isn't handled nicely by GDB. The solution
  implemented is to mimic the little linker that does the relocation
  job in the kernel and do a real link that generates a fully
  relocated file. This file can then be handled like a stantdard
  shared library. There's another major difference between modules
  and shared libraries: part of the module code and data might be
  unmapped after the module's init step is over. GDB isn't designed
  to allow part of debug information to disappear, thus we have to
  work around that. It's important to handle that case, because the
  freed memory will be reused by subsequent module loads, leading to
  a big mess of overlapping informations if the information from the
  unloaded code isn't somehow handled. As said above, GDB can't
  forget part of the debug information. The workaround use is to
  'destroy' the debug information relating to the unloaded code by
  pretending that every object that disappeared is located at
  0xFFFFFFFF (there is a repeating ~(CORE_ADDR)0 pattern in the
  file). The detection of module load, unloads and end of init events
  is done by installing breakpoints at carefully chosen points.

  The other major thing done in this file, is to expose all the
  running tasks of the Linux kernel as threads of the debugged
  application to GDB. To make abstraction more natural from an UI
  point of view, the command 'info tasks' is introduced as an alias
  for 'info threads'.

  Most of the above is achieved by inserting the 'struct target_ops
  linux_aware_ops' on the top of the target stack. The target stack
  is the way GDB talks to the debugged target. It exposes an API
  defined in 'struct target_ops'. Most of the functions have explicit
  names, like 'fetch_register', 'resume', 'xfer_memory'. This is a
  stack because it is constructed by piling up layers that provide
  certain functionality. For example, when you first open an
  executable file, a layer (or stratum in GDB speak) that knows how
  to read the memory from the file is on the target stack. Then you
  run the executable and a layer that knows how to access the runtime
  memory and control the execution of the process is pushed on the
  stack. Then it might be that this is a threaded application, and
  the thread awareness is pushed as another layer on the target
  stack. Each stratum has the ability to overload the functions
  defined by the target_ops structure and to access the layers below
  its level. The code in target.c constructs the current_target
  structure each time the target stack is modified by a call to
  (push|unpush)_target (). In this file we push 'linux_aware_ops' at
  the very top of the target stack, and thus it's able to intercept
  every communication between GDB and the debugged processor. For
  example we trap virtual memory accesses this way and do the
  required setup before passing the access to the lower layer of the
  target stack that will really perform the access.

  A last thing that is implemented in this file is a few generic data
  display commands like 'dmesg', 'proc_iomem', 'proc_ioports', ...
 */
#ifndef __LINUX_AWARENESS_H__
#define __LINUX_AWARENESS_H__

#define LKD_VERSION_STRING "7.11-development"

#ifdef __LA_DISP_TIME_
/*
 * target profiling
 **/
extern int display_time;
#define __trgt_time_start_ long time = get_run_time();
#define __trgt_time_appen_  {cumulated_beneath_time+=get_run_time()-time;};
#define __trgt_xfer_start_ long time = get_run_time(); cumulated_xfer_size+=len;
#define __trgt_xfer_appen_	{cumulated_xfer_time+=get_run_time()-time;};
#else
#define __trgt_time_start_
#define __trgt_xfer_start_
#define __trgt_time_appen_
#define __trgt_xfer_appen_
#endif

/*options under development or temporarily disabled.*/
//#define HAS_PAGE_MONITORING
//#define HAS_ANDROID_SUPPORT

#ifndef NULL
#define NULL ((void*)0)
#endif


/********** from breakpoint.c **********************/

extern struct breakpoint *breakpoint_chain;
extern struct bp_location **bp_location;
extern int breakpoint_count;
extern unsigned bp_location_count;

#define ALL_BREAKPOINTS(B)  for (B = breakpoint_chain; B; B = B->next)

#define ALL_BREAKPOINTS_SAFE(B,TMP)	\
	for (B = breakpoint_chain;	\
	     B ? (TMP=B->next, 1): 0;	\
	     B = TMP)

#define ALL_BP_LOCATIONS(B,BP_TMP)					\
	for (BP_TMP = bp_location;					\
	     BP_TMP < bp_location + bp_location_count && (B = *BP_TMP);	\
	     BP_TMP++)

/*************************************************/

#define LKD_BYTE_ORDER BFD_ENDIAN_LITTLE

/* target stack ordering */
#define LKD_STRATUM_LINUX (thread_stratum + 10)


typedef enum
{
  LKD_NOTLOADED = 0,
  LKD_LOADED = 1,		/*must be one */
  LKD_LOADING = 2,
} lkd_load_states_t;

/**
 *  LKD user parameters.
 */
struct linux_awareness_params
{

  /* Global flag set by 'set linux-awareness enabled'. The user
     shouldn't have to use that as the enablementlinux_awareness_check should be triggered
     automatically by the kernel autodetection routines. */
  int enabled;

  /* Flag indicating that the kernel has been loaded. This is set by the
     'load' command, but it might be necessary to set it by hand ('set
     linux-awareness loaded 1'), eg. when attaching to a running target
     with another command than the standard 'attach'. */
  lkd_load_states_t loaded;

  /* For debugging. One can disable the task handling
     issuing 'set linux-awareness enable_task_awareness 0' */
  int enable_task_awareness;

  /* A user might disable the automatic load of the Linux awareness
     layer by issuing 'set linux-awareness auto_activate 0' before
     loading the kernel binary. (This might be usefull in a .(sh)gdbinit
     file. */
  int auto_activate;

  /* The current global loglevel as set by 'set linux-awareness
     debug-all' */
  int loglevel;

  /* skip the schedule() frame in the backtrace */
  int skip_schedule_frame;

  /* disable thread info coloring */
  int no_colors;
};

extern struct linux_awareness_params lkd_params;

/* use scratch area for messing around with strings
 * to avoid static arrays and dispersed mallocs and frees
 **/
struct lkd_private_data
{
  lkd_load_states_t loaded;
  int connected;
  int keep_do_exit_event;

  unsigned char *string_buf;
  int string_buf_size;

  char *banner_file;		/* string for the banner as read from vmlinx */
  int banner_file_size;		/* max size allocated */
  int banner_file_valid;	/* valid or to refresh */

  int proc_list_invalid;

  char *banner_mem;		/* string for the banner as read from vmlinx */
  int banner_mem_size;		/* max size allocated */
  int banner_mem_valid;		/* valid or to refresh */

  /* The UTS name as extracted from the file or the memory. This serves
     to build the path that points to the depmod cache. */
  char *utsname_release;
  int utsname_release_size;	/* max size allocated */
  int utsname_release_valid;	/* valid or to refresh */

  struct type* target_pointer_type;

  uint32_t kflags;
};

extern struct lkd_private_data lkd_private;

void lkd_loaded_set (char *arg, int from_tty, struct cmd_list_element *c);
void lkd_enabled_set (char *args, int from_tty, struct cmd_list_element *c);
void lkd_reset_thread_list (void);
long lkd_eval_long (char *string);

/* lkd-irqs.c*/
void interrupts_command (char *args, int from_tty);

/*
 * arch-common mmu info
 **/
struct mmu_infos
{
  uint32_t curr_virt_pgd;
  uint32_t prev_phys_pgd;
  uint32_t prev_asid;
  int dirty;
};

extern struct mmu_infos mmu_info[];

/* Mimic kernel macros */
#define container_of(ptr, struc, field)  ((ptr) - F_OFFSET(struc, field))

extern int max_cores;
#define MAX_CORES 5
#define CORE_INVAL (-1)		/* 0 = name on the inferior, cannot be used */

extern const struct objfile_data *linux_uprocess_objfile_data_key;

extern int stopped_core;
extern int lkd_stepping;

struct process_t_;

struct linux_awareness_ops
{
  const char *name;

  /* Check if the current application is a compatible Linux kernel. */
  int (*lo_check_kernel) ();

  int (*lo_check_mem_rdy) (); /*must implement.*/

  /* Called at the beginning of a debugging session. */
  int (*lo_init) ();
  /* Called at the end of a debugging session. Can be NULL. */
  void (*lo_close) ();
  /* Called before detaching from the targe. Can be NULL. */
  int (*lo_pre_detach) (char *prog, int fromtty);
  /* Called before the load of the kernel. Can be NULL. */
  void (*lo_pre_load) (char *prog, int fromtty);
  /* Called after the load of the kernel. Can be NULL. */
  void (*lo_post_load) (char *prog, int fromtty);
  /* Called before the processor is resumed. Can be NULL. */
  void (*lo_pre_exec_start) ();


  /* Returns wether the page containing addr in the context of task_struct
     is mapped as writable. */
  int (*lo_can_write) (CORE_ADDR addr, CORE_ADDR task_struct);
  /* Returns wether the passed address is a userspace address. */
  int (*lo_is_user_address) (CORE_ADDR addr);
  /* Returns wether the passed address is a kernelspace address. */
  int (*lo_is_kernel_address) (CORE_ADDR addr);
  /* Returns wether the passed handler lies inside a TLB miss
     handler. This is used to singlestep through code in virtual
     memory: when this code produces an exception, the awareness
     layer will hide from the user (by silently singlstepping
     through) all the code where that callback returns true. */
  int (*lo_is_tlb_miss_handler) (CORE_ADDR addr);
  /* Flush the processor cache lines corresponding to the virtual
     address virtaddr and physical addr physaddr (as returned by
     lo_translate_memory_address() above).
     Called with virtaddr == physaddr, the aim is to flush the
     aliased line that might have been introduced by directly
     accessing the physical address.

     Precondition :
     [virtaddr..virtaddr+len[ lies on the same physical page.
   */
  void (*lo_flush_cache) (CORE_ADDR virtaddr, CORE_ADDR physaddr,
			  int len, int write);
  /* If the target has to use software singlestepping, this callback
     is called and returns the instruction that'll be executed after
     the one at pc. Can be NULL. */
    CORE_ADDR (*lo_single_step_destination) (CORE_ADDR pc);
  /* This callback is called when the execution is resumed and we
     might switch task. It's different from lo_pre_exec_start() that
     will be called systematically. For example, cached virtual
     memory translations can be discarded here. When this called
     back isn't called, the debugger stays in the same task, thus
     the cached translations should stay valid. */
  void (*lo_clear_cache) ();

  /* Should supply the current regcache with the value of register
     regno in the context of task_struct. This will only be called
     for tasks that are stopped in the scheduler. The way the task
     state is stored on context switch is target specific. */
  int (*lo_fetch_context_register) (int regno, CORE_ADDR task_struct);
  /* Should store in the target the value of register regno from the
     current regcache in the context of task_struct. This will only
     be called for tasks that are stopped in the scheduler. The way
     the task state is stored on context switch is target specific. */
  int (*lo_store_context_register) (int regno, CORE_ADDR task_struct);

  int kernel_offset;
};

extern struct target_ops linux_aware_ops;
extern struct linux_awareness_ops *linux_awareness_ops;

extern bfd *cur_bfd;

struct type;
struct cmd_list_element;

extern struct cmd_list_element *set_linux_awareness_cmd_list;
extern struct cmd_list_element *show_linux_awareness_cmd_list;

struct addr_info
{
  char *name;
  struct bound_minimal_symbol bmsym;
  struct addr_info *next;
};

struct field_info
{
  char *struct_name;
  char *field_name;
  struct symbol *type;
  int offset;
  int size;
  struct field_info *next;
};

#define FIELD_INFO(s_name, field) _FIELD_##s_name##__##field

#define DECLARE_FIELD(s_name, field) \
		static struct field_info FIELD_INFO(s_name, field) \
		= { .struct_name = #s_name, .field_name = #field, 0 }

#define F_OFFSET(struct, field) \
		linux_get_field_offset (&FIELD_INFO(struct, field))
#define F_SIZE(struct, field) \
		linux_get_field_size (&FIELD_INFO(struct, field))
#define HAS_FIELD(struct, field) \
		(FIELD_INFO(struct, field).type != NULL \
				|| (linux_init_field(&FIELD_INFO(struct, field), 1), \
						FIELD_INFO(struct, field).type != NULL))

#define ADDR_INFO(symb) _ADDR_##symb

#define DECLARE_ADDR(symb) \
		static struct addr_info ADDR_INFO(symb) = { .name = #symb, .bmsym = {NULL, NULL} }

#define HAS_ADDR(symb) \
		(ADDR_INFO(symb).bmsym.minsym != NULL \
				|| (linux_init_addr(&ADDR_INFO(symb), 1), ADDR_INFO(symb).bmsym.minsym != NULL))

#define ADDR(sym) linux_get_address (&ADDR_INFO(sym))

#define read_unsigned_field(base, struct, field) \
		read_memory_unsigned_integer (base + F_OFFSET (struct, field), \
				F_SIZE (struct, field), LKD_BYTE_ORDER)

#define read_signed_field(base, struct, field) \
		read_memory_integer (base + F_OFFSET (struct, field), \
				F_SIZE (struct, field), LKD_BYTE_ORDER)

#define read_pointer_field(base, struct, field) \
		read_memory_typed_address (base + F_OFFSET (struct, field), \
				builtin_type (target_gdbarch ())->builtin_data_ptr)

#define read_unsigned_embedded_field(base, struct, field, emb_str, emb_field) \
		read_memory_unsigned_integer (base + F_OFFSET (struct, field) \
				+ F_OFFSET (emb_str, emb_field), \
				F_SIZE (emb_str, emb_field), LKD_BYTE_ORDER)

#define read_signed_embedded_field(base, struct, field, emb_str, emb_field) \
		read_memory_integer (base + F_OFFSET (struct, field) \
				+ F_OFFSET (emb_str, emb_field), \
				F_SIZE (emb_str, emb_field), LKD_BYTE_ORDER)

#define read_pointer_embedded_field(base, struct, field, emb_str, emb_field) \
		read_memory_typed_address (base + F_OFFSET (struct, field) \
				+ F_OFFSET (emb_str, emb_field), \
				builtin_type (target_gdbarch ())->builtin_data_ptr)

#define extract_unsigned_field(base, struct, field) \
		extract_unsigned_integer(base + F_OFFSET (struct, field), \
				F_SIZE (struct, field), LKD_BYTE_ORDER)

#define extract_signed_field(base, struct, field) \
		extract_signed_integer (base + F_OFFSET (struct, field), \
				F_SIZE (struct, field), LKD_BYTE_ORDER)

#define extract_pointer_field(base, struct, field) \
		extract_typed_address (base + F_OFFSET (struct, field), \
				builtin_type(target_gdbarch ())->builtin_data_ptr)

/*cleanup macro to compare an address to a bp loc value*/
#define IS_LOC(pc,evnt)  ((evnt != NULL) && (pc == evnt->loc->address))

enum page_status
{
  PAGE_PRESENT,
  PAGE_SWAPPED,
  PAGE_NOTMAPPED,
  PAGE_NOPAGE,
  PAGE_UNKNOWN
};

/*kversion building macros */
#define KERNEL_VERSION(MM,mm,bb) (((MM) << 16) + ((mm) << 8) + (bb))

/* last known (validated) STLinux kernel version for this LKD.
 * if we're beyond this version, of not on STLinux, issue a warning
 **/
#define KFLAG_NOLINUX	0x00000000	/* not linux */
#define KFLAG_LINUX 	0x00000001	/* is linux */
#define KFLAG_STLINUX	0x00000002	/* STMicroelectronics linux distro */
#define KFLAG_DBGINFO	0x00000004	/* has debug information */

/* kernel release string */
extern char g_utsname_release[];

struct debug_domain
{
  const char *name;
  int level;
};

extern struct debug_domain linux_aware_debug_domains_info[];

enum linux_aware_debug_domain
{
  TASK,
  TARGET,
  D_INIT,
  FRAME,
  BP,
  KEEP_LAST
};

#define DEBUG(domain, l, ...) \
		({if (domain < KEEP_LAST \
				&& linux_aware_debug_domains_info[domain].level >= l) \
				fprintf_filtered(gdb_stdlog, "linux: " __VA_ARGS__);})

/*do thing a different way in debug mode.*/
#define DBG_IF(domain)          if (linux_aware_debug_domains_info[domain].level) {
#define DBG_ELSE                } else {
#define DBG_ENDIF(domain)       }

#define LA_NOT_LOADED_STRING "Please type \"set linux-awareness loaded\".\n"

int linux_init_addr (struct addr_info *field, int check);
int linux_init_field (struct field_info *field, int check);

static inline CORE_ADDR
linux_get_address (struct addr_info *addr)
{
  if (addr->bmsym.minsym == NULL)
    linux_init_addr (addr, 0);

  return BMSYMBOL_VALUE_ADDRESS (addr->bmsym);
}

static inline unsigned int
linux_get_field_offset (struct field_info *field)
{
  if (field->type == NULL)
    linux_init_field (field, 0);

  return field->offset;
}

static inline unsigned int
linux_get_field_size (struct field_info *field)
{
  if (field->type == NULL)
    linux_init_field (field, 0);

  return field->size;
}

int lkd_try_push_target (void);

void linux_read_process_symbols (void);
void lkd_uninstall_do_exit_event (void);

char *read_dentry (CORE_ADDR dentry);

void page_error_clear (void);

void sanitize_path (char *path);
char *linux_aware_get_target_root_prefix (void);

struct objfile;
struct partial_symtab;
extern void (*dwarf2_psymtab_to_symtab) (struct partial_symtab *pst,
					 struct objfile *objfile);

void linux_aware_read_symtab (struct partial_symtab *pst,
			      struct objfile *objfile);

int linux_aware_translate_address_safe (CORE_ADDR * addr, int silent);


int linux_aware_target_core (void);

/* === sdi_VirtualMem API definition === */

/* This API (provided by Antony KING in his emulation libraries) is
   used through a dlopen/dlsym call, ie. in a type-unsafe way. This
   needs to be watched in future versions, especially if the API
   evolves to handle ASIDs.
*/

typedef enum sdi_pte_type_e
{
  sdi_pte_unmapped,
  sdi_pte_fixed,
  sdi_pte_dynamic
} sdi_pte_type_t;

typedef struct sdi_pte_s
{
  uint32_t vaddress;
  uint32_t paddress;
  uint32_t size;
  sdi_pte_type_t type;
  struct
  {
    unsigned int read:1;
    unsigned int write:1;
  } access;
  uint32_t ptel;
  uint32_t pteh;
} sdi_pte_t;

int (*sdi_VirtualMem) (int ptesize, const sdi_pte_t * ptelist);


#endif /*__LINUX_AWARENESS_H__*/
