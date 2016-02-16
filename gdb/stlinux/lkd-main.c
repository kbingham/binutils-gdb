/*
  Copyright 2005-2013 STMicroelectronics.

  This file contains the architecture neutral part of the Linux
  Awareness layer for GDB.

 */

#include <ctype.h>

#include "defs.h"
#include "ui-out.h"
#include "arch-utils.h"
#include "block.h"
#include "breakpoint.h"
#include "cli/cli-decode.h"
#include "cli/cli-script.h"
#include "command.h"
#include "completer.h"
#include "dictionary.h"
#include "event-loop.h"
#include "exceptions.h"
#include "exec.h"
#include "frame.h"
#include "frame-unwind.h"
#include "gdb.h"
#include "gdb_assert.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "gdbthread.h"
#include "gdbtypes.h"
#include "inferior.h"
#include "location.h"
#include "objfiles.h"
#include "observer.h"
#include "regcache.h"
#include "solib.h"
#include "solist.h"
#include "symtab.h"
#include "psympriv.h"
#include "target.h"
#include "top.h"

#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"

#include "tui/tui.h"

#include "value.h"		/*KERN_310-dmesg */


#include "lkd.h"
#include "lkd-android.h"
#include "lkd-process.h"
#include "lkd-modules.h"

/******************************* from shtdi.c *********************************/
/* Signal Handling.  */
#include <signal.h>

/* A target interrupt has been requested.  */
static volatile int interrupt_requested = 0;
static int target_interrupted = 0;

/* A SIGTERM has been requested.  */
static volatile int terminate_requested = 0;

/* Remember the regular SIG handlers while ours are installed.  */
static void (*old_interrupt_handler) (int);
static void (*old_terminate_handler) (int);
static void terminate_once (int signo);
static void disable_terminate (void);
static void enable_terminate (void);

/******************************************************************************/

//#define AUTO_ASM /*provide short asm context when not in TUI*/

#define BENEATH linux_aware_ops.beneath

/* This function is normally private to symfile.c, but we export it to
 be able to use it here. */
char *find_separate_debug_file_by_debuglink (struct objfile *objfile);

/*************************** Copied from breakpoint.c *************************/

extern struct breakpoint *set_raw_breakpoint (struct gdbarch *gdbarch,
					      struct symtab_and_line,
					      enum bptype);

extern int hw_watchpoint_used_count (enum bptype type, int *other_type_used);

extern void set_breakpoint_count (int);

struct lkd_private_data lkd_private;

/********************* Handling of the depmod cache ***************************/

/* The actual cache that is maintained in the debugger. */
struct depmod_cache
{
  char *filename;
  char *modname;		/* points into filename */
};
static struct depmod_cache *depmod_cache;
static int depmod_cache_length, depmod_cache_capacity;
static time_t depmod_cache_timestamp;

/***************************** Added commands *********************************/
static char linux_awareness_doc[] = "";

/* The cmd_list_element where we register all the 'set
 linux-awareness...' and 'show linux-awareness...' commands. */
struct cmd_list_element *set_linux_awareness_cmd_list;
struct cmd_list_element *show_linux_awareness_cmd_list;

/* The definition of the log domains and the storage for their
 associated log levels. */
struct debug_domain linux_aware_debug_domains_info[] = {
  {"debug-vm", 0},
  {"debug-task", 0},
  {"debug-module", 0},
  {"debug-target", 0},
  {"debug-init", 0},
  {"debug-user", 0},
  {"debug-frame", 0},
  {"debug-bp", 0},
  {NULL, 0}
};

/* The definition of the log domains and the storage for their
 associated log levels. */
struct linux_awareness_params lkd_params = {
  .enabled = 0,
  .loaded = LKD_NOTLOADED,
  .enable_module_load = 0,
  .enable_vm_translation = 1,
  .enable_task_awareness = 1,
  .auto_activate = 1,
  .auto_debug_process = 1,
  .skip_schedule_frame = 0, /*RnDCT0001394: changed default behavior*/
  .no_colors = 0,
  .loglevel = 0
};

/* GDB user experience tuning */
extern enum auto_boolean pending_break_support;

#ifdef AUTO_ASM
extern enum auto_boolean disassemble_next_line;
#endif

/* 'set target-root-prefix' is introduced as an alias for 'set
 solib-absolute-prefix', this variable contains a pointer to the value
 of that variable. */
char **target_root_prefix;
static int target_root_prefix_dirty = 1;

/* The 'dmesg' command reads the log buffer in chunks. This is the
 default size of the chunks. It can be set with 'set linux-awareness
 log_chunk_size xxx'. */
static unsigned int log_chunk_size = 128;

/********************************* GDB glue ***********************************/

/* The target ops that adds the linux awareness. */
struct target_ops linux_aware_ops;

/* The structure that gives access to target-dependant knowledge
 required by the Linux awareness layer. Declared in linux-awreness.h
 and defined in a targetting file (eg. linux-awareness-sh4.c). */
struct linux_awareness_ops *linux_awareness_ops;

/**************************** Execution control *******************************/

/* This ugly variable is a way to pass information from the
 target_ops->to_resume to the target_ops->to_wait callbacks. It
 indicates if the last execution request was a singlstep. It's used
 in linux_aware_wait to perform additional step in some
 circumstances. */
int lkd_stepping;

/* A simple flag indicating that the target is running (ie. we are
 between a target_resume () and a target_wait () call). This is used
 to properly disconnect when the debugger is killed by a signal. */
static int running;

/* This is the observer registered for the normal_stop event. The
 observer callback (normal_stop_callback ()) is called when the user
 gets the hand back after a target execution. It's used to collect
 some information and to cleanup some state. */
static struct observer *normal_stop_observer;

/******************************* Function Prototypes **************************/

void set_skip_schedule_frame (char *arg, int from_tty, struct cmd_list_element *c);

/*********************** Addresses and Structure descriptions *****************/

/* The Linux Awareness Layer needs to know a lot about the addresses
 and layout of the data structures used in the kernel. This is
 handled through these declaration and the associated macros and
 functions (see linux-awareness.h). */

/* Storage for the field layout and addresses already gathered. */
struct field_info *field_info;
struct addr_info *addr_info;

/* Declaration of the required addresses. */
DECLARE_ADDR (start_kernel);
DECLARE_ADDR (secondary_start_kernel);
DECLARE_ADDR (do_exit);

DECLARE_ADDR (init_thread_union);
DECLARE_ADDR (module_address_lookup);
DECLARE_ADDR (__symbol_put);
DECLARE_ADDR (modules);
DECLARE_ADDR (init_task);
DECLARE_ADDR (try_to_unmap);
DECLARE_ADDR (search_binary_handler);

/*Log buffer symbol for dmesg */
DECLARE_ADDR (log_end);
DECLARE_ADDR (log_start);
DECLARE_ADDR (log_buf_len);
DECLARE_ADDR (__log_buf);
/* F_KERN_310 */
DECLARE_ADDR (log_next_idx);
DECLARE_ADDR (log_first_idx);
DECLARE_FIELD (log, len);
DECLARE_FIELD (log, level);
/* Kernel 3.11+ */
DECLARE_FIELD (printk_log, len);
DECLARE_FIELD (printk_log, level);

DECLARE_ADDR (shm_ids);
DECLARE_ADDR (sem_ids);
DECLARE_ADDR (msg_ids);
DECLARE_ADDR (ioport_resource);
DECLARE_ADDR (iomem_resource);
DECLARE_ADDR (linux_banner);
DECLARE_ADDR (saved_command_line);
DECLARE_ADDR (totalram_pages);
DECLARE_ADDR (pgdat_list);
DECLARE_ADDR (contig_page_data);
DECLARE_ADDR (all_bdevs);
DECLARE_ADDR (swapper_space);
DECLARE_ADDR (nr_swap_pages);
DECLARE_ADDR (totalswap_pages);
DECLARE_ADDR (nr_swapfiles);
DECLARE_ADDR (swap_info);
DECLARE_ADDR (per_cpu__page_states);
DECLARE_ADDR (totalhigh_pages);
DECLARE_ADDR (nr_pagecache);

DECLARE_ADDR (vm_committed_space);
DECLARE_ADDR (vm_committed_as);
DECLARE_FIELD (percpu_counter, count);

DECLARE_ADDR (sysctl_overcommit_ratio);
DECLARE_ADDR (vmlist);
DECLARE_ADDR (nr_huge_pages);
DECLARE_ADDR (last_pid);
DECLARE_ADDR (system_utsname);
DECLARE_ADDR (init_uts_ns);
DECLARE_ADDR (init_pid_ns);
DECLARE_ADDR (vm_stat);

DECLARE_ADDR (sys_set_tid_address);
DECLARE_ADDR (per_cpu__kstat);

/* Structure fields */
DECLARE_FIELD (block_device, bd_list);
DECLARE_FIELD (block_device, bd_inode);
DECLARE_FIELD (dentry, d_parent);
DECLARE_FIELD (dentry, d_name);
DECLARE_FIELD (dentry, d_flags);
DECLARE_FIELD (Elf32_Ehdr, e_shnum);
DECLARE_FIELD (Elf32_Ehdr, e_shstrndx);
DECLARE_FIELD (Elf32_Shdr, sh_addr);
DECLARE_FIELD (Elf32_Shdr, sh_name);
DECLARE_FIELD (Elf32_Shdr, sh_flags);
DECLARE_FIELD (Elf32_Shdr, sh_link);
DECLARE_FIELD (Elf32_Shdr, sh_type);
DECLARE_FIELD (file, f_dentry);
DECLARE_FIELD (file, f_path);
DECLARE_FIELD (file_system_type, name);
DECLARE_FIELD (inode, i_mapping);

DECLARE_FIELD (list_head, next);
DECLARE_FIELD (mm_struct, mmap);
DECLARE_FIELD (mm_struct, map_count);
DECLARE_FIELD (mm_struct, arg_start);
DECLARE_FIELD (mm_struct, arg_end);
DECLARE_FIELD (mm_struct, env_start);
DECLARE_FIELD (mm_struct, env_end);
DECLARE_FIELD (mm_struct, pgd);
DECLARE_FIELD (task_struct, active_mm);
DECLARE_FIELD (mnt_namespace, list);
 /**/ DECLARE_FIELD (module, list);
DECLARE_FIELD (module, name);
DECLARE_FIELD (module, init);
DECLARE_FIELD (module, module_init);
DECLARE_FIELD (module, module_core);
DECLARE_FIELD (module, init_size);
DECLARE_FIELD (module, init_text_size);
DECLARE_FIELD (module, core_size);
DECLARE_FIELD (module, core_text_size);
DECLARE_FIELD (module, args);	/* far offset in the modules structure, to bulk-read everything needed. */
 /**/ DECLARE_FIELD (msg_queue, q_cbytes);
DECLARE_FIELD (msg_queue, q_qnum);
DECLARE_FIELD (namespace, list);
DECLARE_FIELD (nsproxy, ipc_ns);
DECLARE_FIELD (nsproxy, mnt_ns);

DECLARE_FIELD (new_utsname, release);
DECLARE_FIELD (page_state, nr_dirty);
DECLARE_FIELD (page_state, nr_mapped);
DECLARE_FIELD (page_state, nr_writeback);
DECLARE_FIELD (page_state, nr_slab);
DECLARE_FIELD (page_state, nr_page_table_pages);
DECLARE_FIELD (path, dentry);
DECLARE_FIELD (pglist_data, node_zones);
DECLARE_FIELD (pglist_data, pgdat_next);
DECLARE_FIELD (pid_namespace, last_pid);
DECLARE_FIELD (qstr, len);
DECLARE_FIELD (qstr, name);
DECLARE_FIELD (resource, name);
DECLARE_FIELD (resource, start);
DECLARE_FIELD (resource, end);
DECLARE_FIELD (resource, parent);
DECLARE_FIELD (resource, child);
DECLARE_FIELD (resource, sibling);
DECLARE_FIELD (sem_array, sem_nsems);
DECLARE_FIELD (shmid_kernel, shm_nattch);
DECLARE_FIELD (shmid_kernel, shm_segsz);
DECLARE_FIELD (super_block, s_type);
DECLARE_FIELD (super_block, s_flags);
DECLARE_FIELD (swap_info_struct, flags);
DECLARE_FIELD (swap_info_struct, inuse_pages);
 /**/ DECLARE_FIELD (task_struct, mm);
DECLARE_FIELD (task_struct, tasks);
DECLARE_FIELD (task_struct, children);
DECLARE_FIELD (task_struct, thread_group);
DECLARE_FIELD (task_struct, sibling);
DECLARE_FIELD (task_struct, pid);
DECLARE_FIELD (task_struct, tgid);
DECLARE_FIELD (task_struct, namespace);
DECLARE_FIELD (task_struct, nsproxy);
DECLARE_FIELD (task_struct, prio);
DECLARE_FIELD (task_struct, cred);
DECLARE_FIELD (task_struct, comm);	/* far offset in the task_struct, to bulk-read everything needed. */

/*android*/
DECLARE_FIELD (cred, fsuid);

 /**/ DECLARE_FIELD (thread_info, preempt_count);
DECLARE_FIELD (uts_namespace, name);
DECLARE_FIELD (vm_area_struct, vm_next);
DECLARE_FIELD (vm_area_struct, vm_file);
DECLARE_FIELD (vm_area_struct, vm_flags);
DECLARE_FIELD (vm_area_struct, vm_start);
DECLARE_FIELD (vm_area_struct, vm_end);
DECLARE_FIELD (vm_area_struct, vm_pgoff);
DECLARE_FIELD (vm_struct, next);
DECLARE_FIELD (vm_struct, size);

DECLARE_FIELD (vfsmount, mnt_sb);
DECLARE_FIELD (vfsmount, mnt_flags);

/*2.6*/
DECLARE_FIELD (vfsmount, mnt_list);
DECLARE_FIELD (vfsmount, mnt_parent);
DECLARE_FIELD (vfsmount, mnt_devname);
DECLARE_FIELD (vfsmount, mnt_mountpoint);

/*3.3*/
DECLARE_FIELD (mount, mnt);
DECLARE_FIELD (mount, mnt_list);
DECLARE_FIELD (mount, mnt_parent);
DECLARE_FIELD (mount, mnt_devname);
DECLARE_FIELD (mount, mnt_mountpoint);

DECLARE_FIELD (zone, free_pages);
DECLARE_FIELD (zone, nr_active);
DECLARE_FIELD (zone, nr_inactive);

int max_cores = MAX_CORES;

/****************************** Task handling *********************************/

/* The internal breakpoints used to be notified of interesting task
 events. */
static struct breakpoint *thread_event_low_mem_bp;
static struct breakpoint *thread_event_do_exec_bp;
static struct breakpoint *thread_event_do_exit_bp;
static struct breakpoint *thread_event_do_exec_return_bp;

/* This value is incremented and decremented by
 thread_awareness_(in|ex)hibit (). The target actions (eg. read
 register) requested by the platform specific part of the linux
 awareness are guaranteed to access the real state of the target,
 whatever the user selected as current task in the debugger. To
 achieve this, this variable is incremented/decremented around the
 calls to linux_awareness_ops, and tested in each target access
 method. */
static int _inhibit_thread_register_awareness;

/* the core that triggered the event (zero-based)*/
int stop_core = 0;
/* When doing userspace debug, there's the very annoying limitation
 that the debugged application creation isn't handled by the
 debugger, but by the user in an environement decorelated from the
 debugger. This precludes using the debugger to debug an application
 from the start.
 To overcome that annoying limitation, tha command 'wait_exe' has
 been added. It's used like that:

 (gdb) wait_exe foo
 Type commands that will be executed the next time the binary is exec'd:
 End with a line saying just "end".
 >b main
 >p global = 1
 >end

 This tells the debugger to watch for process creation, and that
 when a process called 'foo' is launched, the debugger should
 execute 'b main' and 'p global = 1' before the process is allowed
 to start executing. Once the user launches the process it should
 then stop on main. Of course this is just an example; the
 machinery is generic enough to allow many other uses.

 Note that putting a control execution command (next, continue...)
 inside the wait_exe command list will break things (Unfortunately
 it's not possible to detect it genericaly).

 The below struct and list contains the wait_exe requests currently
 in fly.
 */
struct waited_exe
{
  struct waited_exe *next;
  char *name;
  struct command_line *cmds;
  uid_t uid;
} *waited_exes = NULL;

/* The bellow data structures deal with the handling of breakpoints on
 virtual memory pages that aren't mapped to memory yet. The idea is
 to put a watchpoint on the page table entry that represents the
 page and to associate commands that create the final breakpoint
 with the watchpoint. */
struct bp_list
{
  struct bp_list *next;
  struct breakpoint *b;
};

#ifdef HAS_PAGE_MONITORING

struct monitored_page
{
  struct monitored_page *next;
  CORE_ADDR addr;
  CORE_ADDR virt_addr;
  int stop;
  struct breakpoint *watchpoint;
  struct bp_list *bps;
};

static struct monitored_page *monitored_pages;

struct monitored_page;
static void add_bpt_to_monitored_page (struct monitored_page *page,
				       struct breakpoint *bpt);
static struct monitored_page *find_monitored_page (CORE_ADDR addr);
static struct monitored_page *create_monitored_page (CORE_ADDR addr,
						     struct breakpoint *bp);
#endif

/* This key is used to store a reference count associated with GDB
 objfiles. Objfiles are shared between userspace thread of the same
 application, thus we reference count them to know when we can
 discard the information. */
const struct objfile_data *linux_uprocess_objfile_data_key;

/****************** Local functions forward declarations **********************/

static void (*deprecated_call_command_chain) (struct cmd_list_element * c,
					      char *cmd, int from_tty);
static void (*deprecated_create_breakpoint_chain) (struct breakpoint * bpt);
static void (*deprecated_delete_breakpoint_chain) (struct breakpoint * bpt);
static void (*deprecated_context_chain) (int id);

static void normal_stop_callback (struct bpstats *bs, int);

static void check_exec_actions (void);

/***************** End Local functions forward declarations *******************/

/* Called by ADDR to fetch the address of a symbol declared using
 DECLARE_ADDR. */
int
linux_init_addr (struct addr_info *addr, int check)
{
  if (addr->bmsym.minsym)
    return 1;

  addr->bmsym = lookup_minimal_symbol (addr->name, NULL, NULL);

  if (addr->bmsym.minsym)
    {
      DEBUG (D_INIT, 4, "Checking for address of '%s' : OK\n", addr->name);
    }
  else
    {
      DEBUG (D_INIT, 1, "Checking for address of '%s' : NOT FOUND\n",
	     addr->name);
      if (!check)
	error ("Couldn't find address of %s", addr->name);
      return 0;
    }

  /* Chain initialized entries for cleanup. */
  addr->next = addr_info;
  addr_info = addr;

  DEBUG (D_INIT, 4, "%s address is %s\n", addr->name,
	 phex (BMSYMBOL_VALUE_ADDRESS (addr->bmsym), 4));
  return 1;
}

/* Helper for linux_init_field. */
static int
find_struct_field (struct type *type, char *field, int *offset, int *size)
{
  int i;

  for (i = 0; i < TYPE_NFIELDS (type); ++i)
    {
      if (!strcmp (FIELD_NAME (TYPE_FIELDS (type)[i]), field))
	break;
    }

  if (i >= TYPE_NFIELDS (type))
    return 0;

  *offset = FIELD_BITPOS (TYPE_FIELDS (type)[i]) / TARGET_CHAR_BIT;
  *size = TYPE_LENGTH (check_typedef (TYPE_FIELDS (type)[i].type));
  return 1;
}

/* Called by F_OFFSET or F_SIZE to compute the description of a field
 declared using DECLARE_FIELD. */
int
linux_init_field (struct field_info *field, int check)
{
  if (field->type != NULL)
    return 1;

  field->type = lookup_symbol (field->struct_name, NULL, STRUCT_DOMAIN, NULL).symbol;
  if (field->type)
    {
      DEBUG (D_INIT, 4, "Checking for 'struct %s' : OK\n", field->struct_name);
    }
  else
    {
      field->type = lookup_symbol (field->struct_name,
				   NULL, VAR_DOMAIN, NULL).symbol;

      if (field->type
	  && TYPE_CODE (check_typedef (SYMBOL_TYPE (field->type)))
	  != TYPE_CODE_STRUCT)
	field->type = NULL;

      if (field->type != NULL)
	DEBUG (D_INIT, 4, "Checking for 'struct %s' : TYPEDEF\n",
	       field->struct_name);
      else
	DEBUG (D_INIT, 1, "Checking for 'struct %s' : NOT FOUND\n",
	       field->struct_name);
    }

  if (field->type == NULL
      || !find_struct_field (check_typedef (SYMBOL_TYPE (field->type)),
			     field->field_name, &field->offset, &field->size))
    {
      field->type = NULL;
      if (!check)
	error ("No such field %s::%s\n", field->struct_name,
	       field->field_name);

      return 0;
    }

  /* Chain initialized entries for cleanup. */
  field->next = field_info;
  field_info = field;

  DEBUG (D_INIT, 4, "%s::%s => offset %i  size %i\n", field->struct_name,
	 field->field_name, field->offset, field->size);
  return 1;
}

/* Cleanup all the field and address info that has been gathered. */
static void
fields_and_addrs_clear (void)
{
  struct field_info *next_field = field_info;
  struct addr_info *next_addr = addr_info;

  while (next_field)
    {
      next_field = field_info->next;
      field_info->type = NULL;
      field_info->next = NULL;
      field_info = next_field;
    }

  while (next_addr)
    {
      next_addr = addr_info->next;
      addr_info->bmsym.minsym = NULL;
      addr_info->bmsym.objfile = NULL;
      addr_info->next = NULL;
      addr_info = next_addr;
    }
}

/* If this returns true, we want to access the target registers and
 memory whatever the user nominated as the current task. */
static int
thread_awareness_inhibited (void)
{
  return !lkd_params.enable_task_awareness
    || _inhibit_thread_register_awareness;
}

/* See the description of _inhibit_thread_register_awareness. */
static void
thread_awareness_inhibit (void)
{
  ++_inhibit_thread_register_awareness;
}

/* See the description of _inhibit_thread_register_awareness. */
static void
thread_awareness_exhibit (void *unused)
{
  --_inhibit_thread_register_awareness;
}

/* Remove the trailing white spaces from target-root-prefix.
 FIXME: do this when the string is input, not all the time !
 */
void
sanitize_path (char *path)
{
  char *dir = path + strlen (path) - 1;
  while (dir > path && isspace (*dir))
    {
      *dir-- = '\0';
    };
  /* remove trailing '/' too.
   **/
  if (*dir == '/')
    *dir = '\0';
}

char *
linux_aware_get_target_root_prefix (void)
{
  if (target_root_prefix_dirty && *target_root_prefix)
    {
      sanitize_path (*target_root_prefix);
      target_root_prefix_dirty = 0;
    }
  return *target_root_prefix;
}

/* avoid error spamming*/
static CORE_ADDR last_warned = (CORE_ADDR) - 1;

static void
page_error_warn (enum page_status res, CORE_ADDR page)
{
  page = get_page (page);

  if (last_warned == page)
    return;

  printf_filtered ("Error translating memory address");

  switch (res)
    {
    case PAGE_SWAPPED:
      printf_filtered (", page 0x%s is swapped out.\n", phex (page, 4));
      break;
    case PAGE_NOTMAPPED:
      printf_filtered (", page 0x%s is not mapped to memory.\n",
		       phex (page, 4));
      break;
    case PAGE_NOPAGE:
      printf_filtered (", page 0x%s is not allocated yet.\n", phex (page, 4));
      break;
    default:
      printf_filtered (" in page 0x%s.\n", phex (page, 4));
    }
  last_warned = page;
}

inline void
page_error_clear (void)
{
  last_warned = (CORE_ADDR) - 1;
};

/* This function is used to prepare the target for an access at
 ADDR. The platform specific implementation of the Linux Awareness
 (called through linux_awareness_ops->lo_translate_memory_address)
 might choose to just prepare the H/W for the access, or to modify
 ADDR to point the physical location of the memory location. */
int
linux_aware_translate_address_safe (CORE_ADDR * addr, int silent)
{
  static int translating = 0;
  struct cleanup *cleanup;
  enum page_status res;
  process_t *ps;

  if (!lkd_params.enable_vm_translation)
    return 1;

  if (!linux_awareness_ops->lo_address_needs_translation (*addr))
    return 1;

  ps = lkd_proc_get_by_ptid (inferior_ptid);

  gdb_assert (ps);

  gdb_assert (!translating);

  /* if we need translation while we're translating, stop recursion: error. */
  cleanup = make_cleanup_restore_integer (&translating);
  translating = 1;

  thread_awareness_inhibit ();
  make_cleanup (thread_awareness_exhibit, NULL);

  res = linux_awareness_ops->lo_translate_memory_address (addr, ps);

  do_cleanups (cleanup);

  if (res != PAGE_PRESENT)
    {
      CORE_ADDR page = get_page (*addr);
      if (!silent)
	page_error_warn (res, page);

      return 0;
    }

  return 1;
}

/* Asks the platform specific layer if ADDR lies in a writable
 mapping. */
static int
page_writable (CORE_ADDR addr)
{
  if (!lkd_params.enable_vm_translation)
    return 1;

  return linux_awareness_ops->lo_can_write (addr,
					    lkd_proc_get_by_ptid
					    (inferior_ptid)->task_struct);
}

/****************************************************************************/

/* Reads the Linux version string from memory
 * into global lkd_private.utsname_release. */
static int
set_utsname_release (void)
{
  int i = 0;
  CORE_ADDR release_addr;
  asection *data;
  int ret = 0;
  int build = 0;

  gdb_assert (lkd_private.utsname_release);

  lkd_private.utsname_release[0] = '\0';
  lkd_private.utsname_release_valid = 0;

  /* Find the address of the string. */
  if (HAS_ADDR (init_uts_ns)
      && HAS_FIELD (uts_namespace, name) && HAS_FIELD (new_utsname, release))
    release_addr = ADDR (init_uts_ns)
      + F_OFFSET (uts_namespace, name) + F_OFFSET (new_utsname, release);
  else if (HAS_ADDR (system_utsname) && HAS_FIELD (new_utsname, release))
    release_addr = ADDR (system_utsname) + F_OFFSET (new_utsname, release);
  else
    return -1;

  ret = target_read_memory (release_addr,
			    (gdb_byte *) (lkd_private.utsname_release),
			    lkd_private.utsname_release_size);

  lkd_private.utsname_release_valid = ret ? 0 : 1;

  return ret;
}

/******************************************************************************/
/*****************              TASK AWARENESS               ******************/
/******************************************************************************/

/* target_ops callback that GDB queries to know if the given PTID is
 still an active task. */
static int
linux_aware_thread_alive (struct target_ops *ops, ptid_t ptid)
{
  /* if we are resetting the thread list, return false
   * because shtdi will return true for the h/w thread
   * and this would lead to keep a previous occurrence of the ptid.
   */
  if (lkd_private.loaded == LKD_LOADING)
    return 0;

  if (lkd_private.loaded == LKD_NOTLOADED)
    {
      if (BENEATH && BENEATH->to_thread_alive)
	return BENEATH->to_thread_alive (ops, ptid);
      return 0;			/* GDB default */
    }

  return (lkd_proc_get_by_ptid (ptid) != NULL);
}

/* target_ops callback that GDB queries to know core id of the given PTID. */
static int
linux_aware_core_of_thread (struct target_ops *ops, ptid_t ptid)
{
  if (lkd_private.loaded == LKD_LOADED)
    return lkd_proc_core_of_thread (ptid);
  else if (BENEATH->to_core_of_thread)
    return BENEATH->to_core_of_thread (ops, ptid);

  return CORE_INVAL;
}

/* target_ops callback that GDB queries add new threads to its thread
 list. */
static void
linux_aware_update_thread_list (struct target_ops *ops)
{
  if (lkd_private.loaded != LKD_LOADED)
    {
      /* in case the user attaches, but did not yet set the target pack. */
      if (BENEATH->to_update_thread_list)
	BENEATH->to_update_thread_list (ops);	/* may not exist */
    }
  else
    lkd_proc_get_list ();
}

/*
 * the default post exec stop handler tries  to activatie L-A
 * if it previously failed
 **/
static void
linux_aware_post_exec_stop (int step)
{
  if (!step && lkd_private.connected	/*make sure kernel code is in target-ram */
      && (lkd_private.loaded == LKD_NOTLOADED)
      && (lkd_params.auto_activate == 1))
    {
      CORE_ADDR pc = regcache_read_pc (get_current_regcache ());

      /* if we broke in start_kernel, we may be about to execute
       * the user "set" commands, do not rely on lkd_params yet.
       **/
      if (pc == ADDR (start_kernel))
	return;
      /* In case we need to delay set loaded by the time the mmu is correctly set,
       * this will be set at latest by the time the user breaks
       **/
      lkd_params.loaded = LKD_LOADED;
      lkd_loaded_set (NULL, 0, NULL);
    }
}

extern void nullify_last_target_wait_ptid (void);

static int
dump_thread_list (struct thread_info *tp, void *ignored)
{
  printf_filtered ("thread_list: {%d.%d}= {%d-%ld-%ld}\n",
		   tp->global_num, tp->per_inf_num,
		   ptid_get_pid (tp->ptid),
		   ptid_get_lwp (tp->ptid), ptid_get_tid (tp->ptid));
  return 0;
}

void
lkd_reset_thread_list (void)
{
  struct thread_info *tp = NULL;
  int pid = ptid_get_pid (inferior_ptid);
  int loaded_state = lkd_private.loaded;
  struct cleanup *cleanup;

  switch_to_thread (null_ptid);	/* Ensure inferior_ptid is invalid.  */

  /* remove all gdb threads, we need to call this as
   * gdb and complying targets assume there is always a thread
   * but we need to manage our own thread numbering.
   */
  init_thread_list ();

  DBG_IF (D_INIT)
	iterate_over_threads (dump_thread_list, NULL);
  DBG_ENDIF (D_INIT)
    /* setup LKD "thread alive" method to return FALSE and "find new threads"
       method to call the BENEATH version */
    lkd_private.loaded = LKD_LOADING;

  cleanup = make_cleanup_restore_integer (&print_thread_events);
  print_thread_events = 0;
  update_thread_list ();
  do_cleanups (cleanup);

  DBG_IF (D_INIT)
	iterate_over_threads (dump_thread_list, NULL);
  DBG_ENDIF (D_INIT)

  tp = any_live_thread_of_process (pid);
  gdb_assert (tp != NULL);	/* A live thread must exist.  */
  switch_to_thread (tp->ptid);

  /* make sure update_inferior_thread will not switch to a wait_ptid
   * that is no-more upon resuming
   */
  nullify_last_target_wait_ptid ();

  /* return LKD "thread alive" and "find new threads" methods to their
     natural states */
  lkd_private.loaded = loaded_state;
}

/* target_ops callback that GDB queries to translate a PTID to a human
 readable string to display. */
static char *
linux_aware_pid_to_str (struct target_ops *ops, ptid_t ptid)
{
  process_t *ps;
  struct thread_info *tp;

  if (lkd_private.loaded == LKD_NOTLOADED)
    {
      if (BENEATH && BENEATH->to_pid_to_str)
	return BENEATH->to_pid_to_str (ops, ptid);
      return normal_pid_to_str (ptid);	/* GDB default */
    }

  if (!ptid_get_tid (ptid))	/* when quitting typically */
    return "Linux Kernel";

  tp = find_thread_ptid (ptid);

  if (!tp || !tp->priv)
    return "";

  /* we use the gdb thread private field for storing the process_t */
  ps = (process_t *) tp->priv;

  gdb_assert (ps->comm);
  return ps->comm;
}

/* extra informations with display options
 **/
static char *
extra_thread_info_ext (struct thread_info *thread)
{
  static char msg[256];
  char *pos = msg, *ret;
  process_t *ps;
  int core;

  if (!(tui_active || lkd_params.no_colors))
    pos += sprintf (pos, "\e[30m");
  else
    *pos = '\0';
  ret = pos;			/* skip color setting by default */

  ps = (process_t *) thread->priv;

  DBG_IF (TASK) if (!ps)
    {
      printf_filtered ("thread_info %p not found in process_list\n",
		        thread);
      printf_filtered ("  thread_info.ptid = {%d, %ld, %ld}\n",
		       ptid_get_pid (thread->ptid),
		       ptid_get_lwp (thread->ptid),
		       ptid_get_tid (thread->ptid));
      printf_filtered ("  thread_info.num = %d.%d\n", thread->global_num, thread->per_inf_num);
    }
  DBG_ENDIF (TASK) if (ps)
    {
      core = ps->core;

      DBG_IF (TASK) if (core != CORE_INVAL)
	pos += sprintf (pos,
			"lwp=%li, tid=%li, gdbt=%lx, task_str=%lx-%lx",
			ptid_get_lwp (PTID_OF (ps)),
			ptid_get_tid (PTID_OF (ps)),
			(unsigned long) ps->gdb_thread,
			(unsigned long) ps->task_struct,
			(unsigned long) lkd_proc_get_rq_curr (core));
      else
	pos += sprintf (pos,
			"lwp=%li, tid=%li, gdbt=%lx, task_str=%lx",
			ptid_get_lwp (PTID_OF (ps)),
			ptid_get_tid (PTID_OF (ps)),
			(unsigned long) ps->gdb_thread,
			(unsigned long) ps->task_struct);
      DBG_ELSE if (ps->tgid == ptid_get_lwp (PTID_OF (ps)))
	/* thread group leader */
	pos += sprintf (pos, "TGID:%i", ps->tgid);
      else
	/* thread of a thread group */
	pos += sprintf (pos, "|----%li", ptid_get_lwp (PTID_OF (ps)));
      DBG_ENDIF (TASK) if (lkd_proc_is_curr_task (ps))
	{
	  pos += sprintf (pos, " <C%u>", core);

	  /* highlight currently running threads */
	  if (!(tui_active || lkd_params.no_colors))
	    {
	      ret = msg;
	      msg[3] = '1' + (2 * core);
	      strcpy (pos, "\e[m");
	    }
	}
    }

  return ret;
}

/* target_ops callback that GDB queries to get extra information to
 display for a given thread. */
static char *
linux_aware_extra_thread_info (struct target_ops *ops, struct thread_info *thread)
{
  if (lkd_private.loaded == LKD_LOADED)
    {
      /* FIXME: Bodge for STWorkbench which expects different format */
      if (lkd_params.no_colors)
	{
	  process_t *ps = (process_t *) thread->priv;

	  if (ps)
	    {
	      static char msg[256];
	      char *pos = msg;

	      pos += sprintf (pos, "pid: %li tgid: %i",
			      ptid_get_lwp (PTID_OF (ps)), ps->tgid);
	      if (lkd_proc_is_curr_task (ps))
		sprintf (pos, " <C%u>", ps->core);

	      return msg;
	    }
	}
      else
	return extra_thread_info_ext (thread);
    }
  else if (BENEATH->to_extra_thread_info)
    return BENEATH->to_extra_thread_info (ops, thread);

  return "";
}

static const char *
linux_aware_thread_name (struct target_ops * ops, struct thread_info * thread)
{
	/* All the thread name information has generally been
	 * returned already through the pid_to_str.
	 *
	 * We could refactor this around and 'correct' the naming
	 * but then you wouldn't get niceties such as
	 *    [Switching to thread 52 (getty)]
	 */

	return NULL;
}

/* target_ops callback queried by GDB to read the registers of the
 currently selected task. */
static void
linux_aware_fetch_registers (struct target_ops *ops,
			     struct regcache *rc, int regno)
{
  struct cleanup *cleanup;
  process_t *ps;
  int res;

  DEBUG (TARGET, 2, "fetch_registers %i\n", regno);

  if ((lkd_private.loaded != LKD_LOADED)	/*check this first */
      || !(ps = lkd_proc_get_by_ptid (inferior_ptid))
      || lkd_proc_is_curr_task (ps))
    return BENEATH->to_fetch_registers (ops, rc, regno);

  /* Call the platform specific code. */
  thread_awareness_inhibit ();
  cleanup = make_cleanup (thread_awareness_exhibit, NULL);
  res =
    linux_awareness_ops->lo_fetch_context_register (regno, ps->task_struct);
  do_cleanups (cleanup);

  if (!res)
    warning ("Could not fetch task register.");

  return;
}

/* target_ops callback queried by GDB to write the registers of the
 currently selected task. */
static void
linux_aware_store_registers (struct target_ops *ops,
			     struct regcache *rc, int regno)
{
  struct cleanup *cleanup;
  process_t *ps;
  int res;

  DEBUG (TARGET, 2, "store_registers %i\n", regno);

  if ((lkd_private.loaded != LKD_LOADED)	/*check this first */
      || !(ps = lkd_proc_get_by_ptid (inferior_ptid))
      || lkd_proc_is_curr_task (ps))
    return BENEATH->to_store_registers (ops, rc, regno);

  /* Call the platform specific code. */
  thread_awareness_inhibit ();
  cleanup = make_cleanup (thread_awareness_exhibit, NULL);
  res =
    linux_awareness_ops->lo_store_context_register (regno, ps->task_struct);
  do_cleanups (cleanup);

  if (res)
    warning ("Could not store task register.");

  return;
}

/*****************************************************************************/
/*                 EXECUTION CONTROL / TARGET_OPS INTEGRATION                */
/*****************************************************************************/
/* We need to access some information that is stored within the
 breakpoints structure, but only 'struct bp_target_info' is passed
 to insert|remove_breakpoint. This function returns the 'struct
 bp_location' corresponding to INFO, or NULL (for the software
 singlestep breakpoint). */
static struct bp_location *
bp_location_from_shadow_contents (struct bp_target_info *info)
{
  struct bp_location *bp_loc;

  bp_loc =
    (struct bp_location *) ((char *) info -
			    offsetof (struct bp_location, target_info));
  if (bp_loc->address != info->placed_address
      || bp_loc->requested_address != info->placed_address)
    {
      warning
	("Unknown bp location passed to target: placed@= %s, requested@= %s.",
	 phex (info->placed_address, 4), phex (bp_loc->requested_address, 4));
      return NULL;
    }

  return bp_loc;
}

/* This is the target_ops callback that is called by GDB to insert a
 breakpoint. After having prepared the access, it calls back to the
 real underlying target_ops to do the insertion. */
static int
linux_aware_insert_breakpoint (struct target_ops *ops,
			       struct gdbarch *gdbarch,
			       struct bp_target_info *info)
{
  struct cleanup *cleanup = make_cleanup (null_cleanup, NULL);
  struct bp_location *bp_loc;
  int res;
  CORE_ADDR v_addr = info->placed_address;
  CORE_ADDR p_addr = v_addr;

  if (lkd_private.loaded != LKD_LOADED)
    return BENEATH->to_insert_breakpoint (ops, gdbarch, info);

  bp_loc = bp_location_from_shadow_contents (info);

  if (bp_loc == NULL)
    DEBUG (BP, 1, "bp is SS ??\n");

  /* We use this convention to prevent some breakpoints from being inserted.
     Also we do not allow breakpoints to be set in user space.  */
  if (v_addr == ~(CORE_ADDR) 0)
    return 0;
  else if (linux_awareness_ops->lo_is_user_address (v_addr))
    {
      DEBUG (BP, 1, "inserting user space bp at %s\n", phex (v_addr, 4));
      if (bp_loc != NULL && bp_loc->owner->number < 0)
	/* Lie to GDB that breakpoint has been set if a "special" hidden
	   breakpoint (RnDCT00013003 workaround).  */
	return 0;
      else
	{
	  warning ("User space breakpoints not supported");
	  return 1;
	}
    }

  disable_terminate ();

  /* Prepare the access. */
  if (!linux_aware_translate_address_safe (&p_addr, 1))
    {
      enable_terminate ();
      DEBUG (BP, 1, "error inserting bp at 0x%x\n", (unsigned int) p_addr);
      return 1;
    }

  /* If the platform specific layer has modified the address we
     need to make sure there's no cache line for the real
     address, or this unpatched cache line might be used
     instead of our patched instruction. */
  if (info->placed_address != p_addr)
    {
      info->placed_address = p_addr;
      thread_awareness_inhibit ();
      make_cleanup (thread_awareness_exhibit, NULL);
      linux_awareness_ops->lo_flush_cache (info->placed_address,
					   p_addr, 2, 1);
    }

  res = BENEATH->to_insert_breakpoint (ops, gdbarch, info);


  if (info->placed_address != v_addr)
    {
      info->placed_address = v_addr;
      /* Again cache handling: remove aliases introduced by our
         de-routed access. */
      linux_awareness_ops->lo_flush_cache (p_addr, p_addr, 2, 1);
    }

  do_cleanups (cleanup);

  if (!res)
    {
      struct minimal_symbol *msymbol =
	lookup_minimal_symbol_by_pc (info->placed_address).minsym;
      DEBUG (BP, 1, "Insert @ 0x%x - %s\n", (unsigned int) p_addr,
	     (msymbol && msymbol->mginfo.name) ? msymbol->mginfo.name : "???");
    }

  enable_terminate ();
  return res;
}

/* Same as linux_aware_insert_breakpoint, but for removing
 breakpoints. */
static int
linux_aware_remove_breakpoint (struct target_ops *ops,
			       struct gdbarch *gdbarch,
			       struct bp_target_info *info)
{
  struct cleanup *cleanup = make_cleanup (null_cleanup, NULL);
  struct bp_location *bp_loc;
  ptid_t saved_ptid = inferior_ptid;
  int res;
  CORE_ADDR addr = info->placed_address;
  CORE_ADDR requested_addr = addr;
  CORE_ADDR saved_addr;

  if (lkd_private.loaded != LKD_LOADED)
    return BENEATH->to_remove_breakpoint (ops, gdbarch, info);

  bp_loc = bp_location_from_shadow_contents (info);

  if (addr == ~(CORE_ADDR) 0)
    return 0;
  else if (linux_awareness_ops->lo_is_user_address (addr))
    {
      DEBUG (BP, 1, "removing user space bp at %s\n", phex (addr, 4));
      if (bp_loc != NULL && bp_loc->owner->number < 0)
	/* Lie to GDB that breakpoint has been removed if a "special" hidden
	   breakpoint since never set (RnDCT00013003 workaround).  */
	return 0;
      else
	{
	  internal_error (__FILE__, __LINE__,
			  "removing user space breakpoint");
	  return 1;
	}
    }

  disable_terminate ();

  if (bp_loc != NULL)
    {
      if (bp_loc->owner->thread != -1)
	inferior_ptid = global_thread_id_to_ptid (bp_loc->owner->thread);
    }

  if (!linux_aware_translate_address_safe (&addr, 1))
    {
      DEBUG (BP, 1, "\tError translating address\n");
      inferior_ptid = saved_ptid;

      if (bp_loc != NULL
	  && bp_loc->owner->thread != -1
	  && linux_awareness_ops->lo_is_user_address (bp_loc->address))
	{
	  warning
	    ("The page containing breakpoint %i seems to have been unmapped from memory\n"
	     "You will need to reset the breakpoint.", bp_loc->owner->number);
	  // disable_breakpoint (bp_loc->owner);
	}

      enable_terminate ();
      return 1;
    }

  if (requested_addr != addr)
    {
      thread_awareness_inhibit ();
      make_cleanup (thread_awareness_exhibit, NULL);
      linux_awareness_ops->lo_flush_cache (requested_addr, addr, 2, 1);
      DEBUG (BP, 1, "\t real addr 0x%x\n", (unsigned int) addr);
    }

  /* Pass the translated address down, but keep the original value in
     info->placed_address. */
  saved_addr = info->placed_address;
  info->placed_address = addr;

  res = BENEATH->to_remove_breakpoint (ops, gdbarch, info);

  info->placed_address = saved_addr;

  if (requested_addr != addr)
    linux_awareness_ops->lo_flush_cache (addr, addr, 2, 1);

  do_cleanups (cleanup);

  if (!res)
    {
      struct minimal_symbol *msymbol =
	lookup_minimal_symbol_by_pc (info->placed_address).minsym;
      DEBUG (BP, 1, "remove @ 0x%x - %s\n", (unsigned int) addr,
	     (msymbol && msymbol->mginfo.name) ? msymbol->mginfo.name : "???");
    }

  inferior_ptid = saved_ptid;
  enable_terminate ();
  return res;
}

/* This is the target_ops callback that is called by GDB to insert a
 H/W breakpoint. No special treatment from the Linux Awareness
 layer. */
static int
linux_aware_insert_hw_breakpoint (struct target_ops *ops,
				  struct gdbarch *gdbarch,
				  struct bp_target_info *info)
{
  int ret = 0;
  __trgt_time_start_
    DEBUG (BP, 1, "inserting hw bp at 0x%x\n",
	   (unsigned int) info->placed_address);

  ret = BENEATH->to_insert_hw_breakpoint (ops, gdbarch, info);
  __trgt_time_appen_ return ret;
}

/* This is the target_ops callback that is called by GDB to remove a
 H/W breakpoint. No special treatment from the Linux Awareness
 layer. */
static int
linux_aware_remove_hw_breakpoint (struct target_ops *ops,
				  struct gdbarch *gdbarch,
				  struct bp_target_info *info)
{
  int ret = 0;
  DEBUG (BP, 1, "removing hw bp at 0x%x\n",
	 (unsigned int) info->placed_address);

  ret = BENEATH->to_remove_hw_breakpoint (ops, gdbarch, info);

  return ret;
}


/* Linux will copy to memory userspace pages when they are first
 accessed. It means that the user can request to display the contents
 of a memory location that isn't yet available in RAM. However, if
 that address corresponds to a file mapping and if the
 target-root-prefix is set, then the debugger ought to be able to
 find the memory contents directly in the corresponding file. This
 is implemented by the below read_from_file() and
 get_file_mapped_data() functions.

 These variables define a cache that is used to avoid to repeatedly
 open/close the same file. */
static CORE_ADDR cache_task_struct;
static int cache_pid;
static CORE_ADDR cache_start;
static CORE_ADDR cache_end;
static unsigned int cache_pgoff;
static FILE *cached_file;

/* Helper for get_file_mapped_data(). FILE points to the 'struct
 file' describing the file we have to read from. */
static int
read_from_file (CORE_ADDR file, CORE_ADDR start, unsigned int pgoffset,
		CORE_ADDR addr, unsigned int len, gdb_byte * myaddr,
		FILE * file_desc)
{
  char *filename;
  unsigned int page_shift = linux_awareness_ops->page_shift;
  unsigned int in_page_offset = addr & ((1 << page_shift) - 1);
  unsigned int page_len = (1 << page_shift) - in_page_offset;

  pgoffset += (addr - start) >> page_shift;

  if (file_desc == NULL)
    {
      CORE_ADDR dentry;
      unsigned int len;

      dentry = read_pointer_embedded_field (file, file, f_path, path, dentry);

      filename = read_dentry (dentry);

      if (filename == NULL)
	return -1;

      len = strlen (filename) + strlen (*target_root_prefix) + 1;
      filename = xrealloc (filename, len);
      memmove (filename + strlen (*target_root_prefix),
	       filename, strlen (filename) + 1);
      memcpy (filename, *target_root_prefix, strlen (*target_root_prefix));

      DEBUG (VM, 2, "Trying to read %s from %s\n", phex (addr, 4), filename);

      file_desc = fopen (filename, "r");
      xfree (filename);

      if (file_desc == NULL)
	return -1;
    }

  /* Never cross a page boundary.  */
  len = len > page_len ? page_len : len;

  if (fseek
      (file_desc, in_page_offset + pgoffset * (1 << page_shift), SEEK_SET))
    {
      fclose (file_desc);
      return -1;
    }

  if ((len = fread (myaddr, len, 1, file_desc)) <= 0)
    {
      fclose (file_desc);
      return -1;
    }

  if (cached_file != NULL && cached_file != file_desc)
    {
      fclose (cached_file);
    }

  cached_file = file_desc;
  return len;
}

/* ADDR isn't currently mapped to memory. If it lies in a file
 mapping, try to read LEN bytes corresponding to that address from
 the file. MYADDR points to the buffer receiving the data. */
static int
get_file_mapped_data (CORE_ADDR addr, gdb_byte * myaddr, int len)
{
  process_t *ps;
  CORE_ADDR task;
  enum page_status stat;
  CORE_ADDR memaddr = addr;
  CORE_ADDR mm, mmap;

  if (lkd_private.loaded != LKD_LOADED)
    {
      printf_filtered (LA_NOT_LOADED_STRING);
      return -1;
    }

  ps = lkd_proc_get_by_ptid (inferior_ptid);
  task = ps->task_struct;

  /* If the address is in the cache read from it. */
  if (cache_task_struct == task
      && cache_pid == ptid_get_lwp (PTID_OF (ps))
      && cache_start <= addr && cache_end > addr)
    {
      int res;
      res = read_from_file (0, cache_start, cache_pgoff,
			    addr, len, myaddr, cached_file);
      if (res < 0)
	{
	  cache_task_struct = 0;
	  cache_pid = 0;
	  cache_start = 0;
	  cache_end = 0;
	  cached_file = NULL;	/* fclosed by read_from_file.  */
	}
      return res;
    }

  stat = linux_awareness_ops->lo_translate_memory_address (&memaddr, ps);

  DEBUG (VM, 2, "Looking if we can read %s from a file\n", phex (addr, 4));

  /* Check for a file mapping. */
  if (stat != PAGE_NOPAGE && stat != PAGE_NOTMAPPED)
    return -1;

  /* Get the mm field for the task. */
  mm = read_pointer_field (task, task_struct, mm);

  if (!mm)
    /* No mm: kernel thread. This shouldn't happen as kernel
       thread can't have a file mapping... */
    return -1;

  /* Walk the list of vmas for the current process and find the one
     Corresponding to the requested address. */
  mmap = read_pointer_field (mm, mm_struct, mmap);
  while (mmap)
    {
      CORE_ADDR file;

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_GROWSUP	0x00000200

      CORE_ADDR start, end;

      start = read_pointer_field (mmap, vm_area_struct, vm_start);
      end = read_pointer_field (mmap, vm_area_struct, vm_end);

      if (start > addr || end <= addr)
	{
	  /* Address does not match, go to the next VMA. */
	  mmap = read_pointer_field (mmap, vm_area_struct, vm_next);
	  continue;
	}

      /* Get corresponding file. */
      file = read_pointer_field (mmap, vm_area_struct, vm_file);

      if (file)
	{
	  int res;
	  unsigned int pgoff = read_unsigned_field (mmap,
						    vm_area_struct,
						    vm_pgoff);
	  res = read_from_file (file, start, pgoff, addr, len, myaddr, NULL);

	  if (res > 0)
	    {
	      /* Populate cache. */
	      cache_task_struct = task;
	      cache_pid = ptid_get_lwp (PTID_OF (ps));
	      cache_start = start;
	      cache_end = end;
	      cache_pgoff = pgoff;
	    }

	  return res;
	}
      else
	{
	  return -1;
	}
#undef VM_READ
#undef VM_WRITE
#undef VM_EXEC
#undef VM_SHARED

#undef VM_MAYREAD
#undef VM_MAYWRITE
#undef VM_MAYEXEC
#undef VM_MAYSHARE

#undef VM_GROWSDOWN
#undef VM_GROWSUP
    }

  return -1;
}



static enum target_xfer_status
linux_aware_xfer_partial (struct target_ops *ops, enum target_object object,
			  const char *annex, gdb_byte * readbuf,
			  const gdb_byte * writebuf, ULONGEST offset,
			  ULONGEST len, ULONGEST *xfered_len)
{
    int res = 0;
    enum target_xfer_status status;
    static int countt = 0;
    CORE_ADDR page_end, orig_addr = offset;
    int page_incr = 1 << linux_awareness_ops->page_shift;
    int write = (writebuf ? 1 : 0);

    gdb_assert( !(readbuf && writebuf) );

    /* protect against too early accesses to RAM with "-ex" command
     * typically, while targetpack is not yet configured.
     */
    if (!BENEATH->to_xfer_partial)
      {
        DEBUG (D_INIT, 1,
	     "failed trying to %s %lld bytes @0x%lx while not accessing target\n",
	     (writebuf ? "WRITE" : "READ"), len, (unsigned long) offset );

        return TARGET_XFER_UNAVAILABLE;
      }

    /*just don't deal with it if we're not yet loaded !
     **/
    if (lkd_private.loaded != LKD_LOADED)
      return BENEATH->to_xfer_partial (ops, object, annex, readbuf, writebuf,
					offset, len, xfered_len);

    DEBUG (TARGET, 2,
	 "linux_aware_xfer_partial(%d):\t%s %lld bytes @ 0x%lx\n",
	 countt++, (writebuf ? "WRITE" : "READ"), len, (unsigned long) offset);

    if (readbuf && offset < 4096)
      {
	/* Perhaps overkill... */
	if (offset + len > 4096)
	    len -= (offset + len) & (4096 - 1);

        /* Just avoid those buggy accesses to the zero page. Nothing
           can come from there. */
        memset (readbuf, 0, len);
        *xfered_len = len;
        return TARGET_XFER_OK;
      }

    if (!linux_aware_translate_address_safe ((CORE_ADDR*)&offset, 0))
      {

        /* Can't translate the address, but maybe we can get the
           contents from an underlying file. */
        if (readbuf)
	{
	  res = get_file_mapped_data (offset, readbuf, len);

	  if (res >= 0)
	    return TARGET_XFER_UNAVAILABLE;
	}

        /* Don't report an error, but do what GDB would do on
         * memory access error : read zero and do nothing on
         * write. The error has been reported to the user. If we
         * report an error, then the target beneath will be called
         * and do useless things. See target.c:target_xfer_memory
         **/
        if (readbuf)
            memset (readbuf, 0, len);

        return len;
      }

    /* Read at most one page: contiguous virtual address spaces
       doesn't map to contiguous physical memory.
       The calling memory access code will handle the loop for us. */
    page_end = (orig_addr & ~(CORE_ADDR) (page_incr - 1)) + page_incr;
    len = min (len, (int) (page_end - orig_addr));

    /* KPB-Porting: This following statement can never be true????
     * The orig_addr is set to offset above and never modified after
     * Never mind - The lo_flush_cache isn't even implemented on lkd-arm yet ...
     * So it looks like this has come from SH ? */
    if (orig_addr != offset && (writebuf || page_writable (orig_addr)))
	/* Flush the virtual address cache line. */
	linux_awareness_ops->lo_flush_cache (orig_addr, offset, len, write);


    status = BENEATH->to_xfer_partial (ops, object, annex, readbuf, writebuf,
				offset, len, xfered_len);

    if (orig_addr != offset)
	/* Flush the aliased physical address cache line. */
	linux_awareness_ops->lo_flush_cache (offset, offset, len, write);

    return status;
}

/* If the system gets low on memory, we simply disable userspace
 breakpoints, as it might start to unmap userspace pages. */
static void
disable_userspace_breakpoints (void)
{
  struct breakpoint *bp;
  int disabled = 0;

  ALL_BREAKPOINTS (bp)
    if (bp->loc
	&& bp->enable_state == bp_enabled
	&& bp->loc->loc_type == bp_loc_software_breakpoint
	&& linux_awareness_ops->lo_is_user_address (bp->loc->address))
    {
      bp->enable_state = bp_disabled;
      ++disabled;
    }

  if (disabled)
    warning
      ("Your target system is getting low on memory. Userspace debugging will\n"
       "become unreliable due to code memory getting unmapped. All the userspace\n"
       "breakpoints have been disabled.");
}

/* This is the target_ops callback that is called by GDB to start the
 execution of the processor. */
static void
linux_aware_resume (struct target_ops *ops,
		    ptid_t pid, int step, enum gdb_signal sig)
{
  struct cleanup *cleanup;

  DEBUG (TARGET, 1, "Resuming %i with sig %i (step %i)\n",
	 (int) ptid_get_pid (pid), (int) sig, step);

  /* Store the last execution request type. See the stepping
     variable comment above, and the usage in linux_aware_wait. */
  lkd_stepping = step;

  /* Call platform dependant resume callback if needed. */
  if (linux_awareness_ops->lo_pre_exec_start)
    {
      thread_awareness_inhibit ();
      cleanup = make_cleanup (thread_awareness_exhibit, NULL);
      linux_awareness_ops->lo_pre_exec_start ();
      do_cleanups (cleanup);
    }

  if (lkd_private.loaded != LKD_LOADED)
    return BENEATH->to_resume (ops, pid, step, sig);

  if (thread_event_do_exec_bp && thread_event_do_exec_return_bp)
    {
      delete_breakpoint (thread_event_do_exec_bp);
      thread_event_do_exec_bp = NULL;
    }

  lkd_uninstall_do_exit_event ();

  /* Before restarting first need to clear some caches.  */
  thread_awareness_inhibit ();
  cleanup = make_cleanup (thread_awareness_exhibit, NULL);
  linux_awareness_ops->lo_clear_cache ();
  do_cleanups (cleanup);

  /* Perform the execution request. */
  BENEATH->to_resume (ops, pid, step, sig);

  /* Forget about last memory access error. */
  page_error_clear ();

  /* Set the running flag. (See the variable's comment). */
  running = 1;
}

/* This is the target_ops callback that is called by GDB to wait for the
 processor to stop executing. */
static ptid_t
linux_aware_wait (struct target_ops *ops,
		  ptid_t ptid, struct target_waitstatus *status, int opts)
{
  struct cleanup *cleanup;
  ptid_t stop_ptid;

  /* Disable the Linux Awareness AutoLoad feature for now, as it is buggy with Qemu */
  if (lkd_private.loaded != LKD_LOADED)
    return BENEATH->to_wait (ops, ptid, status, opts);

  if (thread_awareness_inhibited () || !(lkd_private.kflags & KFLAG_DBGINFO))
    return BENEATH->to_wait (ops, ptid, status, opts);

  /* We aren't running anymore. */
  running = 0;

  /* The linux aware wait begins here. */
  thread_awareness_inhibit ();
  cleanup = make_cleanup (thread_awareness_exhibit, NULL);

  stop_ptid = BENEATH->to_wait (ops, ptid, status, opts);
  if (max_cores > 1)
    stop_core = ptid_get_tid (stop_ptid) - 1;
  else
    stop_core = 0;

  disable_terminate ();

  /*reset the inferior_ptid to the stopped ptid */
  inferior_ptid = stop_ptid;

  /* if we are not just stepping, check for auto-activation */
  linux_aware_post_exec_stop (lkd_stepping);

  if (lkd_private.loaded == LKD_LOADED)
    {
      CORE_ADDR pc;
      CORE_ADDR task;
      int i;
      struct regcache *regcache;

      /* tweak user experience... */
#ifdef AUTO_ASM
      disassemble_next_line =
	tui_active ? AUTO_BOOLEAN_FALSE : AUTO_BOOLEAN_TRUE;
#endif

      /* rescan for new task, but avoid storming the debug connection
       **/
      lkd_proc_refresh_info (stop_core);

      /* The above calls might will end up accessing the registers
         of the target because of inhibit_thread_awareness(). However,
         this will populate a register cache associated with
         inferior_ptid, which we haven't updated yet. Force a flush
         of these cached values so that they end up associated to
         the right context. */
      registers_changed ();

      /* This is normally done by infrun.c:handle_inferior_event (),
         but we need it set to access the frames for some operations
         below (eg. in check_exec_actions (), where we don't know
         what the user will ask in his commands. */
      set_executing (minus_one_ptid, 0);

      regcache = get_thread_regcache (inferior_ptid);

      pc = regcache_read_pc (regcache);

      /*
       * Handle the installation of the module's specific init routine hook.
       **/
      thread_awareness_inhibit ();
      make_cleanup (thread_awareness_exhibit, NULL);

      /* pull-in the symbols of each core's running process if auto-debug
       * is activated
       **/
      target_root_prefix_dirty = 1;	// fixme: code a proper command handler.

      /* automatically pull symbols, but for that user-mode thread that
       * was responsible for the event only, if any.
       **/
      lkd_proc_read_symbols ();

      /* Do the symbol tables modification to reflect the
         namespace of the current process. */
      lkd_proc_set_symfile ();

      if (IS_LOC (pc, thread_event_low_mem_bp))
	{
	  disable_userspace_breakpoints ();
	}
      else if (IS_LOC (pc, thread_event_do_exec_bp))
	{
	  CORE_ADDR a =
	    linux_awareness_ops->lo_return_address_at_start_of_function ();
	  thread_event_do_exec_return_bp =
	    create_thread_event_breakpoint (target_gdbarch (), a);
	}
      else if (IS_LOC (pc, thread_event_do_exec_return_bp))
	{
	  /* Call potential actions set by the user with the
	     wait_exe command. */
	  check_exec_actions ();
	}
      else if (IS_LOC (pc, thread_event_do_exit_bp) && wait_process)
	{
	  lkd_proc_remove_bpts (wait_process);
	}
      /* wait_process is non-null once we've successfully loaded lkd,
       * and we could compute the current process for that core.
       **/
      if (wait_process)
	{
	  inferior_ptid = PTID_OF (wait_process);
	  stop_ptid = inferior_ptid;
	}
    }

  do_cleanups (cleanup);

  enable_terminate ();

  return stop_ptid;
}

/*
 * arch-common post load op
 **/

/*
 * try to find a BFD
 **/
static bfd *
get_cur_bfd (int from_tty)
{
  /*give precedence to symfile */
  if (symfile_objfile && symfile_objfile->obfd)
    return symfile_objfile->obfd;

  if (from_tty && !exec_bfd)
    printf_filtered ("No executable file specified\n");

  return exec_bfd;
}

/* the post load hook, and the callback to re-install
 * what ever LKD patches into the gdb arch.*/
static void
linux_aware_post_load (char *prog, int fromtty)
{
  DEBUG (D_INIT, 1, "linux_aware_POST_load %s\n", prog);

  /*let the arch specific part decide when loaded = 1 */
  if (linux_awareness_ops->lo_post_load)
    linux_awareness_ops->lo_post_load (prog, fromtty);

  /* make sure the solib ops are installed if the user asked for
   * support. */
  if (lkd_params.enable_module_load)
    enable_module_events_command (NULL, 0, NULL);
}

/* The target_ops callback called by GDB to load the debugged program
 to the target. Just a wrapper for BENEATH->to_load with hooks that
 call into the platform specific part. */
static void
linux_aware_load (struct target_ops *ops, const char *prog, int fromtty)
{
  DEBUG (D_INIT, 1, "linux_aware_load %s\n", prog);

  /* make sure the load conditions are met, so that putting
     'set linux-awareness loaded 1' in his .shgdbinit file does not crash. */

  if ((BENEATH->to_shortname[0] == 'e' /*exec */ )
      || (BENEATH->to_shortname[0] == 'n' /*none */ ))
    {
      execute_command ("maint print target-stack", 0);
      error ("underlying target is not valid (might be exec or none).\n");
    }

  BENEATH->to_load (ops, prog, fromtty);

  lkd_params.loaded = LKD_NOTLOADED;
  lkd_private.loaded = LKD_NOTLOADED;

  if (lkd_params.auto_activate)
    {
      lkd_params.loaded = LKD_LOADED;
      lkd_loaded_set (0, 0, 0);
    }

  lkd_private.connected = 1;
}

/* The target_ops callback called by GDB to load the attach to an
 already running program. Just sets 'loaded' to 1, as the program is
 already loaded. If you attach with a non standard command, you have
 to do 'set linux-awareness loaded 1' by hand. */
static void
linux_aware_attach (struct target_ops *ops, const char *prog, int fromtty)
{
  DEBUG (D_INIT, 1, "linux_aware_attach %s\n", prog);

  if (BENEATH
      && BENEATH->to_attach != NULL)
    BENEATH->to_attach (ops, prog, fromtty);

  if (lkd_params.auto_activate)
    {
      lkd_params.loaded = LKD_LOADED;
      lkd_loaded_set (0, 0, 0);
    }

  lkd_private.connected = 1;
  DEBUG (TARGET, 3, "end linux_aware_attach %s\n", prog);
}

/* Used to trigger the disconnection. */
static void
linux_aware_disconnect (struct target_ops *target, const char *args, int from_tty)
{
  DEBUG (D_INIT, 1, "linux_aware_disconnect\n");

  unpush_target (&linux_aware_ops);
  target_disconnect (args, from_tty);

  lkd_private.connected = 0;
}

/* This callback is called on 'normal stop', ie. when the user gets
 the control back. We do various bookkeeping at this point. */
static void
normal_stop_callback (struct bpstats *bs, int unsused)
{
  /* If there's no userspace breakpoint left, remove the breakpoints
     we use to notify about conditions we need to handle like 'out of
     memory' or 'process exit'. */
  if (thread_event_low_mem_bp != NULL)
    {
      int has_bp = 0;
      struct bp_location *loc;
      struct breakpoint *bp;

      ALL_BREAKPOINTS (bp) for (loc = bp->loc; loc; loc = loc->next)
	{
	  if (loc->address
	      && linux_awareness_ops->lo_is_user_address (loc->address))
	    {
	      has_bp = 1;
	      break;
	    }
	}

      if (!has_bp)
	{
	  if (thread_event_low_mem_bp != NULL)
	    {
	      delete_breakpoint (thread_event_low_mem_bp);
	      thread_event_low_mem_bp = NULL;
	    }
	}
    }
}

/* target_has_all_memory() target_ops callback.
   Note that if a beneath target exists then return 0 to indicate that the
   beneath target to be used if this target cannot handle the request.  */
static int
linux_aware_has_all_memory (struct target_ops *ops)
{
  if (BENEATH && BENEATH->to_has_all_memory)
    return 0;
  return default_child_has_all_memory (ops);
}

/* target_has_memory() target_ops callback. */
static int
linux_aware_has_memory (struct target_ops *ops)
{
  if (BENEATH && BENEATH->to_has_memory)
    return BENEATH->to_has_memory (ops);
  return default_child_has_memory (ops);
}

/* target_has_stack() target_ops callback. */
static int
linux_aware_has_stack (struct target_ops *ops)
{
  if (BENEATH && BENEATH->to_has_stack)
    return BENEATH->to_has_stack (ops);
  return default_child_has_stack (ops);
}

/* target_has_registers() target_ops callback. */
static int
linux_aware_has_registers (struct target_ops *ops)
{
  if (BENEATH && BENEATH->to_has_registers)
    return BENEATH->to_has_registers (ops);
  return default_child_has_registers (ops);
}

/* target_has_execution() target_ops callback. */
static int
linux_aware_has_execution (struct target_ops *ops, ptid_t ptid)
{
  if (BENEATH && BENEATH->to_has_execution)
    return BENEATH->to_has_execution (ops, ptid);
  return default_child_has_execution (ops, ptid);
}

/* target_close() target_ops callback. */
static void
linux_aware_close (struct target_ops *ops)
{
  struct target_waitstatus dummy;

  DEBUG (D_INIT, 1, "Closing... \n");

  /* We might be called by a signal handler */
  if (running)
    {
      target_stop (inferior_ptid);
      if (BENEATH != NULL && BENEATH->to_wait != NULL)
	BENEATH->to_wait (&linux_aware_ops, minus_one_ptid, &dummy, 0);
    }

  lkd_params.enabled = 0;
  lkd_enabled_set (0, 0, 0);

  if (normal_stop_observer)
    {
      observer_detach_normal_stop (normal_stop_observer);
      normal_stop_observer = NULL;
    }

  wait_process = NULL;

  _inhibit_thread_register_awareness = 0;

  if (thread_event_low_mem_bp)
    {
      delete_breakpoint (thread_event_low_mem_bp);
      thread_event_low_mem_bp = NULL;
    }

  lkd_modules_close ();

  lkd_proc_free_list ();

  fields_and_addrs_clear ();

  if (running)
    {
      /* If we leave the board run, we'd better remove breakpoints
         so that it's functional. */
      remove_breakpoints ();

      if (BENEATH != NULL && BENEATH->to_resume != NULL)
	BENEATH->to_resume (&linux_aware_ops, inferior_ptid, 0, 0);
    }

  lkd_private.banner_file_valid = 0;
  lkd_private.banner_mem_valid = 0;
  running = 0;
}

static void
linux_aware_files_info (struct target_ops *target)
{
  printf_filtered (_("Connected to remote linux kernel\n"));
}

static int
linux_aware_can_async_p (struct target_ops *ops)
{
  return 0;
}

static int
linux_aware_is_async_p (struct target_ops *ops)
{
  return 0;
}

/* Setup the target_ops callbacks. */
static void
init_linux_aware_target (void)
{
  DEBUG (D_INIT, 1, "init_linux_aware_target\n");

  linux_aware_ops.to_shortname = "linux-aware";
  linux_aware_ops.to_longname = "Linux-aware target interface";
  linux_aware_ops.to_doc = linux_awareness_doc;

  /* Dirty hook to stack above anythin else, event something above
     the thread stratum (like starm) */
  linux_aware_ops.to_stratum = LKD_STRATUM_LINUX;

  linux_aware_ops.to_load = linux_aware_load;
  linux_aware_ops.to_close = linux_aware_close;
  linux_aware_ops.to_attach = linux_aware_attach;
  linux_aware_ops.to_disconnect = linux_aware_disconnect;
  linux_aware_ops.to_magic = OPS_MAGIC;

  /* Breakpoints */
  linux_aware_ops.to_insert_breakpoint = linux_aware_insert_breakpoint;
  linux_aware_ops.to_remove_breakpoint = linux_aware_remove_breakpoint;
  linux_aware_ops.to_insert_hw_breakpoint = linux_aware_insert_hw_breakpoint;
  linux_aware_ops.to_remove_hw_breakpoint = linux_aware_remove_hw_breakpoint;

  /* ?? Watchpoints ?? */

  /* Memory */
  linux_aware_ops.to_xfer_partial = linux_aware_xfer_partial;

  /* Registers */
  linux_aware_ops.to_fetch_registers = linux_aware_fetch_registers;
  linux_aware_ops.to_store_registers = linux_aware_store_registers;

  /* Execution */
  linux_aware_ops.to_resume = linux_aware_resume;
  linux_aware_ops.to_wait = linux_aware_wait;

  /* Threads */
  linux_aware_ops.to_thread_alive = linux_aware_thread_alive;
  linux_aware_ops.to_update_thread_list = linux_aware_update_thread_list;
  linux_aware_ops.to_pid_to_str = linux_aware_pid_to_str;
  linux_aware_ops.to_extra_thread_info = linux_aware_extra_thread_info;
  linux_aware_ops.to_thread_name = linux_aware_thread_name;
  linux_aware_ops.to_core_of_thread = linux_aware_core_of_thread;
  linux_aware_ops.to_has_thread_control = tc_none;

  linux_aware_ops.to_has_all_memory = linux_aware_has_all_memory;
  linux_aware_ops.to_has_memory = linux_aware_has_memory;
  linux_aware_ops.to_has_stack = linux_aware_has_stack;
  linux_aware_ops.to_has_registers = linux_aware_has_registers;
  linux_aware_ops.to_has_execution = linux_aware_has_execution;
  linux_aware_ops.to_files_info = linux_aware_files_info;

  /* Prevent Async operations
   * LKD doesn't yet support ASync,
   * Particularly on connect/resume, which can break things
   * when connecting to an async target such as QEmu
   */
  linux_aware_ops.to_can_async_p = linux_aware_can_async_p;
  linux_aware_ops.to_is_async_p = linux_aware_is_async_p;
}

/******************************************************************************/
/**************                USERSPACE DEBUG                   **************/
/******************************************************************************/

/* Helper for make_cleanup. */
static void
restore_confirm (void *saved_confirm)
{
  confirm = (long) saved_confirm;
}

/* Helper for make_cleanup. */
static void
restore_inferior_ptid (void *saved_ptid)
{
  inferior_ptid = *(ptid_t *) saved_ptid;
}

/* This function is called when a process just called exec() to see if
 the user has requested a specific action to be taken when the new
 executable starts. */
static void
check_exec_actions (void)
{
  char *execed;
  process_t *ps;
  struct waited_exe *exe = waited_exes, *prev = NULL;
  struct command_line *cmd;
  uid_t uid;
  CORE_ADDR mm;
  int found = 0;

  ps = wait_process;
  mm = lkd_proc_get_mm (ps);

  if (!ps || !mm)
    return;

  /* Get the exectuable name for the new image. */
  execed = lkd_proc_get_exe (mm);
  if (execed == NULL)
    return;

  uid = lkd_proc_get_uid (ps->task_struct);

  DEBUG (USER, 2, "%s: The executable is : %s\n", __FUNCTION__, execed);

  disable_terminate ();

  /* Iterate the waited executables. */
  while (exe && !found)
    {
      struct cleanup *cleanup;
      ptid_t saved_ptid = inferior_ptid;

      if (exe->name)
	{
	  /* Look if the new executable ends with the requested name. */
	  DEBUG (USER, 3, "\tComparing to '%s'\n", exe->name);

	  if ((strstr (execed, exe->name) ==
	       (execed + strlen (execed) - strlen (exe->name))))
	    found = 1;		/*found */
	}

      DEBUG (USER, 3, "\tComparing exe->uid= %d to %d\n", exe->uid, uid);
      if ((uid == exe->uid) || ((exe->uid == -2) && (uid >= AID_APP)))
	found = 1;		/*found */

      if (found)
	{
	  /* Set confirm to 0 so that the interactive questions get
	     automatically answered with their default answer. */
	  cleanup = make_cleanup (restore_confirm, (void *) (long) confirm);
	  make_cleanup (restore_inferior_ptid, &saved_ptid);
	  confirm = 0;
	  inferior_ptid = PTID_OF (wait_process);

	  /* Load the debug info for the process. */
	  debug_process_command (NULL, 0);
	  cmd = exe->cmds;
	  /* execute the user entered commands. */
	  while (cmd != NULL)
	    {
	      execute_control_command (cmd);
	      cmd = cmd->next;
	    }
	  do_cleanups (cleanup);

	  /* Remove the waited_exe from the list. */
	  if (prev != NULL)
	    prev->next = exe->next;
	  else
	    waited_exes = exe->next;

	  xfree (exe->name);
	  free_command_lines ((struct command_line **) &(exe->cmds));
	  xfree (exe);
	}
      else
	{
	  prev = exe;
	  exe = exe->next;
	}
    }

  enable_terminate ();

  return;
}

#ifdef HAS_PAGE_MONITORING

/* This function create the commands that will be executed when the
 watchpoint that monitors a page triggers. */
static void
create_watchpoint_commands (struct monitored_page *page)
{
  struct command_line **cmds;
  struct bp_list *bps = page->bps;

  free_command_lines ((struct command_line **) &(page->watchpoint->commands));

  /* Don't mention the watchpoint when it's hit. */
  cmds = (struct command_line **) &page->watchpoint->commands;
  *cmds = xmalloc (sizeof (struct command_line));
  (*cmds)->line = xstrdup ("silent");
  (*cmds)->control_type = simple_control;
  (*cmds)->body_count = 0;
  (*cmds)->next = NULL;

  /* If we stop execution, print a message explaining why. */
  if (page->stop)
    {
      cmds = &(*cmds)->next;
      *cmds = xmalloc (sizeof (struct command_line));
      (*cmds)->line =
	xstrprintf
	("printf \"The page at address 0x%s has just been mapped to memory.\n\"",
	 phex (page->virt_addr, 4));
      (*cmds)->control_type = simple_control;
      (*cmds)->body_count = 0;
    }

  /* Enable all the breakpoints on the waited page. The breakpoints
     are already created but disabled. */
  if (bps != NULL)
    do
      {
	cmds = &(*cmds)->next;
	*cmds = xmalloc (sizeof (struct command_line));
	(*cmds)->line = xstrprintf ("enable %i", bps->b->number);
	(*cmds)->control_type = simple_control;
	(*cmds)->body_count = 0;
	bps = bps->next;
      }
    while (bps);

  /* Delete the watchpoint. */
  cmds = &(*cmds)->next;
  *cmds = xmalloc (sizeof (struct command_line));
  (*cmds)->line = xstrprintf ("delete %i", page->watchpoint->number);
  (*cmds)->control_type = simple_control;
  (*cmds)->body_count = 0;

  /* If we don't want to stop, restart execution. */
  if (!page->stop)
    {
      cmds = &(*cmds)->next;
      *cmds = xmalloc (sizeof (struct command_line));
      (*cmds)->line = xstrdup ("continue");
      (*cmds)->control_type = simple_control;
      (*cmds)->body_count = 0;
    }

  (*cmds)->next = NULL;
}

/* Monitor a page mapping event for page table entry at ADDR, and
 insert the breakpoint BP when the page is mapped to memory. */
static struct monitored_page *
create_monitored_page (CORE_ADDR addr, struct breakpoint *bp)
{
  struct monitored_page *res = xmalloc (sizeof (struct monitored_page));
  int bpnum, i, other_type_used, target_resources_ok;
  struct symtab_and_line sal;
  char *text, *exp_text;
  struct expression *exp;
  struct value *val, *mark;
  struct breakpoint *b;

  res->next = monitored_pages;
  monitored_pages = res;

  res->addr = addr;
  if (bp != NULL)
    {
      res->bps = xmalloc (sizeof (struct bp_list));
      res->bps->next = NULL;
      res->bps->b = bp;
    }
  else
    res->bps = NULL;

  res->stop = 0;

  /* Create the watchpoint expression. */
  init_sal (&sal);		/* initialize to zeroes */

  sal.pspace = current_program_space;

  text = xstrprintf ("*0x%s", phex (addr, 4));
  exp_text = text;
  exp = parse_exp_1 (&exp_text, 0, 0);
  mark = value_mark ();
  val = evaluate_expression (exp);
  release_value (val);
  if (value_lazy (val))
    value_fetch_lazy (val);

  /* Check if we have enough watchpoints available. */
  i = hw_watchpoint_used_count (bp_hardware_watchpoint, &other_type_used);
  target_resources_ok =
    target_can_use_hardware_watchpoint (bp_hardware_watchpoint, i + 1,
					other_type_used);

  if (target_resources_ok <= 0)
    {
      /* FIXME : leaks */
      warning ("The hardware watchpoints are exhausted.\n"
	       "The debugger is unable to monitor this page's load.");
      return NULL;
    }

  /* Create the watchpoint. */
  b = set_raw_breakpoint (target_gdbarch (), sal, bp_hardware_watchpoint);
  set_breakpoint_count (breakpoint_count + 1);
  b->number = breakpoint_count;
  b->disposition = disp_donttouch;
  b->exp = exp;
  b->exp_valid_block = NULL;
  b->exp_string = savestring (text, exp_text - text);
  xfree (text);
  b->val = val;
  b->loc->cond = NULL;
  if (bp != NULL)
    b->thread = bp->thread;
  else
    b->thread = pid_to_thread_id (inferior_ptid);
  b->commands = NULL;

  res->watchpoint = b;

  /* Create the watchpoint commands. */
  create_watchpoint_commands (res);
  return res;
}

/* If we try to insert a breakpoint on a page not yet mapped to
 memory, but already monitored, we'll end up here. */
static void
add_bpt_to_monitored_page (struct monitored_page *page,
			   struct breakpoint *bpt)
{
  struct bp_list *list = xmalloc (sizeof (struct bp_list));
  list->next = page->bps;
  list->b = bpt;
  page->bps = list;

  /* Regenerate commands with the new breakpoint. */
  create_watchpoint_commands (page);
}

/* Check if the page table entry at ADDR is already monitored. */
static struct monitored_page *
find_monitored_page (CORE_ADDR addr)
{
  struct monitored_page *page = monitored_pages;

  while (page != NULL)
    {
      if (page->addr == addr)
	break;
      page = page->next;
    }

  return page;
}

/* This function is called when the user tries to set the breakpoint
 BPT at address ADDR, which isn't yet mapped to memory. */
static struct monitored_page *
add_monitored_page (struct breakpoint *bpt, CORE_ADDR addr)
{
  CORE_ADDR faulty_addr;
  struct monitored_page *res;
  process_t *ps = lkd_proc_get_by_ptid (inferior_ptid);
  faulty_addr =
    linux_awareness_ops->lo_translate_memory_watch_address (addr, ps);
  if (!faulty_addr)
    {
      error ("Could not find a place to put the page watchpoint.");
    }

  res = find_monitored_page (faulty_addr);

  if (res == NULL)
    {
      if (yquery
	  ("The page where you tried to set a breakpoint is not currently mapped to\n"
	   "memory. The debugger can monitor the page load and set the breakpoint when it\n"
	   "gets loaded. This will use a hardware watchpoint. Do you want the debugger to\n"
	   "monitor the page load? "))
	{
	  res = create_monitored_page (faulty_addr, bpt);
	}
      if (res == NULL)
	warning ("Your breakpoint has been disabled.");
    }
  else
    {
      add_bpt_to_monitored_page (res, bpt);
    }
  return res;
}

/* Evaluates the passed expression as an address and sets up a
 watchpoint that'll trigger when that address is ammped to memory. */
static void
wait_page_command (char *args, int from_tty)
{
  enum page_status stat;
  CORE_ADDR addr = parse_and_eval_address (args);
  CORE_ADDR orig_addr = addr;
  process_t *ps;
  CORE_ADDR faulty_addr;
  struct monitored_page *res;

  if (lkd_private.loaded != LKD_LOADED)
    {
      printf_filtered (LA_NOT_LOADED_STRING);
      return;
    }

  ps = lkd_proc_get_by_ptid (inferior_ptid);

  stat = linux_awareness_ops->lo_translate_memory_address (&addr, ps);
  if (stat == PAGE_PRESENT)
    {
      printf_filtered ("The page is already in memory!\n");
      return;
    }

  faulty_addr
    = linux_awareness_ops->lo_translate_memory_watch_address (orig_addr, ps);

  res = find_monitored_page (faulty_addr);

  if (res == NULL)
    {
      res = create_monitored_page (faulty_addr, NULL);
    }

  /* create_monitored_page will have emited a warning if needed.  */
  if (res != NULL)
    {
      res->stop = 1;
      res->virt_addr = orig_addr;
      create_watchpoint_commands (res);
    }
}
#endif

/* Implements the wait_exe command. See the  'struct waited_exe'
 comment. */
static void
set_wait_exe (char *comm, uid_t uid, int from_tty)
{
  struct command_line *cmds;
  struct waited_exe *prev, *res = waited_exes;
  struct waited_exe **new;

  int display = 0, erase = 0;

  if (comm == NULL)
    {
      if (uid == -1)
	display = 1;
    }
  else if (comm[0] == '-')
    erase = 1;

  new = &waited_exes;
  prev = res;

  while (res)
    {
      if (display)
	{
	  if (res->uid == -1)
	    /*seeking for a given name */
	    printf_filtered
	      ("waiting for %s: will do \"%s\"...\n",
	       res->name, res->cmds->line);
	  else if (res->uid == -2)
	    /*seeking for any ANDROID vm */
	    printf_filtered
	      ("waiting for any Android app_xx: will do \"%s\"...\n",
	       res->cmds->line);
	  else
	    /*seeking for a given uid */
	    printf_filtered
	      ("waiting for UID %d: will do \"%s\"...\n",
	       res->uid, res->cmds->line);
	}
      prev = res;
      res = res->next;
      if (erase)
	xfree (prev);
    }

  if (erase)
    {
      waited_exes = NULL;
      if (thread_event_do_exec_bp)
	delete_breakpoint (thread_event_do_exec_bp);
      if (thread_event_do_exec_return_bp)
	delete_breakpoint (thread_event_do_exec_return_bp);
      thread_event_do_exec_bp = NULL;
      thread_event_do_exec_return_bp = NULL;
      printf_filtered ("cleared wait list.\n");
      return;
    }

  if (display)
    return;

  if (prev)
    new = &(prev->next);

  *new = xcalloc (1, sizeof (struct waited_exe));

  (*new)->uid = uid;

  if (uid == -1)
    (*new)->name = xstrdup (comm);

  cmds =
    read_command_lines
    ("Type commands that will be executed the next time the binary is executed.\n"
     "Setting breakpoints is OK, but do not continue or step before the breakpoint is hit.",
     from_tty, 1, NULL, NULL);

  (*new)->cmds = cmds;

  if (thread_event_do_exec_return_bp == NULL)
    thread_event_do_exec_bp
      = create_thread_event_breakpoint (target_gdbarch (),
					ADDR (search_binary_handler));
}

static void
wait_exe_command (char *args, int from_tty)
{
  if ((args == NULL) && (waited_exes == NULL))
    {
      printf_filtered ("You must supply an executable name.\n");
      return;
    }

  set_wait_exe (args, -1, from_tty);
};

static void
wait_exe_uid_command (char *args, int from_tty)
{
  uid_t uid = -1;

  if (args == NULL)
    {
      if (waited_exes == NULL)
	{
	  printf_filtered ("You must supply a UID.\n");
	  return;
	}
    }
  else if (args[0] == '-')
    /*clear */
    return set_wait_exe (args, -1, from_tty);
  else
    /*non-null argument */
    uid = strtoul (args, NULL, 0);

  set_wait_exe (NULL, uid, from_tty);
};

#ifdef HAS_ANDROID_SUPPORT
static void
wait_android_vm_command (char *args, int from_tty)
{
  uid_t uid = -1;

  if (args == NULL)
    {
      if (waited_exes == NULL)
	{
	  printf_filtered
	    ("You must supply a number (for app_#) or the * token (for app_*).\n");
	  return;
	}
    }
  else if (args[0] == '*')
    /* app_* */
    uid = -2;
  else if (args[0] != '-')
    {
      /* app_? */
      uid = AID_APP + strtoul (args, NULL, 0);
    }
  else				/* clear list */
    return set_wait_exe (args, -1, from_tty);

  set_wait_exe (NULL, uid, from_tty);
};
#endif

/* This function replaces dwarf2_psymtab_to_symtab in the userspace
 processes psymtabs. This version calls dwarf2_psymtab_to_symtab but
 it rewrites paths to take target_root_prefix into account. */
void
linux_aware_read_symtab (struct partial_symtab *pst, struct objfile *objfile)
{
  struct stat stat_struct;

  if (!dwarf2_psymtab_to_symtab)
    return;

  if (!pst)
    return;

  dwarf2_psymtab_to_symtab (pst, objfile);

  if (pst->dirname && stat (pst->dirname, &stat_struct) == -1)
    {
      char *host_dir = xstrprintf ("%s/%s",
				   *target_root_prefix,
				   pst->dirname);

      if (stat (host_dir, &stat_struct) == 0)
	{
	  char * dirname = obstack_alloc (&objfile->objfile_obstack, strlen (host_dir) + 1);
	  strcpy (dirname, host_dir);

	  // Are we freeing the existing pointer?
	  pst->dirname = dirname;
	}

      xfree (host_dir);
    }
}

/* This function is here to replace the default display for
 breakpoints set on code that has been unloaded. This display
 routine doesn't display the 0xFFFFFFFF that could confuse the
 user. */
static void
init_bp_mention (struct breakpoint *bpt)
{
  bpt->ops = NULL;
  printf_filtered (_("Breakpoint %d (%s) pending."),
		   bpt->number,
		   event_location_to_string(bpt->location) );
}

static struct breakpoint_ops init_breakpoints_ops = {
  .print_mention = init_bp_mention
};

static void
lkd_install_do_exit_event (void)
{
/* install hook for do_exit */
  if (thread_event_do_exit_bp == NULL)
    {
      thread_event_do_exit_bp =
	create_thread_event_breakpoint (target_gdbarch (), ADDR (do_exit));

      /*do no remove on resume */
      lkd_private.keep_do_exit_event = 1;
    }
}

void
lkd_uninstall_do_exit_event (void)
{
  /* uninstall hook for do_exit */
  if ((thread_event_do_exit_bp != NULL) && (!lkd_private.keep_do_exit_event))
    {
      delete_breakpoint (thread_event_do_exit_bp);
      thread_event_do_exit_bp = NULL;
    }
}

/* This callback is called when a new breakpoint is created. */
static void
linux_aware_create_breakpoint_hook (struct breakpoint *bpt)
{
  struct lm_info *info;

  if (lkd_private.loaded != LKD_LOADED)
    return;

  /* defect 10646: install the solib hooks if the user adds a pending bp.
   **/
  if (((bpt->loc == NULL) && (lkd_private.kflags & KFLAG_DBGINFO))	/* pending */
      || (lkd_params.enable_module_load == 1))
    {				/* or explicitly turned on while no dbg-info */
      lkd_params.enable_module_load = 1;
      enable_module_events_command (NULL, 0, NULL);
      execute_command ("sharedlibrary", 0);
    }

  if (bpt->loc && bpt->loc->address == ~(CORE_ADDR) 0)
    {
      warning
	("You have inserted a breakpoint on a location that is not currently\n"
	 "mapped to memory (it is flagged as __init code and the initialization\n"
	 "phase of the module has completed). The breakpoint will be reset if you\n"
	 "reload the module.");
      /* Display correct breakpoint info and disable the breakpoint. */
      bpt->ops = &init_breakpoints_ops;
      bpt->loc->shlib_disabled = 1;
    }
  else if (bpt->loc
	   && bpt->loc->address
	   && bpt->loc->loc_type == bp_loc_software_breakpoint
	   && linux_awareness_ops->lo_is_user_address (bpt->loc->address))
    {
      CORE_ADDR addr = bpt->loc->address;

      /* All the userspace breakpoints are set to a specific task. */
      bpt->thread = ptid_to_global_thread_id (inferior_ptid);

      /* for the time being, until we rework the page monitoring
       * support btp'ing in usermode pages, "as is" */
#ifdef HAS_PAGE_MONITORING
      if (!linux_aware_translate_address_safe (&addr, 1))
	{
	  /* The page containing the breakpoint isn't available
	     yet. */
	  disable_breakpoint (bpt);
	  add_monitored_page (bpt, addr);
	}
#endif

      lkd_install_do_exit_event ();

      /*Q: does setting a bpt to a usermode pages prevent Linux
       * to unmap it ? This seems to say so.*/
      if (HAS_ADDR (try_to_unmap))
	{
	  if (thread_event_low_mem_bp == NULL)
	    thread_event_low_mem_bp =
	      create_thread_event_breakpoint
	      (target_gdbarch (), ADDR (try_to_unmap));
	}
      else
	warning ("'try_to_unmap' wasn't found.");
    }
}

#ifdef HAS_PAGE_MONITORING
/* This callback is called when a breakpoint is deleted. */
static void
linux_aware_delete_breakpoint_hook (struct breakpoint *bpt)
{
  struct monitored_page **page = &monitored_pages, *p;
  struct bp_list **bps, *bp;

  if (lkd_private.loaded != LKD_LOADED)
    return;

  /* If that breakpoint was the only one requiring a certain
     monitored page, we can stop monitorin it. */
  while (*page)
    {
      if ((*page)->watchpoint == bpt)
	{
	  /* FIXME : we leak the bp_list */
	  p = *page;
	  *page = (*page)->next;
	  xfree (p);
	  break;
	}

      bps = &(*page)->bps;
      while (*bps)
	{
	  if ((*bps)->b == bpt)
	    {
	      bp = *bps;
	      *bps = (*bps)->next;
	      xfree (bp);
	      create_watchpoint_commands (*page);
	      return;
	    }
	  bps = &(*bps)->next;
	}

      page = &(*page)->next;
    }
}
#endif

/********************************************************************************/
/**********                   Data diplay commands                    ***********/
/********************************************************************************/

/* The below fucntions aren't documented specifically. All they do is
 to extract some information from the kernel data structure and
 display it to the user. */

char *
read_dentry (CORE_ADDR dentry)
{
  CORE_ADDR parent, name;
  char *res, *tmp;
  unsigned int len;

  parent = read_pointer_field (dentry, dentry, d_parent);

  if (parent == dentry)
    {
      res = xmalloc (1);
      res[0] = '\0';
      return res;
    }

  if (HAS_FIELD (qstr, len))
    len = read_unsigned_embedded_field (dentry, dentry, d_name, qstr, len);
  else
    /* KERN_310
     * For now, qssume this is a 310 kernel.
     * the problem here is that qstr has an unnamed union, making the lookup
     * for the offset of len very complex
     * include/linux/dcache.h
     * also: FIXME check for current_target_byte_order .
     */
    len = read_memory_unsigned_integer (dentry + F_OFFSET (dentry, d_name)
					+
					4 /*offset of ."unnamed union".len */
					,
					4 /*for little endian */ ,
					LKD_BYTE_ORDER);

  tmp = read_dentry (parent);
  res = xmalloc (strlen (tmp) + 1 /* slash */  + len + 1 /* '\0' */ );
  sprintf (res, "%s/", tmp);
  name = read_pointer_embedded_field (dentry, dentry, d_name, qstr, name);
  read_memory_string (name, res + strlen (tmp) + 1, len + 1);
  xfree (tmp);
  return res;
}

static void
pmap_command (char *args, int from_tty)
{
  process_t *ps;
  CORE_ADDR mm;
  CORE_ADDR mmap;
  unsigned int size, total = 0, writable = 0, shared = 0;

  if (lkd_private.loaded != LKD_LOADED)
    {
      printf_filtered (LA_NOT_LOADED_STRING);
      return;
    }

  /* get the process by ptid as command thread
   * may set the selection to a non-running one
   **/
  ps = lkd_proc_get_by_ptid (inferior_ptid);

  mm = lkd_proc_get_mm (ps);
  if (!mm)
    {
      printf_filtered ("%s has no memory mapping.\n", ps->comm);
      return;
    }

  printf_filtered ("Start         Size Perm Mapping\n");

  mmap = read_pointer_field (mm, mm_struct, mmap);
  while (mmap)
    {
      CORE_ADDR file;

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_GROWSUP	0x00000200

      unsigned int flags;
      CORE_ADDR start, end;

      flags = read_unsigned_field (mmap, vm_area_struct, vm_flags);
      start = read_pointer_field (mmap, vm_area_struct, vm_start);
      end = read_pointer_field (mmap, vm_area_struct, vm_end);
      file = read_pointer_field (mmap, vm_area_struct, vm_file);

      size = (end - start) >> 10;
      total += size;
      printf_filtered ("%s % 8dK %c%c%c%c ",
		       phex (start, 4),
		       size,
		       flags & VM_READ ? 'r' : '-',
		       flags & VM_WRITE ? 'w' : '-',
		       flags & VM_EXEC ? 'x' : '-',
		       flags & VM_MAYSHARE ? 's' : 'p');

      if (flags & VM_WRITE)
	writable += size;

      if (flags & VM_MAYSHARE)
	shared += size;

      if (file)
	{
	  CORE_ADDR dentry;
	  char *filename;

	  dentry = read_pointer_embedded_field (file, file, f_path, path,
						dentry);

	  filename = read_dentry (dentry);
	  printf_filtered ("%s\n", filename);
	  xfree (filename);
	}
      else if (flags & (VM_GROWSDOWN | VM_GROWSUP))
	{
	  printf_filtered ("[ stack ]\n");
	}
      else
	{
	  printf_filtered ("[ anon ]\n");
	}

      mmap = read_pointer_field (mmap, vm_area_struct, vm_next);
    }

#undef VM_READ
#undef VM_WRITE
#undef VM_EXEC
#undef VM_SHARED

#undef VM_MAYREAD
#undef VM_MAYWRITE
#undef VM_MAYEXEC
#undef VM_MAYSHARE

#undef VM_GROWSDOWN
#undef VM_GROWSUP

  printf_filtered ("mapped: %uK, writeable/private: %uK, shared: %uK\n",
		   total, writable, shared);
}

static void
print_resource (CORE_ADDR resource, int depth, int width)
{
  CORE_ADDR next;
  unsigned long start, end;
  CORE_ADDR name_addr;
  char buf[64];

begin:
  start = read_unsigned_field (resource, resource, start);
  end = read_unsigned_field (resource, resource, end);
  name_addr = read_pointer_field (resource, resource, name);

  if (name_addr)
    {
      read_memory_string (name_addr, buf, 64);
      buf[63] = '\0';
    }

  printf_filtered ("%*s%0*lx-%0*lx : %s\n",
		   depth * 2, "",
		   width, start, width, end, name_addr ? buf : "<BAD>");

  next = read_pointer_field (resource, resource, child);
  if (next)
    print_resource (next, depth + 1, width);

  next = read_pointer_field (resource, resource, sibling);
  if (next)
    {
      resource = next;
      goto begin;
    }
}

static void
print_resources (CORE_ADDR resource)
{
  int depth = 0;
  int width = read_unsigned_field (resource, resource, end) < 0x10000 ? 4 : 8;
  CORE_ADDR first = read_pointer_field (resource, resource, child);
  print_resource (first, 0, width);
}

static void
iomem_command (char *args, int from_tty)
{
  print_resources (ADDR (iomem_resource));
}

static void
ioports_command (char *args, int from_tty)
{
  print_resources (ADDR (ioport_resource));
}

static char *
printf_dmesg (char *buf, struct ui_file *fp)
{
  int len = strlen (buf);
  char *newline = strchr (buf, '\n');
  char *full_buf = buf;

  while (newline != NULL)
    {
      if (newline - full_buf > len - 4)
	{
	  *newline = '\0';
	  if (fp)
	    fprintf_unfiltered (fp, "%s", buf);
	  else
	    printf_filtered ("%s", buf);
	  *newline = '\n';
	  return newline;
	}

      if (newline[1] == '<'
	  && newline[2] >= '0' && newline[2] <= '7' && newline[3] == '>')
	{
	  newline[1] = '\0';
	  if (fp)
	    fprintf_unfiltered (fp, "%s", buf);
	  else
	    printf_filtered ("%s", buf);
	  buf = newline + 4;
	}
      else
	{
	  *newline = '\0';
	  if (fp)
	    fprintf_unfiltered (fp, "%s", buf);
	  else
	    printf_filtered ("%s\n", buf);
	  buf = newline + 1;
	}

      newline = strchr (buf, '\n');
    }

  if (fp)
    fprintf_unfiltered (fp, "%s", buf);
  else
    printf_filtered ("%s", buf);
  return "";
}

/* Reuse the same policy than the set logging commands. */
extern int logging_overwrite;

long
lkd_eval_long (char *string)
{
  volatile struct gdb_exception except;
  struct expression *expr;
  struct value *val;
  unsigned char size;

  TRY
  {
    expr = parse_expression (string);
  }
  CATCH (except, RETURN_MASK_ERROR)
  {
    return 0;
  }
  END_CATCH

  val = evaluate_expression (expr);

  return (long) value_as_long (val);
}

static void
dmesg_command (char *args, int from_tty)
{
  unsigned int log_len = read_memory_unsigned_integer (ADDR (log_buf_len),
						       4, LKD_BYTE_ORDER);
  CORE_ADDR buf_end = ADDR (__log_buf) + log_len;
  unsigned long log_end;
  CORE_ADDR log_start;
  CORE_ADDR buf_start;
  int has_printk_log = 0;

  char *dmesg_file = NULL;
  struct ui_file *dmesg_output = NULL;
  struct cleanup *cleanups = NULL;

  /* possible param is an output file. */
  if (args)
    {
      dmesg_file = strtok (args, " ");
      dmesg_output = gdb_fopen (dmesg_file, logging_overwrite ? "w" : "a");
      if (dmesg_output == NULL)
	perror_with_name (_("set dmesg logging"));
      cleanups = make_cleanup_ui_file_delete (dmesg_output);
    }

  /* F_KERN_310 : Check for 3.10 kernels */
  if (!HAS_ADDR (log_end))
    {
      CORE_ADDR first_idx =
	read_memory_unsigned_integer (ADDR (log_first_idx), 4,
				      LKD_BYTE_ORDER);
      CORE_ADDR next_idx =
	read_memory_unsigned_integer (ADDR (log_next_idx), 4, LKD_BYTE_ORDER);
      CORE_ADDR next_log = ADDR (__log_buf);

      unsigned long msg_len, passes;

#define LOG_LINE_MAX 1024	/*from kernel */
      char tmp[1024];
      gdb_byte header[32];
#undef LOG_LINE_MAX

      /* dmesg must succeed if the structure size is not known, for instance with no debug info.
       */
      long header_size = lkd_eval_long ("sizeof(struct log)");

      /* FIXME, if KEXEC was enabled, this can be read from proc, otherwise... */
      if (header_size == 0)
	{
	  /* Linux 3.11-rc3 renamed struct log to struct printk_log */
	  if ( (header_size = lkd_eval_long ("sizeof(struct printk_log)")) != 0)
	  {
		  has_printk_log = 1;
	  }
	  else
	  {
	    printf_filtered
	      ("Symbols missing, trying with 'struct log' size of 16 bytes\n");
	    header_size = 16;
	  }
	}

      msg_len = 1024;
      passes = 2;		/*at most two blocks */
      next_log = first_idx;
      log_end = (next_idx > first_idx) ? next_idx : log_len;

      while (passes--)
	{
	  log_end += ADDR (__log_buf);
	  next_log += ADDR (__log_buf);

	  while (next_log < log_end)
	    {
	      unsigned long long sec;
	      double fsec;
	      char *hint_pos;
	      int level;
	      struct dmesg_header {
		      unsigned long long sec;
		      gdb_byte chars [28];
	      } * hdr = (struct dmesg_header*) header;

	      read_memory (next_log, (gdb_byte *) header, header_size);

	      if (has_printk_log)
		      msg_len = extract_unsigned_field (header, printk_log, len);
	      else
		      msg_len = extract_unsigned_field (header, log, len);

	      if (!msg_len)
		break;		/*done, sanity check. */

	      read_memory (next_log + header_size, (gdb_byte *) tmp,
			   msg_len - header_size);
	      tmp[msg_len - header_size] = 0;

	      next_log += msg_len;

	      sec =  hdr->sec;
	      fsec = (double) sec / (double) 1000000000;

	      if (dmesg_output)
		{
		  /*levels: symbols seem not enough, some empirical extraction
		   * is needed, but this is not likely to change any time soon.
		   */
		  if (has_printk_log)
			  level = extract_unsigned_field (header, printk_log, level);
		  else
			  level = extract_unsigned_field (header, log, level);

		  fprintf_unfiltered (dmesg_output, "<%x>[%04.5lf] %s\n",
				      (level >> 5) & 0x7, fsec, tmp);
		}
	      else
		{
		  /*remove hint for display in GDB, leave it in files, for filtering. */
		  if ((hint_pos = strstr (tmp, "SUBSYSTEM=")))
		    *hint_pos = 0;
		  printf_filtered ("[%04.5lf] %s\n", fsec, tmp);
		}
	    }

	  if (first_idx <= next_idx)
	    passes = 0;		/*done */
	  else
	    {
	      /*get block at the beginning of the ring buffer */
	      next_log = 0;
	      log_end = first_idx;
	    }
	}			/*passes */

    }
  else
    {
      /* Non 3.10 kernels */

      CORE_ADDR buf_end = ADDR (__log_buf) + log_len;
      CORE_ADDR log_start;
      CORE_ADDR buf_start;
      char *buf = alloca (log_chunk_size + 1);
      char *buf2 = alloca (log_chunk_size * 2);
      char *tmp;

      log_end = read_memory_unsigned_integer (ADDR (log_end), 4,
					      LKD_BYTE_ORDER);
      log_start = log_end > log_len ?
	((log_end) & (log_len - 1)) + ADDR (__log_buf) : ADDR (__log_buf);
      buf_start = log_start;

      buf[log_chunk_size] = '\0';
      buf2[0] = '\n';
      buf2[1] = '\0';

      do
	{
	  if ((buf_start < log_start)
	      && ((buf_start + log_chunk_size) >= log_start))
	    {
	      read_memory (buf_start, (gdb_byte *) buf,
			   log_start - buf_start);
	      buf[log_start - buf_start] = '\0';	/* end the string */
	      buf[log_chunk_size - 1] = '\0';	/* stop the loop */
	    }
	  else if (buf_start + log_chunk_size >= buf_end)
	    {
	      read_memory (buf_start, (gdb_byte *) buf, buf_end - buf_start);
	      buf[buf_end - buf_start] = '\0';	/* end the string */
	      buf_start = ADDR (__log_buf);
	      if (buf_start == log_start)	/*we are done */
		buf[log_chunk_size - 1] = '\0';
	    }
	  else
	    {
	      read_memory (buf_start, (gdb_byte *) buf, log_chunk_size);
	      buf_start += log_chunk_size;
	    }
	  QUIT;
	  tmp = printf_dmesg (strcat (buf2, buf), dmesg_output);
	  strcpy (buf2, tmp);
	}
      while (buf[log_chunk_size - 1] != '\0');
    }				// old scheme.

  if (dmesg_output)
    {
      fprintf_filtered (dmesg_output, "\n");
      do_cleanups (cleanups);
      printf_filtered ("Wrote dmesg log to file %s.\n", dmesg_file);
    }
  else
    printf_filtered ("\n");
}

static void
vm_translate_command (char *args, int from_tty)
{
  CORE_ADDR addr = parse_and_eval_address (args);
  CORE_ADDR phys = addr;

  if (linux_aware_translate_address_safe (&phys, 0))
    printf_filtered
      ("Virtual address %s translates to physical address %s in the current context.\n",
       hex_string (addr), hex_string (phys));
}

static char *
get_banner_from_file (bfd * cur_bfd)
{
  CORE_ADDR banner_addr = ADDR (linux_banner);
  CORE_ADDR section_addr, section_size;
  asection *data;

  gdb_assert (lkd_private.banner_file);

  if (lkd_private.banner_file_valid)
    return lkd_private.banner_file;

  lkd_private.banner_file_valid = 1;

  /* first try to find linux_banner in .rodata */
  data = bfd_get_section_by_name (cur_bfd, ".rodata");
  if (data)
    {
      section_addr = bfd_get_section_vma (cur_bfd, data);
      section_size = bfd_get_section_size (data);
      if ((banner_addr < section_addr)
	  || (banner_addr >= section_addr + section_size))
	data = NULL;
    }

  if (!data)
    {
      /* then, try .text */
      data = bfd_get_section_by_name (cur_bfd, ".text");
      if (data)
	{
	  section_addr = bfd_get_section_vma (cur_bfd, data);
	  section_size = bfd_get_section_size (data);
	  if ((banner_addr < section_addr)
	      || (banner_addr >= section_addr + section_size))
	    data = NULL;
	}
    }

  if (data)
    {
      int i = 0;
      char c;
      bfd_seek (cur_bfd,
		data->filepos + banner_addr -
		bfd_get_section_vma (cur_bfd, data), SEEK_SET);
      do
	{
	  bfd_bread (&c, 1, cur_bfd);
	  lkd_private.banner_file[i++] = c;
	}
      while ((c != '\0') && (i < lkd_private.banner_file_size));
    }
  else
    {
      printf_filtered ("Linux banner not found in any of .text or .rodata\n");
      lkd_private.banner_file_valid = 0;
    }

  /* for security */
  lkd_private.banner_file[lkd_private.banner_file_size - 1] = '\0';

  DEBUG (D_INIT, 1, "Got banner from file: %s\n", lkd_private.banner_file);

  return lkd_private.banner_file;
}

static char *
get_banner (void)
{
  if (lkd_private.banner_mem_valid)
    return lkd_private.banner_mem;

  gdb_assert (lkd_private.banner_mem);

  lkd_private.banner_mem_valid = 1;

  read_memory_string (ADDR (linux_banner),
		      lkd_private.banner_mem, lkd_private.banner_mem_size);

  lkd_private.banner_mem[lkd_private.banner_mem_size - 1] = '\0';

  DEBUG (D_INIT, 1, "Read banner from mem: %s\n", lkd_private.banner_mem);

  return lkd_private.banner_mem;
}

static unsigned long
get_buffered_ram (unsigned long *buffered_pages,
		  unsigned long *swapcache_pages)
{
  int size = 0;
  int offset = 0;
  struct type *type;
  struct symbol *sym;
  char *error_msg = NULL;
  int i;
  CORE_ADDR all_bdevs = 0;
  CORE_ADDR next;

  if (!HAS_ADDR (all_bdevs))
    {
      error_msg = "Can't find the all_bdevs variable";
      goto error;
    }
  all_bdevs = ADDR (all_bdevs);

  error_msg = "Can't find the struct address_space definition";

  /* GCC generates the description of ``struct address_space'' only
     in function scopes, which means it won't be put in GDB's global
     struct type list. We have to get it's description by some other
     way. */
  if (!HAS_FIELD (inode, i_mapping))
    goto error;

  sym = FIELD_INFO (inode, i_mapping).type;
  type = SYMBOL_TYPE (sym);

  /* Type is struct inode.  */
  type = check_typedef (type);

  for (i = 0; i < TYPE_NFIELDS (type); ++i)
    if (!strcmp (FIELD_NAME (TYPE_FIELDS (type)[i]), "i_mapping"))
      break;

  if (i >= TYPE_NFIELDS (type))
    goto error;

  type = FIELD_TYPE (TYPE_FIELDS (type)[i]);
  type = check_typedef (type);

  /* Type should be ptr to struct address_space.  */
  if (TYPE_CODE (type) != TYPE_CODE_PTR)
    goto error;

  type = TYPE_TARGET_TYPE (type);
  type = check_typedef (type);

  /* Type should be struct address_space.  */
  if (TYPE_CODE (type) != TYPE_CODE_STRUCT)
    goto error;

  for (i = 0; i < TYPE_NFIELDS (type); ++i)
    if (!strcmp (FIELD_NAME (TYPE_FIELDS (type)[i]), "nrpages"))
      break;

  if (i >= TYPE_NFIELDS (type))
    goto error;

  /* address_space::nrpages_offset */
  offset = FIELD_BITPOS (TYPE_FIELDS (type)[i]) / TARGET_CHAR_BIT;
  /* address_space::nrpages_size */
  size = TYPE_LENGTH (check_typedef (TYPE_FIELDS (type)[i].type));

  for (next = read_pointer_field (all_bdevs, list_head, next);
       next != all_bdevs; next = read_pointer_field (next, list_head, next))
    {
      CORE_ADDR bdev = next - F_OFFSET (block_device, bd_list);
      CORE_ADDR inode = read_pointer_field (bdev, block_device, bd_inode);
      CORE_ADDR mapping = read_pointer_field (inode, inode, i_mapping);
      *buffered_pages +=
	read_memory_unsigned_integer (mapping + offset, size, LKD_BYTE_ORDER);
    }

  if (HAS_ADDR (swapper_space))
    {
      *swapcache_pages =
	read_memory_unsigned_integer (ADDR (swapper_space)
				      + offset, size, LKD_BYTE_ORDER);
    }

  return 1;
error:
  warning ("%s. Buffers numbers won't be accurate.", error_msg);
  return 0;
}

static void
get_swap (unsigned long *totalswap, unsigned long *freeswap)
{
  unsigned int i;
  unsigned long nr_swap_pages = 0;
  unsigned long total_swap_pages = 0;
  unsigned long nr_swapfiles = 0;
  unsigned long nr_to_be_unused = 0;
  unsigned long swap_info_size = 0;
  struct symbol *sym;
  CORE_ADDR swap_info;

  enum
  {
    SWP_USED = (1 << 0),	/* is slot in swap_info[] used? */
    SWP_WRITEOK = (1 << 1),	/* ok to write to this swap?    */
    SWP_ACTIVE = (SWP_USED | SWP_WRITEOK),
  };

  if (!HAS_ADDR (nr_swap_pages)
      || !HAS_ADDR (totalswap_pages)
      || !HAS_ADDR (nr_swapfiles) || !HAS_ADDR (swap_info))
    return;

  nr_swap_pages = read_memory_unsigned_integer (ADDR (nr_swap_pages), 4,
						LKD_BYTE_ORDER);
  total_swap_pages = read_memory_unsigned_integer (ADDR (totalswap_pages),
						   4, LKD_BYTE_ORDER);
  nr_swapfiles = read_memory_unsigned_integer (ADDR (nr_swapfiles), 4,
					       LKD_BYTE_ORDER);
  swap_info = ADDR (swap_info);

  if (!HAS_FIELD (swap_info_struct, flags))
    return;

  sym = FIELD_INFO (swap_info_struct, flags).type;
  swap_info_size = TYPE_LENGTH (SYMBOL_TYPE (sym));

  for (i = 0; i < nr_swapfiles; i++)
    {
      unsigned long flags =
	read_unsigned_field (swap_info + i * swap_info_size,
			     swap_info_struct, flags);
      if (!(flags & SWP_USED) || (flags & SWP_WRITEOK))
	continue;
      nr_to_be_unused +=
	read_unsigned_field (swap_info + i * swap_info_size,
			     swap_info_struct, inuse_pages);
    }

  *freeswap = nr_swap_pages + nr_to_be_unused;
  *totalswap = total_swap_pages + nr_to_be_unused;
}

#define K(x) (unsigned long)((x) << (linux_awareness_ops->page_shift - 10))

enum zone_stat_item
{
  /* First 128 byte cacheline (assuming 64 bit words) */
  NR_FREE_PAGES,
  NR_LRU_BASE,
  NR_INACTIVE_ANON = NR_LRU_BASE,	/* must match order of LRU_[IN]ACTIVE */
  NR_ACTIVE_ANON,		/*  "     "     "   "       "         */
  NR_INACTIVE_FILE,		/*  "     "     "   "       "         */
  NR_ACTIVE_FILE,		/*  "     "     "   "       "         */
  NR_UNEVICTABLE,		/*  "     "     "   "       "         */
  NR_MLOCK,			/* mlock()ed pages found and moved off LRU */
  NR_ANON_PAGES,		/* Mapped anonymous pages */
  NR_FILE_MAPPED,		/* pagecache pages mapped into pagetables.
				   only modified from process context */
  NR_FILE_PAGES,
  NR_FILE_DIRTY,
  NR_WRITEBACK,
  NR_SLAB_RECLAIMABLE,
  NR_SLAB_UNRECLAIMABLE,
  NR_PAGETABLE,			/* used for pagetables */
  NR_KERNEL_STACK,
  /* Second 128 byte cacheline */
  NR_UNSTABLE_NFS,		/* NFS unstable pages */
  NR_BOUNCE,
  NR_VMSCAN_WRITE,
  NR_VMSCAN_IMMEDIATE,		/* Prioritise for reclaim when writeback ends */
  NR_WRITEBACK_TEMP,		/* Writeback using temporary buffers */
  NR_ISOLATED_ANON,		/* Temporary isolated pages from anon lru */
  NR_ISOLATED_FILE,		/* Temporary isolated pages from file lru */
  NR_SHMEM,			/* shmem pages (included tmpfs/GEM pages) */
  NR_DIRTIED,			/* page dirtyings since bootup */
  NR_WRITTEN,			/* page writings since bootup */

  /* ASSUMING NO NUMA. */

  NR_ANON_TRANSPARENT_HUGEPAGES,
  NR_VM_ZONE_STAT_ITEMS
};

static void
proc_meminfo_command (char *args, int from_tty)
{
  unsigned long totalram = 0;
  unsigned long totalhigh = 0;
  unsigned long free_pages = 0;
  unsigned long active_pages = 0;
  unsigned long inactive_pages = 0;
  unsigned long active_pages_file = 0;
  unsigned long inactive_pages_file = 0;
  unsigned long active_pages_anon = 0;
  unsigned long inactive_pages_anon = 0;
  unsigned long free_highpages = 0;
  unsigned long buffered_pages = 0;
  unsigned long swapcache_pages = 0;
  unsigned long pagecache_pages = 0;
  unsigned long totalswap_pages = 0;
  unsigned long freeswap_pages = 0;
  unsigned long dirty_pages = 0;
  unsigned long mapped_pages = 0;
  unsigned long writeback_pages = 0;
  unsigned long slab_pages = 0;
  unsigned long slab_reclaimable = 0;
  unsigned long slab_unreclaimable = 0;
  unsigned long kernel_stack = 0;
  unsigned long pagetable_pages = 0;
  unsigned long vm_committed_space = 0;
  unsigned long sysctl_overcommit_ratio = 0;
  unsigned long nr_huge_pages = 0;
  unsigned long committed = 0;
  unsigned long allowed = 0;
  unsigned long vmalloc = 0;
  CORE_ADDR vmlist = 0;
  unsigned int struct_zone_size;
  CORE_ADDR pgdat;
  CORE_ADDR page_states = 0;
  unsigned int max_nr_zones = 3;
  unsigned int zone_highmem = 2;

  if (HAS_ADDR (per_cpu__page_states))
    {
      page_states = ADDR (per_cpu__page_states);
      dirty_pages = read_unsigned_field (page_states, page_state, nr_dirty);
      mapped_pages = read_unsigned_field (page_states, page_state, nr_mapped);
      writeback_pages =
	read_unsigned_field (page_states, page_state, nr_writeback);
      slab_pages = read_unsigned_field (page_states, page_state, nr_slab);
      pagetable_pages =
	read_unsigned_field (page_states, page_state, nr_page_table_pages);
    }
  else if (HAS_ADDR (vm_stat))
    {
      dirty_pages = global_page_state (NR_FILE_DIRTY);
      mapped_pages = global_page_state (NR_FILE_MAPPED);
      writeback_pages = global_page_state (NR_WRITEBACK);

      slab_reclaimable = global_page_state (NR_SLAB_RECLAIMABLE);
      slab_unreclaimable = global_page_state (NR_SLAB_UNRECLAIMABLE);
      slab_pages = slab_reclaimable + slab_unreclaimable;

      pagetable_pages = global_page_state (NR_PAGETABLE);
      pagecache_pages = global_page_state (NR_FILE_PAGES);

      active_pages_anon = global_page_state (NR_ACTIVE_ANON);
      inactive_pages_anon = global_page_state (NR_INACTIVE_ANON);
      active_pages_file = global_page_state (NR_ACTIVE_FILE);
      inactive_pages_file = global_page_state (NR_INACTIVE_FILE);
      active_pages = active_pages_anon + active_pages_file;
      inactive_pages = inactive_pages_anon + inactive_pages_file;

      free_pages = global_page_state (NR_FREE_PAGES);
      kernel_stack = global_page_state (NR_KERNEL_STACK);
    }
  else
    {
      warning ("Cannot find the per_cpu__page_states variable.\n"
	       "Numbers will not be accurate.");
    }

  /* ok 3.3: see si_meminfo. */
  if (HAS_ADDR (totalram_pages))
    totalram = read_memory_unsigned_integer (ADDR (totalram_pages), 4,
					     LKD_BYTE_ORDER);
  else
    warning ("Cannot find the totalram_pages variable.\n"
	     "Total memory will not be accurate.");

  /* ok 3.3: see si_meminfo. */
  if (HAS_ADDR (totalhigh_pages))
    totalhigh =
      read_memory_unsigned_integer (ADDR (totalhigh_pages), 4,
				    LKD_BYTE_ORDER);
  else
    /* When compiled without HIGHMEM, totalhigh_pages is a
       #define to 0 */
    totalhigh = 0;

  if (HAS_ADDR (nr_pagecache))
    pagecache_pages =
      read_memory_unsigned_integer (ADDR (nr_pagecache), 4, LKD_BYTE_ORDER);
  else if (!HAS_ADDR (vm_stat))
    warning ("Cannot find the nr_pagecache variable.\n"
	     "Caches memory will not be accurate.");

  if (HAS_ADDR (vm_committed_space))
    vm_committed_space
      = read_memory_unsigned_integer (ADDR (vm_committed_space),
				      4, LKD_BYTE_ORDER);
  else if (HAS_ADDR (vm_committed_as))
    /* 3.3, this is a per-cpu-counter. */
    vm_committed_space
      = read_unsigned_field (ADDR (vm_committed_as), percpu_counter, count);
  else
    warning ("Cannot find the vm_commited_space variable.\n"
	     "Commited memory will not be accurate.");

  if (HAS_ADDR (sysctl_overcommit_ratio))
    sysctl_overcommit_ratio
      =
      read_memory_unsigned_integer (ADDR (sysctl_overcommit_ratio),
				    4, LKD_BYTE_ORDER);
  else
    warning ("Cannot find the sysctl_overcommit_ratio variable.\n"
	     "Commited memory will not be accurate.");

  if (HAS_ADDR (vmlist))
    vmlist = ADDR (vmlist);
  else
    warning ("Cannot find the vmlist variable.\n"
	     "Vmalloced memory will not be accurate.");

  if (HAS_ADDR (nr_huge_pages))
    {
      nr_huge_pages =
	read_memory_unsigned_integer (ADDR (nr_huge_pages), 4,
				      LKD_BYTE_ORDER);
    }
  else
    {
      /* Might not be compiled in. */ ;
    }

  get_buffered_ram (&buffered_pages, &swapcache_pages);
  get_swap (&totalswap_pages, &freeswap_pages);

  committed = vm_committed_space;
  allowed = totalram * sysctl_overcommit_ratio / 100 + totalswap_pages;

  for (vmlist = read_memory_typed_address (vmlist, lkd_private.target_pointer_type);
       vmlist != 0; vmlist = read_pointer_field (vmlist, vm_struct, next))
    {
      vmalloc += read_unsigned_field (vmlist, vm_struct, size);
    }

  printf_filtered ("MemTotal:      %8lu kB\n"
		   "MemFree:       %8lu kB\n"
		   "Buffers:       %8lu kB\n"
		   "Cached:        %8lu kB\n"
		   "SwapCached:    %8lu kB\n"
		   "Active:        %8lu kB\n"
		   "Inactive:      %8lu kB\n"
		   "Active(anon):  %8lu kB\n"
		   "Inactive(anon):%8lu kB\n"
		   "Active(file):  %8lu kB\n"
		   "Inactive(file):%8lu kB\n"
		   "HighTotal:     %8lu kB\n"
		   "HighFree:      %8lu kB\n"
		   "LowTotal:      %8lu kB\n"
		   "LowFree:       %8lu kB\n"
		   "SwapTotal:     %8lu kB\n"
		   "SwapFree:      %8lu kB\n"
		   "Dirty:         %8lu kB\n"
		   "Writeback:     %8lu kB\n"
		   "Mapped:        %8lu kB\n"
		   "Slab:          %8lu kB\n"
		   "SReclaimable:  %8lu kB\n"
		   "SUnreclaim:    %8lu kB\n"
		   "KernelStack:   %8lu kB (assuming 8k THREAD_SIZE)\n"
		   "CommitLimit:   %8lu kB (minus %lu huge pages)\n"
		   "Committed_AS:  %8lu kB\n"
		   "PageTables:    %8lu kB\n"
		   "VmallocUsed:   %8lu kB\n",
		   K (totalram),
		   K (free_pages),
		   K (buffered_pages),
		   K (pagecache_pages - swapcache_pages - buffered_pages),
		   K (swapcache_pages),
		   K (active_pages),
		   K (inactive_pages),
		   K (active_pages_anon),
		   K (inactive_pages_anon),
		   K (active_pages_file),
		   K (inactive_pages_file),
		   K (totalhigh),
		   K (free_highpages),
		   K (totalram - totalhigh),
		   K (free_pages - free_highpages),
		   K (totalswap_pages),
		   K (freeswap_pages),
		   K (dirty_pages),
		   K (writeback_pages),
		   K (mapped_pages),
		   K (slab_pages),
		   K (slab_reclaimable),
		   K (slab_unreclaimable),
		   kernel_stack * 8,
		   K (allowed),
		   K (nr_huge_pages * sysctl_overcommit_ratio / 100),
		   K (committed), K (pagetable_pages), vmalloc >> 10);
}

#undef K
#undef MAX_NR_ZONES
#undef ZONE_HIGHMEM

static void
proc_version_command (char *args, int from_tty)
{
  printf_filtered ("utsname_release: %s\n", lkd_private.utsname_release);

  /* Not relevant for the user. */
  DEBUG (D_INIT, 1, "kflags: %08x\n", lkd_private.kflags);

  printf_filtered ("banner: %s", get_banner ());
}

static void
proc_cmdline_command (char *args, int from_tty)
{
  static char cmdline[1024];
  CORE_ADDR cmd_addr;

  cmd_addr = read_memory_typed_address (ADDR (saved_command_line),
		  lkd_private.target_pointer_type);

  read_memory_string (cmd_addr, cmdline, 1024);
  cmdline[1023] = '\0';

  printf_filtered ("%s\n", cmdline);
}

struct proc_fs_info
{
  int flag;
  char *str;
};

/*from linux/mount.h */
#define MNT_NOSUID      0x01
#define MNT_NODEV       0x02
#define MNT_NOEXEC      0x04
#define MNT_NOATIME     0x08
#define MNT_NODIRATIME  0x10
#define MNT_RELATIME    0x20
#define MNT_READONLY    0x40
#define MNT_SHRINKABLE  0x100
#define MNT_WRITE_HOLD  0x200
#define MNT_SHARED      0x1000
#define MNT_UNBINDABLE  0x2000

static struct proc_fs_info mnt_info[] = {
  {MNT_NOSUID, ",nosuid"},
  {MNT_NODEV, ",nodev"},
  {MNT_NOEXEC, ",noexec"},
  {MNT_NOATIME, ",noatime"},
  {MNT_NODIRATIME, ",nodiratime"},
  {MNT_RELATIME, ",relatime"},
  {0, NULL}
};

/*from include/linux/fs.h */
#define MS_RDONLY	 1	/* Mount read-only */
#define MS_SYNCHRONOUS	16	/* Writes are synced at once */
#define MS_MANDLOCK	64	/* Allow mandatory locks on an FS */
#define MS_DIRSYNC	128	/* Directory modifications are synchronous */
#define MS_NOATIME	1024	/* Do not update access times. */
#define MS_NODIRATIME	2048	/* Do not update directory access times */

static struct proc_fs_info fs_info[] = {
  {MS_SYNCHRONOUS, ",sync"},
  {MS_DIRSYNC, ",dirsync"},
  {MS_MANDLOCK, ",mand"},
  {MS_NOATIME, ",noatime"},
  {MS_NODIRATIME, ",nodiratime"},
  {0, NULL}
};

static void
proc_mounts_command (char *args, int from_tty)
{
  process_t *ps;
  CORE_ADDR task;
  CORE_ADDR namespace;
  CORE_ADDR list_head = 0, next_vfs, vfs, tmp, tmp2, sb;
  static char buf[256];
  char *str;
  unsigned int flags, len;
  struct proc_fs_info *fs_infop;

  if (lkd_private.loaded != LKD_LOADED)
    {
      printf_filtered (LA_NOT_LOADED_STRING);
      return;
    }

  ps = lkd_proc_get_by_ptid (inferior_ptid);
  task = ps->task_struct;

  buf[255] = '\0';

  namespace = read_pointer_field (task, task_struct, nsproxy);
  namespace = read_pointer_field (namespace, nsproxy, mnt_ns);

  if (!namespace)
    {
      printf_filtered ("No namespace for current process. Kernel thread?\n");
      return;
    }

  list_head = namespace + F_OFFSET (mnt_namespace, list);

  next_vfs = read_pointer_field (list_head, list_head, next);

  if (!strncmp ("2.6", lkd_private.utsname_release, 3))
    while (next_vfs != list_head)
      {

	vfs = next_vfs - F_OFFSET (vfsmount, mnt_list);

	tmp = read_pointer_field (vfs, vfsmount, mnt_devname);
	if (tmp)
	  read_memory_string (tmp, buf, 255);
	else
	  strcpy (buf, "none");
	printf_filtered ("%s ", buf);

	tmp2 = vfs;
	len = 0;
	do
	  {
	    tmp = read_pointer_field (tmp2, vfsmount, mnt_mountpoint);
	    str = read_dentry (tmp);
	    memmove (buf + strlen (str), buf, len);
	    len += strlen (str);

	    strcpy (buf, str);
	    buf[strlen (str)] = '/';
	    xfree (str);

	    tmp = tmp2;
	    tmp2 = read_pointer_field (tmp2, vfsmount, mnt_parent);
	  }
	while (tmp != tmp2);

	buf[len ? len : 1] = '\0';
	printf_filtered ("%s ", buf);

	sb = read_pointer_field (vfs, vfsmount, mnt_sb);
	tmp = read_pointer_field (sb, super_block, s_type);
	tmp = read_pointer_field (tmp, file_system_type, name);
	read_memory_string (tmp, buf, 255);
	printf_filtered ("%s ", buf);

	flags = read_unsigned_field (sb, super_block, s_flags);
	if (flags & MS_RDONLY)
	  printf_filtered ("ro");
	else
	  printf_filtered ("rw");

	for (fs_infop = fs_info; fs_infop->flag; fs_infop++)
	  {
	    if (flags & fs_infop->flag)
	      printf_filtered ("%s", fs_infop->str);
	  }

	flags = read_unsigned_field (vfs, vfsmount, mnt_flags);

	for (fs_infop = mnt_info; fs_infop->flag; fs_infop++)
	  {
	    if (flags & fs_infop->flag)
	      printf_filtered ("%s", fs_infop->str);
	  }

	printf_filtered ("\n");

	next_vfs = read_pointer_field (next_vfs, list_head, next);
      }
  else
    while (next_vfs != list_head)
      {
	CORE_ADDR vfs_mount;

	vfs = container_of (next_vfs, mount, mnt_list);

	tmp = read_pointer_field (vfs, mount, mnt_devname);
	if (tmp)
	  read_memory_string (tmp, buf, 255);
	else
	  strcpy (buf, "none");
	printf_filtered ("%s ", buf);

	tmp2 = vfs;
	len = 0;
	do
	  {
	    tmp = read_pointer_field (tmp2, mount, mnt_mountpoint);
	    str = read_dentry (tmp);
	    memmove (buf + strlen (str), buf, len);
	    len += strlen (str);

	    strcpy (buf, str);
	    buf[strlen (str)] = '/';
	    xfree (str);

	    tmp = tmp2;
	    tmp2 = read_pointer_field (tmp2, mount, mnt_parent);
	  }
	while (tmp != tmp2);

	buf[len ? len : 1] = '\0';
	printf_filtered ("%s ", buf);

	sb = read_pointer_embedded_field (vfs, mount, mnt, vfsmount, mnt_sb);
	tmp = read_pointer_field (sb, super_block, s_type);
	tmp = read_pointer_field (tmp, file_system_type, name);
	read_memory_string (tmp, buf, 255);
	printf_filtered ("%s ", buf);

	/*  Parse MS_xxx flags  */
	flags = read_unsigned_field (sb, super_block, s_flags);
	if (flags & MS_RDONLY)
	  printf_filtered ("ro");
	else
	  printf_filtered ("rw");
	for (fs_infop = fs_info; fs_infop->flag; fs_infop++)
	  {
	    if (flags & fs_infop->flag)
	      printf_filtered ("%s", fs_infop->str);
	  }

	/*  Parse MNT_xxx flags */
	flags =
	  read_pointer_embedded_field (vfs, mount, mnt, vfsmount, mnt_flags);
	for (fs_infop = mnt_info; fs_infop->flag; fs_infop++)
	  {
	    if (flags & fs_infop->flag)
	      printf_filtered ("%s", fs_infop->str);
	  }

	printf_filtered ("\n");
	next_vfs = read_pointer_field (next_vfs, list_head, next);
      }
}

/******************************************************************************/
/*************  LINUX AWARENESS INIT / AUTODETECTION / ENABLEMENT   ***********/
/******************************************************************************/
int
lkd_try_push_target (void)
{
  DEBUG (D_INIT, 1, "lkd_try_push_target\n");

  if (!BENEATH)
    push_target (&linux_aware_ops);

  if (lkd_proxy_init_target (BENEATH) != lkd_invalid)
    return LKD_LOADED;

  DEBUG (D_INIT, 1, "lkd_try_push_target: Init target failed : Not Loaded.\n");

  return LKD_NOTLOADED;
}

/* This function is called after load, or after attach, when we know
 that the kernel code is in memory. (This might be called direclty
 by the user by issuing 'set linux-awareness loaded', if he doesn't
 use a standard attach mechanism. */
void
lkd_loaded_set (char *arg, int from_tty, struct cmd_list_element *c)
{
  bfd *cur_bfd;
  process_t *ps;
  char *banner1;
  char *banner2, *file_name;
  int i;

  DEBUG (D_INIT, 1, "lkd_loaded_set\n");

  if (lkd_params.loaded == lkd_private.loaded)
    return;

  if ((lkd_params.loaded == LKD_LOADED) && (!lkd_params.enabled))
    {
      lkd_enabled_set ((char *) 1, 0, NULL);
      /* Could not enable so not debugging a kernel */
      if (!lkd_params.enabled)
	goto __sl_fail;
    }

  stop_core = 0;
  cur_bfd = get_cur_bfd (from_tty);

  /* if user forces loaded = off, also remove auto-load
   **/
  if (lkd_params.loaded == LKD_NOTLOADED)
    {
      struct cleanup *cleanup;

      /* Before switching off first need to clear some caches.  */
      thread_awareness_inhibit ();
      cleanup = make_cleanup (thread_awareness_exhibit, NULL);
      linux_awareness_ops->lo_clear_cache ();
      do_cleanups (cleanup);

      lkd_private.loaded = LKD_NOTLOADED;

      if (lkd_params.auto_activate)
	{
	  lkd_params.auto_activate = 0;
	  if (from_tty)
	    printf_filtered
	      ("(also disabling linux-awareness auto-activation)\n");
	}

      lkd_proc_free_list ();

      /* fallback to any thread that makes sense for the beneath target */
      lkd_reset_thread_list ();

      return;
    }

  /* if the user want to set loaded = on, do some sanity checks
   **/
  if (lkd_params.loaded == LKD_LOADED)
    {
      /* check if symbol-file was set first */
      if (!get_cur_bfd (from_tty))
	goto __sl_fail;

      cur_bfd = get_cur_bfd (from_tty);
      banner2 = get_banner_from_file (cur_bfd);
      file_name = bfd_get_filename (cur_bfd);

	  lkd_private.target_pointer_type =
			builtin_type (target_gdbarch())->builtin_data_ptr;

	  DEBUG (D_INIT, 1, "lkd_loaded_set : target_gdbarch() 0x%p\n", target_gdbarch());
	  DEBUG (D_INIT, 1, "lkd_loaded_set : builtin_type (target_gdbarch()) 0x%p\n", builtin_type (target_gdbarch()));

      DEBUG (D_INIT, 1, "lkd_loaded_set : target_pointer_type set in 0x%p\n", lkd_private.target_pointer_type);


      if (linux_awareness_ops->lo_pre_load)
	linux_awareness_ops->lo_pre_load (file_name, from_tty);

      lkd_private.loaded = LKD_LOADING;

      gdb_assert (lkd_params.enabled);

      if (!(lkd_private.kflags & KFLAG_DBGINFO))
	{
	  warning
	    ("\"set loaded\" failed because kernel has no debug info.\n");
	  goto __sl_fail;
	}

      if (lkd_try_push_target () != LKD_LOADED)
	{
	  warning
	    ("\"set loaded\" failed because L-A target could not be pushed.\n");
	  goto __sl_fail;
	}

      /* check for MMU availability, (if underlying target is of a
       * usable type). */
      if (!linux_awareness_ops->lo_check_mem_rdy ())
	goto __sl_fail;		/* bail out */

      /* (re)init the thread_list with hardware threads */
      lkd_proc_init ();

      /*do arch-specific fixup (mmu for instance) */
      linux_aware_post_load (file_name, 0);

      /*needs access to mem */
      if (set_utsname_release () != 0 /*EOK*/)
	{
	  warning
	    ("\"set loaded\" failed because L-A target could not access target memory.\n");
	  goto __sl_fail;
	}

      /*get banner from mem */
      banner1 = get_banner ();

      /* Check that the kernel in memory corresponds to the
       * binary file we were given.
       */
      if (banner1 == NULL || banner2 == NULL || strcmp (banner1, banner2))
	{
	  if (!nquery
	      ("Kernel banner in debugger file: \n%s\n"
	       "Kernel banner in target memory: \n%s\n"
	       "WARNING: do you want to continue ?\n"
	       "(if the kernels don't match the debugger might crash)",
	       banner2, banner1))
	    {
	      error ("Aborted (kernel banner mismatch).");
	      goto __sl_fail;
	    }
	}

      lkd_proc_invalidate_list ();

      /* scan the linux threads */

      if (!lkd_proc_refresh_info (stop_core))
	{
	  if (from_tty)
	    printf_filtered ("failed: has this kernel started?\n");
	  goto __sl_fail;
	}

      lkd_proc_set_symfile ();

      /* read module list, if possible
       * */
      lkd_modules_build_list ();

      lkd_private.loaded = lkd_params.loaded;
    }

  printf_filtered ("Kernel image version: %s\n", lkd_private.utsname_release);

  return;

__sl_fail:
  /* silently fail, we retry later.
   **/
	DEBUG (D_INIT, 1, "(not so) Silently Failing ...\n");

  lkd_params.loaded = LKD_NOTLOADED;
  lkd_private.loaded = LKD_NOTLOADED;
  return;
}

/* Helper for linux_awareness_fix_debug_info() that locates the lowest
 section in a BFD. */
static void
find_min_load_addr (bfd * abfd, asection * sectp, void *addr)
{
  CORE_ADDR *min_addr = addr;
  CORE_ADDR vma;

  if (!(bfd_get_section_flags (abfd, sectp) & SEC_ALLOC))
    return;
  if (!(bfd_get_section_flags (abfd, sectp) & SEC_HAS_CONTENTS))
    return;

  vma = bfd_get_section_vma (abfd, sectp);
  if (vma < *min_addr)
    *min_addr = vma;
}

/*
 * The functionalities that can be built as modules often have a
 * cleanup routine (marked with module_exit). When the driver is built
 * into the kernel (i.e. not as a module), the cleanup routines aren't
 * linked in, but their debug information remains... These routines
 * all have very low addresses (as they haven't been relocated). This
 * functions try to partially fix the debug info, so that the psymtabs
 * don't advertise a too wide range of text addresses.
 */
static void
linux_awareness_fix_debug_info (void)
{
  CORE_ADDR min_load_addr = (CORE_ADDR) - 1;
  struct partial_symtab *pst;

  bfd_map_over_sections (symfile_objfile->obfd, find_min_load_addr,
			 &min_load_addr);

  ALL_OBJFILE_PSYMTABS (symfile_objfile, pst)
  {
    if (pst->textlow < min_load_addr)
      pst->textlow = min_load_addr;
  }
}

/* GDB wants the stack it reads to have a strictly decreasing SP. This
 relation isn't true when the backtrace goes from kerne- to
 user-space. Overload the inner_than method to hide this
 peculiarity. */
static int
linux_aware_inner_than (CORE_ADDR lhs, CORE_ADDR rhs)
{
  if (linux_awareness_ops->lo_is_kernel_address (rhs)
      && linux_awareness_ops->lo_is_user_address (lhs))
    return 0;

  return core_addr_lessthan (lhs, rhs);
}


/******************* linux thread filtering *****************/

#ifdef FILTERING_SUPPORT	// fixme: filtering
/* call back for thread.c to filter thread_list
 **/
int
thread_list_filter (struct thread_info *tp, void *ignored)
{
  switch (lkd_params.filter)
    {
    case lkd_filter_scheduled_only:
      if ((ptid_get_tid (tp->ptid) == CORE_INVAL)
	  || (ptid_get_tid (tp->ptid) >= MAX_CORES))
	delete_thread (tp->ptid);
      break;
    }
  return 0;
}

void
set_filter (char *arg, int from_tty, struct cmd_list_element *c)
{
  if (lkd_params.filter == lkd_filter_scheduled_only)
    {
      printf_filtered ("setting filter to \"scheduled only\".\n");
    }
  else
    {
      printf_filtered ("resetting filter to default.\n");
      lkd_params.filter = lkd_filter_none;
    }

  iterate_over_threads (thread_list_filter, NULL);
  lkd_proc_invalidate_list ();
  (void) lkd_proc_get_list ();
}

void
show_filter (struct ui_file *f,
	     int from_tty, struct cmd_list_element *c, const char *v)
{
  switch (lkd_params.filter)
    {
    case lkd_filter_scheduled_only:
      fprintf_filtered (f, _("lkd_filter_scheduled_only.\n"));
      break;
    default:
      fprintf_filtered (f, _("no filter.\n"));
    }
}
#endif // fixme: filtering

void
set_skip_schedule_frame (char *arg, int from_tty, struct cmd_list_element *c)
{
  reinit_frame_cache ();
}


/* Function called to init the linux awareness layer once we know
 we're debugging a known kernel. */
static void
linux_awareness_init (void)
{
  struct cmd_list_element *c;
  const char *linux_awareness_postinit = "linux-awareness-postinit";

  DEBUG (D_INIT, 1, "linux_awareness_init\n");

  /* Stack our layer over the real target stack. */
  lkd_try_push_target ();

  /* this may set the OS ABI (reset the solib ops too!) */
  linux_awareness_ops->lo_init ();

  printf_filtered ("Enabling Linux Kernel Debugger %s build %s.\n",
		   LKD_VERSION_STRING, __DATE__);

  /* Set this as early as we can */
  lkd_private.target_pointer_type = builtin_type (target_gdbarch())->builtin_data_ptr;

  /* Init some data structures. */
  linux_awareness_fix_debug_info ();

  /* Register the various callbacks we use. */
  normal_stop_observer = observer_attach_normal_stop (normal_stop_callback);
  observer_attach_breakpoint_created (linux_aware_create_breakpoint_hook);

#ifdef HAS_PAGE_MONITORING
  observer_attach_breakpoint_deleted (linux_aware_delete_breakpoint_hook);
#endif

  set_gdbarch_inner_than (target_gdbarch (), linux_aware_inner_than);

  /* set the solib ops */
  lkd_modules_init ();

  add_info_alias ("tasks", "threads", 0);
  add_com_alias ("task", "thread", class_run, 0);

  add_com ("running_task", class_stm, running_task_command,
	   "Switch to the currently running task.");

  add_com ("dmesg", class_stm, dmesg_command,
	   "Display the contents of the linux log buffer or write to a FILE.");

  add_com ("process_info", class_stm, process_info_command,
	   "Print various info about the current process.");

  add_com ("pmap", class_stm, pmap_command,
	   "Print the memory map of the current process.");

  add_com ("vm_translate", class_stm, vm_translate_command,
	   "Translate a virtual address to a physical one.");

  add_com ("proc_interrupts", class_stm, interrupts_command,
	   "Print interrupt statistics.");

  add_com ("proc_ioports", class_stm, ioports_command,
	   "Print the I/O ports map.");

  add_com ("proc_iomem", class_stm, iomem_command, "Print the I/O mem map.");

  add_com ("proc_version", class_stm, proc_version_command,
	   "Print the contents of /proc/version.");

  add_com ("proc_cmdline", class_stm, proc_cmdline_command,
	   "Print the contents of /proc/cmdline.");

  add_com ("proc_mounts", class_stm, proc_mounts_command,
	   "Print the contents of /proc/mounts.");

  add_com ("proc_meminfo", class_stm, proc_meminfo_command,
	   "Print the contents of /proc/meminfo.");

  add_com ("debug_process", class_stm, debug_process_command,
	   "Allow to debug the current userspace process. "
	   "This will load the required symbols.");

  add_com ("wait_exe", class_stm, wait_exe_command,
	   "Make the debugger execute a list of commands when a given "
	   "executable is exec'd");

  add_com ("wait-exe-uid", class_stm, wait_exe_uid_command,
	   "Make the debugger execute a list of commands when a given "
	   "executable is exec'd with a specific UID");

#ifdef HAS_ANDROID_SUPPORT
  add_com ("wait-android-vm", class_stm, wait_android_vm_command,
	   "Make the debugger execute a list of commands when a given "
	   "Android VM (app_*) is started.");
#endif

#ifdef HAS_PAGE_MONITORING
  add_com ("wait_page", class_stm, wait_page_command,
	   "Make the debugger stop when a given page is mapped to memory.");
#endif

#if HAS_SET_LOG_CHUNK_SIZE
  add_setshow_uinteger_cmd ("log_chunk_size",
			    class_stm,
			    &log_chunk_size,
			    "Set the size of the chunks used while reading"
			    " log_buf",
			    "Show the size of the chunks used while reading"
			    " log_buf",
			    NULL, NULL, NULL,
			    &set_linux_awareness_cmd_list,
			    &show_linux_awareness_cmd_list);
#endif

  add_setshow_integer_cmd ("skip_schedule_frame",
			   class_stm,
			   &lkd_params.skip_schedule_frame,
			   "Set whether the debugger should hide the schedule() frame for sleeping tasks",
			   "Show whether the debugger should hide the schedule() frame for sleeping tasks",
			   "Typical value is between 0 for full stack to 4",
			   &set_skip_schedule_frame, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

#ifdef FILTERING_SUPPORT
  add_setshow_integer_cmd ("filter",
			   class_stm,
			   (int *) &lkd_params.filter,
			   "Set/Show the filter on Linux threads",
			   "Set/Show the filter on Linux threads",
			   "available filters: \n 1: scheduled only",
			   &set_filter, &show_filter,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);
#endif

  /* Call the user-defined linux_awareness_postinit command if it
     exists. (Allows the user to put code in his .gdbinit that will
     be run only if the layer is loaded). */
  c = lookup_cmd (&linux_awareness_postinit, cmdlist, "", 1, 1);
  if (c != NULL && c->theclass == class_user)
    execute_user_command (c, 0);

  /* tune user experience:
   * it's convenient to turn off the y/n query for pending bp
   * to have a chance of silently resolve the symbol
   */
  pending_break_support = AUTO_BOOLEAN_TRUE;
}

/* Helper for the autoactivation symbol lookup. */
static inline int
linux_awareness_lookup_symbol (const char *name)
{
  int found = lookup_minimal_symbol (name, NULL, NULL).minsym != NULL;

  if (!found)
    DEBUG (D_INIT, 1, "Symbol '%s' not found\n", name);
  else
    DEBUG (D_INIT, 4, "Symbol '%s' found\n", name);

  return found;
}

/* Helper for the autoactivation symbol lookup. */
static inline int
linux_awareness_lookup_symtab (const char *name)
{
  int found = lookup_symtab (name) != NULL;

  if (!found)
    DEBUG (D_INIT, 1, "Symtab '%s' not found\n", name);
  else
    DEBUG (D_INIT, 4, "Symtab '%s' found\n", name);

  return found;
}

/* make sure we have a kernel objfile */
static int
linux_awareness_check (void)
{
  int build = 0;
  int check = 0;

  DEBUG (D_INIT, 1, "linux_awareness_check\n");

  /* reset flags */
  lkd_private.kflags &= ~(KFLAG_LINUX | KFLAG_DBGINFO);

  /* Look for some specific Linux symbols. */
  if (!linux_awareness_lookup_symbol ("schedule")
      || !linux_awareness_lookup_symbol ("linux_banner"))
    return 0;			/* KO */

  lkd_private.kflags |= KFLAG_LINUX;

  /* More checks. */
  lookup_symtab ("page_io.c");

  /* check for mandatory structure and fields */

  check = HAS_FIELD (pid_namespace, last_pid)
    && HAS_FIELD (task_struct, nsproxy);

  if (!check)			/*look for older kernels */
    check = HAS_FIELD (list_head, next) && HAS_FIELD (task_struct, namespace);

  check = check && HAS_FIELD (task_struct, children)
    && HAS_FIELD (task_struct, sibling)
    && HAS_FIELD (task_struct, thread_group)
    && HAS_FIELD (task_struct, pid)
    && HAS_FIELD (task_struct, tgid)
    && HAS_FIELD (task_struct, comm)
    && HAS_FIELD (thread_info, preempt_count);

  /* load some data that GDB seems to loose otherwise */
  if (check && linux_awareness_lookup_symtab ("mmap.c")
      && linux_awareness_lookup_symtab ("fork.c")
      && linux_awareness_lookup_symtab ("block_dev.c")
      && linux_awareness_lookup_symtab ("vmalloc.c")
      && linux_awareness_lookup_symtab ("page_alloc.c")
      && linux_awareness_ops->lo_check_kernel ())
    lkd_private.kflags |= KFLAG_DBGINFO;
  else
    warning ("debug information missing.");

  lkd_private.kflags |= KFLAG_DBGINFO;

  return 1;			/* OK */
}

/* Function called when we enable or disable the linux awareness
 layer. */
void
lkd_enabled_set (char *args, int from_tty, struct cmd_list_element *c)
{
  static int stored_state = 0;

  DEBUG (D_INIT, 1, "lkd_enabled_set\n");

  /*if not from tty, we can use args as a parameter. */
  if ((!from_tty) && ((int) args == 1))
    lkd_params.enabled = 1;

  if (lkd_params.enabled == stored_state)
    return;

  if (lkd_params.enabled == 1)
    {

      /* make sure that a bfd is available,
       * reevaluate the current objfile
       */
      if (linux_awareness_check () && get_cur_bfd (from_tty))
	linux_awareness_init ();
      else
	{
	  /* bare machine debuggee, do not auto-enable
	   * but allow bold user commands...*/
	  lkd_params.enabled = 0;

	  /* try to push the target anyway,
	   * so that we get called into to_load */
	  if (!BENEATH)
	    push_target (&linux_aware_ops);

	  if (from_tty)
	    warning ("Could not enable linux-awareness: no objfile ?");
	}

    }
  else if (!ptid_equal (inferior_ptid, null_ptid))	/*if not `mourned`already */
    {
      struct target_waitstatus dummy;
      struct thread_info *tp;

      /* Make sure the hooks are removed if we toggle back to baremachine */
      lkd_modules_close ();

      /* this will reinit the thread_list.
       * and record the current "loaded" status.
       **/
      lkd_params.loaded = LKD_NOTLOADED;
      lkd_loaded_set (NULL, 0, NULL);
    }

  stored_state = lkd_params.enabled;
}

/* This callback is called each time the user loads a new executable
 in GDB, and it tries to determine if it's a Linux kernel. If it's
 the case, it loads the linux awareness layer. */
static void
linux_awareness_on_new_objfile (struct objfile *objf)
{
  DEBUG (D_INIT, 1, "linux_awareness_on_new_objfile\n");

  /* try pushing target and enabling at least.
   **/
  if (lkd_params.auto_activate)
    lkd_enabled_set ((char *) 1, 0, 0);
}

static void
set_linux_awareness (char *arg, int from_tty)
{
  printf_unfiltered
    ("'set linux-awareness' must be followed by the name of a print subcommand.\n");
  help_list (set_linux_awareness_cmd_list, "set linux-awareness ", -1,
	     gdb_stdout);
}

static void
show_linux_awareness (char *args, int from_tty)
{
  cmd_show_list (show_linux_awareness_cmd_list, from_tty, "");
}

static void
set_global_loglevel (char *arg, int from_tty, struct cmd_list_element *c)
{
  struct debug_domain *domain = linux_aware_debug_domains_info;

  while (domain->name != NULL)
    domain++->level = lkd_params.loglevel;
}

volatile int stop_loop = 1;

/* initialize private data
 * when will gdb go OOP at least !??
 **/
static void
init_private_data (void)
{
  lkd_private.string_buf_size = 4096;
  lkd_private.string_buf =
    xcalloc (lkd_private.string_buf_size, sizeof (char));
  lkd_private.banner_file_size = 256;
  lkd_private.banner_file =
    xcalloc (lkd_private.banner_file_size, sizeof (char));
  lkd_private.banner_file_valid = 0;
  lkd_private.banner_mem_size = 256;
  lkd_private.banner_mem =
    xcalloc (lkd_private.banner_mem_size, sizeof (char));
  lkd_private.banner_mem_valid = 0;
  lkd_private.utsname_release_size = 256;
  lkd_private.utsname_release =
    xcalloc (lkd_private.banner_mem_size, sizeof (char));
  lkd_private.utsname_release_valid = 0;
  lkd_private.kflags = KFLAG_NOLINUX;
}

static void
linux_awareness_inferior_created (struct target_ops *ops, int from_tty)
{
  DEBUG (D_INIT, 1, "linux_awareness_inferior_created\n");
  if (lkd_params.auto_activate)
    lkd_enabled_set ((char *) 1, 0, 0);
}

static ptid_t target_thread_ptid;

static void
linux_awareness_target_thread_changed (ptid_t ptid)
{
  DEBUG (D_INIT, 1, "linux_awareness_target_thread_changed {%d, %ld, %ld}\n",
	 ptid_get_pid (ptid), ptid_get_lwp (ptid), ptid_get_tid (ptid));

  if (ptid_equal (ptid, null_ptid) || ptid_equal (ptid, minus_one_ptid))
    target_thread_ptid = null_ptid;
  else if (ptid_get_tid (ptid) != CORE_INVAL)
    target_thread_ptid = ptid;
}

int
linux_aware_target_core (void)
{
  gdb_assert (!ptid_equal (target_thread_ptid, null_ptid));

  return ptid_get_tid (target_thread_ptid) - 1;
}

/* -Wmissing-prototypes */
extern initialize_file_ftype _initialize_linux_awareness;

/* Function called automatically by GDB on each start. */
void
_initialize_linux_awareness (void)
{
  struct debug_domain *domain;

  while (!stop_loop);

  linux_uprocess_objfile_data_key = register_objfile_data ();

  init_private_data ();

  target_thread_ptid = null_ptid;

  observer_attach_inferior_created (linux_awareness_inferior_created);
  observer_attach_new_objfile (linux_awareness_on_new_objfile);
  observer_attach_target_thread_changed
    (linux_awareness_target_thread_changed);

  init_linux_aware_target ();
  add_target (&linux_aware_ops);

  target_root_prefix = &gdb_sysroot;

  add_prefix_cmd ("linux-awareness",
		  class_stm,
		  set_linux_awareness,
		  "Command for setting linux-awareness variables",
		  &set_linux_awareness_cmd_list,
		  "set linux-awareness ", 0, &setlist);

  add_prefix_cmd ("linux-awareness",
		  class_stm,
		  show_linux_awareness,
		  "Command for showing linux-awareness variables",
		  &show_linux_awareness_cmd_list,
		  "show linux-awareness ", 0, &showlist);

  add_setshow_boolean_cmd ("enabled",
			   class_stm,
			   &lkd_params.enabled,
			   "Set the activation state of the the linux "
			   "awareness layer",
			   "Show the activation state of the the linux "
			   "awareness layer",
			   NULL, &lkd_enabled_set, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("loaded",
			   class_stm,
			   (int*)&lkd_params.loaded, /*warn: can be '2' to detect transient states */
			   "Set the loaded state of the kernel image",
			   "Show the loaded state of the kernel image",
			   NULL, &lkd_loaded_set, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  domain = linux_aware_debug_domains_info;

  while (domain->name != NULL)
    {
      static const char fmt[] =
	"%s the debug level of the linux awareness " "layer %s part.";
      const char *name = domain->name + 6;	/* Skip debug- */
      char *help_set = xstrprintf (fmt, "Set", name);
      char *help_show = xstrprintf (fmt, "Show", name);
      add_setshow_zinteger_cmd ((char *) domain->name,
				class_stm,
				&(domain->level),
				help_set,
				help_show,
				NULL,
				NULL, NULL,
				&set_linux_awareness_cmd_list,
				&show_linux_awareness_cmd_list);
      xfree (help_set);
      xfree (help_show);
      ++domain;
    }

  add_setshow_zinteger_cmd ("debug-all",
			    class_stm,
			    &lkd_params.loglevel,
			    "Set the debug level of the linux awareness "
			    "layer",
			    "Show the debug level of the linux awareness "
			    "layer",
			    NULL,
			    &set_global_loglevel, NULL,
			    &set_linux_awareness_cmd_list,
			    &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("enable_vm_translation",
			   class_stm,
			   &lkd_params.enable_vm_translation,
			   "Set whether we try to translate virtual "
			   "addresses into physical ones",
			   "Show whether we try to translate virtual "
			   "addresses into physical ones",
			   NULL, NULL, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("enable_task_awareness",
			   class_stm,
			   &lkd_params.enable_task_awareness,
			   "Set whether we implement task awareness",
			   "Show whether we implement task awareness",
			   NULL, NULL, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("auto_activate",
			   class_stm,
			   &lkd_params.auto_activate,
			   "Set whether we try to autodetect linux kernels.",
			   "Show whether we try to autodetect linux kernels.",
			   NULL, NULL, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("auto_debug_process",
			   class_stm,
			   &lkd_params.auto_debug_process,
			   "Set whether we try to automatically load "
			   "information for userspace processes.",
			   "Show whether we try to automatically load "
			   "information for userspace processes.",
			   NULL, NULL, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("no-colors",
			   class_stm,
			   &lkd_params.no_colors,
			   "Set disable thread info coloring.",
			   "Show thread info coloring status.",
			   NULL, NULL, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);
}

/******************************* from shtdi.c *********************************/

static void
terminate_once (int signo)
{
  signal (signo, SIG_IGN);	/* Ignore further signals */
  terminate_requested = signo;
}

static void
disable_terminate (void)
{
  terminate_requested = 0;	/* Reset */
  old_terminate_handler = signal (SIGTERM, terminate_once);
  old_interrupt_handler = signal (SIGINT, terminate_once);
}

static void
enable_terminate (void)
{
  signal (SIGTERM, old_terminate_handler);
  signal (SIGINT, old_interrupt_handler);
  if (terminate_requested)
    raise (terminate_requested);
}
