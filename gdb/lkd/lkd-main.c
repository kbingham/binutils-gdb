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
  {"debug-task", 0},
  {"debug-target", 0},
  {"debug-init", 0},
  {"debug-frame", 0},
  {"debug-bp", 0},
  {NULL, 0}
};

/* The definition of the log domains and the storage for their
 associated log levels. */
struct linux_awareness_params lkd_params = {
  .enabled = 0,
  .loaded = LKD_NOTLOADED,
  .enable_task_awareness = 1,
  .auto_activate = 1,
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

/* The structure that gives access to target-dependent knowledge
 required by the Linux awareness layer. Declared in lkd.h
 and defined in a targetting file (eg. lkd-arm.c). */
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
  if (linux_awareness_ops && linux_awareness_ops->lo_pre_exec_start)
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

  /* We aren't running anymore. */
  running = 0;

  if (thread_awareness_inhibited () || !(lkd_private.kflags & KFLAG_DBGINFO))
    return BENEATH->to_wait (ops, ptid, status, opts);

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




/******************************************************************************/
/*************  LINUX AWARENESS INIT / AUTODETECTION / ENABLEMENT   ***********/
/******************************************************************************/
int
lkd_try_push_target (void)
{
  DEBUG (D_INIT, 1, "lkd_try_push_target\n");

  if (!BENEATH)
    push_target (&linux_aware_ops);

  return LKD_LOADED;
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


      lkd_private.loaded = lkd_params.loaded;
    }

  printf_filtered ("Kernel image version: %s\n", lkd_private.utsname_release);

  return;

__sl_fail:
  /* silently fail, we retry later.
   **/
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


  add_info_alias ("tasks", "threads", 0);
  add_com_alias ("task", "thread", class_run, 0);

  add_com ("running_task", class_lkd, running_task_command,
	   "Switch to the currently running task.");


  add_com ("process_info", class_stm, process_info_command,
	   "Print various info about the current process.");

  add_com ("pmap", class_stm, pmap_command,
	   "Print the memory map of the current process.");

#ifdef HAS_ANDROID_SUPPORT
  add_com ("wait-android-vm", class_lkd, wait_android_vm_command,
	   "Make the debugger execute a list of commands when a given "
	   "Android VM (app_*) is started.");
#endif

#ifdef HAS_PAGE_MONITORING
  add_com ("wait_page", class_lkd, wait_page_command,
	   "Make the debugger stop when a given page is mapped to memory.");
#endif

  add_setshow_integer_cmd ("skip_schedule_frame",
			   class_lkd,
			   &lkd_params.skip_schedule_frame,
			   "Set whether the debugger should hide the schedule() frame for sleeping tasks",
			   "Show whether the debugger should hide the schedule() frame for sleeping tasks",
			   "Typical value is between 0 for full stack to 4",
			   &set_skip_schedule_frame, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

#ifdef FILTERING_SUPPORT
  add_setshow_integer_cmd ("filter",
			   class_lkd,
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

  /* Make sure we have an architecture layer */
  if (!linux_awareness_ops)
  {
	  /* More verbose here, as we believe we are looking at a kernel,
	   * and the --enable-linux-awareness configure flag has been set */
	  warning ("Architecture Layer Missing. Can't enable linux awareness");
	  return 0;
  }

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
  if ((!from_tty) && ((uintptr_t)args == 1))
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
		  class_lkd,
		  set_linux_awareness,
		  "Command for setting linux-awareness variables",
		  &set_linux_awareness_cmd_list,
		  "set linux-awareness ", 0, &setlist);

  add_prefix_cmd ("linux-awareness",
		  class_lkd,
		  show_linux_awareness,
		  "Command for showing linux-awareness variables",
		  &show_linux_awareness_cmd_list,
		  "show linux-awareness ", 0, &showlist);

  add_setshow_boolean_cmd ("enabled",
			   class_lkd,
			   &lkd_params.enabled,
			   "Set the activation state of the the linux "
			   "awareness layer",
			   "Show the activation state of the the linux "
			   "awareness layer",
			   NULL, &lkd_enabled_set, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("loaded",
			   class_lkd,
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
				class_lkd,
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
			    class_lkd,
			    &lkd_params.loglevel,
			    "Set the debug level of the linux awareness "
			    "layer",
			    "Show the debug level of the linux awareness "
			    "layer",
			    NULL,
			    &set_global_loglevel, NULL,
			    &set_linux_awareness_cmd_list,
			    &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("enable_task_awareness",
			   class_lkd,
			   &lkd_params.enable_task_awareness,
			   "Set whether we implement task awareness",
			   "Show whether we implement task awareness",
			   NULL, NULL, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("auto_activate",
			   class_lkd,
			   &lkd_params.auto_activate,
			   "Set whether we try to autodetect linux kernels.",
			   "Show whether we try to autodetect linux kernels.",
			   NULL, NULL, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  add_setshow_boolean_cmd ("no-colors",
			   class_lkd,
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
