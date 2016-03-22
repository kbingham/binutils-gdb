/* Linux kernel-level threads support.

   Copyright (C) 2016 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "gdbcore.h"
#include "gdbthread.h"
#include "inferior.h"
#include "objfiles.h"
#include "observer.h"
#include "regcache.h"
#include "target.h"

#include "gdb_obstack.h"

#define DEBUG_LINUX_KTHREAD
#ifdef DEBUG_LINUX_KTHREAD
#define ENTER() do { printf_unfiltered("Enter %s:%d\n", __FUNCTION__, __LINE__); } while (0)
#define DEBUG(d,l,fmt, args...) do { printf_unfiltered("%s:%d: " fmt, __FUNCTION__, __LINE__, ##args); } while (0)
#define DEBUG_DOMAIN(domain) (1)
#else
#define ENTER() do { } while (0)
#define DEBUG(d,l, fmt, args...) do { } while (0)
#define DEBUG_DOMAIN(domain) (0)
#endif

#include "linux-kthread.h"

/* use scratch area for messing around with strings
 * to avoid static arrays and dispersed mallocs and frees
 **/
static struct lkd_private_data
{
  //lkd_load_states_t loaded;
  //int connected;
  //int keep_do_exit_event;

  unsigned char *string_buf;
  int string_buf_size;

  //char *banner_file;		/* string for the banner as read from vmlinx */
  //int banner_file_size;		/* max size allocated */
  //int banner_file_valid;	/* valid or to refresh */

  int proc_list_invalid;

  //char *banner_mem;		/* string for the banner as read from vmlinx */
  //int banner_mem_size;		/* max size allocated */
  //int banner_mem_valid;		/* valid or to refresh */

  /* The UTS name as extracted from the file or the memory. This serves
     to build the path that points to the depmod cache. */
  //char *utsname_release;
  //int utsname_release_size;	/* max size allocated */
  //int utsname_release_valid;	/* valid or to refresh */

  //struct type *target_pointer_type;

  //uint32_t kflags;
} lkd_private;

/* Save the linux_kthreads ops returned by linux_kthread_target.  */
static struct target_ops *linux_kthread_ops;

/* Non-zero if the thread stratum implemented by this module is active.  */
static int linux_kthread_active;

/*****************************************************************************/
/*******************  Architecture-specific operations  **********************/
/*****************************************************************************/

/* Per-architecture data key.  */
static struct gdbarch_data *linux_kthread_data;

struct linux_kthread_ops
{
  /* Supply registers for a thread to a register cache.  */
  void (*supply_kthread) (struct regcache *, int, CORE_ADDR);

  /* Collect registers for a thread from a register cache.  */
  void (*collect_kthread) (const struct regcache *, int, CORE_ADDR);
};

static void *
linux_kthread_init (struct obstack *obstack)
{
  struct linux_kthread_ops *ops;

  ops = OBSTACK_ZALLOC (obstack, struct linux_kthread_ops);
  return ops;
}

/* Set the function that supplies registers from an inactive thread
   for architecture GDBARCH to SUPPLY_UTHREAD.  */

void
linux_kthread_set_supply_thread (struct gdbarch *gdbarch,
				 void (*supply_kthread) (struct regcache *,
							 int, CORE_ADDR))
{
  struct linux_kthread_ops *ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);

  ops->supply_kthread = supply_kthread;
}

/* Set the function that collects registers for an inactive thread for
   architecture GDBARCH to SUPPLY_UTHREAD.  */

void
linux_kthread_set_collect_thread (struct gdbarch *gdbarch,
				  void (*collect_kthread) (const struct
							   regcache *, int,
							   CORE_ADDR))
{
  struct linux_kthread_ops *ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);

  ops->collect_kthread = collect_kthread;
}


static char *
ptid_to_str (ptid_t ptid)
{
  static char str[32];
  snprintf (str, sizeof (str) - 1, "%d:%ld:%ld",
	    ptid_get_pid (ptid), ptid_get_lwp (ptid), ptid_get_tid (ptid));

  return str;
}
/*****************************************************************************/
/**********************  Symbol and Field resolutions  ***********************/
/*****************************************************************************/

/* Storage for the field layout and addresses already gathered. */
static struct field_info *field_info;
static struct addr_info *addr_info;

/* Called by ADDR to fetch the address of a symbol declared using
 DECLARE_ADDR. */
int
linux_init_addr (struct addr_info *addr, int check)
{
  if (addr->bmsym.minsym)
    return 1;

  addr->bmsym = lookup_minimal_symbol (addr->name, NULL, NULL);

  if (!addr->bmsym.minsym)
    {
      DEBUG (INIT, 3, "Checking for address of '%s' : NOT FOUND\n", addr->name);
      if (!check)
	error ("Couldn't find address of %s", addr->name);
      return 0;
    }

  /* Chain initialized entries for cleanup. */
  addr->next = addr_info;
  addr_info = addr;

  DEBUG (INIT, 1, "%s address is %s\n", addr->name,
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

  field->type =
    lookup_symbol (field->struct_name, NULL, STRUCT_DOMAIN, NULL).symbol;
  if (field->type)
    {
      DEBUG (INIT, 1, "Checking for 'struct %s' : OK\n", field->struct_name);
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
	DEBUG (INIT, 1, "Checking for 'struct %s' : TYPEDEF\n", field->struct_name);
      else
	DEBUG (INIT, 1, "Checking for 'struct %s' : NOT FOUND\n", field->struct_name);
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

  DEBUG (INIT, 2, "%s::%s => offset %i  size %i\n", field->struct_name,
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

/*****************************************************************************/
/**********************  Process and Task list Parsing  **********************/
/*****************************************************************************/

DECLARE_ADDR (init_task);
DECLARE_FIELD (list_head, next);
DECLARE_FIELD (task_struct, active_mm);
DECLARE_FIELD (task_struct, mm);
DECLARE_FIELD (task_struct, tasks);
DECLARE_FIELD (task_struct, thread_group);
DECLARE_FIELD (task_struct, pid);
DECLARE_FIELD (task_struct, tgid);
DECLARE_FIELD (task_struct, prio);
DECLARE_FIELD (task_struct, comm);

/*realize cur_rq(cpu)->curr*/
//DECLARE_FIELD (rq, curr);
DECLARE_FIELD (rq, idle);
DECLARE_FIELD (rq, lock);
DECLARE_FIELD (raw_spinlock, magic);
//DECLARE_ADDR (__per_cpu_offset);
//DECLARE_ADDR (per_cpu__process_counts);
//DECLARE_ADDR (process_counts);
DECLARE_ADDR (per_cpu__runqueues);
DECLARE_ADDR (runqueues);


#define MAX_CORES 5
#define CORE_INVAL (-1)		/* 0 = name on the inferior, cannot be used */
int max_cores = MAX_CORES;


/* The current task. */
process_t *process_list = NULL;	/*the processes list from the linux prospective */
process_t *wait_process = NULL;	/*process we stopped at in target_wait */
process_t *running_process[MAX_CORES];	/*scheduled process as seen by each core */
uint32_t per_cpu_offset[MAX_CORES]; /*__per_cpu_offset*/

/* per cpu peeks */
CORE_ADDR runqueues_addr;
CORE_ADDR rq_curr[MAX_CORES];	/*cur_rq(cpu) */
CORE_ADDR rq_idle[MAX_CORES];	/*rq->idle */

static int
find_thread_lkd_pid (struct thread_info *tp, void *arg)
{
  long pid = *(long*)arg;

  return (lkd_ptid_to_pid(tp->ptid) == pid);
}

static int
find_thread_swapper (struct thread_info *tp, void *arg)
{
  long core = *(long*)arg;

  if ((!lkd_ptid_to_pid(tp->ptid)) && (lkd_ptid_to_core(tp->ptid) == core))
    {
      DEBUG (TASK, 2, "swapper found: tp->ptid(%s) core=%ld\n",
	     ptid_to_str(tp->ptid),
	     core);
      return 1;
    }
  return 0;
}

/* invalidate the cached task list. */
static void
proc_private_dtor (struct private_thread_info * dummy)
{
	/* nop, do not free. */
}

/* Create the 'process_t' for the task pointed by the passed
 TASK_STRUCT. */
static void
get_task_info (CORE_ADDR task_struct, process_t ** ps,
	       int core /*zero-based */ )
{
  process_t *l_ps;
  size_t size;
  unsigned char *task_name;
  int i = 0;
  int pid = 0;
  ptid_t this_ptid;

  while (*ps && (*ps)->valid)
      ps = &((*ps)->next);

  if (*ps == NULL)
    *ps = XCNEW (process_t);

  l_ps = *ps;

  if (task_struct == 0)
    {
      /* create a fake swapper entry now for the additional core
       * to keep the gdb_thread ordering
       **/
      l_ps->task_struct = 0;
      l_ps->mm = 0;
      l_ps->tgid = 0;
      l_ps->prio = 0;
      l_ps->core = -1;

      if (l_ps->comm)
        {
	  xfree (l_ps->comm);
	  l_ps->comm = NULL;
        }
      l_ps->comm = xstrdup ("[swapper]");
    }
  else
    {
      size = F_OFFSET (task_struct, comm) + F_SIZE (task_struct, comm);

      task_name = lkd_private.string_buf + F_OFFSET (task_struct, comm);

      /* use scratch area for messing around with strings
       * to avoid static arrays and dispersed mallocs and frees
       **/
      gdb_assert (lkd_private.string_buf);
      gdb_assert (lkd_private.string_buf_size >= size);

      /* the task struct is not likely to change much from one kernel version
       * to another. Knowing that comm is one of the far fields,
       * try read the task struct in one command */
      read_memory (task_struct, lkd_private.string_buf, size);

      l_ps->task_struct = task_struct;
      pid = extract_unsigned_field (lkd_private.string_buf, task_struct, pid);
      l_ps->mm = extract_pointer_field (lkd_private.string_buf,
					task_struct, mm);
      l_ps->active_mm = extract_pointer_field (lkd_private.string_buf,
					       task_struct, active_mm);
      l_ps->tgid = extract_unsigned_field (lkd_private.string_buf,
					 task_struct, tgid);
      l_ps->prio = extract_unsigned_field (lkd_private.string_buf,
					   task_struct, prio);
      l_ps->core = core;	/* for to_core_of_threads */

      if (!l_ps->mm)
	{
	  int len = strlen ((char *)task_name);
	  *(task_name + len) = ']';
	  *(task_name + len + 1) = '\0';
	  *(--task_name) = '[';
	}

      if (l_ps->comm)
        {
	  xfree (l_ps->comm);
	  l_ps->comm = NULL;
        }
      l_ps->comm = xstrdup ((char*)task_name);
    }

  if (core != CORE_INVAL)
    {
      /* Long usage to map to TID */
      long core_mapped = core + 1;

      /* swapper[core] */
      gdb_assert (pid==0);

      this_ptid = lkd_ptid_build (ptid_get_pid(inferior_ptid), core_mapped, pid /* == 0 */);
      l_ps->gdb_thread =
	iterate_over_threads (find_thread_swapper, &core_mapped);

      DEBUG(TASK, 2, "Building %s, found gdbthread @ 0x%p\n", ptid_to_str(this_ptid), l_ps->gdb_thread);
    }
  else
    {
      this_ptid = lkd_ptid_build (ptid_get_pid(inferior_ptid), CORE_INVAL, pid);
      l_ps->gdb_thread = iterate_over_threads (find_thread_lkd_pid, &pid);

      /*reset the thread core value, if existing */
      if (l_ps->gdb_thread)
	{
	  gdb_assert (!l_ps->gdb_thread->priv);
	  LKD_PTID_SET_CORE(PTID_OF (l_ps), CORE_INVAL);
	}
    }

  l_ps->valid = 1;

  /* allocate if not found
   */
  if (!l_ps->gdb_thread)
    {
      if (DEBUG_DOMAIN (TASK))
	{
	  /*sanity check : go through the list and check if pid is already there */
	  process_t *tps = process_list;

	  while (tps && (tps)->valid)
	    {
	      if (pid && (tps)->gdb_thread
		  && (lkd_ptid_to_pid (PTID_OF (tps)) == pid))
		gdb_assert (0);
	      tps = tps->next;
	    };
	}

      /* add with info so that pid_to_string works. */
      l_ps->gdb_thread =  add_thread_with_info (this_ptid,
				(struct private_thread_info *)l_ps);
    }

  /* forcibly update the private fields, as some thread may
   * already have been created without, like hw threads.
   * and this also tell is the gdb_thread is pruned or not!*/
  if (l_ps->gdb_thread->priv != (struct private_thread_info *)l_ps)
    {

      DEBUG (TASK, 1, "******** Updating Thread Private from %p to l_ps (%p) *******\n",
	     l_ps->gdb_thread->priv, l_ps);

      l_ps->gdb_thread->priv = (struct private_thread_info *)l_ps;
    }

  DEBUG (TASK, 1, "gdb_thread->pid %ld <=> ps %p\n",
		  lkd_ptid_to_pid(PTID_OF (*ps)), ps);

  /* the process list freeing is not handled thanks to
   * this `private` facility, yet.
   */
  l_ps->gdb_thread->private_dtor = proc_private_dtor;

  /* keep trace of the last state to notify a change */
  l_ps->old_ptid = PTID_OF (l_ps);
}

static CORE_ADDR
lkd_proc_get_runqueues (int reset)
{
      CORE_ADDR swapper = 0;
      process_t *test_ps;

      runqueues_addr = 0;

      if (HAS_ADDR (runqueues))
	{
	  runqueues_addr = ADDR (runqueues);
	}
      else
	{
	  runqueues_addr = ADDR (per_cpu__runqueues);
	}
      /* check validity */

  if (DEBUG_DOMAIN (TASK))
    {
      if (HAS_FIELD (raw_spinlock, magic))
	{

	  CORE_ADDR lock_magic = ADDR (runqueues)
	    + (CORE_ADDR) per_cpu_offset[0]
	    + F_OFFSET (rq, lock) + F_OFFSET (raw_spinlock,
					      magic);

	  if ((read_memory_unsigned_integer (lock_magic, 4 /*uint32 */ ,
					     LKD_BYTE_ORDER) & 0xdead0000)
	      != 0xdead0000)
	    error ("accessing the core runqueues seems to be compromised.");
	}
      else
	printf_filtered ("runqueues access validated OK.\n");
    }

  return runqueues_addr;
}

/*attempt getting the idle task for a core*/
static CORE_ADDR
get_rq_idle (int core)
{
  CORE_ADDR curr_addr = lkd_proc_get_runqueues (0);

  if (!curr_addr || !HAS_FIELD (rq, idle))
    return 0;

  if (!rq_idle[core])
    {
      curr_addr += (CORE_ADDR) per_cpu_offset[core] + F_OFFSET (rq, idle);

      rq_idle[core] = read_memory_unsigned_integer (curr_addr, 4 /*uint32 */ ,
						    LKD_BYTE_ORDER);
    }
  return rq_idle[core];
};

static CORE_ADDR
_next_task (CORE_ADDR p)
{
  CORE_ADDR cur_entry = read_unsigned_embedded_field (p, task_struct, tasks, list_head, next);

  if (!cur_entry)
    {
      warning ("kernel task list contains NULL pointer");
      return 0;
    }

  return container_of (cur_entry, task_struct, tasks);
}

static CORE_ADDR
_next_thread (CORE_ADDR p)
{
  CORE_ADDR cur_entry = read_unsigned_embedded_field (p, task_struct, thread_group, list_head, next);

  if (!cur_entry)
    {
      DEBUG (TASK, 3, "kernel thread group list contains NULL pointer\n");
      return 0;
    }

  return container_of (cur_entry, task_struct, thread_group);
}


static process_t **
get_list_helper (process_t ** ps)
{
  CORE_ADDR g, t, init_task_addr;
  int core;

  init_task_addr = ADDR (init_task);
  g = init_task_addr;
  core = 0;

  do
    {
      t = g;
      do
        {
#ifdef CUT
          if (!linux_awareness_ops->lo_is_kernel_address (t))
	    {
              warning ("parsing of task list stopped because of invalid address %s", phex (t, 4));
              break;
	    }
#endif

          get_task_info (t, ps, core /*zero-based */ );
          core = CORE_INVAL;

          if (lkd_ptid_to_pid(PTID_OF (*ps)) == 0)
            {
              /* this is init_task, let's insert the other cores swapper now */
              int i;
              for (i = 1; i < max_cores; i++)
                {
                  CORE_ADDR idle;
                  ps = &((*ps)->next);
                  idle = get_rq_idle (i);
                  get_task_info (idle, ps, i);
                }
            }

           DEBUG (TASK, 2, "Got task info for %s (%li)\n",
              (*ps)->comm, lkd_ptid_to_pid (PTID_OF (*ps)));

          ps = &((*ps)->next);

          /* mark end of chain and remove those threads
           * that disappeared from the thread_list
           * to prevent any_thread_of_process() selecting a ghost.
           **/
          if (*ps)
            (*ps)->valid = 0;

          t = _next_thread (t);
        } while (t && (t != g));

      g = _next_task (g);
    } while (g && (g != init_task_addr));

  return ps;
}

/*----------------------------------------------------------------------------------------------*/

/* This function returns a the list of 'process_t' corresponding
 to the tasks in the kernel's task list. */
static process_t *
lkd_proc_get_list (void)
{
  /* Return the cached copy if there's one,
   * or rebuild it.
   **/

  if (process_list && process_list->valid)
    {
      DEBUG(TASK, 1, "Checking the list is valid (%p)\n", process_list);
    return process_list;
    }

  gdb_assert (lkd_private.proc_list_invalid);

  DEBUG(TASK, 1, "Getting the list helper!\n");
  get_list_helper (&process_list);

  lkd_private.proc_list_invalid = 0;

  return process_list;
}


/*****************************************************************************/
/***********************  Target Layer Implementation  ***********************/
/*****************************************************************************/

/* If OBJFILE contains the symbols corresponding to one of the
   supported user-level threads libraries, activate the thread stratum
   implemented by this module.  */

static int
linux_kthread_activate (struct objfile *objfile)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  struct linux_kthread_ops *ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);

  /* Skip if the thread stratum has already been activated.  */
  if (linux_kthread_active)
    return 0;

  /* There's no point in enabling this module if no
     architecture-specific operations are provided.  */
  if (!ops->supply_kthread)
    return 0;

  /* Verify that this represents an appropriate linux target */


  /* Initialise any data before we push */
  memset (&lkd_private, 0, sizeof(lkd_private));

  lkd_private.string_buf_size = 4096;
  lkd_private.string_buf =
    xcalloc (lkd_private.string_buf_size, sizeof (char));

  lkd_private.proc_list_invalid = TRUE;

  push_target (linux_kthread_ops);
  linux_kthread_active = 1;
  return 1;
}

/* Cleanup due to deactivation.  */

static void
linux_kthread_close (struct target_ops *self)
{
  linux_kthread_active = 0;

  /* Reset global variables */
  fields_and_addrs_clear ();
}

/* Deactivate the thread stratum implemented by this module.  */

static void
linux_kthread_deactivate (void)
{
  /* Skip if the thread stratum has already been deactivated.  */
  if (!linux_kthread_active)
    return;

  unpush_target (linux_kthread_ops);
}

static void
linux_kthread_inferior_created (struct target_ops *ops, int from_tty)
{
  linux_kthread_activate (NULL);
}

static void
linux_kthread_mourn_inferior (struct target_ops *ops)
{
  struct target_ops *beneath = find_target_beneath (ops);
  beneath->to_mourn_inferior (beneath);
  linux_kthread_deactivate ();
}

static void
linux_kthread_fetch_registers (struct target_ops *ops,
			       struct regcache *regcache, int regnum)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  struct linux_kthread_ops *kthread_ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);
  CORE_ADDR addr = ptid_get_tid (inferior_ptid);
  struct target_ops *beneath = find_target_beneath (ops);

  /* Always fetch the appropriate registers from the layer beneath.  */
  beneath->to_fetch_registers (beneath, regcache, regnum);
}

static void
linux_kthread_store_registers (struct target_ops *ops,
			       struct regcache *regcache, int regnum)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  struct linux_kthread_ops *kthread_ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);
  struct target_ops *beneath = find_target_beneath (ops);

  beneath->to_store_registers (beneath, regcache, regnum);
}

static ptid_t
linux_kthread_wait (struct target_ops *ops,
		    ptid_t ptid, struct target_waitstatus *status,
		    int options)
{
  struct target_ops *beneath = find_target_beneath (ops);

  /* Pass the request to the layer beneath.  */
  ptid = beneath->to_wait (beneath, ptid, status, options);

  return ptid;
}

static void
linux_kthread_resume (struct target_ops *ops,
		      ptid_t ptid, int step, enum gdb_signal sig)
{
  /* Pass the request to the layer beneath.  */
  struct target_ops *beneath = find_target_beneath (ops);
  beneath->to_resume (beneath, ptid, step, sig);
}

static int
linux_kthread_thread_alive (struct target_ops *ops, ptid_t ptid)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  struct target_ops *beneath = find_target_beneath (ops);

  return beneath->to_thread_alive (beneath, ptid);
}

static void
linux_kthread_update_thread_list (struct target_ops *ops)
{
  struct target_ops *beneath = find_target_beneath (ops);

  /* List is up to date ... ? */
  if (!lkd_private.proc_list_invalid)
    return;

  prune_threads ();

  /* Allow the layer beneath to update */
  if (beneath && beneath->to_update_thread_list)
    beneath->to_update_thread_list (beneath);

  /* Build linux threads on top */
  lkd_proc_get_list ();
}

/* Return a string describing the state of the thread specified by
   INFO.  */

static char *
linux_kthread_extra_thread_info (struct target_ops *self,
				 struct thread_info *info)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  process_t *ps = (process_t *) info->priv;

  if (ps /* && check_ps_magic */)
    {
      char *msg = get_print_cell ();
      size_t len = 0;

      len = snprintf (msg, PRINT_CELL_SIZE, "pid: %li tgid: %i",
		      lkd_ptid_to_pid (PTID_OF (ps)), ps->tgid);

#if 0
      if (lkd_proc_is_curr_task (ps))
	snprintf (msg + len, PRINT_CELL_SIZE - len, " <C%u>", ps->core);
#endif

      return msg;
    }

  return "LinuxThread";
}

static char *
linux_kthread_pid_to_str (struct target_ops *ops, ptid_t ptid)
{
  process_t *ps;
  struct thread_info *tp;

  if (!lkd_ptid_to_core (ptid))	/* when quitting typically */
    return "Linux Kernel";

  tp = find_thread_ptid (ptid);

  if (!tp || !tp->priv)
    return "";

  /* we use the gdb thread private field for storing the process_t */
  ps = (process_t *) tp->priv;

  gdb_assert (ps->comm);
  return ps->comm;
  return ptid_to_str (ptid);
}

static const char *
linux_kthread_thread_name (struct target_ops *ops, struct thread_info *thread)
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

static struct target_ops *
linux_kthread_target (void)
{
  struct target_ops *t = XCNEW (struct target_ops);

  t->to_shortname = "linux-kthreads";
  t->to_longname = "linux kernel-level threads";
  t->to_doc = "Linux kernel-level threads";
  t->to_close = linux_kthread_close;
  t->to_mourn_inferior = linux_kthread_mourn_inferior;
  t->to_fetch_registers = linux_kthread_fetch_registers;
  t->to_store_registers = linux_kthread_store_registers;
  t->to_wait = linux_kthread_wait;
  t->to_resume = linux_kthread_resume;
  t->to_thread_alive = linux_kthread_thread_alive;
  t->to_update_thread_list = linux_kthread_update_thread_list;
  t->to_extra_thread_info = linux_kthread_extra_thread_info;
  t->to_thread_name = linux_kthread_thread_name;
  t->to_pid_to_str = linux_kthread_pid_to_str;
  t->to_stratum = thread_stratum;
  t->to_magic = OPS_MAGIC;
  linux_kthread_ops = t;

  return t;
}

/* Provide a prototype to silence -Wmissing-prototypes.  */
extern initialize_file_ftype _initialize_linux_kthread;

void
_initialize_linux_kthread (void)
{
  complete_target_initialization (linux_kthread_target ());

  linux_kthread_data = gdbarch_data_register_pre_init (linux_kthread_init);

  observer_attach_inferior_created (linux_kthread_inferior_created);
}
