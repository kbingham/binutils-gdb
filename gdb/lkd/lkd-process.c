/*
  Linux Awareness extension target (Linux Kernel Debugger)
  Copyright 2011-2013 STMicroelectronics.
*/

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
#include "gdb.h"
#include "gdb_assert.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "gdbthread.h"
#include "gdbtypes.h"
#include "inferior.h"
#include "objfiles.h"
#include "observer.h"
#include "regcache.h"
#include "solib.h"
#include "solist.h"
#include "symtab.h"
#include "psympriv.h"
#include "target.h"

#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"

#include "tui/tui.h"
#include "lkd.h"
#include "lkd-process.h"

#define BENEATH linux_aware_ops.beneath

/* Declaration of the required addresses. */
DECLARE_ADDR (swapper_pg_dir);
DECLARE_ADDR (init_thread_union);
DECLARE_ADDR (init_task);

DECLARE_ADDR (init_pid_ns);
DECLARE_FIELD (pid_namespace, last_pid);

/*realize cur_rq(cpu)->curr*/
DECLARE_ADDR (__per_cpu_offset);
DECLARE_ADDR (per_cpu__process_counts);
DECLARE_ADDR (process_counts);
DECLARE_ADDR (per_cpu__runqueues);
DECLARE_ADDR (runqueues);

DECLARE_FIELD (rq, curr);
DECLARE_FIELD (rq, idle);
DECLARE_FIELD (rq, lock);
DECLARE_FIELD (raw_spinlock, magic);

DECLARE_FIELD (list_head, next);


DECLARE_FIELD (task_struct, active_mm);
DECLARE_FIELD (mnt_namespace, list);
 /**/ DECLARE_FIELD (path, dentry);
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
DECLARE_FIELD (vm_area_struct, vm_next);
DECLARE_FIELD (vm_area_struct, vm_file);
DECLARE_FIELD (vm_area_struct, vm_flags);
DECLARE_FIELD (vm_area_struct, vm_start);
DECLARE_FIELD (vm_area_struct, vm_end);
DECLARE_FIELD (vm_area_struct, vm_pgoff);
DECLARE_FIELD (vm_struct, next);
DECLARE_FIELD (vm_struct, size);

/* The current task. */

process_t *process_list = NULL;	/*the processes list from the linux prospective */
process_t *wait_process = NULL;	/*process we stopped at in target_wait */
process_t *running_process[MAX_CORES];	/*scheduled process as seen by each core */
uint32_t per_cpu_offset[MAX_CORES]; /*__per_cpu_offset*/

/* per cpu peeks */
CORE_ADDR runqueues_addr;
CORE_ADDR rq_curr[MAX_CORES];	/*cur_rq(cpu) */
CORE_ADDR rq_idle[MAX_CORES];	/*rq->idle */

/* process list housekeeping*/
static int process_counts[MAX_CORES];
static int last_pid;

struct mmu_infos mmu_info[MAX_CORES];


static int
find_thread_lwp (struct thread_info *tp, void *arg)
{
  long lwp = *(long*)arg;

  return (ptid_get_lwp(tp->ptid) == lwp);
}

static int
find_thread_swapper (struct thread_info *tp, void *arg)
{
  long core = *(long*)arg;

  if ((!ptid_get_lwp(tp->ptid)) && (ptid_get_tid(tp->ptid) == core))
    {
      DEBUG (TASK, 2, "swapper found: tp->ptid(%d-%ld-%ld) core=%ld\n",
	     ptid_get_pid(tp->ptid),
	     ptid_get_lwp(tp->ptid),
	     ptid_get_tid(tp->ptid),
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
  int lwp = 0;
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
      lwp = extract_unsigned_field (lkd_private.string_buf, task_struct, pid);
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
      /* Long usage to map to LWP */
      long core_mapped = core + 1;

      /* swapper[core] */
      gdb_assert (lwp==0);

      this_ptid = ptid_build (ptid_get_pid(inferior_ptid), lwp /* == 0 */ , core_mapped);
      l_ps->gdb_thread =
	iterate_over_threads (find_thread_swapper, &core_mapped);
    }
  else
    {
      this_ptid = ptid_build (ptid_get_pid(inferior_ptid), lwp, CORE_INVAL);
      l_ps->gdb_thread = iterate_over_threads (find_thread_lwp, &lwp);

      /*reset the thread core value, if existing */
      if (l_ps->gdb_thread)
	{
	  gdb_assert (!l_ps->gdb_thread->priv);
	  PTID_OF (l_ps).tid = CORE_INVAL;
	}
    }

  l_ps->pgd = 0;
  l_ps->valid = 1;

  /* allocate if not found
   */
  if (!l_ps->gdb_thread)
   {
      DBG_IF (TASK)
	/*sanity check : go through the list and check if lwp already there */
      process_t *tps = process_list;

      while (tps && (tps)->valid)
	{
	  if (lwp && (tps)->gdb_thread && (ptid_get_lwp(PTID_OF (tps)) == lwp))
	    gdb_assert (0);
	  tps = tps->next;
	};
      DBG_ENDIF (TASK)

      /* add with info so that pid_to_string works. */
      l_ps->gdb_thread =  add_thread_with_info (this_ptid,
				(struct private_thread_info *)l_ps);
    }

  /* forcibly update the private fields, as some thread may
   * already have been created without, like hw threads.
   * and this also tell is the gdb_thread is pruned or not!*/
  l_ps->gdb_thread->priv = (struct private_thread_info *)l_ps;

  DEBUG (TASK, 1, "gdb_thread->lwp %ld <=> ps %p\n",
		  ptid_get_lwp(PTID_OF (*ps)), ps);

  /* the process list freeing is not handled thanks to
   * this `private` facility, yet.
   */
  l_ps->gdb_thread->private_dtor = proc_private_dtor;

  /* keep trace of the last state to notify a change */
  l_ps->old_ptid = PTID_OF (l_ps);
}


/* Returns the 'process_t' corresponding to the passed task_struct or
 NULL if not in the list. */
process_t *
lkd_proc_get_by_task_struct (CORE_ADDR task_struct)
{
  process_t *ps = lkd_proc_get_list ();

  while ((ps != NULL) && (ps->valid == 1))
    {
      if (ps->task_struct == task_struct)
	return ps;
      ps = ps->next;
    }
  return NULL;
}

/* Return the process currently scheduled on one core */
process_t *
lkd_proc_get_running (int core)
{
  process_t *current = NULL;
  CORE_ADDR task;
  struct thread_info *tp;	/*gdb ti */
  ptid_t old_ptid;

  if (core == CORE_INVAL)
    return NULL;

  if (running_process[core] == NULL)
    {

      gdb_assert (lkd_proc_get_runqueues (0));

      task = lkd_proc_get_rq_curr (core);

      if (task)
	{			/* smp cpu is initialized */
	  current = lkd_proc_get_by_task_struct (task);

	  if (!current)
	    {
	      /* this task struct is not known yet AND was not seen
	       * while running down the tasks lists, so this is presumably
	       * the swapper of an secondary SMP core.
	       */
	      current =
		lkd_proc_get_by_ptid (ptid_build
				      (ptid_get_pid(inferior_ptid),
				      0, core + 1));
	      gdb_assert(current);

	      current->task_struct = task;
	    }
	  else
	    {
	      /* update the thread's tid in thread_list if it exists and wasn't scheduled
	       * so that tid makes sense for both the gdbserver and infrun.c
	       **/
	      PTID_OF (current).tid = core + 1;
	    }

	  current->core = core;	/* was CORE_INVAL */
	  running_process[core] = current;
	}			// task
    }				// running_process[core]

  return running_process[core];
}

/* Return 1 if this is a current task (or 0)*/
int
lkd_proc_is_curr_task (process_t * ps)
{
  return (ps && (ps == lkd_proc_get_running (ps->core)));
}

static CORE_ADDR get_rq_idle (int core);	/* forward decl. */

/* Helper function that iterates the task list in the kernel
   memory which are stored in a tree like structure. From sched.h:

 #define do_each_thread(g, t) \
        for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do

 #define while_each_thread(g, t) \
        while ((t = next_thread(t)) != g)
*/
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
          if (!linux_awareness_ops->lo_is_kernel_address (t))
	    {
              warning ("parsing of task list stopped because of invalid address %s", phex (t, 4));
              break;
	    }

          get_task_info (t, ps, core /*zero-based */ );
          core = CORE_INVAL;

          if (ptid_get_lwp (PTID_OF (*ps)) == 0)
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
              (*ps)->comm, ptid_get_lwp (PTID_OF (*ps)));

          ps = &((*ps)->next);

          /* mark end of chain and remove those threads
           * that disappeared from the thread_list
           * to avoid any_thread_of_process() to select a ghost.
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
process_t *
lkd_proc_get_list (void)
{
  /* Return the cached copy if there's one,
   * or rebuild it.
   **/
  if (process_list && process_list->valid)
	  return process_list;

  gdb_assert(lkd_private.proc_list_invalid);

  get_list_helper (&process_list);

  lkd_private.proc_list_invalid = 0;

  return process_list;
}

/* Returns a valid 'process_t' corresponding to
 * the passed ptid or NULL if not found.
 */
process_t *
lkd_proc_get_by_ptid (ptid_t ptid)
{
  struct thread_info *tp;
  long lwp = ptid_get_lwp(ptid);
  process_t *ps;

  gdb_assert(!lkd_private.proc_list_invalid);

  if (lwp)
	  /*non-swapper, ignore TID */
	  tp = iterate_over_threads (find_thread_lwp, &lwp);
  else
	  /*swapper, TID gives the core, lwp = 0 is not unique */
	  tp = find_thread_ptid(ptid);

  ps = (process_t *)tp->priv;

  /* Prune the gdb-thread is the process is not valid
   * meaning is was no longer found in the task list. */
  return ps;
}

/* invalidate the gdb thread is the linux ps has died.*/
static int
thread_clear_info (struct thread_info *tp, void *ignored)
{
  tp->priv = NULL;
  return 0;
}

/* invalidate the cached task list. */
void
lkd_proc_invalidate_list (void)
{
  process_t *ps = process_list;
  process_t *cur;
  while (ps)
    {
      cur = ps;
      ps = ps->next;
      cur->valid = 0;
    }

  /* We invalidate the processes attached to the gdb_thread
  * setting tp->private to null tells if the thread can
  * be deleted or not. */
  iterate_over_threads (thread_clear_info, NULL);

  lkd_private.proc_list_invalid = 1;
}

void
lkd_proc_free_list (void)
{
  process_t *ps = process_list;
  process_t *cur;
  while (ps)
    {
      cur = ps;
      ps = ps->next;
      // xfree does check for null pointers.
      xfree (cur->comm);
      xfree (cur);
    }
  process_list = NULL;
}

/* Return the processor core that thread PTID was last seen on.
   This information is updated only when:
   - update_thread_list is called
   - thread stops
   If the core cannot be determined -- either for the specified thread, or
   right now, or in this debug session, or for this target -- return -1.  */
int
lkd_proc_core_of_thread (ptid_t ptid)
{
  int i = 0;
  process_t *ps;

  ps = lkd_proc_get_by_ptid (ptid);

  if (!ps || (ps != lkd_proc_get_running (ps->core)))
    return CORE_INVAL;
  else
    return ps->core;
}

CORE_ADDR
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

    DBG_IF (TASK)
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
	printf_filtered ("runqueues access validated OK.");
    DBG_ENDIF (TASK)

  return runqueues_addr;
}

/*attempt getting the runqueue address for a core*/
CORE_ADDR
lkd_proc_get_rq_curr (int core)
{

  if (!rq_curr[core])
    {
      CORE_ADDR curr_addr = lkd_proc_get_runqueues (0);
      if (!curr_addr)
	return 0;
      curr_addr =
	curr_addr + (CORE_ADDR) per_cpu_offset[core] + F_OFFSET (rq, curr);
      rq_curr[core] = read_memory_unsigned_integer (curr_addr, 4 /*uint32 */ ,
						    LKD_BYTE_ORDER);
    }
  return rq_curr[core];
};

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

static int
get_process_count (int core)
{
  CORE_ADDR curr_addr = (CORE_ADDR) per_cpu_offset[core];
  int proc_cnt;
  static int warned = 0;

  /* curr_addr can be null on UNI systems
   * */
  if (HAS_ADDR (process_counts))
    curr_addr += ADDR (process_counts);
  else if (HAS_ADDR (per_cpu__process_counts))
    curr_addr += ADDR (per_cpu__process_counts);
  else
    {
      /* return a fake, changing value
       * at lest the list will be refreshed, but in a less optimal way.*/
      if (!warned)
	printf_filtered ("this kernel does not support `process_counts`\n");

      if (!lkd_stepping)
	warned++;

      return warned;
    }

  proc_cnt = read_memory_unsigned_integer (curr_addr, 4 /*uint32 */ ,
					   LKD_BYTE_ORDER);

  return proc_cnt;
};

static int
get_last_pid (void)
{
  int new_last_pid = 0;

  if (HAS_ADDR (init_pid_ns))
    {
      /* Since STLinux 2.3 (2.6.23) */
      new_last_pid = read_signed_field (ADDR (init_pid_ns),
					pid_namespace, last_pid);
    }
  else
    printf_filtered ("this kernel does not support `init_pid_ns`\n");

  return new_last_pid;
};

void
lkd_proc_init (void)
{
  int i = MAX_CORES;
  struct thread_info *th = NULL;
  struct cleanup *cleanup;

  memset (per_cpu_offset, 0, MAX_CORES * sizeof (uint32_t));
  memset (mmu_info, 0, MAX_CORES * sizeof (struct mmu_infos));

  /* ensure thread list from beneath target is up to date */
  cleanup = make_cleanup_restore_integer (&print_thread_events);
  print_thread_events = 0;
  update_thread_list ();
  do_cleanups (cleanup);

  /* count the h/w threads
   */
  max_cores = thread_count ();
  gdb_assert (max_cores);

  if (HAS_ADDR (__per_cpu_offset))
    {
      int core = max_cores;

      read_memory (ADDR (__per_cpu_offset),
		   (gdb_byte *) (per_cpu_offset),
		   max_cores * sizeof (uint32_t));

      while (--core)
	if (!per_cpu_offset[core])
	  {
	    warning ("Suspicious null per-cpu offsets,"
		     " or wrong number of detected cores:\n"
		     "ADDR (__per_cpu_offset) = %s\nmax_cores = %d",
		     phex (ADDR (__per_cpu_offset),4), max_cores);
	    break;
	  }
    }
  else
    {
      DEBUG (D_INIT, 1, "Assuming non-SMP kernel.\n");
    }

  if (!lkd_proc_get_runqueues (1 /*reset */ ) && (max_cores > 1))
    printf_filtered ("\nCould not find the address of cpu runqueues:"
		     "\ncurrent context information maybe less precise\n.");
}

/* still useful with non-smp systems
 **/
CORE_ADDR current_task_struct[MAX_CORES];
CORE_ADDR current_thread_info[MAX_CORES];

int
lkd_proc_refresh_info (int cur_core)
{
  int i = max_cores;
  int new_last_pid;
  process_t *ps;
  int do_invalidate = 0;

  memset (running_process, 0, max_cores * sizeof (process_t *));
  memset (current_thread_info, 0, max_cores * (sizeof (CORE_ADDR)));
  memset (current_task_struct, 0, max_cores * (sizeof (CORE_ADDR)));
  memset (rq_curr, 0, max_cores * sizeof (CORE_ADDR));

  DEBUG (TASK, 1, "WAS: last_pid=%d, pcount[0]=%d, pcount[1]=%d\n",
	 last_pid, process_counts[0], process_counts[1]);

  new_last_pid = get_last_pid ();
  if (new_last_pid != last_pid)
    {
      do_invalidate = 1;
      last_pid = new_last_pid;
    }

  /* check if a process exited */
  for (i = 0; i < max_cores; i++)
    {
      int new_pcount = get_process_count (i);
      if (new_pcount != process_counts[i])
	{
	  process_counts[i] = new_pcount;
	  do_invalidate = 1;
	}
    }

  DEBUG (TASK, 1, "NEW: last_pid=%d, pcount[0]=%d, pcount[1]=%d\n",
	 last_pid, process_counts[0], process_counts[1]);

  if (do_invalidate)
    lkd_proc_invalidate_list ();

  /* Update the process_list now, so that init_task is in there. */
  (void) lkd_proc_get_list ();

  /* Call update to prune gdb_thread no longer linked to a linux task.*/
  if (lkd_private.loaded == LKD_LOADED)
    update_thread_list();

  /* Set the running process
   *
   * we now have a thread_list looking like this:
   * [1] = { 42000, 0, 1  }
   * [2] = { 42000, 0, 2  }
   * [3] = { 42000, 1, -1 }
   *  ....
   * [N] = { 42000, PID_N, -1 }
   *
   * Now set the tid according to the running core,
   * */
  for (i = 0; i < max_cores; i++)
    lkd_proc_get_running (i);

  wait_process = lkd_proc_get_running (cur_core);

  if (!wait_process)
    return 0;

  DEBUG (TASK, 1, "wait_process: lwp = %ld\n", ptid_get_lwp(PTID_OF (wait_process)));
  DEBUG (TASK, 1, "wait_process: pid = %d\n", ptid_get_pid(PTID_OF (wait_process)));
  DEBUG (TASK, 1, "wait_process: tid = %ld\n", ptid_get_tid(PTID_OF (wait_process)));

  gdb_assert(wait_process->gdb_thread);
  gdb_assert((process_t *) wait_process->gdb_thread->priv == wait_process);

  /* Notify ptid changed. */
  ps = process_list;
  while (ps && ps->valid)
    {
      if (ptid_get_tid(ps->old_ptid) != ptid_get_tid(PTID_OF (ps)))
	{
	  observer_notify_thread_ptid_changed (ps->old_ptid, PTID_OF (ps));
	  ps->old_ptid.tid = ptid_get_tid(PTID_OF (ps));
	}
      ps = ps->next;
    }

  switch_to_thread(PTID_OF (wait_process));
  gdb_assert(lkd_proc_get_by_ptid(inferior_ptid) == wait_process);

  return 1;
}

/* Setup the symbols to reflect the namespace of the passed
 process. GDB doesn't really support this. We hack this support by
 appending the list of objfiles containing the debug information
 for the process to the list of objfiles that contain the debug
 info for the kernel. When we switch to another process, we remove
 the objfiles for the old process and replace it with the objfiles
 for the new one. The pointers to the objfiles for a given process
 are stored in the associated process_t. */
void
lkd_proc_set_symfile (void)
{
  process_t *ps;


  ps = lkd_proc_get_by_ptid (inferior_ptid);
  if (ps && ps->main_objfile)
        symfile_objfile = ps->main_objfile;
}


/* Selected the task that is really running on the CPU. */
void
running_task_command (char *args, int from_tty)
{
  ptid_t ptid;
  char *thread_id;

  if (!wait_process)
    return;

  ptid = PTID_OF (wait_process);
  thread_id = xstrprintf ("%d", ptid_to_global_thread_id (ptid));

  /* switch_to_thread() sets inferior_ptid to ptid */
  gdb_thread_select (current_uiout, thread_id, NULL);

  xfree (thread_id);
}
