/*
  Linux Awareness extension target (Linux Kernel Debugger)
  Copyright 2011-2013 STMicroelectronics.
*/

#ifndef __LKD_PROCESS_H__
#define __LKD_PROCESS_H__

/* The list of tasks as cached in the debugger. */
typedef struct process_t_
{
  struct process_t_ *next;
  CORE_ADDR task_struct;
  CORE_ADDR mm;
  CORE_ADDR active_mm;
  CORE_ADDR pgd;		/* FIXME: this should be arch specific, needs fix for SH4 */

  ptid_t old_ptid;

  int core;			/*this is the "dynamic" core info */

  int tgid;
  unsigned int prio;
  char *comm;
  int valid;

  struct thread_info *gdb_thread;

  /* user process info */
  struct objfile *objfiles;
  struct objfile *main_objfile;
} process_t;

#define VM_EXECUTABLE   0x00001000
#define VM_EXEC         0x00000004

#define PTID_OF(ps) ((ps)->gdb_thread->ptid)

extern process_t *running_process[];
extern process_t *selected_process;
extern process_t *wait_process;
extern uint32_t per_cpu_offset[];


/* API */
void lkd_proc_init (void);
int lkd_proc_core_of_thread (ptid_t ptid);
void lkd_proc_invalidate_list (void);
void lkd_proc_free_list (void);
int lkd_proc_refresh_info (int core);
void lkd_proc_read_symbols (void);
void lkd_proc_set_symfile (void);
process_t *lkd_proc_get_list (void);
process_t *lkd_proc_get_by_ptid (ptid_t ptid);
process_t *lkd_proc_get_by_task_struct (CORE_ADDR task);
process_t *lkd_proc_get_selected (void);
process_t *lkd_proc_get_running (int core);
CORE_ADDR lkd_proc_get_runqueues (int reset);
CORE_ADDR lkd_proc_get_rq_curr (int core);
CORE_ADDR lkd_proc_get_curr_task (int core);
int lkd_proc_is_curr_task (process_t * ps);
void lkd_proc_remove_bpts(process_t * ps);

void lkd_dump_proc_list (void);
void lkd_dump_rq_info (void);
void lkd_dump_task_struct (CORE_ADDR t);

/*commands*/
void debug_process_command (char *args, int from_tty);
void running_task_command (char *args, int from_tty);

#endif /*__LKD_PROCESS_H__*/
