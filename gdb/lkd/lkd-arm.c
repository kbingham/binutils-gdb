/*
  Copyright 2011-2013 STMicroelectronics.

  This file contains the ARM specific part of the Linux
  Awareness layer for GDB.

  The Linux Awareness layer allows GDB boot or attach-to and debug
  a Linux kernel through a H/W link (presumably JTAG).

  see file linux-awareness.c for more details.
*/

#include "defs.h"
#include "block.h"
#include "command.h"
#include "frame.h"
#include "frame-unwind.h"
#include "gdb_assert.h"
#include "gdbarch.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "gdbtypes.h"
#include "gdb_obstack.h"
#include "inferior.h"
#include "objfiles.h"
#include "regcache.h"
#include "user-regs.h"
#include "symtab.h"
#include "target.h"
#include "top.h"
#include "value.h"
#include "gdbthread.h"

#include "arm-tdep.h"

#include "lkd.h"
#include "lkd-process.h"

/* The target ops that adds the linux awareness. */
extern struct target_ops linux_aware_ops;
#define BENEATH linux_aware_ops.beneath


/* Addresses used by the ARM specific linux awareness. */

DECLARE_ADDR (contig_page_data);
DECLARE_ADDR (init_mm);
DECLARE_ADDR (max_low_pfn);
DECLARE_ADDR (mem_map);
DECLARE_ADDR (min_low_pfn);
DECLARE_ADDR (pmb_init);
DECLARE_ADDR (restore_all);
DECLARE_ADDR (ret_from_exception);
DECLARE_ADDR (ret_from_fork);
DECLARE_ADDR (ret_from_irq);
DECLARE_ADDR (swapper_space);
DECLARE_ADDR (ret_fast_syscall);
DECLARE_ADDR (ret_slow_syscall);
DECLARE_ADDR (sys_syscall);
DECLARE_ADDR (work_resched);

DECLARE_ADDR (__dabt_svc);
DECLARE_ADDR (__irq_svc);
DECLARE_ADDR (__und_svc);
DECLARE_ADDR (__pabt_svc);
DECLARE_ADDR (__dabt_usr);
DECLARE_ADDR (__irq_usr);
DECLARE_ADDR (__und_usr);
DECLARE_ADDR (__pabt_usr);
DECLARE_ADDR (__und_usr_unknown);

/* Fields used by the ARM specific linux awareness. */
DECLARE_FIELD (mm_struct, pgd);
DECLARE_FIELD (mm_struct, context);
DECLARE_FIELD (mm_context_t, id);
DECLARE_FIELD (page, flags);
DECLARE_FIELD (page, mapping);
DECLARE_FIELD (pglist_data, node_start_pfn);
DECLARE_FIELD (task_struct, mm);
DECLARE_FIELD (task_struct, active_mm);
DECLARE_FIELD (task_struct, thread_info);
DECLARE_FIELD (task_struct, thread);
DECLARE_FIELD (task_struct, stack);
DECLARE_FIELD (thread_info, cpu_context);
DECLARE_FIELD (thread_info, task);
DECLARE_FIELD (thread_info, cpu);

/************************* Virtual memory handling ****************************/
DECLARE_ADDR (meminfo);
DECLARE_FIELD (meminfo, bank);
DECLARE_FIELD (membank, start);

struct pt_regs
{
  uint32_t uregs[18];
};



static int
arch_can_write (CORE_ADDR addr, CORE_ADDR task_struct)
{
  return 0;
}

static inline int
is_special_addr (CORE_ADDR addr)
{
  /* ret_fast_syscall is a special address (both sp _and_ pc)
     used to link user and kernel spaces */
  return HAS_ADDR (ret_fast_syscall) && addr == ADDR (ret_fast_syscall);
}

static int
arch_is_user_address (CORE_ADDR addr)
{
  return (addr < linux_awareness_ops->kernel_offset)
    || is_special_addr (addr);
}

static int
arch_is_kernel_address (CORE_ADDR addr)
{
#ifndef HAS_MMU
  return 1;
#endif

  return !arch_is_user_address (addr) || is_special_addr (addr);
}


/*****************************************************************************/
/*                              TASK AWARENESS                               */
/*****************************************************************************/

/* This function gets the register values that the schedule() routine
 * has stored away to be able to restart an asleep task later.
 * this must match the layout in arm/include/asm/thread_info.h
 *
 **/
static CORE_ADDR
fetch_context_register_real (CORE_ADDR task_struct)
{
  struct regcache *regcache;
  int offset = 0, val, i;
  uint32_t thread_info_addr;
  uint32_t cpsr;
  struct cpu_context_save
  {
    uint32_t r4;
    uint32_t r5;
    uint32_t r6;
    uint32_t r7;
    uint32_t r8;
    uint32_t r9;
    uint32_t sl;
    uint32_t fp;
    uint32_t sp;
    uint32_t pc;
  } cpu_cxt;

  /*get thread_info address */
  thread_info_addr = read_unsigned_field (task_struct, task_struct, stack);

  /*get cpu_context as saved by scheduled */
  read_memory ((CORE_ADDR) thread_info_addr +
	       F_OFFSET (thread_info, cpu_context),
	       (gdb_byte *) & cpu_cxt, sizeof (struct cpu_context_save));

  DEBUG (TASK, 4, "fetch_context_register_real (%x)\n", thread_info_addr);

  regcache = get_current_regcache ();

  regcache_raw_supply (regcache, ARM_PC_REGNUM, &cpu_cxt.pc);
  regcache_raw_supply (regcache, ARM_SP_REGNUM, &cpu_cxt.sp);
  regcache_raw_supply (regcache, ARM_FP_REGNUM, &cpu_cxt.fp);

  /*general purpose registers */
  regcache_raw_supply (regcache, 10, &cpu_cxt.sl);
  regcache_raw_supply (regcache, 9, &cpu_cxt.r9);
  regcache_raw_supply (regcache, 8, &cpu_cxt.r8);
  regcache_raw_supply (regcache, 7, &cpu_cxt.r7);
  regcache_raw_supply (regcache, 6, &cpu_cxt.r6);
  regcache_raw_supply (regcache, 5, &cpu_cxt.r5);
  regcache_raw_supply (regcache, 4, &cpu_cxt.r4);

  /* Fake a value for cpsr:T bit.  */
#define IS_THUMB_ADDR(addr)	((addr) & 1)
  cpsr = IS_THUMB_ADDR(cpu_cxt.pc) ? arm_psr_thumb_bit (target_gdbarch ()) : 0;
  regcache_raw_supply (regcache, ARM_PS_REGNUM, &cpsr);

  for (i = 0; i < gdbarch_num_regs (target_gdbarch ()); i++)
    if (REG_VALID != regcache_register_status (regcache, i))
      /* Mark other registers as unavailable.  */
      regcache_invalidate (regcache, i);

  return cpu_cxt.pc;
}

static struct regcache *cached_regcache;
static ptid_t cached_regcache_ptid;

static int
arch_fetch_context_register (int regno, CORE_ADDR task_struct)
{
  CORE_ADDR pc;
  DEBUG (TASK, 4, "fetch_context_register(%i,%x)\n",
	 regno, (unsigned int) task_struct);

  if (REG_VALID != regcache_register_status (get_current_regcache (),
					     ARM_PC_REGNUM))
    {

      pc = fetch_context_register_real (task_struct);

      if (lkd_params.skip_schedule_frame
	  && !(HAS_ADDR (ret_from_fork) && pc == ADDR (ret_from_fork)))
	{
	  int arm_num_regs = gdbarch_num_regs (target_gdbarch ());
	  struct frame_info *f = get_current_frame ();
	  int level = frame_relative_level(f);

	   /* skip this frame, unwind to the next
	    **/
	  while (f && (level++ < lkd_params.skip_schedule_frame))
		  f = get_prev_frame (f);

	  if (f != NULL)
	    {
	      int i;
	      gdb_byte buf[12];
	      int optimized, unavailable;
	      CORE_ADDR addr;
	      int realnum;
	      enum lval_type lval;
	      unsigned long *new_registers = xcalloc (arm_num_regs,
						      sizeof (unsigned long));
	      char *new_registers_valid = xcalloc (arm_num_regs, 1);

	      for (i = 0; i < arm_num_regs; ++i)
		{
		  frame_register_unwind (f, i, &optimized, &unavailable,
					 &lval, &addr, &realnum, buf);
		  if (!optimized && !unavailable)
		    {
		      memcpy (&new_registers[i], buf, 4);
		      new_registers_valid[i] = 1;
		    }
		}

	      reinit_frame_cache ();

	      for (i = 0; i < arm_num_regs; ++i)
		{
		  if (new_registers_valid[i])
		    regcache_raw_supply
		      (get_current_regcache (), i, &new_registers[i]);
		  else
		    /* Mark other registers as unavailable. */
		    regcache_invalidate (get_current_regcache (), i);
		}

	      xfree (new_registers);
	      xfree (new_registers_valid);
	    }
	}
    }

  return 1;
}

// FIXME
static int
arch_store_context_register (int regno, CORE_ADDR task_struct)
{
  DEBUG (TASK, 3, "store_context_register(%i,%x)\n",
	 regno, (unsigned int) task_struct);
  warning ("ARM/store_context_register not implemented yet");
  return 1;
}

static void
arch_clear_cache (void)
{
}


static void
arch_close (void)
{
  arch_clear_cache ();
}


/*
 * default op handler for STGDI (non-remote)
 **/
static void
arch_post_load (char *prog, int fromtty)
{
  CORE_ADDR addr_phys_offset;

  DEBUG (D_INIT, 1, "ARM: arch_post_load\n");


  DEBUG (TARGET, 1, "Assuming 0x%08x as MODULES_VADDR.\n",
	 linux_awareness_ops->kernel_offset);

  /* this installs what ever LKD specific handling is required
   * in the gdb arch data. */

  /* lkd_params.loaded will be set later */
}

static int
arch_init (void)
{
  DEBUG (D_INIT, 1, "ARM: arch_init.\n");

  return 1;
}

static int
arch_check_kernel (void)
{
  int res = HAS_FIELD (mm_struct, pgd)
    && HAS_FIELD (task_struct, stack)
    && HAS_FIELD (task_struct, thread)
    && HAS_FIELD (task_struct, mm) && HAS_FIELD (thread_info, cpu_context);
  return res;
}

//#define ARMv7_PAGESHIFT       12

struct linux_awareness_ops arm_linux_awareness_ops = {
  .name = "armv7",
  .lo_check_kernel = arch_check_kernel,
  .lo_init = arch_init,
  .lo_close = arch_close,
  .lo_post_load = arch_post_load,
  .lo_can_write = arch_can_write,
  .lo_is_user_address = arch_is_user_address,
  .lo_is_kernel_address = arch_is_kernel_address,
  .lo_single_step_destination = NULL,
  .lo_clear_cache = arch_clear_cache,
  .lo_fetch_context_register = arch_fetch_context_register,
  .lo_store_context_register = arch_store_context_register,
  .kernel_offset = 0x0,
};

extern process_t *running_process[];


/* -Wmissing-prototypes */
extern initialize_file_ftype _initialize_armv7_lkd;

/* _initialize_xxx routines are added to the ugly autogenerates init code
 * see gdb makefile.
 **/
void
_initialize_armv7_lkd (void)
{
  linux_awareness_ops = &arm_linux_awareness_ops;
}
