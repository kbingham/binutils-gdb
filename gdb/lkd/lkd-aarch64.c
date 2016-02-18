/*
  Copyright 2016 STMicroelectronics.

  This file contains the ARM64 specific part of the Linux
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
DECLARE_ADDR (swapper_pg_dir);
DECLARE_ADDR (start_kernel);
DECLARE_ADDR (secondary_start_kernel);
DECLARE_ADDR (kernel_thread_exit);
DECLARE_ADDR (do_exit);

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
  ULONGEST uregs[18];
};

/******************************************************************
 * (Architecture specific) kernel `main`: end-of-backtrace sniffer
 ******************************************************************/

static enum unwind_stop_reason
kmain_frame_unwind_stop_reason (struct frame_info *this_frame,
				void **this_cache)
{
  return UNWIND_OUTERMOST;
}

static void
kmain_frame_this_id (struct frame_info *next_frame, void **this_cache,
		     struct frame_id *this_id)
{
  *this_id =
    frame_id_build (get_frame_sp (next_frame), get_frame_pc (next_frame));
}

/* cause backtracing to stop on any `main` entrypoints for the kernel.
 */
static int
kmain_frame_sniffer (const struct frame_unwind *self,
		     struct frame_info *next_frame, void **this_cache)
{
  CORE_ADDR ker = ADDR (start_kernel);
  CORE_ADDR xit = ADDR (do_exit);

  CORE_ADDR fnc = get_frame_func (next_frame);
  CORE_ADDR pc = get_frame_pc (next_frame);

#define PC_OR_FNC_IS(addr)	((pc == addr) || (fnc == addr))

  if (PC_OR_FNC_IS (ker) || PC_OR_FNC_IS (xit))
    return 1;

  if ((HAS_ADDR (kernel_thread_exit))
      && PC_OR_FNC_IS (ADDR (kernel_thread_exit)))
    return 1;

  if ((HAS_ADDR (secondary_start_kernel))
      && PC_OR_FNC_IS (ADDR (secondary_start_kernel)))
    return 1;

#undef PC_OR_FNC_IS

  return 0;
}

static const struct frame_unwind kmain_frame_unwind = {
  .type = KENTRY_FRAME,
  .stop_reason = kmain_frame_unwind_stop_reason,
  .this_id = kmain_frame_this_id,
  .prev_register = NULL,
  .unwind_data = NULL,
  .sniffer = kmain_frame_sniffer,
  .dealloc_cache = NULL,
  .prev_arch = NULL
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
/*                                UNWINDERS                                  */
/*****************************************************************************/

static struct pt_regs *
ptregs_frame_cache (struct frame_info *this_frame,
		    void **this_cache, int offset_from_sp)
{
  ULONGEST sp, stack_top;
  CORE_ADDR regs_addr;
  struct pt_regs *regs;
  ULONGEST *my_regs;
  int i;

  if (*this_cache)
    return *this_cache;

  sp = get_frame_register_unsigned (this_frame, ARM_SP_REGNUM);
  regs_addr = sp + offset_from_sp;

  *this_cache = FRAME_OBSTACK_ZALLOC (struct pt_regs);
  regs = *this_cache;
  memset (regs, 0, sizeof (struct pt_regs));

  i = 0;

  my_regs = (ULONGEST *) regs;
  while (i < sizeof (struct pt_regs) / sizeof (ULONGEST))
    {
      *my_regs = read_memory_unsigned_integer (regs_addr, 4, LKD_BYTE_ORDER);
      regs_addr += 4;
      ++my_regs;
      ++i;
    }

  return regs;
}

/* Unwinder callback that builds a frame_id representing THIS_FRAME in
   THIS_ID. THIS_CACHE points to the cache for THIS_FRAME. */
static void
exception_frame_this_id (struct frame_info *next_frame, void **this_cache,
			 struct frame_id *this_id)
{
  *this_id =
    frame_id_build (get_frame_sp (next_frame), get_frame_pc (next_frame));
}

#define EXCEPTION_FRAME_OFFSET_TO_SP	0

static struct value *
exception_frame_prev_register (struct frame_info
			       *this_frame, void **this_cache, int regnum)
{
  struct pt_regs *cache = ptregs_frame_cache (this_frame, this_cache,
					      EXCEPTION_FRAME_OFFSET_TO_SP);
  gdb_byte buf[4];
  int val = -1;

  if (!cache)
    error ("Can't unwind exception frame.");

  switch (regnum)
    {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
      val = cache->uregs[regnum];
      break;
    case ARM_PS_REGNUM:
      val = cache->uregs[16];
      break;
    default:
      return frame_unwind_got_optimized (this_frame, regnum);
    }

  DEBUG (FRAME, 1, "e_f_p_r(%d)[%02x] = %x\n",
	 frame_relative_level (this_frame), regnum, (unsigned int) val);

  store_unsigned_integer (buf, 4, LKD_BYTE_ORDER, (unsigned int) val);
  return frame_unwind_got_bytes (this_frame, regnum, buf);
}

static int
exception_frame_sniffer (const struct frame_unwind *self,
			 struct frame_info *next_frame, void **this_cache)
{
  CORE_ADDR func = get_frame_func (next_frame);
  CORE_ADDR pc = get_frame_pc (next_frame);

  if ((HAS_ADDR (__dabt_svc) && func == ADDR (__dabt_svc))
      || (HAS_ADDR (__irq_svc) && func == ADDR (__irq_svc))
      || (HAS_ADDR (__pabt_svc) && func == ADDR (__pabt_svc))
      || (HAS_ADDR (__und_svc) && func == ADDR (__und_svc))
      || (HAS_ADDR (__dabt_usr) && func == ADDR (__dabt_usr))
      || (HAS_ADDR (__irq_usr) && func == ADDR (__irq_usr))
      || (HAS_ADDR (__pabt_usr) && func == ADDR (__pabt_usr))
      || (HAS_ADDR (__und_usr) && func == ADDR (__und_usr))
      || (HAS_ADDR (ret_from_exception) && pc == ADDR (ret_from_exception))
      || (HAS_ADDR (__und_usr_unknown) && pc == ADDR (__und_usr_unknown)))
    {
      return 1;
    }

  return 0;
}

static const struct frame_unwind exception_frame_unwind = {
  .type = SIGTRAMP_FRAME,
  .stop_reason = default_frame_unwind_stop_reason,
  .this_id = exception_frame_this_id,
  .prev_register = exception_frame_prev_register,
  .unwind_data = NULL,
  .sniffer = exception_frame_sniffer,
  .dealloc_cache = NULL,
  .prev_arch = NULL
};

//---- from entry-header.S---------------------------------------
//@
//@ Most of the stack format comes from struct pt_regs, but with
//@ the addition of 8 bytes for storing syscall args 5 and 6.
//@ This _must_ remain a multiple of 8 for EABI.
//@
#define S_OFF		8

static void
syscall_frame_this_id (struct frame_info *this_frame, void **this_cache,
		       struct frame_id *this_id)
{
  struct pt_regs *cache = ptregs_frame_cache (this_frame, this_cache, S_OFF);

  *this_id =
    frame_id_build (get_frame_sp (this_frame), get_frame_func (this_frame));
}

static struct value *
syscall_frame_prev_register (struct frame_info *this_frame,
			     void **this_cache, int regnum)
{
  struct pt_regs *cache = ptregs_frame_cache (this_frame, this_cache, S_OFF);
  gdb_byte buf[4];
  int val = -1;

  if (!cache)
    error ("Can't unwind syscall frame.");

  switch (regnum)
    {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
      val = cache->uregs[regnum];
      break;
    case ARM_PS_REGNUM:
      val = cache->uregs[16];
      break;
    default:
      return frame_unwind_got_optimized (this_frame, regnum);
    }

  DEBUG (FRAME, 1, "s_f_p_r(%d)[%02x] = %x\n",
	 frame_relative_level (this_frame), regnum, (unsigned int) val);

  store_unsigned_integer (buf, 4, LKD_BYTE_ORDER, (unsigned int) val);
  return frame_unwind_got_bytes (this_frame, regnum, buf);
}

static int
syscall_frame_sniffer (const struct frame_unwind *self,
		       struct frame_info *next_frame, void **this_cache)
{
  CORE_ADDR func = get_frame_pc (next_frame);

  int test_ret = ((HAS_ADDR (ret_from_fork) && func == ADDR (ret_from_fork))
		  || (HAS_ADDR (ret_fast_syscall)
		      && func == ADDR (ret_fast_syscall))
		  || (HAS_ADDR (ret_slow_syscall)
		      && func == ADDR (ret_slow_syscall)));


  if (test_ret)
    {
      DEBUG (FRAME, 1, "F(%d):syscall_frame_sniffer\n",
	     frame_relative_level (next_frame));
      return 1;
    }

  return 0;
}

/* Structure defining the unwinder for syscalls. */
static const struct frame_unwind syscall_frame_unwind = {
  .type = KENTRY_FRAME,
  .stop_reason = default_frame_unwind_stop_reason,
  .this_id = syscall_frame_this_id,
  .prev_register = syscall_frame_prev_register,
  .unwind_data = NULL,
  .sniffer = syscall_frame_sniffer,
  .dealloc_cache = NULL,
  .prev_arch = NULL
};

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
  uint64_t thread_struct_addr;
  uint64_t thread_info_addr;
  uint64_t cpsr;


  struct cpu_context_save {
  	unsigned long x19;
  	unsigned long x20;
  	unsigned long x21;
  	unsigned long x22;
  	unsigned long x23;
  	unsigned long x24;
  	unsigned long x25;
  	unsigned long x26;
  	unsigned long x27;
  	unsigned long x28;
  	unsigned long fp;
  	unsigned long sp;
  	unsigned long pc;
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
  /* Need to ensure that these are checked against their actual regcache numbers ********************** */
  regcache_raw_supply (regcache, 19, &cpu_cxt.x19);
  regcache_raw_supply (regcache, 20, &cpu_cxt.x20);
  regcache_raw_supply (regcache, 21, &cpu_cxt.x21);
  regcache_raw_supply (regcache, 22, &cpu_cxt.x22);
  regcache_raw_supply (regcache, 23, &cpu_cxt.x23);
  regcache_raw_supply (regcache, 24, &cpu_cxt.x24);
  regcache_raw_supply (regcache, 25, &cpu_cxt.x25);
  regcache_raw_supply (regcache, 26, &cpu_cxt.x26);
  regcache_raw_supply (regcache, 27, &cpu_cxt.x27);
  regcache_raw_supply (regcache, 28, &cpu_cxt.x28);

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

/*****************************************************************************/
/*                      VARIOUS KERNEL AWARENESS HOOKS                       */
/*****************************************************************************/

/* The first pointer argument of a function is stored in ARG0_REGNUM
   at the function entry point. */
static CORE_ADDR
arch_first_pointer_arg_value (void)
{
  ULONGEST ret;
  regcache_cooked_read_unsigned (get_current_regcache (), 0, &ret);
  return ret;
}

/* The second pointer argument of a function is stored in ARG0_REGNUM+1
   at the function entry point. */
static CORE_ADDR
arch_second_pointer_arg_value (void)
{
  ULONGEST ret;
  regcache_cooked_read_unsigned (get_current_regcache (), 1, &ret);
  return ret;
}

/* The third pointer argument of a function is stored in ARG0_REGNUM+2
   at the function entry point. */
static CORE_ADDR
arch_third_pointer_arg_value (void)
{
  ULONGEST ret;
  regcache_cooked_read_unsigned (get_current_regcache (), 2, &ret);
  return ret;
}

/* The return address of a function is stored in PR at the function
   entry point. */
static CORE_ADDR
arch_return_address_at_start_of_function (void)
{
  ULONGEST ret;
  regcache_cooked_read_unsigned (get_current_regcache (), 14, &ret);
  return ret;
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
  frame_unwind_prepend_unwinder (target_gdbarch (), &exception_frame_unwind);
  frame_unwind_prepend_unwinder (target_gdbarch (), &syscall_frame_unwind);
  frame_unwind_prepend_unwinder (target_gdbarch (), &kmain_frame_unwind);

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


struct linux_awareness_ops armv8_linux_awareness_ops = {
  .name = "armv8",
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



/* -Wmissing-prototypes */
extern initialize_file_ftype _initialize_armv8_lkd;

/* _initialize_xxx routines are added to the ugly autogenerates init code
 * see gdb makefile.
 **/
void
_initialize_armv8_lkd (void)
{
  linux_awareness_ops = &armv8_linux_awareness_ops;
}
