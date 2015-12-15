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
  uint32_t uregs[18];
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

/************************** Forward declarations **************************/
static void pgtable_command (char *args, int from_tty);

/*****************************************************************************/
/*                         VIRTUAL ADDRESS TRANSLATION                       */
/*****************************************************************************/

/* TTBR<n> control bits mask */
#define TTBRn_CONTROL_BITS_MASK 0x7F

/* some (reasonable) kernel configuration assumptions */
#define PAGE_OFFSET	0xc0000000
#define PAGE_SHIFT	12
#define THREAD_SIZE	(8*1024)

/* h/w Level 1 descriptor (PMD)
*/
#define PMD_TYPE_TABLE		(1 << 0)
#define PMD_FLAGS_MASK		(0x3ff)

/* h/w Level 2 descriptor (PTE)
*/
#define PTE_TYPE_SMALL		(2 << 0)
#define PTE_TYPE_LARGE		(1 << 0)
#define PTE_TYPE_PAGE		(PTE_TYPE_SMALL|PTE_TYPE_LARGE)
#define PTE_SFLGS_MASK		(0x0FFF)

/* linux Level 1 descriptor
*/
#define L_PTE_PRESENT	(1 << 0)
#define L_PTE_YOUNG	(1 << 1)
#define L_PTE_DEFAULT	(L_PTE_PRESENT|L_PTE_YOUNG)

/*
 * PMD_SHIFT determines the size of the area a second-level page table can map
 * PGDIR_SHIFT determines what a third-level page table entry can map
 */
#define PGDIR_SHIFT             21	// include/asm/pgtable.h
#define pgd_index(addr)         ((addr) >> PGDIR_SHIFT)

/* This flushing routine is called only for virtual memory adresses.
   If we pass access_addr == phys_addr, it means that we want to
   suppress the alias we may have introduced through our direct access
   to this physical address.

   Precondition :
   [access_addr..access_addr+len[ lies on the same physical page. */

static void
arch_flush_cache_for_region (CORE_ADDR access_addr,
			     CORE_ADDR phys_addr, int len, int write)
{
}

static void
arch_save_mmu_info (int core)
{
  char *reply;

  /*already saved*/
  if (mmu_info[core].dirty)
    return;

  reply = PROXY_EXEC (rd_cp15_ASID);
  sscanf (reply, "%x", &(mmu_info[core].prev_asid));

  reply = PROXY_EXEC (rd_cp15_TTBR0);
  sscanf (reply, "%x", &(mmu_info[core].prev_phys_pgd));

  DEBUG (VM, 2, "core %d: mmu SAVE phy_pgd 0x%08x, asid %u\n", core,
	 mmu_info[core].prev_phys_pgd, mmu_info[core].prev_asid);

  mmu_info[core].dirty = 1;
}

static void
switch_mm (uint32_t virt_pgd, uint32_t asid)
{
  static char comm[256];
  int core = linux_aware_target_core ();
  uint32_t phy_pgd = virt_to_phys (virt_pgd);

  /* target core may change if current thread a core thread */
  if (ptid_get_tid (inferior_ptid) != CORE_INVAL)
    core = ptid_get_tid (inferior_ptid) - 1;

  /* already switched */
  if (mmu_info[core].curr_virt_pgd == virt_pgd)
    return;

  arch_save_mmu_info (core);

  /* Inherit control bits from current TTBR0.  */
  phy_pgd |= mmu_info[core].prev_phys_pgd & TTBRn_CONTROL_BITS_MASK;

  sprintf (comm, PROXY->wr_cp15_ASID, 0); /* reserved asid */
  PROXY->exec (comm);

  sprintf (comm, PROXY->wr_cp15_TTBR0, (uint32_t) (phy_pgd));
  PROXY->exec (comm);

  if (asid)
    {
      sprintf (comm, PROXY->wr_cp15_ASID, asid);
      PROXY->exec (comm);
    }

  DEBUG (VM, 2, "core %d: mmu PROG phy_pgd 0x%08x, pgd 0x%08x, asid %u\n",
         core, phy_pgd, virt_pgd, asid);

  mmu_info[core].curr_virt_pgd = virt_pgd;
}

static void
arch_restore_mmu_info (void)
{
  int core;
  static char comm[256];

  for (core = 0; core < max_cores; core++)
    if (mmu_info[core].dirty)
      {
      if (ptid_get_tid (inferior_ptid) != (core - 1))
	{
	   DEBUG (VM, 2, "switching back to core %d to restore mmu settings\n",
		  core);
	   /* we need switch the remote back to the right core
	    **/
	   switch_to_thread (lkd_proc_get_running (core)->gdb_thread->ptid);
	}

	sprintf (comm, PROXY->wr_cp15_ASID, 0);
	PROXY->exec (comm);

	sprintf (comm, PROXY->wr_cp15_TTBR0,
		 (uint32_t) (mmu_info[core].prev_phys_pgd));
	PROXY->exec (comm);

	sprintf (comm, PROXY->wr_cp15_ASID, mmu_info[core].prev_asid);
	PROXY->exec (comm);

	DEBUG (VM, 2,
	    "restore mmu settings for core %d: mmu PROG (phy_pgd=0x%08x, asid=%u)\n",
	    core, mmu_info[core].prev_phys_pgd, mmu_info[core].prev_asid);

	mmu_info[core].curr_virt_pgd = phys_to_virt (mmu_info[core].prev_phys_pgd);
	mmu_info[core].dirty = 0;
      }
}


/* FIXME: Highmem support will not work well currently, maybe this is
 * fixed next year with the changes for ARMv8. */
static int
arch_address_needs_translation (CORE_ADDR addr)
{
	/* QEMU: let's skip the
	 * translation code except for kernel modules. */
	if (lkd_proxy_get_current() == lkd_remote_qemu)
	return ((addr >= linux_awareness_ops->kernel_offset)
		&& (addr < linux_awareness_ops->page_offset));

	return ((unsigned long) (addr) < linux_awareness_ops->page_offset);
}

    /*  MVA to PA for the Hardware:
     *
     *  TTBR0=        [translation base ][XXX 14 XXX] = swapper_pg_dir or task.mm.pgd
     *  ADDR=                   |          [ index1 ][index2][page offset]
     *                          |               /         /
     *          PGD=    [translation base ][ index1 ]00         PA of first level descriptor
     *           PMD=   [ page table base ][  flags  ]01        value of first level desc. (PMD)
     *                          |                      /
     *          &PTE=   [ page table base ][  index2  ]00       PA of the PTE.
     *          PTE=    [base page address][ AC flags ]1x       value of the PTE.
     *                                         |
     *          PA=     [base page address][page offset]
     *
     *  MVA to PA for Linux, when no PAE and on 32 bits systems:
     *  512*32 bit entries go into in a 4k page twice : once in ARM/mmu version one in Linux version.
     *  now PDG_index starts at bit 21, where index1 started at bit 20.
     *
     *  ADDR=   [ PGD_index ][ PTE_index ][page offset]
     *
     *  PGD=    [pgd base ][PGD_index]000  PA of first level descriptor
     *                              |
     *                              l--> PTE_page from 0x000 to 0x400 : 256 hw PTE (index2's)
     *  PGD + 0x4 ---------------------> PTE_page from 0x400 to 0x800 : 256 hw PTE (next index2's)
     *  Linux versions of the PTE -----> PTE_page from 0x800 to 0xFFF : 512 Linux PTE
     *
     **/
static void dump_translation (uint32_t ttbr0, uint32_t vma);

static enum page_status
arch_translate_memory_address (CORE_ADDR * addr, process_t *ps)
{
  uint32_t pgd = -1;
  uint32_t asid = 0; /* reserved asid */

  if (*addr >= linux_awareness_ops->kernel_offset)
      pgd = ADDR (swapper_pg_dir);
  else
    {
      CORE_ADDR mm = lkd_proc_get_mm (ps);

      pgd = lkd_proc_get_pgd (ps);
      if (mm)
	asid = read_unsigned_embedded_field (mm,
					     mm_struct, context,
					     mm_context_t, id);
    }

  switch_mm (pgd, asid);

  /* addr is unchanged in case or ARM. because the VMA is used
     by the `beneath` target. */
  return PAGE_PRESENT;
}

/* VMA translation debug/checker helper.
*/
void
dump_translation (uint32_t ttbr0, uint32_t vma)
{
  uint32_t pa_1st;
  uint32_t pa_2nd;
  uint32_t val_1st;
  uint32_t val_2nd;
  uint32_t pa_addr;
  uint32_t va_pa;
  uint32_t value;
  enum target_xfer_status status;
  ULONGEST len;

  printf_filtered ("ttbr0 = %08x\n", ttbr0);
  printf_filtered ("vma = %08x\n", vma);

  pa_1st = phys_to_virt (ttbr0 & 0xFFFFC000)
	   + (((vma & 0xFFF00000) >> 20) << 2);

  printf_filtered ("address of 1ST level descriptor= %08x\n", pa_1st);



  // read_memory(pa_1st, ((gdb_byte *) & val_1st), 4);
  status = BENEATH->to_xfer_partial (BENEATH,
				  TARGET_OBJECT_MEMORY, NULL,
				  ((gdb_byte *) & val_1st), NULL,
				  (pa_1st), 4, &len);

  printf_filtered ("value   of 1ST level descriptor= %08x\n", val_1st);

  switch (val_1st & 0x3)
    {
    case 0:
      printf_filtered ("FAULT\n");
      return;
      break;
    case 1:
      printf_filtered ("PAGE_TABLE\n");
      pa_2nd = phys_to_virt (val_1st & 0xFFFFFC00)
	       + (((vma & 0x000FF000) >> 12) << 2);
      printf_filtered ("address of 2ND level descriptor= %08x\n", pa_2nd);

      // read_memory(pa_2nd, ((gdb_byte *) & val_2nd), 4);
      status = BENEATH->to_xfer_partial (BENEATH,
				      TARGET_OBJECT_MEMORY, NULL,
				      ((gdb_byte *) & val_2nd), NULL,
				      (pa_2nd), 4, &len);

      printf_filtered ("value   of 2ND level descriptor= %08x\n", val_2nd);

      pa_addr = ((val_2nd & 0xFFFFF000) + (vma & 0xFFF));
      va_pa = phys_to_virt (pa_addr);

      printf_filtered ("PA decoded = %08x\n", pa_addr);

      // read_memory(va_pa, ((gdb_byte *) & value), 4);
      status = BENEATH->to_xfer_partial (BENEATH,
				      TARGET_OBJECT_MEMORY, NULL,
				      ((gdb_byte *) & value), NULL,
				      (va_pa), 4, &len);

      printf_filtered ("=> value = %08x\n", value);

      break;
    case 2:
      printf_filtered ("SECTION or SUPERSECTION\n");
      break;
    case 3:
      printf_filtered ("RESERVED\n");
      break;
    default:
      gdb_assert ("Not reached" && 0);
    }
}

static CORE_ADDR
arch_translate_memory_watch_address (CORE_ADDR addr, process_t *ps)
{
  return 0;
}

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
  uint32_t *my_regs;
  int i;

  if (*this_cache)
    return *this_cache;

  sp = get_frame_register_unsigned (this_frame, ARM_SP_REGNUM);
  regs_addr = sp + offset_from_sp;

  *this_cache = FRAME_OBSTACK_ZALLOC (struct pt_regs);
  regs = *this_cache;
  memset (regs, 0, sizeof (struct pt_regs));

  i = 0;

  my_regs = (uint32_t *) regs;
  while (i < sizeof (struct pt_regs) / sizeof (uint32_t))
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
      lkd_proc_read_symbols ();
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

  if ((frame_relative_level (next_frame) != -1)
      && ((HAS_ADDR (work_resched) && func == ADDR (work_resched))
	  || test_ret))
    {
      /* Do that here because.... it should work. :-/  */
      lkd_proc_read_symbols ();
    }

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
  /* if post_stop context was different, switch back.
   **/
  arch_restore_mmu_info ();
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

/* returns 1 if MMU is enabled */
static int
arch_check_mem_rdy(void)
{
#define ARMv7_BIT_MMUE (1<<0)
	  int val;
	  char *scr;

	  /* Make sure we are testing on core0, as smp linux
	   * may be init'ing core0, while coreN is on hold. */
	  switch_to_thread (ptid_build (ptid_get_pid (inferior_ptid),0,1));

	  scr = PROXY_EXEC (rd_cp15_SCR0);
	  sscanf (scr, "%x", &val);

	  DEBUG (D_INIT, 1, "SCR Returned %s, and determined 0x%x (%s)\n", scr, val,
			  ((val & ARMv7_BIT_MMUE) != 0) ? "True" : "False");

	  return ((val & ARMv7_BIT_MMUE) != 0);

#undef ARMv7_BIT_MMUE
}

/*
 * default op handler for STGDI (non-remote)
 **/
static void
arch_post_load (char *prog, int fromtty)
{
  CORE_ADDR addr_phys_offset;
  char *ttbr0_str;

  DEBUG (D_INIT, 1, "ARM: arch_post_load\n");

  ttbr0_str = PROXY_EXEC (rd_cp15_TTBR0);

  printf_unfiltered ("\nLoaded ARMv7 LKD support.\n");
  DEBUG (TARGET, 1, "scr0: %s\n", PROXY_EXEC (rd_cp15_SCR0));
  DEBUG (TARGET, 1, "ttr0: %s\n", ttbr0_str);
  DEBUG (TARGET, 1, "asid: %s\n", PROXY_EXEC (rd_cp15_ASID));

#define KMEM_GUESS_MASK 0xC0000000

  /* store the physical offset of the first memory bank.
   **/
  if (!HAS_ADDR (meminfo))
    {
      sscanf (ttbr0_str, "%x", &(linux_awareness_ops->phys_offset));
      linux_awareness_ops->phys_offset &= 0xC0000000;
      warning ("Will use 0x%08x as PHYS_OFFSET without guaranty.",
	       linux_awareness_ops->phys_offset);
    }
  else
    {
      linux_awareness_ops->phys_offset =
	read_unsigned_embedded_field (ADDR (meminfo), meminfo, bank, membank,
				      start);

      DEBUG (TARGET, 1, "Got 0x%08x as PHYS_OFFSET offset for bank 0.\n",
	     linux_awareness_ops->phys_offset);
    }

  linux_awareness_ops->page_offset = ADDR (start_kernel) & KMEM_GUESS_MASK;

  DEBUG (TARGET, 1, "Assuming 0x%08x as PAGE_OFFSET.\n",
	 linux_awareness_ops->page_offset);

#undef KMEM_GUESS_MASK

  linux_awareness_ops->kernel_offset =
    linux_awareness_ops->page_offset - MODULES_VADDR_D;

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

  add_com ("pgtable", class_stm, pgtable_command,
	   "Print page table status for given address.");
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
  .lo_check_mem_rdy = arch_check_mem_rdy,
  .lo_address_needs_translation = arch_address_needs_translation,
  .lo_translate_memory_address = arch_translate_memory_address,
  .lo_translate_memory_watch_address = arch_translate_memory_watch_address,
  .lo_can_write = arch_can_write,
  .lo_is_user_address = arch_is_user_address,
  .lo_is_kernel_address = arch_is_kernel_address,
  .lo_flush_cache = arch_flush_cache_for_region,
  .lo_single_step_destination = NULL,
  .lo_clear_cache = arch_clear_cache,
  .lo_first_pointer_arg_value = arch_first_pointer_arg_value,
  .lo_second_pointer_arg_value = arch_second_pointer_arg_value,
  .lo_third_pointer_arg_value = arch_third_pointer_arg_value,
  .lo_return_address_at_start_of_function =
    arch_return_address_at_start_of_function,
  .lo_fetch_context_register = arch_fetch_context_register,
  .lo_store_context_register = arch_store_context_register,
  .lo_save_mmu_info = arch_save_mmu_info,
  .page_shift = PAGE_SHIFT,
  .thread_size = THREAD_SIZE,
  .kernel_offset = 0x0,
  .page_offset = 0x0,
  .phys_offset = 0x0,		/*Target specific */
  .proxy = NULL
};

extern process_t *running_process[];

static void
pgtable_command (char *args, int from_tty)
{
  CORE_ADDR addr;
  unsigned int tbl, pgdval, pte, pteval, i;
  int core = linux_aware_target_core ();

  /* target core may change if current thread a core thread */
  if (ptid_get_tid (inferior_ptid) != CORE_INVAL)
    core = ptid_get_tid (inferior_ptid) - 1;

  /* This command uses the CURRENT PGD setting, according to the
   * current selected thread
   **/
  printf_filtered ("TTBRO: %s\n", PROXY_EXEC (rd_cp15_TTBR0));
  printf_filtered ("ASID: %s\n", PROXY_EXEC (rd_cp15_ASID));

  printf_filtered ("mmu_info[0].PGD:\t%08x\n", mmu_info[0].curr_virt_pgd);
  printf_filtered ("mmu_info[1].PGD:\t%08x\n", mmu_info[1].curr_virt_pgd);

  printf_filtered ("inferior_ptid = %d-%ld-%ld\n",
		   ptid_get_pid (inferior_ptid),
		   ptid_get_lwp (inferior_ptid),
		   ptid_get_tid (inferior_ptid));

  printf_filtered ("phys_offset = %08x\n", linux_awareness_ops->phys_offset);
  printf_filtered ("page_offset = %08x\n", linux_awareness_ops->page_offset);

  if (!args && from_tty)
    {
      lkd_dump_rq_info ();
      return;
    }

  addr = parse_and_eval_address (args);
  printf_filtered ("Addr:\t%lx\n", addr);

  printf_filtered ("translation through core = %d\n", core);
  dump_translation (virt_to_phys (mmu_info[core].curr_virt_pgd), addr);

  linux_aware_translate_address_safe (&addr, 0);
}

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
