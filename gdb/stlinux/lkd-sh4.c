/*
   Copyright 2005-2013 STMicroelectronics.

   This file contains the SH4 platform specific part of the Linux
   awareness layer.

   The contributions of this file are three-fold:
    - implementing the platform specific operations defined by the
   'struct linux_awareness_ops' (see linux-awarness.h)
    - implementing excepetion, interruption and syscall frame
   unwinders (the code that constructs the backtraces)
    - implementing some ST40 specific GDB commands

    You'd better have the ST40 architecture manual around if you want
    to understand all the intricates of this file.
*/

#include <dlfcn.h>

#include "defs.h"
#include "block.h"
#include "command.h"
#include "frame.h"
#include "frame-unwind.h"
#include "inline-frame.h"
#include "gdb_assert.h"
#include "gdbarch.h"
#include "gdbcore.h"
#include "gdbtypes.h"
#include "gdb_obstack.h"
#include "inferior.h"
#include "regcache.h"
#include "user-regs.h"
#include "symtab.h"
#include "target.h"
#include "value.h"

#include "sh-tdep.h"

#include "lkd.h"
#include "lkd-process.h"

extern lkd_proxy_id_t sh4_check_target (struct target_ops *beneath);
/**************************** Virtual memory ****************************/
/* Virtual address translation cache, because it's frequent that GDB
   queries memory for nearby addresses in a row. */
static long int last_pid;
static unsigned int last_page;
static unsigned int last_translation;
static unsigned int last_can_write;

#ifdef HAS_TLB_SUPPORT
/* Nowadays, we by default reprogram the TLB to allow the debugger to
   access virtual memory. This means we overwrite one TLB entry with
   the mapping we want to use. The variables below store the saved
   translation and the translation that we have programmed in the TLB. */
/* TLB cache */
static unsigned int saved_tlb_config_virt;
static unsigned int saved_tlb_config_phys;
static unsigned int current_tlb_config_virt;
static unsigned int current_tlb_config_phys;
#endif

/* Choose to use TLB reprogramming rather than access through physical
   addresses. This is the default now. */
static int force_tlb_reprogramming = 1;

/* The SH4 has a so called 32bits mode (or SE mode) that adds an
   additional layer to the virtual address translation done by the
   CPU. We have to detect that mode and handle it specifically during
   address translation. */
static unsigned long memory_start, memory_end;
static enum
{ PMB_UNKNOWN, PMB_ON, PMB_OFF } pmb_mode;

/* The below data structures define the page table cache we maintain
   in this file. The ST40 uses a 2 level page table, see the
   reference manual. */
typedef struct pte
{
  CORE_ADDR address;
  CORE_ADDR pages[1024];
} pte_t;

typedef struct pgd
{
  CORE_ADDR address;
  pte_t *ptes[1024];
} pgd_t;

/* Page table data for a specific user process. */
typedef struct user_pgd
{
  CORE_ADDR task_struct;
  pgd_t pgd;
  struct user_pgd *next;
} user_pgd_t;

/* Page table cache for the kernel, and a chained list of caches for
   user processes. */
struct vm_cache
{
  pgd_t *kernel_pgd;
  user_pgd_t *user_pgds;
} linux_sh4_cache;

/* Pointer to the current userspace page table cache. */
user_pgd_t *current_user_pgd;

/* Various masks and flags. */
#define mem_mask  0xE0000000
#define P0_mask   0x00000000
#define P1_mask   0x80000000
#define P2_mask   0xA0000000
#define P3_mask   0xC0000000
#define P4_mask   0xE0000000

#define PAGE_SHIFT	12
#define PAGE_OFFSET	P1_mask
#define THREAD_SIZE	(8*1024)
#define KERNEL_OFFSET	PAGE_OFFSET
#define PHYS_OFFSET     0x00000000

#define _PAGE_PRESENT 0x100
#define _PAGE_DIRTY   0x004
#define _PAGE_RW      0x020

/* We allocate our page table caches on an obstack to allow rapid
   freeing. */
#define CACHE_ALLOC(size) ({ \
          void* mem = obstack_alloc(&linux_sh4_obstack, (size)); \
          memset(mem, 0, size); \
          cache_used = 1; \
          mem; })

/* The obstack for the page table cache. */
static struct obstack linux_sh4_obstack;
/* A flag indicating that some cache has been allocated and should be
   freed. (Freeing an empty cache crashes) */
static unsigned int cache_used;

/* In order to correctly handle the virtual memory access, the Linux
   Awareness Layer will ask to flush some cache lines. To do this, we
   need to know the cache layout. This information is stored in the
   below variables. */
static int cache_layout_known = 0;

struct cache_info
{
  unsigned int ways;
  unsigned int sets;
  unsigned int linesz;
  unsigned int way_incr;
  unsigned int entry_shift;
  unsigned int entry_mask;
} i_cache_info, o_cache_info;

/*********************** Addresses and Structure descriptions *****************/

/* Addresses used by the SH4 specific linux awareness. */
DECLARE_ADDR (start_kernel);
DECLARE_ADDR (secondary_start_kernel);
DECLARE_ADDR (kernel_thread_helper);
DECLARE_ADDR (do_exit);

DECLARE_ADDR (contig_page_data);
DECLARE_ADDR (init_thread_union);
DECLARE_ADDR (max_low_pfn);
DECLARE_ADDR (mem_map);
DECLARE_ADDR (min_low_pfn);
DECLARE_ADDR (pmb_init);
DECLARE_ADDR (restore_all);
DECLARE_ADDR (ret_from_exception);
DECLARE_ADDR (ret_from_fork);
DECLARE_ADDR (ret_from_irq);
DECLARE_ADDR (swapper_pg_dir);
DECLARE_ADDR (swapper_space);
DECLARE_ADDR (syscall_call);
DECLARE_ADDR (tlb_miss);
DECLARE_ADDR (work_resched);

/* Fields used by the SH4 specific linux awareness. */
DECLARE_FIELD (irqaction, name);
DECLARE_FIELD (irqaction, next);
DECLARE_FIELD (mm_struct, pgd);
DECLARE_FIELD (page, flags);
DECLARE_FIELD (page, mapping);
DECLARE_FIELD (pglist_data, node_start_pfn);
DECLARE_FIELD (task_struct, mm);
DECLARE_FIELD (task_struct, thread_info);
DECLARE_FIELD (task_struct, thread);
DECLARE_FIELD (task_struct, stack);
DECLARE_FIELD (thread_info, task);
DECLARE_FIELD (thread_struct, pc);
DECLARE_FIELD (thread_struct, sp);

/***************************** Unwinders ******************************/

/* During an exception or interrupt, the register state at the point
   of interrupt or trap is stored in a struct pt_regs
   structure. Replicate this structure here. */
struct pt_regs
{
  unsigned long regs[16];
  unsigned long pc;
  unsigned long pr;
  unsigned long sr;
  unsigned long gbr;
  unsigned long mach;
  unsigned long macl;
  long tra;
};

/* The arg, return value, and caller-save scratch registers ids. */
enum registers
{
  R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
  R7B1 = 58
};
#define SH_NUM_REGS 109

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
	  CORE_ADDR kth = ADDR (kernel_thread_helper);

	  CORE_ADDR fnc = get_frame_func (next_frame);
	  CORE_ADDR pc = get_frame_pc (next_frame);

#define PC_OR_FNC_IS(addr)	((pc == addr) || (fnc == addr))

	  if ( PC_OR_FNC_IS(ker)
		|| PC_OR_FNC_IS(kth))
		  return 1;

	  if ( (HAS_ADDR (secondary_start_kernel))
		&& PC_OR_FNC_IS(ADDR (secondary_start_kernel)))
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


/*****************************************************************************/
/*                         VIRTUAL ADDRESS TRANSLATION                       */
/*****************************************************************************/

/* Lookup the translation cache and see if *ADDR can be translated
   without querying the target. */
static int
try_cached_translation (CORE_ADDR * addr)
{
  if (last_page && last_pid == TIDGET (inferior_ptid)
      && last_page == (*addr & ~0xfffLL) && !force_tlb_reprogramming)
    {
      *addr = last_translation | (*addr & 0xfffLL);
      return 1;
    }

  return 0;
}

/* Are we in SE mode? */
static int
in_se_mode ()
{
  if (pmb_mode)
    return pmb_mode == PMB_ON;

  if (!HAS_ADDR (pmb_init)
      || !HAS_ADDR (min_low_pfn) || !HAS_ADDR (max_low_pfn))
    {
      pmb_mode = PMB_OFF;
      DEBUG (VM, 1, "Not in PMB mode\n");
      return 0;
    }

  /* If in SE mode, we'll need these values to perform address
     translation. */
  memory_start = read_memory_unsigned_integer (ADDR (min_low_pfn), 4,
					       LKD_BYTE_ORDER) << 12;
  memory_end = read_memory_unsigned_integer (ADDR (max_low_pfn), 4,
					     LKD_BYTE_ORDER) << 12;
  pmb_mode = PMB_ON;
  return 1;
}

/* nothing to savee here, because nothing to restore:
 * the tlb changes are discarded by invalidating the
 * first entry : see below.
 **/
static void
arch_save_mmu_info (int core)
{
}

/* Called after a 'continue' to clear the page table cache. */
static void
translate_memory_address_clear_cache ()
{
#ifdef HAS_TLB_SUPPORT
  if (current_tlb_config_phys)
    {
      /* Forget about the TLB programation we've done... */
      current_tlb_config_phys = current_tlb_config_virt = 0;
      /* ... and restore the first TLB entry */
      write_memory_unsigned_integer (0xF6000000, 4, LKD_BYTE_ORDER,
				     saved_tlb_config_virt);
      write_memory_unsigned_integer (0xF7000000, 4, LKD_BYTE_ORDER,
				     saved_tlb_config_phys);
      saved_tlb_config_phys = saved_tlb_config_virt = 0;
    }
#endif

  /* Free the cache if necessary. */
  if (cache_used)
    {
      obstack_free (&linux_sh4_obstack, 0);
      obstack_init (&linux_sh4_obstack);
      linux_sh4_cache.kernel_pgd = NULL;
      linux_sh4_cache.user_pgds = NULL;
      current_user_pgd = NULL;
      cache_used = 0;
    }
}

/* Helper for struct_page_from_phys_addr() */
static int
get_start_pfn (unsigned int *start_pfn)
{
  CORE_ADDR pagedata = HAS_ADDR (contig_page_data) ?
    ADDR (contig_page_data) : (CORE_ADDR) - 1;

  if (pagedata == (CORE_ADDR) - 1)
    return 0;

  *start_pfn = read_unsigned_field (pagedata, pglist_data, node_start_pfn);
  return 1;
}

/* Return the address of the 'struct page' that describes the physical
   address ADDR. */
static CORE_ADDR
struct_page_from_phys_addr (CORE_ADDR addr)
{
  unsigned int pfn = (addr & ~P1_mask) >> 12;
  unsigned int start_pfn;
  struct type *data_ptr;

  if (!HAS_ADDR (mem_map) || !get_start_pfn (&start_pfn))
    return (CORE_ADDR) - 1;

  data_ptr = builtin_type (target_gdbarch ())->builtin_data_ptr;
  return read_memory_typed_address (ADDR (mem_map) + 4 * (pfn - start_pfn),
				    data_ptr);
}

/* Return the value stored in the given PTE for the virtual address in
   ADDR. That value contains the physical address and some flags in
   the low bits. */
static unsigned int
get_address_pte_value (CORE_ADDR addr, pte_t * pte)
{
  unsigned int offset;
  CORE_ADDR page_addr;

  gdb_assert (pte != NULL);

  /* Compute the page offset in the PTE. */
  offset = ((unsigned int) addr << 10) >> 22;
  page_addr = pte->pages[offset];

  /* If the cache isn't populated, do it. */
  if (page_addr == 0)
    {
      page_addr =
	read_memory_unsigned_integer (pte->address + offset * 4, 4,
				      LKD_BYTE_ORDER);
      DEBUG (VM, 3,
	     "Reading page address for 0x%s (*0x%s) -> 0x%s\n",
	     phex (addr, 4), phex (pte->address + offset * 4, 4),
	     phex (page_addr, 4));

      pte->pages[offset] = page_addr;
    }

  return page_addr;
}

/* Returns the right PTE cache for the provided virtual ADDR as
   translated to PGD. */
static pte_t *
get_address_pte (CORE_ADDR addr, pgd_t * pgd)
{
  unsigned int offset;
  pte_t *pte = NULL;

  gdb_assert (pgd != NULL);

  /* Compute the offset into the PGD. */
  offset = ((unsigned int) addr) >> 22;
  pte = pgd->ptes[offset];

  /* If the pte cache doesn't exist, create it. */
  if (pte == NULL)
    {
      pte = CACHE_ALLOC (sizeof (pte_t));

      pte->address =
	read_memory_unsigned_integer (pgd->address + offset * 4, 4,
				      LKD_BYTE_ORDER);
      DEBUG (VM, 3,
	     "Reading PTE address for 0x%s (*0x%s) -> 0x%s\n",
	     phex (addr, 4), phex (pgd->address + offset * 4, 4),
	     phex (pte->address, 4));

      /* When using the TLB optimization patch
         ( https://bugzilla.stlinux.com/attachment.cgi?id=334 ) the
         PTE doesn't contain the PAGE_PRESENT flag and it is directly a
         P1 address. */

      if ((pte->address & P1_mask) != P1_mask)
	if (!(pte->address & _PAGE_PRESENT))
	  return NULL;

      pte->address &= ~0xFFF;
      pte->address |= P1_mask;

      pgd->ptes[offset] = pte;
    }

  return pte;
}

/* Translates the virtual address *ADDR by using the cached pte in
   PTE. Returns the status of the corresponding page, eg PAGE_PRESENT
   if the translation succeeds. */
static enum page_status
translate_address_through_pte (CORE_ADDR * addr, pte_t * pte)
{
  unsigned int page_addr;
  unsigned int page_offset;
  enum page_status res = PAGE_UNKNOWN;
  page_offset = ((unsigned int) *addr) & 0xFFF;
  page_addr = get_address_pte_value (*addr, pte);

  /* page_addr contains some status flags in the low bits. Here we
     handle the cases that won't allow for an address translation. */
  if (!(page_addr & _PAGE_PRESENT))
    {
      if (!page_addr)
	{
	  /* The page simply does not exist. */
	  res = PAGE_NOPAGE;
	}
      else
	{
	  CORE_ADDR struct_page;
	  struct_page = struct_page_from_phys_addr (page_addr);

	  if (struct_page == (CORE_ADDR) - 1 || !HAS_ADDR (swapper_space))
	    res = PAGE_UNKNOWN;
	  else if (		/* PG_swapcache is the bit 15 in the page flags. */
		    read_unsigned_field (struct_page, page,
					 flags) & (1 << 15))
	    /* Page swapped to disk. */
	    res = PAGE_SWAPPED;
	  else
	    /* Page not yet loaded to memory. */
	    res = PAGE_NOTMAPPED;
	}

      /* Mask out the low bits. */
      page_addr &= ~0xFFF;

      DEBUG (VM, 2, "addr = %x => P1 address : %x (%s)\n",
	     (unsigned int) *addr,
	     page_addr + page_offset,
	     (res == PAGE_NOPAGE ? "PAGE_NOPAGE"
	      : (res == PAGE_SWAPPED ? "PAGE_SWAPPED"
		 : (res == PAGE_NOPAGE ? "PAGE_NOTMAPPED"
		    : (res == PAGE_UNKNOWN ? "PAGE_UNKNOWN" : "??")))));

      return res;
    }

  /* OK, the page is present. */
  if (in_se_mode () || force_tlb_reprogramming)
    {
      /* Don't use tlb reprogramming for userspace virtual memory
         access. We might remove that restriction in the future if
         the sdi_VirtualMem API grows ASIDs awareness, but for now
         just access the underlying 'translated' address. (This
         allows us to ignore ASIDs and page access restrictions)
       */
      if (page_addr >= memory_start
	  && page_addr < memory_end
	  && !(force_tlb_reprogramming && (*addr & 0x80000000)))
	{
	  page_addr -= memory_start;
	}
      else
	{
	  CORE_ADDR tlb_addr;
	  unsigned int virt, phys;

	  /* Here we are... we got an address translation and we
	     need to reprogram the TLB to access it. */

	  /* page_addr contains most of the bits already setup
	     correclty. No need to do anything for 'V', 'SH', 'SZ0',
	     'SZ1',...
	     However, when want to override a few things:
	     - Mark the page as dirty. Otherwise, if the page is
	     clean and we try to write it, the write wont happen.
	     - Mark the page as RW, so that we're not limited by
	     software memory protection.

	     Also, use a mask of 0xfff for the address. Although the SH4
	     supports 1K pages the minimum page size is 4K.
	   */
	  virt = *addr & ~0xfffLL;

	  phys = (page_addr & ~(1 << 9)) /* UB */
               | (1 << 8) /* valid */
               | (3 << 5) /* PR */
               | (1 << 2) /* dirty */
               ;

	  /* If available, use the STMC API for TLB programming. */
	  if (sdi_VirtualMem)
	    {
	      sdi_pte_t pte;
	      pte.vaddress = virt;
	      pte.paddress = page_addr & ~0xfff;
	      pte.size = 4096;
	      pte.type = sdi_pte_dynamic;
	      pte.access.read = 1;
	      pte.access.write = 1;
	      pte.ptel = phys;
	      pte.pteh = virt;

	      sdi_VirtualMem (1, &pte);
	      return PAGE_PRESENT;
	    }

#ifdef HAS_TLB_SUPPORT
	  /* We'll program the first TLB entry using the memory
	     mapped interface. */

	  /* page_addr contains the bus address, but we don't know
	     if there's currently a TLB entry for this address. */

	  /* Check if we already setup the TLB for this mapping. */
	  if (current_tlb_config_phys
	      && current_tlb_config_phys == phys
	      && current_tlb_config_virt == virt)
	    return PAGE_PRESENT;

	  /* Save the current configuration of the first TLB.  */
	  if (saved_tlb_config_phys == 0)
	    {
	      tlb_addr = 0xF6000000;
	      saved_tlb_config_virt =
		read_memory_unsigned_integer (tlb_addr, 4, LKD_BYTE_ORDER);
	      tlb_addr = 0xF7000000;
	      saved_tlb_config_phys =
		read_memory_unsigned_integer (tlb_addr, 4, LKD_BYTE_ORDER);
	    }

	  /* Flush any existing TLB entry correspnding to this
	     address. This prevents a multimapping fault from
	     happening.
	     We achieve that using an associative write to the UTLB
	     memory mapped data array. (see arch manual) */
	  tlb_addr = 0xF6000000 | (1 << 7);	/* Bit 7 means associative write. */
	  write_memory_unsigned_integer (tlb_addr, 4, LKD_BYTE_ORDER, virt);

	  /* Add a TLB entry for this page */
	  /* Address array => VPN */
	  tlb_addr = 0xF6000000;
	  write_memory_unsigned_integer (tlb_addr, 4, LKD_BYTE_ORDER, virt);
	  /* Data array => PPN + flags + valid bit + dirty bit */
	  tlb_addr = 0xF7000000;
	  write_memory_unsigned_integer (tlb_addr, 4, LKD_BYTE_ORDER, phys);

	  current_tlb_config_virt = virt;
	  current_tlb_config_phys = phys;

	  DEBUG (VM, 2,
		 "addr = %s => Reprogrammed TLB (virt %08x phys %08x PAGE_PRESENT)\n",
		 phex(*addr, 4), virt, phys);

	  /* Access the page through its virtual address. */
	  return PAGE_PRESENT;
#else
	  gdb_assert (sdi_VirtualMem);
#endif
	}
    }

  /* No TLB reprogramming, return the translated physical address. */
  page_addr += P1_mask;
  res = PAGE_PRESENT;
  page_addr &= ~0xFFF;

  DEBUG (VM, 2, "addr = %x => P1 address : %x (PAGE_PRESENT)\n",
	 (unsigned int) *addr, page_addr + page_offset);

  *addr = page_addr + page_offset;

  return res;
}

/* Translates the virtual address *ADDR by using the cached pgd in
   PGD. Returns the status of the corresponding page, eg PAGE_PRESENT
   if the translation succeeds. */
static enum page_status
translate_address_through_pgd (CORE_ADDR * addr, pgd_t * pgd)
{
  unsigned int offset;
  pte_t *pte;
  enum page_status res;
  CORE_ADDR orig = *addr;

  DEBUG (VM, 2, "Trying to translate %x\n", (unsigned int) *addr);

  pte = get_address_pte (*addr, pgd);

  if (pte == NULL)
    {
      return PAGE_NOPAGE;
    }

  /* Walk the second level of the page table. */
  res = translate_address_through_pte (addr, pte);

  /* Populate the simple translation cache. */
  if (res == PAGE_PRESENT && orig != *addr)
    {
      last_page = orig & ~0xfffLL;
      last_pid = TIDGET (inferior_ptid);
      last_translation = *addr & ~0xfffLL;
      last_can_write = get_address_pte_value (orig, pte) & _PAGE_RW;
    }

  return res;
}

/* Returns the page table cache for kernel space addresses. */
static pgd_t *
get_kernel_pgd ()
{
  if (linux_sh4_cache.kernel_pgd == NULL)
    {
      linux_sh4_cache.kernel_pgd = CACHE_ALLOC (sizeof (pgd_t));
      linux_sh4_cache.kernel_pgd->address = ADDR (swapper_pg_dir);
    }

  return linux_sh4_cache.kernel_pgd;
}

/* Returns the page table cache for user space addresses in the
   context of the given TASK_STRUCT. */
static pgd_t *
find_user_pgd (CORE_ADDR addr, CORE_ADDR task_struct)
{
  user_pgd_t *u_pgd = linux_sh4_cache.user_pgds;
  unsigned int mm_struct_address;
  unsigned int pgd_address;

  if (current_user_pgd && current_user_pgd->task_struct == task_struct)
    return &current_user_pgd->pgd;

  while (u_pgd != NULL)
    {
      if (u_pgd->task_struct == task_struct)
	break;

      u_pgd = u_pgd->next;
    }

  if (u_pgd != NULL)
    {
      current_user_pgd = u_pgd;
      return &current_user_pgd->pgd;
    }

  /* Some sanity checks. */
  if ((task_struct & mem_mask) != P1_mask)
    {
      DEBUG (VM, 1, "Task struct should be at a P1 address.");
      return NULL;
    }
  mm_struct_address = read_unsigned_field (task_struct, task_struct, mm);
  if (mm_struct_address == 0)
    {
      DEBUG (VM, 1, "No userspace address allowed in a kernel thread.");
      return NULL;
    }
  if ((mm_struct_address & mem_mask) != P1_mask)
    {
      DEBUG (VM, 1, "mm struct should be at a P1 address.");
      return NULL;
    }
  pgd_address = read_unsigned_field (mm_struct_address, mm_struct, pgd);
  if ((pgd_address & mem_mask) != P1_mask)
    {
      DEBUG (VM, 1, "pgd should be at a P1 address.");
      return NULL;
    }

  /* Allocate new cache */
  u_pgd = CACHE_ALLOC (sizeof (user_pgd_t));
  u_pgd->task_struct = task_struct;
  u_pgd->pgd.address = pgd_address;
  current_user_pgd = u_pgd;

  u_pgd->next = linux_sh4_cache.user_pgds;
  linux_sh4_cache.user_pgds = u_pgd;

  return &current_user_pgd->pgd;
}

/* Returns the first level page table for the given ADDR in the
   context of TASK_STRUCT. */
static pgd_t *
get_address_pgd (CORE_ADDR addr, CORE_ADDR task_struct)
{
  switch (addr & mem_mask)
    {
    case P3_mask:
      return get_kernel_pgd ();
    case P1_mask:
    case P2_mask:
    case P4_mask:
      gdb_assert (0 && "No pgd for non-translatable addresses.");
    default:
      return find_user_pgd (addr, task_struct);
    }

  return NULL;
}

/* Helper for translate_memory_watch_address() */
static CORE_ADDR
translate_watch_address_pgd (CORE_ADDR addr, pgd_t * pgd)
{
  unsigned int offset;
  pte_t *pte;
  CORE_ADDR res;

  pte = get_address_pte (addr, pgd);

  if (pte != NULL)
    {
      offset = ((unsigned int) addr << 10) >> 22;
      return pte->address + offset * 4;
    }

  /* The PTE isn't mapped */
  offset = ((unsigned int) addr) >> 22;
  return pgd->address + offset * 4;
}

/* Does ADDR need special handling before access? */
static int
arch_address_needs_translation (CORE_ADDR addr)
{
  addr &= mem_mask;
  return addr != P1_mask && addr != P2_mask && addr != P4_mask;
}

/* Translate *ADDR in the context of TASK_STRUCT. */
static enum page_status
arch_translate_memory_address (CORE_ADDR * addr, process_t *ps)
{
  pgd_t *pgd;

  DEBUG (VM, 3, "Asking to translate %x (mem %x)\n",
	 (unsigned int) *addr, (unsigned int) (*addr) & mem_mask);

  if (!arch_address_needs_translation (*addr))
    return PAGE_PRESENT;

  if (try_cached_translation (addr))
    {
      DEBUG (VM, 3, "Cached translation: %s\n", phex (*addr, 4));
      return PAGE_PRESENT;
    }

  pgd = get_address_pgd (*addr, ps->task_struct);

  if (pgd == NULL)
    return PAGE_UNKNOWN;;

  return translate_address_through_pgd (addr, pgd);
}

/* Returns the address of the page table 'cell' that will change when
   the memory mapping state for the page containing ADDR in the
   context of TASK_STRCUT will change. This is used to wait for a page
   to be loaded to memory (see linux-awareness.c:monitored_page). */
static CORE_ADDR
arch_translate_memory_watch_address (CORE_ADDR addr, process_t *ps)
{
  pgd_t *pgd;

  if (!arch_address_needs_translation (addr))
    return 0;

  if (try_cached_translation (&addr))
    return 0;

  pgd = get_address_pgd (addr, ps->task_struct);

  if (pgd == NULL)
    return 0;

  return translate_watch_address_pgd (addr, pgd);
}

/* Is ADDR in the context of TASK_STRUCT a writable mapping? */
static int
arch_can_write (CORE_ADDR addr, CORE_ADDR task_struct)
{
  pgd_t *pgd;
  pte_t *pte;

  if (!arch_address_needs_translation (addr))
    return 1;

  if (try_cached_translation (&addr))
    return last_can_write;

  pgd = get_address_pgd (addr, task_struct);

  if (pgd == NULL)
    return 0;

  pte = get_address_pte (addr, pgd);

  if (pte == NULL)
    return 0;

  if (get_address_pte_value (addr, pte) & _PAGE_RW)
    return 1;

  return 0;
}

/* Is ADDR a userspace address? */
static int
arch_is_user_address (CORE_ADDR addr)
{
  return !(addr & 0x80000000);
}

/* Is ADDR a kernelspace address? */
static int
arch_is_kernel_address (CORE_ADDR addr)
{
  return !arch_is_user_address (addr);
}

/* Debug output describing the cache layout passed as parameter. */
static void
print_cache_info (const char *name, const struct cache_info *info)
{
  DEBUG (VM, 3,
	 "%s info:\n"
	 "sets: %i\tlinesz: %i\n"
	 "ways: %i\tway_incr: 0x%x\n"
	 "entry_shift: %i\tentry_mask: 0x%x\n",
	 name, info->sets, info->linesz,
	 info->ways, info->way_incr, info->entry_shift, info->entry_mask);
}

/* Decode the cache size part of cache descriptors. */
static unsigned int
cache_size (unsigned int s)
{
  switch (s)
    {
    case 0x1:
      return (1 << 12);
    case 0x2:
      return (1 << 13);
    case 0x4:
      return (1 << 14);
    case 0x8:
      return (1 << 15);
    case 0x9:
      return (1 << 16);
    default:
      error ("Invalid cache size : 0x%x", s);
    };
}

/* Routine detecting the cache layout. Hugely inspired from the same
   purpose code in the Linux kernel. */
static void
detect_cache_layout ()
{
  unsigned int PVR, CVR, CCR, RAMCR;
  unsigned int size;

  enum
  { SH4_1XX, SH4_2XX, SH4_3XX } variant;

  PVR = read_memory_unsigned_integer (0xff000030, 4, LKD_BYTE_ORDER);
  CVR = read_memory_unsigned_integer (0xff000040, 4, LKD_BYTE_ORDER);
  CCR = read_memory_unsigned_integer (0xFF00001C, 4, LKD_BYTE_ORDER);

  PVR >>= 16;
  PVR &= 0xFF;

  switch (PVR)
    {
    case 0x80:
    case 0x81:
      variant = SH4_1XX;
      break;
    case 0x06:
      variant = SH4_2XX;
      break;
    case 0x90:
      variant = SH4_3XX;
      break;
    default:
      error ("Couldn't detect the ST40 variant, got 0x%x.", PVR);
    }

  /* FIXME : hardcoded cachecline size ? */
  o_cache_info.linesz = i_cache_info.linesz = 32;
  o_cache_info.entry_shift = i_cache_info.entry_shift = 5;
  o_cache_info.ways = i_cache_info.ways = 1;

  if (variant == SH4_2XX && CCR >> 31)
    {
      o_cache_info.ways = i_cache_info.ways = 2;
    }
  else if (variant == SH4_3XX)
    {
      RAMCR = read_memory_unsigned_integer (0xFF000074, 4, LKD_BYTE_ORDER);
      o_cache_info.ways = (RAMCR & (1 << 6)) ? 2 : 4;
      i_cache_info.ways = (RAMCR & (1 << 7)) ? 2 : 4;
    }

  i_cache_info.sets = cache_size ((CVR >> 20) & 0xF) / i_cache_info.linesz;
  o_cache_info.sets = cache_size ((CVR >> 16) & 0xF) / o_cache_info.linesz;

  i_cache_info.sets /= i_cache_info.ways;
  o_cache_info.sets /= o_cache_info.ways;

  i_cache_info.entry_mask =
    (i_cache_info.sets - 1) << i_cache_info.entry_shift;
  o_cache_info.entry_mask =
    (o_cache_info.sets - 1) << o_cache_info.entry_shift;

  i_cache_info.way_incr = i_cache_info.sets << i_cache_info.entry_shift;
  o_cache_info.way_incr = o_cache_info.sets << o_cache_info.entry_shift;

  cache_layout_known = 1;

  print_cache_info ("O-Cache", &o_cache_info);
  print_cache_info ("I-Cache", &i_cache_info);
}

/* This flushing routine is called only for virtual memory adresses.
   If we pass access_addr == phys_addr, it means that we want to
   suppress the alias we may have introduced through our direct access
   to this physical address.

   This routine flushes the caches lines through the memory mapped
   cache interface.

   Precondition :
   [access_addr..access_addr+len[ lies on the same physical page. */

static void
arch_flush_cache_for_region (CORE_ADDR access_addr,
			     CORE_ADDR phys_addr, int len, int write)
{
  unsigned long start_addr, end_addr, cur_phys_addr, val;
  unsigned int i;

  if (!cache_layout_known)
    detect_cache_layout ();

  DEBUG (VM, 4,
	 "Asking to flush O-Cache for access=%llx phys=%llx (+%d)\n",
	 (ULONGEST) access_addr, (ULONGEST) phys_addr, len);

  start_addr = access_addr & ~(o_cache_info.linesz - 1);
  end_addr = (access_addr + len) & ~(o_cache_info.linesz - 1);
  cur_phys_addr = phys_addr & ~(o_cache_info.linesz - 1);

  /* The cache tags are bus addresses, no memory space identifier */
  cur_phys_addr -= P1_mask;

  if (in_se_mode ())
    {
      /* When in SE mode, we come here for RAM pages that were
         translated from a P0 or p3 mapping to a P1 mapping. BUT, in
         SE mode P1 addresses are virtual ones mapped to physical
         ones through the PMB. To use the right cache tags, we need to get
         a real physical address. */
      cur_phys_addr += memory_start;
    }

  /* OCache */
  /* See arch manual for the details of the cache handling
     interfaces. */
  while (start_addr <= end_addr)
    {
      unsigned long cache_addr = 0xF4000000
	| (start_addr & o_cache_info.entry_mask);
      unsigned long cache_data;
      for (i = 0; i < o_cache_info.ways; ++i)
	{
	  cache_data = read_memory_unsigned_integer (cache_addr, 4,
						     LKD_BYTE_ORDER);

	  DEBUG (VM, 4, "Cache address : %8lx => %8lx (tag %lx)\n",
		 cache_addr, cache_data, (cache_data & ~0x3FF));
	  DEBUG (VM, 4,
		 "      phys_addr             %8lx (tag %lx)\n",
		 cur_phys_addr, (cur_phys_addr & 0xFFFFFC00));

	  if ((cache_data & 0x1)	/* valid */
	      && (write || (cache_data & 0x2)	/* dirty */
		  || (phys_addr == access_addr) /* Aliased cachelines */ )
	      && ((cache_data & ~0x3FF) == (cur_phys_addr & 0xFFFFFC00)))
	    {
	      DEBUG (VM, 3,
		     "Flushing O-Cache for access=%llx phys=%llx\n",
		     (ULONGEST) start_addr, (ULONGEST) cur_phys_addr);
	      write_memory_unsigned_integer (cache_addr, 4, LKD_BYTE_ORDER, 0);
	    }

	  cache_addr += o_cache_info.way_incr;
	}

      start_addr += o_cache_info.linesz;
      cur_phys_addr += o_cache_info.linesz;
    }
}

/*****************************************************************************/
/*                                UNWINDERS                                  */
/*****************************************************************************/

/* Unwinder callback that builds a frame_id representing THIS_FRAME in
   THIS_ID. THIS_CACHE points to the cache for THIS_FRAME. */
static void
exception_frame_this_id (struct frame_info *this_frame, void **this_cache,
			 struct frame_id *this_id)
{
  *this_id = frame_id_build (get_frame_sp (this_frame),
			     get_frame_pc (this_frame));
}

/* Builds the cache containing the information relative to THIS_FRAME
   and stores it in THSI_CACHE. */
static struct pt_regs *
exception_frame_cache (struct frame_info *this_frame, void **this_cache)
{
  CORE_ADDR pc;
  CORE_ADDR regs_addr;
  struct block *b;
  struct symbol *sym;
  struct value *val;
  struct pt_regs *regs;
  unsigned int i;
  unsigned long *my_regs;

  /* Has the cache already been populated? */
  if (*this_cache)
    return *this_cache;

  regs_addr = get_frame_sp (this_frame);

  /* Our cache is a struct pt_regs. */
  *this_cache = FRAME_OBSTACK_ZALLOC (struct pt_regs);
  regs = *this_cache;
  memset (regs, 0, sizeof (struct pt_regs));

  /* When an exception occurs, the struct pt_regs representing the
     interrupted register state is just stored on the stack. */
  i = 0;
  my_regs = (unsigned long *) regs;
  while (i < sizeof (struct pt_regs) / sizeof (unsigned long))
    {
      *my_regs = read_memory_unsigned_integer (regs_addr, 4, LKD_BYTE_ORDER);
      regs_addr += 4;
      ++my_regs;
      ++i;
    }

  return regs;
}

/* Callback that GDB queries on an interrupt/excpetion frame to get the register
   values at the point the exception occured. */
static struct value *
exception_frame_prev_register (struct frame_info
			       *this_frame, void **this_cache, int regnum)
{
  struct pt_regs *cache = exception_frame_cache (this_frame, this_cache);
  gdb_byte buf[4];
  int val = -1;

  if (!cache)
    error ("Can't unwind exception frame.");

  /* Store the right bytes in buf. */
  switch (regnum)
    {
    case R0:
    case R1:
    case R2:
    case R3:
    case R4:
    case R5:
    case R6:
    case R7:
    case R8:
    case R9:
    case R10:
    case R11:
    case R12:
    case R13:
    case R14:
    case R15:
      val = cache->regs[regnum - R0];
      break;
    case PC_REGNUM:
      val = cache->pc;
      break;
    case PR_REGNUM:
      val = cache->pr;
      break;
    case SR_REGNUM:
      val = cache->sr;
      break;
    case GBR_REGNUM:
      val = cache->gbr;
      break;
    case MACH_REGNUM:
      val = cache->mach;
      break;
    case MACL_REGNUM:
      val = cache->macl;
      break;
    default:
      /* EXIT */
      return frame_unwind_got_optimized (this_frame, regnum);
    }

  DEBUG (FRAME, 1, "e_f_p_r(%d)[%02x] = %x\n",
	 frame_relative_level (this_frame), regnum, (unsigned int) val);

  store_unsigned_integer (buf, 4, LKD_BYTE_ORDER, (unsigned int) val);

  return frame_unwind_got_bytes (this_frame, regnum, buf);
}

/* This callback is queried by GDB to check if this unwinder is the
   right one to handle THIS_FRAME. */
static int
exception_frame_sniffer (const struct frame_unwind *self,
			 struct frame_info *this_frame, void **this_cache)
{
  CORE_ADDR func = get_frame_pc (this_frame);

  /* This unwinder handles interrupts and exceptions. */
  if ((HAS_ADDR (ret_from_irq) && func == ADDR (ret_from_irq))
      || (HAS_ADDR (ret_from_exception)
	  && func == ADDR (ret_from_exception))
      || (HAS_ADDR (restore_all) && func == ADDR (restore_all)))
    {

      /* Read the userspace process symbols, because the
         interrupt/exception might have occured during user code. */
      lkd_proc_read_symbols ();
      DEBUG (FRAME, 1, "F(%d):exception_frame_sniffer\n",
	     frame_relative_level (this_frame));
      return 1;
    }

  return 0;
}

/* Structure defining the unwinder for interrupts/exceptions. The
   frame type is set to SIGTRAMP_FRAME because this way GDB won't
   modify the stored PC and the frame will appear as <signal handler called>. */
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

/* Build the frame cache for the syscall unwinder. */
static struct pt_regs *
syscall_frame_cache (struct frame_info *this_frame, void **this_cache)
{
  ULONGEST sp, stack_top;
  CORE_ADDR regs_addr;
  struct pt_regs *regs;
  unsigned long *my_regs;
  unsigned int i;

  if (*this_cache)
    return *this_cache;

  sp = get_frame_register_unsigned (this_frame, R15);
  /* SP should be near the top of the stack which is on a page
     boundary. In fact, SP should certainly be pointing just after
     the pt_regs struct, but this seems more flexible if the asm in entry.S
     changes, or if the SP unwinding is slightly off.

     As the struct is at the top of the kernel stack, one needs to
     compute the start address of the *next* page to substract from.
   */
  stack_top = (sp + 4096) & ~0xFFF;

  /* The userspace pt_regs are stored at the top of the kernel stack. */
  regs_addr = stack_top - sizeof (struct pt_regs);

  /* Here again the cache is a struct pt_regs. */
  *this_cache = FRAME_OBSTACK_ZALLOC (struct pt_regs);
  regs = *this_cache;
  memset (regs, 0, sizeof (struct pt_regs));

  i = 0;
  my_regs = (unsigned long *) regs;
  while (i < sizeof (struct pt_regs) / sizeof (unsigned long))
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
syscall_frame_this_id (struct frame_info *this_frame, void **this_cache,
		       struct frame_id *this_id)
{
  struct pt_regs *cache = syscall_frame_cache (this_frame, this_cache);

  *this_id = frame_id_build (get_frame_sp (this_frame),
			     get_frame_func (this_frame));
}

/* Callback that GDB queries on a syscall frame to get the register
   values at the (userspace) point where the call occured. */
static struct value *
syscall_frame_prev_register (struct frame_info *this_frame,
			     void **this_cache, int regnum)
{
  struct pt_regs *cache = syscall_frame_cache (this_frame, this_cache);
  gdb_byte buf[4];
  int val = -1;

  if (!cache)
    error ("Can't unwind syscall frame.");

  /* Store the right bytes in buf. */
  switch (regnum)
    {
    case R0:
    case R1:
    case R2:
    case R3:
    case R4:
    case R5:
    case R6:
    case R7:
    case R8:
    case R9:
    case R10:
    case R11:
    case R12:
    case R13:
    case R14:
    case R15:
      val = cache->regs[regnum - R0];
      break;
    case PC_REGNUM:
      val = cache->pc;
      break;
    case PR_REGNUM:
      val = cache->pr;
      break;
    case SR_REGNUM:
      val = cache->sr;
      break;
    case GBR_REGNUM:
      val = cache->gbr;
      break;
    case MACH_REGNUM:
      val = cache->mach;
      break;
    case MACL_REGNUM:
      val = cache->macl;
      break;
    default:
      /* EXIT */
      return frame_unwind_got_optimized (this_frame, regnum);
    }

  DEBUG (FRAME, 1, "s_f_p_r(%d)[%02x] = %x\n",
	 frame_relative_level (this_frame), regnum, (unsigned int) val);

  store_unsigned_integer (buf, 4, LKD_BYTE_ORDER, (unsigned int) val);

  return frame_unwind_got_bytes (this_frame, regnum, buf);
}

/* This callback is queried by GDB to check if SELF is the
   right one to handle THIS_FRAME. */
static int
syscall_frame_sniffer (const struct frame_unwind *self,
		       struct frame_info *this_frame, void **this_cache)
{
  CORE_ADDR func;
  struct frame_info *next_frame = get_next_frame (this_frame);
  if ((frame_relative_level (next_frame) != -1)
      && ((HAS_ADDR (work_resched)
	   && get_frame_func (next_frame) == ADDR (work_resched))
	  || (HAS_ADDR (ret_from_fork)
	      && get_frame_func (next_frame) == ADDR (ret_from_fork))
	  || (HAS_ADDR (syscall_call)
	      && get_frame_func (next_frame) == ADDR (syscall_call))))
    {
      /* The next frame was a transition from kernelspace to
         userspace. Read the userspace process symbols. We do that
         here because that sniffer function should be called before
         the real Dwarf2 unwinder tries to do its job on the frame. */
      lkd_proc_read_symbols ();
    }

  func = get_frame_func (this_frame);

  /* We handle syscalls and forks with this unwinder. */
  if ((HAS_ADDR (syscall_call) && func == ADDR (syscall_call))
      || (HAS_ADDR (ret_from_fork) && func == ADDR (ret_from_fork)))
    {
      DEBUG (FRAME, 1, "F(%d):syscall_frame_sniffer\n",
	     frame_relative_level (this_frame));
      return 1;
    }

  return 0;
}

/* Structure defining the unwinder for syscalls. */
static const struct frame_unwind syscall_frame_unwind = {
  .type = NORMAL_FRAME,
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
   has stored away to be able to restart an asleep task later. */
static CORE_ADDR
fetch_context_register_real (CORE_ADDR task_struct)
{
  gdb_byte *thread_info_buffer;
  gdb_byte *stack_buffer;
  gdb_byte *thread_struct_buffer;
  struct cleanup *clean;
  struct regcache *regcache;
  int offset = 0, val, i;
  CORE_ADDR pc;

  thread_struct_buffer = xmalloc (F_SIZE (task_struct, thread));
  thread_info_buffer = xmalloc (4);
  stack_buffer = xmalloc (9 * 4);

  clean = make_cleanup (xfree, thread_struct_buffer);
  make_cleanup (xfree, thread_info_buffer);
  make_cleanup (xfree, stack_buffer);

  /* read task_struct->thread into thread_struct_buffer */
  read_memory (task_struct + F_OFFSET (task_struct, thread),
	       thread_struct_buffer, F_SIZE (task_struct, thread));

  /* read task_struct->thread_info into thread_info_buffer */
  read_memory (task_struct + F_OFFSET (task_struct, stack),
	       thread_info_buffer, F_SIZE (task_struct, stack));

  /* Read 36 bytes at the address in thread_struct->sp. This is the
     space the register were saved in.
     We read all registers at once since what's costly is the
     number of memory accesses, not the size of the accesses. */
  read_memory (extract_unsigned_integer (thread_struct_buffer
					 + F_OFFSET (thread_struct, sp), 4,
					 LKD_BYTE_ORDER), stack_buffer, 36);

  /* The frame info for schedule doesn't take into account the SP
     modifications in the switch_to macro (see asm/system.h). Thus
     we need to point SP to its value after the macro has finished
     to get correct backtracing. */
  /* R15 - SP */
  val =
    extract_unsigned_integer (thread_struct_buffer +
			      F_OFFSET (thread_struct, sp), 4,
			      LKD_BYTE_ORDER);
  val += 9 * 4;			/* 36 bytes adjustement corresponding to the saved
				   registers. */
  /* Put the adjusted value back in the buffer (to get proper target
     endianness, whatever the host is). */
  store_unsigned_integer (thread_struct_buffer +
			  F_OFFSET (thread_struct, sp), 4, LKD_BYTE_ORDER,
			  val);

  /* Now populate the regcache. */
  regcache = get_current_regcache ();
  regcache_raw_supply (regcache, R15,
		       thread_struct_buffer + F_OFFSET (thread_struct, sp));
  /* PC_REGNUM */
  regcache_raw_supply (regcache, PC_REGNUM,
		       thread_struct_buffer + F_OFFSET (thread_struct, pc));
  pc = extract_typed_address (thread_struct_buffer +
			      F_OFFSET (thread_struct, pc),
			      builtin_type
			      (target_gdbarch ())->builtin_data_ptr);

  regcache_raw_supply (regcache, R14, stack_buffer + offset);
  offset += 4;
  regcache_raw_supply (regcache, R13, stack_buffer + offset);
  offset += 4;
  regcache_raw_supply (regcache, R12, stack_buffer + offset);
  offset += 4;
  regcache_raw_supply (regcache, R11, stack_buffer + offset);
  offset += 4;
  regcache_raw_supply (regcache, R10, stack_buffer + offset);
  offset += 4;
  regcache_raw_supply (regcache, R9, stack_buffer + offset);
  offset += 4;
  regcache_raw_supply (regcache, R8, stack_buffer + offset);
  offset += 4;
  regcache_raw_supply (regcache, PR_REGNUM, stack_buffer + offset);
  offset += 4;
  regcache_raw_supply (regcache, GBR_REGNUM, stack_buffer + offset);
  offset += 4;

  /* R7B1: thread_info_buffer contains the representation of the
     thread_info address. */
  regcache_raw_supply (regcache, R7B1, thread_info_buffer);

  for (i = 0; i < gdbarch_num_regs (target_gdbarch ()); i++)
    if (REG_VALID != regcache_register_status (regcache, i))
      /* Mark other registers as unavailable.  */
      regcache_invalidate (regcache, i);

  do_cleanups (clean);

  return pc;
}

/* Callback called by the Linux Awareness Layer to feed the current
   regcache with the value of the registers for the asleep task
   corresponding to TASK_STRUCT. */
static int
arch_fetch_context_register (int regno, CORE_ADDR task_struct)
{
  struct frame_info *f;
  struct regcache *regcache;
  ULONGEST pc;
  int arch_num_regs = gdbarch_num_regs (target_gdbarch ());

  DEBUG (TASK, 4, "fetch_context_register(%i,%x)\n",
	 regno, (unsigned int) task_struct);

  if (REG_VALID == regcache_register_status (get_current_regcache (),
					     PC_REGNUM))
    /* The regcache is already populated. */
    return 1;

  /* Retrieve the stored registers in the task_struct. */
  pc = fetch_context_register_real (task_struct);

  /* All the non-running tasks are stopped in a schedule()
     call. Thus the first frame (displayed eg. in 'info tasks' in
     nearly meaningless. We offer the option (active by default) to
     skip that frame, but this forces us to play dirty tricks with
     GDB's frame machinery. */
  /* Don't skip the frames beginning in ret_from_fork. These frames
     will be handled by the syscall unwinder. */
  if (lkd_params.skip_schedule_frame
      && !(HAS_ADDR (ret_from_fork) && pc == ADDR (ret_from_fork)))
    {
      /* This will be hackish: fetch_context_register_real() built a
         full register cache, but we need to:
         - Get the register values of the prev frame
         - Store these values
         - Destroy the current register cache
         - Recreate it with the stored values

         It can't really be easier because we need to use GDB's
         frame unwinding functions to get the register values in
         the previous frame... and for that we need a frame fully
         setup.
       */
	f = get_current_frame ();

      /* Skip this frame, unwind to the next. */
	f = get_prev_frame (f);

      if (f != NULL)
	{
	  int i;
	  gdb_byte buf[4];
	  int optimized, unavailable;
	  CORE_ADDR addr;
	  int realnum;
	  enum lval_type lval;
	  unsigned long *new_registers = xcalloc (SH_NUM_REGS,
						  sizeof (unsigned long));
	  char *new_registers_valid = xcalloc (SH_NUM_REGS, 1);

	  /* Get the values in the previous frame by unwinding the
	     current one that we've just built. */
	  for (i = 0; i < arch_num_regs; ++i)
	    {
	      frame_register_unwind (f, i, &optimized, &unavailable,
				     &lval, &addr, &realnum, buf);
	      if (!optimized && !unavailable)
		{
		  memcpy (&new_registers[i], buf, 4);
		  new_registers_valid[i] = 1;
		}
	    }

	  /* R7B1 won't be in the frame debug information, but as
	     it's a global register we know it's value. */
	  regcache = get_current_regcache ();
	  regcache_raw_collect (regcache, R7B1, &new_registers[R7B1]);
	  new_registers_valid[R7B1] = 1;

	  /* Destroy the information we've gathered in
	     fetch_context_register_real (). */
	  reinit_frame_cache ();

	  /* Recreate a register cache with the unwound
	     values. These values will appear to be the ones of the
	     first frame. */
	  for (i = 0; i < arch_num_regs; ++i)
	    {
	      if (new_registers_valid[i])
		regcache_raw_supply (regcache, i, &new_registers[i]);
	      else
		/* Mark other registers as unavailable. */
		regcache_invalidate (regcache, i);
	    }

	  xfree (new_registers);
	  xfree (new_registers_valid);
	}
    }

  return 1;
}

/* This is the 'write' routine corresponding to
   fetch_context_register_real () above. */
static int
store_context_register_real (int regno, CORE_ADDR task_struct)
{
  gdb_byte buf[4];
  int offset = 0;

  /*
   * Otherwise we have to collect the thread registers from the stack
   * built by switch function (see include/asm-sh/system.h)
   */

  if (lkd_params.skip_schedule_frame)
    return 0;

  /* The registers are stored in the thread_struct, which address is
     stored in the task_struct. Use this switch to compute the
     offset of the passed register in the thread_struct. */
  switch (regno)
    {
    case GBR_REGNUM:
      offset -= 4;
    case PR_REGNUM:
      offset -= 4;
    case R8:
      offset -= 4;
    case R9:
      offset -= 4;
    case R10:
      offset -= 4;
    case R11:
      offset -= 4;
    case R12:
      offset -= 4;
    case R13:
      offset -= 4;
    case R14:
      offset += read_memory_unsigned_integer (task_struct
					      + F_OFFSET (task_struct,
							  thread)
					      + F_OFFSET (thread_struct,
							  sp), 4,
					      LKD_BYTE_ORDER);
      break;
    default:
      return 0;
    }

  regcache_raw_collect (get_current_regcache (), regno, buf);
  target_write_memory (offset, buf, 4);
  return 1;
}

/* This is the 'write' routine corresponding to
   fetch_context_register () above. */
static int
arch_store_context_register (int regno, CORE_ADDR task_struct)
{
  DEBUG (TASK, 3, "fetch_context_register(%i,%x)\n",
	 regno, (unsigned int) task_struct);

  if (regno == -1)
    {
      /* Store all available registers. */
      for (regno = R8; regno <= GBR_REGNUM; ++regno)
	store_context_register_real (regno, task_struct);
    }

  if (regno < R8 || regno > GBR_REGNUM)
    return 0;

  return store_context_register_real (regno, task_struct);
}

/* Callback called when the caches should be cleared. */
static void
arch_clear_cache ()
{
  DEBUG (D_INIT, 1, "SH4: arch_clear_cache\n");

  translate_memory_address_clear_cache ();
}

/*****************************************************************************/
/*                      VARIOUS KERNEL AWARENESS HOOKS                       */
/*****************************************************************************/

/* The first pointer argument of a function is stored in ARG0_REGNUM
   at the function entry point. */
static CORE_ADDR
arch_first_pointer_arg_value ()
{
  ULONGEST ret;
  regcache_cooked_read_unsigned (get_current_regcache (), ARG0_REGNUM, &ret);
  return ret;
}

/* The second pointer argument of a function is stored in ARG0_REGNUM+1
   at the function entry point. */
static CORE_ADDR
arch_second_pointer_arg_value ()
{
  ULONGEST ret;
  regcache_cooked_read_unsigned (get_current_regcache (), ARG0_REGNUM + 1,
				 &ret);
  return ret;
}

/* The third pointer argument of a function is stored in ARG0_REGNUM+2
   at the function entry point. */
static CORE_ADDR
arch_third_pointer_arg_value ()
{
  ULONGEST ret;
  regcache_cooked_read_unsigned (get_current_regcache (), ARG0_REGNUM + 2,
				 &ret);
  return ret;
}

/* The return address of a function is stored in PR at the function
   entry point. */
static CORE_ADDR
arch_return_address_at_start_of_function ()
{
  ULONGEST ret;
  regcache_cooked_read_unsigned (get_current_regcache (), PR_REGNUM, &ret);
  return ret;
}

/* Macros for single step instruction identification */
#define OPCODE_BT(op)         (((op) & 0xff00) == 0x8900)
#define OPCODE_BF(op)         (((op) & 0xff00) == 0x8b00)
#define OPCODE_BTF_DISP(op)   (((op) & 0x80) ? (((op) | 0xffffff80) << 1) : \
			      (((op) & 0x7f ) << 1))
#define OPCODE_BFS(op)        (((op) & 0xff00) == 0x8f00)
#define OPCODE_BTS(op)        (((op) & 0xff00) == 0x8d00)
#define OPCODE_BRA(op)        (((op) & 0xf000) == 0xa000)
#define OPCODE_BRA_DISP(op)   (((op) & 0x800) ? (((op) | 0xfffff800) << 1) : \
			      (((op) & 0x7ffU) << 1))
#define OPCODE_BRAF(op)       (((op) & 0xf0ff) == 0x0023)
#define OPCODE_BRAF_REG(op)   (((op) & 0x0f00) >> 8)
#define OPCODE_BSR(op)        (((op) & 0xf000) == 0xb000)
#define OPCODE_BSR_DISP(op)   (((op) & 0x800) ? (((op) | 0xfffff800) << 1) : \
			      (((op) & 0x7ffU) << 1))
#define OPCODE_BSRF(op)       (((op) & 0xf0ff) == 0x0003)
#define OPCODE_BSRF_REG(op)   (((op) >> 8) & 0xf)
#define OPCODE_JMP(op)        (((op) & 0xf0ff) == 0x402b)
#define OPCODE_JMP_REG(op)    (((op) >> 8) & 0xf)
#define OPCODE_JSR(op)        (((op) & 0xf0ff) == 0x400b)
#define OPCODE_JSR_REG(op)    (((op) >> 8) & 0xf)
#define OPCODE_RTS(op)        ((op) == 0xb)
#define OPCODE_RTE(op)        ((op) == 0x2b)

#define SR_T_BIT_MASK           0x1

/* Decodes the current instruction and register state to predict what
   the next executed instruction will be. */
static CORE_ADDR
arch_single_step_destination (CORE_ADDR pc)
{
  unsigned short op = read_memory_unsigned_integer (pc, 2, LKD_BYTE_ORDER);
  struct frame_info *frame = get_current_frame ();
  CORE_ADDR addr;

  /* BT */
  if (OPCODE_BT (op))
    {
      if (get_frame_register_unsigned (frame, SR_REGNUM) & SR_T_BIT_MASK)
	addr = pc + 4 + OPCODE_BTF_DISP (op);
      else
	addr = pc + 2;
    }

  /* BTS */
  else if (OPCODE_BTS (op))
    {
      if (get_frame_register_unsigned (frame, SR_REGNUM) & SR_T_BIT_MASK)
	addr = pc + 4 + OPCODE_BTF_DISP (op);
      else
	addr = pc + 4;		/* Not in delay slot */
    }

  /* BF */
  else if (OPCODE_BF (op))
    {
      if (!(get_frame_register_unsigned (frame, SR_REGNUM) & SR_T_BIT_MASK))
	addr = pc + 4 + OPCODE_BTF_DISP (op);
      else
	addr = pc + 2;
    }

  /* BFS */
  else if (OPCODE_BFS (op))
    {
      if (!(get_frame_register_unsigned (frame, SR_REGNUM) & SR_T_BIT_MASK))
	addr = pc + 4 + OPCODE_BTF_DISP (op);
      else
	addr = pc + 4;		/* Not in delay slot */
    }

  /* BRA */
  else if (OPCODE_BRA (op))
    addr = pc + 4 + OPCODE_BRA_DISP (op);

  /* BRAF */
  else if (OPCODE_BRAF (op))
    addr = pc + 4 + get_frame_register_unsigned (frame, OPCODE_BRAF_REG (op));

  /* BSR */
  else if (OPCODE_BSR (op))
    addr = pc + 4 + OPCODE_BSR_DISP (op);

  /* BSRF */
  else if (OPCODE_BSRF (op))
    addr = pc + 4 + get_frame_register_unsigned (frame, OPCODE_BSRF_REG (op));

  /* JMP */
  else if (OPCODE_JMP (op))
    addr = get_frame_register_unsigned (frame, OPCODE_JMP_REG (op));

  /* JSR */
  else if (OPCODE_JSR (op))
    addr = get_frame_register_unsigned (frame, OPCODE_JSR_REG (op));

  /* RTS */
  else if (OPCODE_RTS (op))
    addr = get_frame_register_unsigned (frame, PR_REGNUM);

  /* RTE */
  else if (OPCODE_RTE (op))
    addr = get_frame_register_unsigned (frame, R15);

  /* Other */
  else
    addr = pc + 2;

  return addr & 0xFFFFFFFF;
}

/* Callback called before shutting down. */
static void
arch_close ()
{
  DEBUG (D_INIT, 1, "SH4: arch_close\n");

  arch_clear_cache ();
  cache_layout_known = 0;
  pmb_mode = PMB_UNKNOWN;
  sdi_VirtualMem = NULL;
}

/* returns 1 if MMU is enabled */
static int
arch_check_mem_rdy(void)
{
	  return 1;
}

/* Is the passed PC in the pagefault handler? */
static int
arch_is_tlb_miss_handler (CORE_ADDR pc)
{
  /* This isn't 100% accurate, but we just want not to stop in the
     minor pagefault handler that is small. */
  return HAS_ADDR (tlb_miss) &&
    ADDR (tlb_miss) <= pc && pc < ADDR (tlb_miss) + 100;
}


extern void
lkd_enabled_set (char *args, int from_tty, struct cmd_list_element *c);

/* Callback called after the code in loaded to memory. */

void shtdi_vm_init (void); /*fwd decl*/

static void
arch_pre_load (char *prog, int fromtty)
{
  if (sdi_VirtualMem == NULL)
    shtdi_vm_init ();
}

static void
arch_post_load(char *prog, int fromtty)
{
  frame_unwind_prepend_unwinder (target_gdbarch (), &exception_frame_unwind);
  frame_unwind_prepend_unwinder (target_gdbarch (), &syscall_frame_unwind);
  frame_unwind_prepend_unwinder (target_gdbarch (), &kmain_frame_unwind);
}

/* Callback called when the Linux Awareness layer is loaded. */
static int
arch_init ()
{
  DEBUG (D_INIT, 1, "SH4: arch_init\n");

  obstack_init (&linux_sh4_obstack);

  add_setshow_boolean_cmd ("force_tlb_reprogramming",
			   class_stm,
			   &force_tlb_reprogramming,
			   "Set whether the debugger should systematicaly "
			   "reprogram the TLB to access virtual memory "
			   "instead of accessing the physical address.",
			   "Set whether the debugger should systematicaly "
			   "reprogram the TLB to access virtual memory "
			   "instead of accessing the physical address.",
			   NULL, NULL, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  return 1;
}

/* Check if the loaded kernel contains the minimum info we need. */
static int
arch_check_kernel ()
{
  int res = 0;

  DEBUG (D_INIT, 1, "SH4: arch_check_kernel\n");

  res = HAS_FIELD (mm_struct, pgd)
    && HAS_FIELD (task_struct, stack)
    && HAS_FIELD (task_struct, thread)
    && HAS_FIELD (task_struct, mm)
    && HAS_FIELD (thread_info, task)
    && HAS_FIELD (thread_struct, pc) && HAS_FIELD (thread_struct, sp);

  /* Don't include address check here, because most of the addresses
     aren't fundamental for the awareness layer.  */
  return res;
}

/* The structure hooking this file in the generic Linux awareness
   layer. */

struct linux_awareness_ops sh4_linux_awareness_ops = {
  .name = "SH4",
  .lo_check_kernel = arch_check_kernel,
  .lo_init = arch_init,
  .lo_close = arch_close,
  .lo_pre_load = arch_pre_load,
  .lo_post_load = arch_post_load,
  .lo_check_mem_rdy = arch_check_mem_rdy,
  .lo_address_needs_translation = arch_address_needs_translation,
  .lo_translate_memory_address = arch_translate_memory_address,
  .lo_translate_memory_watch_address = arch_translate_memory_watch_address,
  .lo_can_write = arch_can_write,
  .lo_is_user_address = arch_is_user_address,
  .lo_is_kernel_address = arch_is_kernel_address,
  .lo_is_tlb_miss_handler = arch_is_tlb_miss_handler,
  .lo_flush_cache = arch_flush_cache_for_region,
  .lo_single_step_destination = arch_single_step_destination,
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
  .page_offset = PAGE_OFFSET,
  .thread_size = THREAD_SIZE,
  .kernel_offset = KERNEL_OFFSET,
  .phys_offset = PHYS_OFFSET
};

/* -Wmissing-prototypes */
extern initialize_file_ftype _initialize_sh4_lkd;

/* _initialize_xxx routines are added to the ugly autogenerates init code
 * see gdb makefile. */
void
_initialize_sh4_lkd (void)
{
  linux_awareness_ops = &sh4_linux_awareness_ops;
}

/* support for sdi_VirtualMem API in the STMC libraries (SH4 specific) */
void
shtdi_vm_init (void)
{
  FILE *maps;
  char *lib, *line, *endline;
  size_t sz;
  void *libhandle;
  ssize_t len;

  /* Try to locate the sdi_VirtualMem API in the STMC libraries. */
  static char stmc1[] = "libsh4sdi-ethmp.so";
  static char stmc2[] = "libsh4sdi-stmc2.so";
  static char stmclite[] = "libsh4sdi-server.so";

  DEBUG (D_INIT, 1, "SH4: shtdi_vm_init\n");

  maps = fopen ("/proc/self/maps", "r");
  line = NULL;
  lib = NULL;

  if (maps == NULL)
    goto fail;

  while ((len = getline (&line, &sz, maps)) >= 0)
    {
      /* The '- 1' here is for the terminating '\n' character. */
      endline = line + len - 1;
      if (len > (int) sizeof (stmc1)
	  && strncmp (endline - strlen (stmc1), stmc1, strlen (stmc1)) == 0)
	{
	  printf_unfiltered ("Loading ST40 LKD support (stmc1).\n");
	  lib = stmc1;
	  break;
	}
      if (len > (int) sizeof (stmc2)
	  && strncmp (endline - strlen (stmc2), stmc2, strlen (stmc2)) == 0)
	{
	  printf_unfiltered ("Loading ST40 LKD support (stmc2).\n");
	  lib = stmc2;
	  break;
	}
      if (len > (int) sizeof (stmclite)
	  && strncmp (endline - strlen (stmclite), stmclite,
		      strlen (stmclite)) == 0)
	{
	  printf_unfiltered ("Loading ST40 LKD support (stmclite).\n");
	  lib = stmclite;
	  break;
	}
    }

  fclose (maps);
  xfree (line);
  if (lib == NULL)
    goto fail;

  libhandle = dlopen (lib, RTLD_LAZY);
  if (libhandle == NULL)
    goto fail;
  sdi_VirtualMem = dlsym (libhandle, "sdi_VirtualMem");
  if (sdi_VirtualMem == NULL)
    goto fail;

  return;

fail:
  warning
    ("Impossible to find the current target connection library. The\n"
     "sdi_VirtualMem API won't be used.");
}
