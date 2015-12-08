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

DECLARE_ADDR (sys_set_tid_address);
DECLARE_ADDR (irq_desc);
DECLARE_FIELD (irq_desc, irq_data);
DECLARE_FIELD (irq_data, chip);

/* CONFIG_SPARSE_IRQ - KERN_310 */
DECLARE_ADDR (irq_desc_tree);
DECLARE_ADDR (nr_irqs);

DECLARE_ADDR (irq_stat);
DECLARE_FIELD (irq_cpustat_t, ipi_irqs);
DECLARE_ADDR (irq_err_count);
DECLARE_ADDR (ipi_types);

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
DECLARE_FIELD (ipc_id_ary, size);
DECLARE_FIELD (ipc_id_ary, p);
DECLARE_FIELD (ipc_ids, in_use);
DECLARE_FIELD (ipc_ids, entries);
DECLARE_FIELD (ipc_namespace, ids);

DECLARE_FIELD (irq_chip, name);
DECLARE_FIELD (irq_desc, action);
DECLARE_FIELD (irq_desc, handler);
DECLARE_FIELD (irq_desc, chip);
DECLARE_FIELD (irq_desc, name);
DECLARE_FIELD (irq_desc, kstat_irqs);
DECLARE_FIELD (irqaction, name);
DECLARE_FIELD (irqaction, next);
DECLARE_FIELD (kernel_stat, irqs);
DECLARE_FIELD (hw_interrupt_type, typename);

/* Radix Trees */
DECLARE_ADDR (height_to_maxindex);
DECLARE_FIELD (radix_tree_root, rnode);
DECLARE_FIELD (radix_tree_node, height);
DECLARE_FIELD (radix_tree_node, slots);

DECLARE_FIELD (kern_ipc_perm, deleted);
DECLARE_FIELD (kern_ipc_perm, key);
DECLARE_FIELD (kern_ipc_perm, uid);
DECLARE_FIELD (kern_ipc_perm, gid);
DECLARE_FIELD (kern_ipc_perm, cuid);
DECLARE_FIELD (kern_ipc_perm, cgid);
DECLARE_FIELD (kern_ipc_perm, mode);
DECLARE_FIELD (kern_ipc_perm, seq);
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

/* small 64-bytes string buffer */
static char temp_buf64[65];

/* Irqd name cache helper functions. */
struct name
{
  CORE_ADDR addr;
  char name[65];
  struct name *next;
} *names1 = NULL, *names2 = NULL, *cur;

 /**/ static struct name *
find_name_aux (CORE_ADDR addr, struct name *list)
{
  struct name *n = list;

  while (n)
    {
      if (n->addr == addr)
	return n;
      n = n->next;
    }

  return NULL;
}

 /**/ static struct name *
register_name (CORE_ADDR base, struct field_info *field)
{
  struct name *name = xmalloc (sizeof (struct name));
  struct name *n;
  CORE_ADDR addr;

  addr =
    read_memory_typed_address (base +
			       linux_get_field_offset (field),
			       lkd_private.target_pointer_type);
  n = find_name_aux (addr, names2);
  if (n)
    return n;

  read_memory_string (addr, temp_buf64, 64);
  strcpy (name->name, temp_buf64);
  name->addr = base;
  name->next = names1;
  names1 = name;

  name = xmalloc (sizeof (struct name));
  strcpy (name->name, temp_buf64);
  name->addr = addr;
  name->next = names2;
  names2 = name;

  return name;
}

 /**/ static struct name *
find_name (CORE_ADDR addr, struct field_info *field)
{
  struct name *cur = find_name_aux (addr, names1);

  if (cur)
    return cur;

  return register_name (addr, field);
}

 /**/ static void
free_names (void)
{
  while (names1)
    {
      cur = names1->next;
      xfree (names1);
      names1 = cur;
    }
  while (names2)
    {
      cur = names2->next;
      xfree (names2);
      names2 = cur;
    }
}



/* Trees */
#define RADIX_TREE_INDIRECT_PTR 1
#define radix_tree_is_indirect_ptr(ptr)  ((int)(ptr & RADIX_TREE_INDIRECT_PTR))
#define indirect_to_ptr(ptr)  ((int)(ptr & ~RADIX_TREE_INDIRECT_PTR))
#define CONFIG_BASE_SMALL 0	/*fixme */
#define RADIX_TREE_MAP_SHIFT  (CONFIG_BASE_SMALL ? 4 : 6)
#define RADIX_TREE_MAP_SIZE (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK (RADIX_TREE_MAP_SIZE-1)
#define RADIX_TREE_INDEX_BITS  (8 /* CHAR_BIT */ * sizeof(unsigned long))
#define DIV_ROUND_UP(x,y)       (((x) + ((y) - 1)) / (y))
#define RADIX_TREE_MAX_PATH (DIV_ROUND_UP(RADIX_TREE_INDEX_BITS, \
			                                                          RADIX_TREE_MAP_SHIFT))

static struct
{
  unsigned long data[RADIX_TREE_MAX_PATH + 1];
  int valid;
} cached_height_to_maxindex;

/* Do once upon entering debug mode, to optimize. */
static void
radix_tree_update_maxindex (void)
{
  read_memory (ADDR (height_to_maxindex),
	       (gdb_byte *) cached_height_to_maxindex.data,
	       sizeof (cached_height_to_maxindex));
  cached_height_to_maxindex.valid = 1;
}

 /**/ static void
get_nr_irqs (int *size, int *number)
{
  *size = -1;
  *number = 0;
  /*we test if the cache is used, to diff if radix-tree scheme or not. */
  cached_height_to_maxindex.valid = 0;

  if (HAS_ADDR (irq_desc))
    {
      struct block_symbol bsym = lookup_symbol ("irq_desc", NULL,
					  VAR_DOMAIN, NULL);
      if (bsym.symbol && TYPE_CODE (SYMBOL_TYPE (bsym.symbol)) == TYPE_CODE_ARRAY)
	{
	  *size = TYPE_LENGTH (TYPE_TARGET_TYPE (SYMBOL_TYPE (bsym.symbol)));
	  if (*size)
	    *number = TYPE_LENGTH (SYMBOL_TYPE (bsym.symbol)) / *size;
	}
    }
  else
    {
      *number =
	read_memory_unsigned_integer (ADDR (nr_irqs), 4, LKD_BYTE_ORDER);
      *size = lkd_eval_long ("sizeof(struct irq_desc)");
      radix_tree_update_maxindex ();
    }

  if ((*size == -1) || !*number)
    error
      ("Cannot find the NR_IRQS kernel setting using the debug info.\n"
       "might be a simple array starting on irq_desc, or a radix-tree bailing out.\n");
}

 /**/ static void
show_ipi_list (void)
{
#define NR_IPI 10

  unsigned int cpu, i, count[MAX_CORES][NR_IPI];

  struct block_symbol stat_sym = lookup_symbol ("irq_stat", NULL,
					   VAR_DOMAIN, NULL);
  int stat_type_length =
    TYPE_LENGTH (TYPE_TARGET_TYPE (SYMBOL_TYPE (stat_sym.symbol)));

  int ipi_type_length = F_SIZE (irq_cpustat_t, ipi_irqs);
  int nr_ipi = ipi_type_length /
    TYPE_LENGTH (lkd_private.target_pointer_type);

  gdb_assert (nr_ipi <= NR_IPI);

  if (!nr_ipi)
	  return;

  for_each_present_cpu (cpu)
    read_memory (ADDR (irq_stat) + cpu * stat_type_length +
		 F_OFFSET (irq_cpustat_t, ipi_irqs),
		 (gdb_byte *) & count[cpu][0], F_SIZE (irq_cpustat_t,
						       ipi_irqs));

  temp_buf64[64] = '\0';

  for (i = 0; i < nr_ipi; i++)
    {
      CORE_ADDR this_name_addr;
      printf_filtered ("%s%u:", "IPI", i);
      for_each_present_cpu (cpu) printf_filtered ("\t%10u ", count[cpu][i]);

      this_name_addr =
	(CORE_ADDR) (read_memory_unsigned_integer
		     (ADDR (ipi_types) + i * 4, 4, LKD_BYTE_ORDER));

      read_memory_string (this_name_addr, temp_buf64, sizeof (temp_buf64));
      printf_filtered ("\t %s\n", temp_buf64);
    }
}

 /**/ static CORE_ADDR
radix_tree_lookup_element (CORE_ADDR root /*struct radix_tree_root *root */ ,
			   unsigned long index, int is_slot)
{
  unsigned int height, shift;

  CORE_ADDR node /*struct radix_tree_node *node */ ;
  CORE_ADDR slot;

  node = read_pointer_field (root, radix_tree_root, rnode);
  if ((node == 0) || (node == -1))
    return 0;

  if (!radix_tree_is_indirect_ptr (node))
    {
      if (index > 0)
	return 0;
      return is_slot ? (root + F_OFFSET (radix_tree_root, rnode)) : node;
    }

  node = indirect_to_ptr (node);

  height = read_unsigned_field (node, radix_tree_node, height);
  if (index > cached_height_to_maxindex.data[height])
    return 0;

  shift = (height - 1) * RADIX_TREE_MAP_SHIFT;

  do
    {
      slot = node + F_OFFSET (radix_tree_node, slots) +
	((index >> shift) & RADIX_TREE_MAP_MASK)
	* TYPE_LENGTH (lkd_private.target_pointer_type);

      node = read_memory_unsigned_integer (slot, 4, LKD_BYTE_ORDER);
      if ((node == 0) || (node == -1))
	return 0;

      shift -= RADIX_TREE_MAP_SHIFT;
      height--;
    }
  while (height > 0);

  return is_slot ? slot : indirect_to_ptr (node);
}

 /**/ static CORE_ADDR
irq_to_desc (unsigned int irq)
{
  /* radix_tree_lookup */
  return radix_tree_lookup_element (ADDR (irq_desc_tree), irq, 0);
}

 /**/ void
interrupts_command (char *args, int from_tty)
{
  gdb_byte *irq_descs;
  int nr_irqs, irq_desc_size;
  int i, cpu;

  temp_buf64[64] = '\0';

  get_nr_irqs (&irq_desc_size, &nr_irqs);

  printf_filtered ("IRQ\t\t ");

  for_each_present_cpu (cpu) printf_filtered ("CPU%d\t\t ", cpu);

  printf_filtered (" Triggered Handler => Action\n");
  printf_filtered ("---------------------------------------------------\n");

  irq_descs = xmalloc (nr_irqs * irq_desc_size);

  if (!cached_height_to_maxindex.valid)
    read_memory (ADDR (irq_desc), irq_descs, nr_irqs * irq_desc_size);

  for (i = 0; i < nr_irqs; ++i)
    {
      CORE_ADDR name;
      CORE_ADDR irqs_addr;
      CORE_ADDR chip;
      CORE_ADDR p_irq_data;
      CORE_ADDR this_irq_desc_p;
      gdb_byte *this_irq_desc;
      CORE_ADDR action;

      if (cached_height_to_maxindex.valid)
	{
	  /* tree search */
	  this_irq_desc_p = irq_to_desc (i);
	  this_irq_desc = irq_descs;
	  read_memory (this_irq_desc_p, irq_descs, irq_desc_size);

	}
      else
	{
	  /* read in one block */
	  this_irq_desc_p = ADDR (irq_desc) + i * irq_desc_size;
	  this_irq_desc = irq_descs + i * irq_desc_size;
	}

      action = extract_pointer_field (this_irq_desc, irq_desc, action);
      if (!action)
	continue;

      irqs_addr = extract_pointer_field (this_irq_desc, irq_desc, kstat_irqs);

      printf_filtered ("%3d", i);

      /*this is a per_cpu pointer */
      for_each_present_cpu (cpu)
      {
	int count;
	CORE_ADDR per_cpu_irqs_addr =
	  irqs_addr + (CORE_ADDR) per_cpu_offset[cpu];
	count = read_memory_integer (per_cpu_irqs_addr, 4, LKD_BYTE_ORDER);
	printf_filtered ("\t%10u ", count);
      }

      if (HAS_FIELD (irq_desc, irq_data))
	{
	  chip =
	    extract_typed_address (this_irq_desc +
				   F_OFFSET (irq_desc,
					     irq_data) + F_OFFSET (irq_data,
								   chip),
				   builtin_type
				   (target_gdbarch ())->builtin_data_ptr);
	}
      else
	chip = extract_pointer_field (this_irq_desc, irq_desc, chip);

      cur = find_name (chip, &FIELD_INFO (irq_chip, name));
      printf_filtered ("\t%s", cur->name);

      cur = find_name (this_irq_desc_p, &FIELD_INFO (irq_desc, name));
      printf_filtered ("-%-8s ", cur->name);

      cur = find_name (action, &FIELD_INFO (irqaction, name));
      printf_filtered ("=> %s", cur->name);

      do
	{
	  action = read_pointer_field (action, irqaction, next);
	  if (!action)
	    break;
	  cur = find_name (action, &FIELD_INFO (irqaction, name));
	  printf_filtered (", %s", cur->name);
	}
      while (1);

      printf_filtered ("\n");
    }

  if (HAS_ADDR (ipi_types))
    show_ipi_list ();

  printf_filtered ("Err:\t%lu\n",
		   (unsigned long)
		   read_memory_unsigned_integer (ADDR (irq_err_count), 4,
						 LKD_BYTE_ORDER));
  xfree (irq_descs);
  free_names ();
}
