/*
  Copyright 2005-2013 STMicroelectronics. All rights reserved.

  This file contains the architecture neutral part of the Linux
  Awareness layer for GDB.

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

#include "lkd.h"
#include "lkd-android.h"
#include "lkd-process.h"
#include "lkd-modules.h"

#include "gdb_bfd.h"		/*gdb_bfd_ref */

#define BENEATH linux_aware_ops.beneath

/* This function is normally private to symfile.c, but we export it to
 be able to use it here. */
char *find_separate_debug_file_by_debuglink (struct objfile *objfile);

/* The actual cache that is maintained in the debugger. */
struct depmod_cache
{
  char *filename;
  char *modname;		/* points into filename */
};
static struct depmod_cache *depmod_cache;
static int depmod_cache_length, depmod_cache_capacity;
static time_t depmod_cache_timestamp;

/* The shared library handler that implements knowledge of the kernel
 modules. */
struct target_so_ops lkd_so_ops;

/***************************** Added commands *********************************/

/* 'set module-search-path' is introduced as an alias for 'set
 solib-search-path', this variable contains a pointer to the value
 of that variable. */
static char **module_search_path;
static char *install_mod_path = NULL;
static int install_mod_path_changed = 0;

static void
show_install_mod_path (struct ui_file *file, int from_tty,
                       struct cmd_list_element *c, const char *value);
static void
set_install_mod_path (char *args, int from_tty, struct cmd_list_element *c);

static char *
get_install_mod_path (void);

/* 'set linux-awareness module-init-hook-blacklist' */
static char *module_init_hook_blacklist;
static VEC (char_ptr) *module_init_hook_blacklist_vec;

/*********************** Addresses and Structure descriptions *****************/

/* The Linux Awareness Layer needs to know a lot about the addresses
 and layout of the data structures used in the kernel. This is
 handled through these declaration and the associated macros and
 functions (see linux-awareness.h). */

/* Declaration of the required addresses. */
DECLARE_ADDR (module_finalize);
DECLARE_ADDR (module_arch_cleanup);
DECLARE_ADDR (module_free);
DECLARE_ADDR (module_address_lookup);
DECLARE_ADDR (__symbol_put);
DECLARE_ADDR (modules);

/* Structure fields */
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
 /**/ DECLARE_FIELD (path, dentry);
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

/* The internal breakpoints used to be notified of module liveness
 events. */
struct shlib_event
{
  struct breakpoint *bp;
  int bpno;
};

struct lkd_modules_private
{
  struct shlib_event e_load;
  struct shlib_event e_cleanup;
  struct shlib_event e_free;
} lkd_modules_private;

#define shlib_event_load_bp (lkd_modules_private.e_load.bp)
#define shlib_event_load_no (lkd_modules_private.e_load.bpno)

#define shlib_event_cleanup_bp (lkd_modules_private.e_cleanup.bp)
#define shlib_event_cleanup_no (lkd_modules_private.e_cleanup.bpno)

#define shlib_event_free_bp (lkd_modules_private.e_free.bp)
#define shlib_event_free_no (lkd_modules_private.e_free.bpno)

/* The list of loaded modules. */
struct lm_info_list *lm_infos;
/* A pointer to the last loaded module.
 We previously used the beginning of the lm_info list as the last
 loaded modules, but this breaks if the user does 'info
 sharedlibrary' while in the init function: the list gets re-read in
 a different order. */
struct lm_info *last_loaded;

static const char *fallback_tmpdirs[] = { "/tmp", "/var/tmp", "." };

static const char *tmpdir = NULL;

/* We store in this pointer the address of
 dwarf2read.c:dwarf2_read_symtab that we find in the
 psymtabs. We store it so that we can replace it with our own
 routine and still call it to do the real work. */
void (*dwarf2_psymtab_to_symtab) (struct partial_symtab *pst,
				  struct objfile *objfile);

extern struct symtab *psymtab_to_symtab (struct objfile *objfile,
					 struct partial_symtab *pst);
extern void fixup_psymbol_section (struct partial_symbol *psym,
				   struct objfile *objfile);

/* This key is used to store a reference count associated with GDB
 objfiles. Objfiles are shared between userspace thread of the same
 application, thus we reference count them to know when we can
 discard the information. */
const struct objfile_data *linux_uprocess_objfile_data_key;

static void lm_info_free_list ();
static void lkd_modules_objfile_relocate (struct objfile *objfile,
					  CORE_ADDR init_start,
					  CORE_ADDR init_end,
					  CORE_ADDR core_start,
					  CORE_ADDR core_end);

/***************** End Local functions forward declarations *******************/

/* This function reads the layout of a module's section in memory from
 the ELF headers that have been copied into the kernel at module
 load time. The information is read into INFO from the ELF header
 located at HDR and the section headers located at SECHDRS.

 This function is not called in the normal codepath for a module
 load. Reading this information from the kernel memory is
 costly. This function is called only when the layout algorithm from
 the debugger produces incompatible results with what has been read
 from the kernel. This can happen if the user strips its modules and
 loads the stripped version while pointing the debugger at the
 unstripped version: this changes sections sizes and thus the final
 layout.

 Moreover, the required information is only available before the
 module code runs. The ELF headers get freed by the kernel as they
 are useless for the runtime. As a consequence, this can only be
 done if we intercepted the module load. Later the information isn't
 available anymore.

 Anyway, stripping modules should be discouraged and users should be
 pointed at using separate debug files instead.
 */
static void
get_module_section_layout (struct lm_info *info,
			   CORE_ADDR hdr, CORE_ADDR sechdrs)
{
  /* This function could cause troubles since Kernel 2.6.32
     cause of the way th layout of the section is done.
     see : Layout_symtab into kernel/module.c to more information */
  unsigned int i;
  unsigned int shnum;
  unsigned int stridx;
  unsigned int sec_size;
  CORE_ADDR sechdr;
  CORE_ADDR strtab = 0;
  CORE_ADDR strsize = 0;
  struct field_info *sec_field = &FIELD_INFO (Elf32_Shdr, sh_addr);

  if (sec_field->type == NULL)
    linux_init_field (sec_field, 0);

  sec_size = TYPE_LENGTH (check_typedef (SYMBOL_TYPE (sec_field->type)));
  shnum = read_unsigned_field (hdr, Elf32_Ehdr, e_shnum);
  info->shnum = shnum;
  info->sections = xcalloc (sizeof (info->sections[0]), shnum);

  stridx = read_unsigned_field (hdr, Elf32_Ehdr, e_shstrndx);
  strtab = read_unsigned_field (sechdrs + stridx * sec_size,
				Elf32_Shdr, sh_addr);
  sechdr = sechdrs;
  for (i = 0; i < shnum; ++i, sechdr += sec_size)
    {
      unsigned int type = read_unsigned_field (sechdr, Elf32_Shdr, sh_type);
      unsigned int flags;

      if (type == SHT_SYMTAB || type == SHT_STRTAB)
	continue;		// Do nothing

      flags = read_unsigned_field (sechdr, Elf32_Shdr, sh_flags);
      if (flags & SHF_ALLOC)
	{
	  info->sections[i].nameidx = read_unsigned_field (sechdr,
							   Elf32_Shdr,
							   sh_name);
	  info->sections[i].addr = read_unsigned_field (sechdr,
							Elf32_Shdr, sh_addr);
	}
    }

  for (i = 0; i < shnum; ++i)
    {
      if (info->sections[i].addr == 0)
	continue;

      info->sections[i].name = xmalloc (32);
      read_memory (strtab + info->sections[i].nameidx,
		      (gdb_byte *) info->sections[i].name, 32);
    }
}

/*****************************************************************************/
/*               Copied and adapted from kernel/module.c                     */

/* Sections are aligned, thus we need to round up during size
 computation. Update SIZE with this SECHDR and return offset. */
static long
get_offset (unsigned long *size, Elf_Internal_Shdr * sechdr)
{
  long ret;

#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

  ret = ALIGN (*size, sechdr->sh_addralign ? : 1);
  *size = ret + sechdr->sh_size;
  return ret;
}

/* This isn't true for ia64 and alpha. But we don't care... */
#define ARCH_SHF_SMALL 0

#define BITS_PER_LONG 32
#define INIT_OFFSET_MASK (1UL << (BITS_PER_LONG-1))

/* We reproduce the layout algorithm used by the kernel for the
 module sections.  If we find that our sizes differ from the one
 stored within the kernel memory, we try to read the layout from
 there.  This is usefull if you point your debugger to a module
 with debug info, but you load the same module with the debug info
 stripped (stripping the debug info will reduce the size of loaded
 sections like .strtab).  We don't systematically load the layout
 from memory as it's simply too slow. */
static void
layout_sections (bfd * file, struct lm_info *lm_info)
{
  static unsigned long const masks[][2] = {
    /* NOTE: all executable code must be the first section
     * in this array; otherwise modify the text_size
     * finder in the two loops below */
    {SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL},
    {SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL},
    {SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL},
    {ARCH_SHF_SMALL | SHF_ALLOC, 0}
  };
  Elf_Internal_Shdr *symsect = NULL;
  Elf_Internal_Shdr *strsect = NULL;
  unsigned int symindex = 0;
  unsigned int strindex = 0;
  unsigned int room_str = 0;
  unsigned int room_sym = 0;
  size_t symbols_count = 0;
  Elf_Internal_Sym *ret_sym;
  const char *name;

  unsigned int i, m, j;
  unsigned long core_size = 0;
  unsigned long init_size = 0;
  unsigned long base = lm_info->module_init;
  unsigned int sec_count = file->section_count;
  asection *bfd_sec;
  Elf_Internal_Shdr **sechdrs = elf_elfsections (file);
  Elf_Internal_Ehdr *hdr = elf_elfheader (file);

  unsigned long *offsets = alloca (hdr->e_shnum * sizeof (unsigned long));
  memset (offsets, 0xFF, hdr->e_shnum * sizeof (unsigned long));

  /* Is this kosher ? Maybe we should copy the flags in a local
     array before we modify these. */
  for (i = 0; i < hdr->e_shnum; ++i)
    {
      Elf_Internal_Shdr *s = sechdrs[i];
      int ix = elf_elfheader (file)->e_shstrndx;
      char *name = bfd_elf_string_from_elf_section (file, ix, s->sh_name);

      /* HAS_ADDR(module_address_lookup) tests if CONFIG_KALLSYMS is
         defined. */
      if (!strcmp (name, ".modinfo") || !strcmp (name, "__versions"))
	s->sh_flags &= ~SHF_ALLOC;
      else if (!strcmp (name, ".symtab") && HAS_ADDR (module_address_lookup))
	s->sh_flags |= SHF_ALLOC;
      else if (!strcmp (name, ".strtab") && HAS_ADDR (module_address_lookup))
	s->sh_flags |= SHF_ALLOC;
      /*CONFIG_MODULE_UNLOAD */
      else if ((strncmp (name, ".exit", 5) == 0) && !HAS_ADDR (__symbol_put))
	s->sh_flags &= ~SHF_ALLOC;

    }

  DEBUG (MODULE, 4, "Core section allocation\n");
  for (m = 0; m < ARRAY_SIZE (masks); ++m)
    {
      for (i = 0; i < hdr->e_shnum; ++i)
	{
	  Elf_Internal_Shdr *s = sechdrs[i];
	  int ix = elf_elfheader (file)->e_shstrndx;
	  char *name = bfd_elf_string_from_elf_section (file, ix,
							s->sh_name);

	  if ((s->sh_flags & masks[m][0]) != masks[m][0]
	      || (s->sh_flags & masks[m][1])
	      || offsets[i] != ~0UL || strncmp (name, ".init", 5) == 0)
	    continue;

	  if (strncmp (name, ".symtab", 7) == 0)
		{
		  symsect = s;
		  symindex = i;
		  continue;
		}
	  else if (strncmp (name, ".strtab", 7) == 0)
		{
		  strsect = s;
		  strindex = i;
		  continue;
		}

	  offsets[i] = get_offset (&core_size, s) + lm_info->module_core;

	  /* give a better chance to be happy with this module
	   * if at least the core text size and the init text size are OK,
	   * config switches like CONFIG_KALLSYMS_ALL are not easy
	   * to test from within LKD.
	   * */
	  if (m == 0)
	    lm_info->computed_core_text_size = core_size;

	  DEBUG (MODULE, 4, "\t%s %lx\n", name, core_size);
	}
    }

  if (base == 0)
    {
      /* This happens when we read module debug information after
         the init is finished (eg. after attaching). We need a base
         for the init code and data. Take the beginning of the next
         page, this will be erased from the debuginfo anyway.

         Avoid using just the end of the module_core part to avoid a
         BFD warning when there's an empty bss section at the end of
         module_core. When this happens, this section will overlap
         with the first of module_init if we don't round up to the
         next page.
       */
      base = (lm_info->module_core + core_size + 4096) & ~0xFFF;
    }

  DEBUG (MODULE, 4, "Init section allocation\n");
  for (m = 0; m < ARRAY_SIZE (masks); ++m)
    {
      for (i = 0; i < hdr->e_shnum; ++i)
	{
	  Elf_Internal_Shdr *s = sechdrs[i];
	  int ix = elf_elfheader (file)->e_shstrndx;
	  char *name = bfd_elf_string_from_elf_section (file, ix,
							s->sh_name);
	  if ((s->sh_flags & masks[m][0]) != masks[m][0]
	      || (s->sh_flags & masks[m][1])
	      || offsets[i] != ~0UL || strncmp (name, ".init", 5) != 0)
	    continue;

	  offsets[i] = get_offset (&init_size, s) + base;
	  DEBUG (MODULE, 4, "\t%s %lx\n", name, init_size);
	}
    }

  lm_info->computed_init_text_size = init_size;

  if (init_size && !lm_info->module_init)
    lm_info->module_init = base;

  if ((lm_info->computed_core_text_size != lm_info->core_text_size)
       || (lm_info->init_text_size /* The init section may be gone by now.  */
	   && (lm_info->computed_init_text_size != lm_info->init_text_size)))
    {

      CORE_ADDR current_pc;

      printf_filtered ("The module loaded by the kernel does not have the same text sections as the\n"
		       "module the debugger has opened. Reading the section layout from kernel memory\n"
		       "(core text size: calc %s / peeked %s)\n"
		       "(init text size: calc %s / peeked %s)\n",
		       phex (lm_info->computed_core_text_size, 4),
		       phex (lm_info->core_text_size, 4),
		       phex (lm_info->computed_init_text_size, 4),
		       phex (lm_info->init_text_size, 4));

      /* Something went wrong. The size of the section layout we
         produced is different from the one stored in the kernel
         data structures... */
      current_pc = regcache_read_pc (get_current_regcache ());

      if (shlib_event_load_bp != NULL
	  && current_pc == shlib_event_load_bp->loc->address
	  && last_loaded == lm_info)
	{
	  CORE_ADDR elf_hdr, elf_sechdrs;

	  elf_hdr = linux_awareness_ops->lo_first_pointer_arg_value ();
	  elf_sechdrs = linux_awareness_ops->lo_second_pointer_arg_value ();

	  get_module_section_layout (lm_info, elf_hdr, elf_sechdrs);
	}
      else
	{
	  warning ("The debugger has to be active at module load time to handle such cases.");
	}
    }
  else
    {
      lm_info->shnum = hdr->e_shnum;
      lm_info->sections =
	xcalloc (sizeof (lm_info->sections[0]), hdr->e_shnum);

      for (i = 0; i < hdr->e_shnum; ++i)
	{
	  Elf_Internal_Shdr *s = sechdrs[i];
	  int ix = elf_elfheader (file)->e_shstrndx;
	  char *name = bfd_elf_string_from_elf_section (file, ix,
							s->sh_name);
	  if (offsets[i] != ~0UL)
	    {
	      lm_info->sections[i].addr = offsets[i];
	      lm_info->sections[i].name = savestring (name, strlen (name));
	    }
	}
    }

  DEBUG (MODULE, 4, "Final fixes:\n");
  for (i = 0; i < hdr->e_shnum; ++i)
    {
      Elf_Internal_Shdr *s = sechdrs[i];
      int ix = elf_elfheader (file)->e_shstrndx;
      char *name = bfd_elf_string_from_elf_section (file, ix, s->sh_name);
      asection *sect = bfd_get_section_by_name (file, name);

      if (sect == NULL || offsets[i] == ~0UL)
	continue;

      if ((shlib_event_load_bp != NULL)
	  && (strncmp (sect->name, ".init.", 6) == 0
	      || strncmp (sect->name, ".exit.", 6) == 0))
	/* If we have sections that might get discarded, we need
	   to use the intermediate reloacted file. */
	lm_info->needs_relocated_file = 1;
    }
}

/****************************************************************************/

/* Helper returning the address of a named section for the given
 module. Returns 0 if the section isn't found. */
static CORE_ADDR
get_module_section_addr (struct lm_info *info, const char *name)
{
  unsigned int i;

  for (i = 0; i < info->shnum; ++i)
    {
      if (info->sections[i].name != NULL
	  && strcmp (name, info->sections[i].name) == 0)
	return info->sections[i].addr;
    }

  return 0;
}

/* Helper for the creation of the 'linked' module file. This function
 is called through bfd_map_over_sections () to set the relocated
 section addresses for the sections in the real module file. */
static void
set_section_offsets (bfd * abfd, asection * sectp, void *dummy)
{
  struct lm_info *info = (struct lm_info *) dummy;
  CORE_ADDR addr, base;

  addr = get_module_section_addr (info, bfd_get_section_name (abfd, sectp));

  if (addr != 0)
    {
      /*  We want the file we create to be totally relocated with a
         base address of 0. Find the lowest section which will be
         one of init or core and substract it here. This way the
         module file we create looks like a real shared library to
         GDB, which just has to offset all the debug information by
         this base address. */
      base = info->module_core;

      if (info->module_init && info->module_init < base)
	base = info->module_init;
      bfd_set_section_vma (abfd, sectp, addr - base);

      DEBUG (MODULE, 4, "Setting vma of %s to %s (%s)\n",
	     bfd_get_section_name (abfd, sectp),
	     phex (addr, 4), phex (addr - base, 4));
    }
}

/* Helper for the creation of the 'linked' module file. This function
 is called through bfd_map_over_sections (). It iterates over the
 sections of the module file and creates the corresponding sections
 in the 'linked' module file we want to create. */
static void
create_sections (bfd * abfd, asection * sectp, void *i)
{
  struct module_bfd_copy_info *info = (struct module_bfd_copy_info *) i;
  asection *sec;
  flagword flags = bfd_get_section_flags (abfd, sectp);

  /* Only create useful sections. All other sections might cause
     warning by the BFD because of inconsistent flags/addresses,
     thus we simply don't create these. */
  if (!(flags & (SEC_ALLOC | SEC_DEBUGGING))
      || !strcmp (bfd_get_section_name (abfd, sectp), ".modinfo")
      || !strcmp (bfd_get_section_name (abfd, sectp), "__versions")
	  /* RnDCT00012666: Remove that ugly warning, seems OK
	   * with c++ kernel modules...*/
	  || !strncmp (bfd_get_section_name (abfd, sectp),".ARM.exidx", 10)
	)
    return;

  /* Make sure the section at 0 gets the SEC_LOAD flag, otherwise
     the symbol at 0 will get discarded by the dwarf reader. This is
     normally the case as this section is .text or .init.text, but
     with separate debuginfo files, these sections are marked NOBITS
     and thus not loadable. As the generated binary file won't get
     loaded anyway, there's no harm in forcing that flag here. */
  if (!(flags & SEC_DEBUGGING) && bfd_get_section_vma (abfd, sectp) == 0)
    flags |= SEC_LOAD;

  DEBUG (MODULE, 4, "Adding section %s to new file at %s.\n",
	 bfd_get_section_name (abfd, sectp),
	 phex (bfd_get_section_vma (abfd, sectp), 4));
  sec = bfd_make_section (info->new, bfd_get_section_name (abfd, sectp));
  /* We'll get rid of relocations. */
  bfd_set_section_flags (info->new, sec, flags & ~SEC_RELOC);
  bfd_set_section_vma (info->new, sec, bfd_get_section_vma (abfd, sectp));
  bfd_set_section_alignment (info->new, sec,
			     bfd_get_section_alignment (abfd, sectp));
  bfd_set_section_size (info->new, sec, bfd_section_size (abfd, sectp));

  info->sec_mapping[sectp->index] = sec;
}

/* Helper for the creation of the 'linked' module file. Create the
 symbol table for the 'linked' module file by iterating and
 modifying the symbols of the real mofule file. */
static void
create_symbols (struct module_bfd_copy_info *info)
{
  long storage_needed;
  asymbol **symbol_table;
  asymbol **new_symbol_table, *new_sym;
  int cur_new_sym = 0;
  long number_of_symbols;
  long i;

  /* Create the new symtab. This is standard BFD code copied from
     elsewhere... */
  storage_needed = bfd_get_symtab_upper_bound (info->old);
  if (storage_needed < 0)
    error ("Error reading old symtab.");

  if (storage_needed == 0)
    return;

  symbol_table = xmalloc (storage_needed);
  new_symbol_table = xmalloc (storage_needed);
  memset (new_symbol_table, 0, storage_needed);

  number_of_symbols = bfd_canonicalize_symtab (info->old, symbol_table);
  if (number_of_symbols < 0)
    error ("Error reading old symbols.");

  /* Iterate the old symtab. */
  for (i = 0; i < number_of_symbols; i++)
    {
      asymbol *sym = symbol_table[i];

      /* The section symbols will get recreated by the BFD. */
      if (sym->flags & BSF_SECTION_SYM)
	continue;

      /* Skip names that don't exist (shouldn't happen), or names
         that are null strings (may happen). */
      if (sym->name == NULL || *sym->name == '\0')
	continue;

      if (sym->section == bfd_und_section_ptr)
	continue;

      if (info->sec_mapping[sym->section->index] == 0)
	{
	  DEBUG (MODULE, 6,
		 "Ignoring symbol %s because of missing section.\n",
		 bfd_asymbol_name (sym));
	  continue;
	}

      new_sym = bfd_make_empty_symbol (info->new);
      new_symbol_table[cur_new_sym] = new_sym;
      new_sym->name = bfd_asymbol_name (sym);
      new_sym->section = info->sec_mapping[sym->section->index];
      new_sym->flags = sym->flags;

      /* The symbols already got their value offset by the section
         load address when we applied set_section_offsets on
         info->old. We will recreate a file were the sections will
         have the same load offsets, but we don't want this offset
         to be added twice. Thus we substract it here. */
      new_sym->value = bfd_asymbol_value (sym)
	- bfd_get_section_vma (info->new, new_sym->section);

      DEBUG (MODULE, 6, "Adding sym %s to new file with value 0x%s\n",
	     new_symbol_table[cur_new_sym]->name,
	     phex (new_symbol_table[cur_new_sym]->value, 4));

      ++cur_new_sym;
    }

  /* Register the new symtab in the new BFD. */
  bfd_set_symtab (info->new, new_symbol_table, cur_new_sym);
  xfree (symbol_table);
}

/* Helper for the creation of the 'linked' module file. This function
 is called through bfd_map_over_sections (). It iterates over the
 sections of the old BFD and creates the corresponding fully
 relocated section in the new file. */
static void
set_section_contents (bfd * abfd, asection * sectp, void *i)
{
  bfd_byte *buf;
  struct cleanup *clean;
  struct module_bfd_copy_info *info = (struct module_bfd_copy_info *) i;

  if (info->sec_mapping[sectp->index] == 0)
    return;

  if (!(bfd_get_section_flags (abfd, sectp) & SEC_HAS_CONTENTS))
    return;

  if (!(bfd_get_section_flags (abfd, sectp) & SEC_RELOC)
      || !(bfd_get_section_flags (abfd, sectp) & SEC_DEBUGGING))
    {

      /* Simply copy over section contents that don't need a relocation. */
      bfd_byte *buf = xmalloc (bfd_get_section_size (sectp));
      struct cleanup *clean = make_cleanup (xfree, buf);
      if (!bfd_get_section_contents (abfd, sectp,
				     buf, 0, bfd_get_section_size (sectp)))
	error ("Can't read non-relocated section contents.");

      if (!bfd_set_section_contents (info->new,
				     info->sec_mapping[sectp->index],
				     buf, 0, bfd_get_section_size (sectp)))
	error ("Can't set section contents: %s.",
	       bfd_errmsg (bfd_get_error ()));

      do_cleanups (clean);
      return;
    }

  /* Apply the relocations. */
  DEBUG (MODULE, 4, "Relocating %s\n", bfd_get_section_name (abfd, sectp));

  buf = xmalloc (bfd_get_section_size (sectp));
  clean = make_cleanup (xfree, buf);

  if (bfd_simple_get_relocated_section_contents (abfd, sectp,
						 buf, NULL) == NULL)
    error ("Can't relocate section contents.");

  if (!bfd_set_section_contents (info->new,
				 info->sec_mapping[sectp->index],
				 buf, 0, bfd_get_section_size (sectp)))
    error ("Can't relocate section contents.");

  do_cleanups (clean);
}

/* This is the function that will create a 'linked' (ie. fully
 relocated) module file from the real module file that got
 loaded. ABFD points to the bfd for the read file, LM_INFO gives the
 information regarding the module's load addresses and the path to
 the newly created file will be stored in TEMP_PATHNAME. The
 function returns an open BFD to the new file. */
static bfd *
make_temporary_bfd (bfd * abfd, struct lm_info *lm_info, char **temp_pathname)
{
  struct module_bfd_copy_info info;
  bfd *newbfd;
  char *tmpname;
  char *filename;
  int fd = -1, len;

  /* Generate a random filename for the 'linked' module. */
  tmpname = xstrprintf ("gdb-module-%s-XXXXXX", lm_info->module_name);
  filename = xstrprintf ("%s/%s", tmpdir, tmpname);
  len = strlen (filename);

  if (len >= SO_NAME_MAX_PATH_SIZE)
    warning ("Can't create temporary file in '%s': "
	     "dirname too long.", tmpdir);
  else
    fd = mkstemp (filename);

  /* Try alternate locations for the temporary file. */
  if (fd == -1)
    {
      unsigned int i;
      for (i = 0; fd == -1 && i < ARRAY_SIZE (fallback_tmpdirs); ++i)
	{
	  xfree (filename);
	  filename = xstrprintf ("%s/%s", fallback_tmpdirs[i], tmpname);
	  len = strlen (filename);
	  if (len >= SO_NAME_MAX_PATH_SIZE)
	    warning ("Can't create temporary file in '%s': "
		     "dirname too long.", tmpdir);
	  else
	    fd = mkstemp (filename);
	}
      if (fd == -1)
	{
	  xfree (tmpname);
	  xfree (filename);
	  return NULL;
	}
    }

  close (fd);
  *temp_pathname = xstrdup (filename);
  /* Open the new BFD for writing. */
  /* Serge CHATROUX: RnDCT00013980 Use gdb_bfd_openX functions instead of bfd_openX functions. */
  newbfd = gdb_bfd_openw (xstrdup (filename), bfd_get_target (abfd));

  if (!newbfd)
    {
      error ("Can't open newbfd.");
    }

  bfd_set_format (newbfd, bfd_object);
  bfd_set_arch_mach (newbfd, bfd_get_arch (abfd), bfd_get_mach (abfd));

  /* Make the generated file a shred object, so that GDB doesn't try
     to randomly layout the relocatable sections. */
  if (!bfd_set_file_flags (newbfd, bfd_get_file_flags (newbfd) | DYNAMIC))
    warning ("Could not set temporary file flags to DYNAMIC.");

  /* The 'info' struct contains pointers to all the information
     needed in the relocation process. This struct is used to pass
     the paramters to the bfd_map_over_sections() callbacks. */
  info.old = abfd;
  info.new = newbfd;
  info.lm_info = lm_info;
  info.sec_mapping = xmalloc (sizeof (asection *)
			      * bfd_count_sections (info.old));
  memset (info.sec_mapping, 0,
	  sizeof (asection *) * bfd_count_sections (info.old));

  /* Set the final section offsets in the *old* file. We do that on
     the old file so that bfd_simple_get_relocated_section_contents()
     that we call in set_section_contents() can do its job. */
  bfd_map_over_sections (info.old, set_section_offsets, lm_info);
  /* Create the sections in the new BFD. */
  bfd_map_over_sections (info.old, create_sections, &info);
  /* Create the symbols for the new BFD. */
  create_symbols (&info);

  /* Create a PT_LOAD segment in the output file so that the BFD
     doesn't complain when writing the results to the disk. */
  {
    struct elf_segment_map *m;
    unsigned int i, j;
    asection *hdrpp;
    bfd_size_type amt;

    int cmp_sections (const void *s1, const void *s2)
    {
      asection **sec1 = (asection **) s1;
      asection **sec2 = (asection **) s2;
      return bfd_get_section_vma (abfd, *sec1)
	- bfd_get_section_vma (abfd, *sec2);
    }

    amt = sizeof (struct elf_segment_map);
    amt += (bfd_count_sections (info.new)) * sizeof (asection *);
    m = bfd_zalloc (info.new, amt);
    gdb_assert (m != NULL);
    m->next = NULL;
    m->p_type = PT_LOAD;
    for (i = 0, j = 0, hdrpp = info.new->sections;
	 i < bfd_count_sections (info.new); i++, hdrpp = hdrpp->next)
      if (bfd_get_section_flags (info.new, hdrpp) & SEC_ALLOC)
	m->sections[j++] = hdrpp;
    m->count = j;

    qsort (m->sections, m->count = j, sizeof (m->sections[0]), cmp_sections);

    elf_seg_map (info.new) = m;
  }

  /* Generate the relocated section contents for the new file. */
  bfd_map_over_sections (info.old, set_section_contents, &info);

  xfree (info.sec_mapping);
  xfree (tmpname);
  xfree (filename);

  return info.new;
}

/* Frees the data structures containing the depmod cache (see
 build_depmod_cache()). */
static void
free_depmod_cache (void)
{
  int i;

  for (i = 0; i < depmod_cache_length; ++i)
    xfree (depmod_cache[i].filename);

  xfree (depmod_cache);
  depmod_cache_length = depmod_cache_capacity = 0;
  depmod_cache = NULL;
}

/* Grows the depmod cache (see build_depmod_cache()). */
static void
grow_depmod_cache (void)
{
  if (depmod_cache == NULL)
    {
      depmod_cache = xmalloc (64 * sizeof (struct depmod_cache));
      depmod_cache_capacity = 64;
      return;
    }

  depmod_cache_capacity *= 2;
  depmod_cache = xrealloc (depmod_cache,
			   depmod_cache_capacity *
			   sizeof (struct depmod_cache));
  if (depmod_cache == NULL)
    error ("grow_depmod_cache (): your system ran out of memory.");
}

static void
build_depmod_cache (void)
{
  struct stat depmod_stat;
  char depmod_file[PATH_MAX];
  FILE *file;
  size_t n;
  struct depmod_cache *cache;
  char *ptr;

  xsnprintf (depmod_file, PATH_MAX, "%s/lib/modules/%s/modules.dep",
	     get_install_mod_path (), lkd_private.utsname_release);

  DEBUG (MODULE, 5, "build_depmod_cache: %s.\n", depmod_file);

  if (stat (depmod_file, &depmod_stat) < 0)
    {
      printf_filtered ("Could not stat %s.\n", depmod_file);
      return;
    }

  /* exit if not newer than cache. */
  if (depmod_stat.st_mtime == depmod_cache_timestamp)
    return;

  file = fopen (depmod_file, "r");
  if (file == NULL)
    {
      printf_filtered ("Failed to open %s\n", depmod_file);
      return;
    }
  do
    {
      char *file_or_modname = NULL;

      if (depmod_cache_length >= depmod_cache_capacity)
	grow_depmod_cache ();

      cache = depmod_cache + depmod_cache_length;
      if (getline (&file_or_modname, &n, file) < 0)
	break;

      /* The format of a modules.dep line is :
         <module file>: <list of modules dependencies>
       */
      ptr = strchr (file_or_modname, ':');
      if (ptr == NULL)
	continue;

      /* Replace ':' by an end of string marker. */
      *ptr = '\0';

      cache->filename = xmalloc (PATH_MAX);

      if (strstr (file_or_modname, lkd_private.utsname_release))
	{
	  /* full path modname */
	  xsnprintf (cache->filename, PATH_MAX, "%s", file_or_modname);
	}
      else
	{
	  /* relative path modname */
	  xsnprintf (cache->filename, PATH_MAX,
		     "/lib/modules/%s/%s",
		     lkd_private.utsname_release, file_or_modname);
	}
      xfree (file_or_modname);

      /* Look for the basename of the module. */
      cache->modname = cache->filename + strlen (cache->filename);
      while (*(cache->modname - 1) != '/'
	     && (cache->modname - 1) != cache->filename)
	--cache->modname;

      DEBUG (MODULE, 5,
	     "depmod_cache adding entry :\n\tmodname %s,\n\tfilename=%s.\n",
	     cache->modname, cache->filename);

      ++depmod_cache_length;

    }
  while (1);

  depmod_cache_timestamp = depmod_stat.st_mtime;

  DEBUG (MODULE, 5, "depmod_cache_length = %d.\n", depmod_cache_length);
}

/* Lookup module filename STRING in the depmod index (see
 build_depmod_cache()). Returns a file descriptor for the opened
 module file or -1 if not found. */
static int
lookup_module_dep (const char *string, int mode, char **opened)
{
  int i;
  const char *found = NULL;
  build_depmod_cache ();

  for (i = 0; i < depmod_cache_length; ++i)
    {
      if (strcmp (string, depmod_cache[i].modname))
	continue;
      /* skip initial '/' in filename */
      found = depmod_cache[i].filename + 1;
      break;
    }

  if (found == NULL)
    {
      DEBUG (MODULE, 1,
	     "lookup_module_dep: module %s not found in cache.\n", string);
      return -1;
    }

  i = openp (get_install_mod_path (), 0, found, mode, opened);

  DEBUG (MODULE, 1, "lookup_module_dep: openp %s/%s returned %d.\n",
	 get_install_mod_path (), found, i);

  return i;
}

/* Tries to find the module named in STRING in
 PATH. Returns a filedescriptor to the opened module file or -1 if
 the module wasn't found.
 This helped acts like GDB's openp function with the exception that
 it tries to look at the depmod cache if the module isn't found in
 PATH. */
static int
module_openp (const char *path, int opts, const char *string,
	      int mode, char **filename_opened)
{
  /* First try in module_search_path */
  if (path && strlen (path))
    {
      int res = openp (path, opts, string, mode, filename_opened);
      if (res >= 0)
	{
	  DEBUG (MODULE, 1, "using module_search_path %s found.\n", string);
	  return res;
	}
    }
  /* Now look for modules.dep */
  if (lkd_private.utsname_release != NULL
	   && *(get_install_mod_path ()) != '\0')
    {
      DEBUG (MODULE, 1, "module_openp: trying modules.dep.\n");
      return lookup_module_dep (string, mode, filename_opened);
    }

  DEBUG (MODULE, 1, "module_openp:  uts_name = %s.\n",
	 lkd_private.utsname_release);
  DEBUG (MODULE, 1, "module_openp:  install-mod-path= %s.\n",
	 get_install_mod_path ());
  DEBUG (MODULE, 1, "module_openp:  target_root_prefix= %s.\n",
	 gdb_sysroot);
  DEBUG (MODULE, 1, "module_openp:  module_search_path= %s.\n",
	 *module_search_path);
  return -1;
}

/* Implements the walking of the decision tree
 representing all the possible names for the module names
 FILENAME. (This is necessary because a that the kernel represents
 as 'module_name' might stem from a file name 'module_name.ko',
 'module-name.ko' or 'module,name.ko'. */
static int
try_to_open_alternate_names (char *file, char **temp_pathname)
{
  int *tree;
  int nb_chars, allocated_chars;
  int level = 0;
  char *filename;

  void add_char (int pos)
  {

    if (nb_chars == allocated_chars)
      {
	allocated_chars *= 2;
	tree = xrealloc (tree, sizeof (int) * allocated_chars);
      }

    tree[nb_chars] = pos;
    filename[pos] = '\0';
    ++nb_chars;
  }

  void gather_chars (void)
  {
    char *c = filename;

    while (*c)
      {
	if (*c == '_')
	  add_char (c - filename);
	++c;
      }
  }

  filename = alloca (strlen (file) + 1);
  strcpy (filename, file);
  allocated_chars = 4;
  tree = xmalloc (sizeof (int) * 4);
  nb_chars = 0;

  gather_chars ();

  if (!nb_chars)
    {
      xfree (tree);
      return module_openp (*module_search_path, OPF_TRY_CWD_FIRST,
			   filename, O_RDONLY, temp_pathname);
    }

  while (level >= 0)
    {
      switch (filename[tree[level]])
	{
	case 0:
	  filename[tree[level]] = '_';
	  ++level;
	  break;
	case '_':
	  filename[tree[level]] = '-';
	  ++level;
	  break;
	case '-':
	  filename[tree[level]] = ',';
	  ++level;
	  break;
	case ',':
	  filename[tree[level]] = 0;
	  --level;
	  break;
	}

      if (level == nb_chars)
	{
	  int res = module_openp (*module_search_path, OPF_TRY_CWD_FIRST,
				  filename, O_RDONLY, temp_pathname);
	  if (res >= 0)
	    {
	      xfree (tree);
	      return res;
	    }
	  --level;
	}
    }

  xfree (tree);
  return -1;
}

/*****************************************************************
 * 		Linked Modules list management
 *****************************************************************/

/* Returns the structure describing the module corresponding to the
   passed name. Returns NULL if not found. */
static struct lm_info *
lm_info_find_by_name (const char *name, struct lm_info_list *list)
{
  while (list != NULL)
    {
      if (!strcmp (name, list->info->module_name))
	break;
      list = list->next;
    }

  return list ? list->info : NULL;
}

/* Returns the structure describing the module corresponding to the
   passed address. Returns NULL if not found. */
static struct lm_info *
lm_info_find_by_addr (CORE_ADDR this_module, struct lm_info_list *list)
{
  while (list != NULL)
    {
      if (list->info->this_module == this_module)
	break;
      list = list->next;
    }

  return list ? list->info : NULL;
}

/* Frees the memory associated with the given module. */
static void
lm_info_free (struct lm_info *info)
{
  unsigned int i;

  for (i = 0; i < info->shnum; ++i)
    xfree (info->sections[i].name);
  xfree (info->sections);

  if (info->relocated_file != NULL)
    unlink (info->relocated_file);
  /* No need to free info->relocated_file, the BFD structure will point to
     it, and it'll be freed by the solib framework. */
  xfree (info->real_file);

  if (info->mod)
    info->mod->lm_info = NULL;

  xfree (info);

  if (last_loaded == info)
    last_loaded = NULL;
}

/* Removes the information associated with the module described in the
 kernel by the THIS_MODULE pointer from our internal bookkeeping. */
static void
lm_info_remove (struct lm_info *info, int notif)
{
  struct bp_location *loc, **locp_tmp;
  struct lm_info_list *list = lm_infos, *prev = NULL;

  while (list)
    {
      if (list->info == info)
	break;

      prev = list;
      list = list->next;
    }

  if (list == NULL)
    return;

  DEBUG (MODULE, 3,
	 "Really deleting module '%s'.\n", list->info->module_name);
  if (notif)
    printf_filtered ("[Unloading module '%s']\n", list->info->module_name);

  /* This function runs when a module is unloaded. GDB will warn if
     there are breakpoints in that module, but it won't remove the
     breakpoint from memory. This causes issues with 'smart' debug
     agent like the STMC2 that remember what breakpoints have been
     inserted and not removed. Thus we need to call
     target_remove_breakpoint () ourselves.

     See disable_breakpoints_in_unloaded_shlib() for reference.  */

  ALL_BP_LOCATIONS (loc, locp_tmp)
    {
      struct breakpoint *b = loc->owner;

      if (current_program_space == loc->pspace
	  && !loc->shlib_disabled
	  && (((b->type == bp_breakpoint
	        || b->type == bp_jit_event
	        || b->type == bp_hardware_breakpoint)
	       && (loc->loc_type == bp_loc_hardware_breakpoint
		   || loc->loc_type == bp_loc_software_breakpoint)))
	  && loc->address >= list->info->module_core
	  && loc->address < list->info->module_core + list->info->core_size)
	{
	  target_remove_breakpoint (target_gdbarch (), &loc->target_info);
	}
    }

  if (prev != NULL)
    prev->next = list->next;
  else
    lm_infos = list->next;

  if (last_loaded == list->info)
    last_loaded = NULL;

  lm_info_free (list->info);
  xfree (list);
}

/* Is the given INFO in our list of loaded modules ? */
static int
lm_info_exists (struct lm_info *info)
{
  struct lm_info_list *list = lm_infos;

  while (list)
    {
      if (info == list->info)
	break;
      list = list->next;
    }
  return list != NULL;
}

/* Deletes all the temporary 'linked' modules we generated. */
static void
lm_info_free_list (void)
{
  struct lm_info_list *list = lm_infos, *next;

  while (list != NULL)
    {
      next = list->next;
      lm_info_free (list->info);
      xfree (list);
      list = next;
    }

  lm_infos = NULL;
}

/* Reads the information that the kernel stored into the
 'struct module' at address ADDR and fills a 'struct lm_info' with
 that information. The new lm_info is inserted at the start of the
 passed LIST. */
static void
lm_info_add_from_struct_module (CORE_ADDR addr, struct lm_info_list **list)
{
  char *original_name;
  struct lm_info *info;
  struct lm_info_list *elt;

  gdb_byte *buf = malloc (F_OFFSET (module, args));

  /* do only one bulk read assuming the module kernel structure does not change
   * every now and then, which is the case.
   **/
  read_memory (addr, buf, F_OFFSET (module, args));

  original_name = (char*)buf + F_OFFSET (module, name);

  DEBUG (MODULE, 3, "Adding module '%s'.\n", original_name);
  info = lm_info_find_by_name (original_name, *list);

  if (info == NULL)
    {
      DEBUG (MODULE, 3, "Allocation new lm_info for '%s'\n", original_name);

      info = XCNEW (struct lm_info);

      gdb_assert (TYPE_LENGTH
		  (lkd_private.target_pointer_type) ==
		  sizeof (uint32_t *));

      strcpy (info->module_name, original_name);
      info->this_module = addr;
      info->init = extract_pointer_field (buf, module, init);
      info->module_init = extract_pointer_field (buf, module, module_init);
      info->module_core = extract_pointer_field (buf, module, module_core);
      info->init_size = extract_unsigned_field (buf, module, init_size)
	& 0x00ffffff;
      info->core_size = extract_unsigned_field (buf, module, core_size)
	& 0x00ffffff;
      info->init_text_size =
	extract_unsigned_field (buf, module, init_text_size) & 0x00ffffff;
      info->core_text_size =
	extract_unsigned_field (buf, module, core_text_size) & 0x00ffffff;
    }
  else
    return;

  elt = xmalloc (sizeof (struct lm_info_list));
  elt->info = info;
  elt->next = *list;
  *list = elt;

  free (buf);
}

/* Takes our internal list of modules (lm_infos) and
 generates a 'struct so_list' to be passed back to GDB core. */
static struct so_list *
lm_info_build_so_list (void)
{
  struct so_list *res = NULL, *cur;
  struct lm_info_list *list = lm_infos;

  while (list != NULL)
    {
      cur = XCNEW (struct so_list);
      cur->next = res;
      res = cur;

      cur->lm_info = list->info;
      xsnprintf (cur->so_original_name, sizeof (cur->so_original_name),
		 "[%s]", list->info->module_name);
      xsnprintf (cur->so_name, sizeof (cur->so_name),
		 "[%s]", list->info->module_name);
      list = list->next;
    }

  return res;
}

/*****************************************************************
 * 			SO OPS callbacks
 *****************************************************************/

/* Registered as part of the GDB shared library handling
 routines. This callback will be called when a new shared library
 event is encountered (in our case, when a new module is
 loaded). The function tries to find the binary corresponding the
 the module and return an open BFD to it when successful or NULL
 when the binary file wasn't found (or couldn't be opened). */
static bfd *
soops_bfd_open (char *in_soname)
{
  int found_file = -1;
  char realfile[SO_NAME_MAX_PATH_SIZE];
  char soname[SO_NAME_MAX_PATH_SIZE];
  bfd *abfd, *sbfd, *res;
  struct lm_info *lm_info;
  char *c, *sep_file, *temp_pathname;

  DEBUG (MODULE, 3, "soops_bfd_open '%s'.\n", in_soname);

  if (*in_soname == '[')
    {
      strcpy (soname, in_soname + 1);
      soname[strlen (soname) - 1] = '\0';
    }
  else
    {
      strcpy (soname, in_soname);
      DBG_IF (MODULE)
	/* This hack tries to minimize the chance that GDB finds a binary
	   file named like the module in its default search (in
	   solib.c:solib_open).
	   tm46: may happen when called from command 'modules' */
	warning
	("soops_bfd_open: Passed module name wasn't generated by lkd_so_ops!");
    DBG_ENDIF (MODULE)}

  strcpy (realfile, soname);
  strcat (realfile, ".ko");

  while ((c = strchr (realfile, ',')))
    *c = '_';

  while ((c = strchr (realfile, '-')))
    *c = '_';

  /* Do the lookup. */
  found_file = try_to_open_alternate_names (realfile, &temp_pathname);

  if (found_file < 0)
    {
      error
	("The debugger could not find modules '%s' in '%s', nor modules.dep in '%s',\n"
	 "please provide a valid, host-relative path to the module in module-search-path\n"
	 "or provide the path to modules.dep in install-mod-path.",
	 soname, *module_search_path, get_install_mod_path ());
    }

  DEBUG (MODULE, 3, "soops_bfd_open call bfd_openr for file '%s'.\n", temp_pathname);

  /* Open a BFD to the file. */
  /* Serge CHATROUX: RnDCT00013980 Use gdb_bfd_openX functions instead of bfd_openX functions. */
  sbfd = abfd = gdb_bfd_openr (temp_pathname, gnutarget);
  if (!abfd)
    {
      close (found_file);
      error ("Could not open `%s' as an executable file: %s",
	     temp_pathname, bfd_errmsg (bfd_get_error ()));
    }

  if (!bfd_check_format (abfd, bfd_object))
    {
      error ("\"%s\": not in executable format: %s.",
	     temp_pathname, bfd_errmsg (bfd_get_error ()));
    }

  /* Find our description of the module. */
  lm_info = lm_info_find_by_name (soname, lm_infos);
  /* 'Link' it virtually. */
  layout_sections (abfd, lm_info);

  if (lm_info->sections == NULL)
    return NULL;

  printf_unfiltered ("[New module '%s' (%s)]\n", soname, temp_pathname);

  /* Try to lookup separate debug files for the module. */
  if (lm_info->mod && lm_info->mod->objfile)
    {
      DEBUG (MODULE, 3, "soops_bfd_open call find_separate_debug_file_by_debuglink\n");

      sep_file =
	find_separate_debug_file_by_debuglink (lm_info->mod->objfile);
      if (sep_file != NULL)
	{
	  DEBUG (MODULE, 3, "soops_bfd_open callbfd_openr after find_separate_debug_file_by_debuglink\n");

	  /* Serge CHATROUX: RnDCT00013980 Use gdb_bfd_openX functions instead of bfd_openX functions. */
	  sbfd = gdb_bfd_openr (sep_file, gnutarget);

	  if (!bfd_check_format (sbfd, bfd_object))
	    {
	      error ("\"%s\": not in executable format: %s.",
		     sep_file, bfd_errmsg (bfd_get_error ()));
	    }
	}
    }

  if (sbfd != abfd)
    bfd_close (abfd);

  /* If the module doesn't need any special handling, then we're
     done. */
  if (!lm_info->needs_relocated_file)
    {
      DEBUG (MODULE, 3, "soops_bfd_open module doesn't need any special handling close it\n");
      close (found_file);
      return sbfd;
    }

  DEBUG (MODULE, 3, "soops_bfd_open set real path to %s\n", temp_pathname);

  lm_info->real_file = xmalloc (strlen (temp_pathname) + 1);
  strcpy (lm_info->real_file, temp_pathname);
  /* Generate the relocated module. */
  DEBUG (MODULE, 3, "Calling make_temporary_bfd\n");
  res = make_temporary_bfd (sbfd, lm_info, &temp_pathname);

  if (res != NULL)
    {
      lm_info->relocated_file = xmalloc (strlen (temp_pathname) + 1);
      strcpy (lm_info->relocated_file, temp_pathname);
      xfree (temp_pathname);
      DEBUG (MODULE, 3, "Generated relocated module %s\n", lm_info->relocated_file);
      return res;
    }

  return sbfd;
}

/* Registered in GDB's shared library machinery and
 called after a shared library is loaded to apply the load offsets
 to the sections in the library. */
static void
soops_relocate_section_addresses (struct so_list *so,
				  struct target_section *sec)
{
  unsigned int offset;
  DEBUG (MODULE, 4,
	 "soops_relocate_section_addresses (%s:%s) <= %s->%s\n",
	 so->so_name, sec->the_bfd_section->name,
	 phex (sec->addr, 4), phex (sec->endaddr, 4));

  if (so->lm_info->sections == NULL)
    error ("GDB has opened '%s' as the binary file for module '%s'.\n"
	   "This is almost certainly wrong, and will cause problems for the remainder\n"
	   "of this debugging session. Please move this file out of harms way.",
	   so->so_name, so->so_original_name);

  /* This one is in GDB's list, keep a backlink to it. */
  so->lm_info->mod = so;

  if (so->lm_info->needs_relocated_file)
    {
      /* Just do as if our handcrafted file was a real shared
         library and return. */
      CORE_ADDR base = so->lm_info->module_core;
      if (so->lm_info->module_init && base > so->lm_info->module_init)
	base = so->lm_info->module_init;

      sec->endaddr += base;
      sec->addr += base;
      return;
    }

  /* No relocated file, just the relocatable module. */

  /* Put the symbols from the .modinfo section at the end of the
     memory so that they don't interfer with real symbols.
     We can't simply let the offset be 0: the issue is that
     symfile.c:syms_from_objfile re-initializes the 0 offsets to the
     lower initialized offset. Thus we get offset(.modinfo) ==
     offset(.text) and a lot of issues stem from that. */
  if (!strcmp (".modinfo", sec->the_bfd_section->name))
    offset = ~0UL - sec->the_bfd_section->size;
  else
    offset = get_module_section_addr (so->lm_info,
				      sec->the_bfd_section->name);

  sec->addr += offset;
  sec->endaddr += offset;
  DEBUG (MODULE, 4,
	 "soops_relocate_section_addresses (%s:%s) => %s->%s\n",
	 so->so_name, sec->the_bfd_section->name,
	 phex (sec->addr, 4), phex (sec->endaddr, 4));
}

/* Called by GDB when a module disappears.
 **/
static void
soops_free_so (struct so_list *so)
{
  if (so->lm_info && lm_info_exists (so->lm_info) && so->lm_info->mod == so)
    {
      DEBUG (MODULE, 3, "soops_free_so(%s)\n", so->so_name);
      lm_info_remove (so->lm_info, 0);
    }
}

/* Called by GDB to cleanup all the symbol information.
 **/
static void
soops_clear_solib (void)
{
  DEBUG (MODULE, 3, "soops_clear_solib\n");

  lkd_try_push_target ();

  lm_info_free_list ();
}

static void
lkd_modules_create_inferior_hook (void)
{
  DEBUG (MODULE, 3, "lkd_modules_create_inferior_hook\n");

  if (!shlib_event_load_bp && HAS_ADDR (module_finalize))
    {
      CORE_ADDR addr = ADDR (module_finalize);
      shlib_event_load_bp =
	create_solib_event_breakpoint (target_gdbarch (), addr);

      DEBUG (MODULE, 2, "SET `event_load` @%s\n",
	     phex (shlib_event_load_bp->loc->address, 4));

      /* keep track of the number outside the bp struct, because bpno
	 is what the delete observer propagates */
      shlib_event_load_no = shlib_event_load_bp->number;
    }

  if (!shlib_event_cleanup_bp && HAS_ADDR (module_arch_cleanup))
    {
      CORE_ADDR addr = ADDR (module_arch_cleanup);
      shlib_event_cleanup_bp =
	create_solib_event_breakpoint (target_gdbarch (), addr);

      DEBUG (MODULE, 2, "SET `event_cleanup` @%s\n",
	     phex (shlib_event_cleanup_bp->loc->address, 4));
	     
      disable_breakpoint (shlib_event_cleanup_bp); /* Disabled by default.  */

      /* keep track of the number outside the bp struct, because bpno
	 is what the delete observer propagates */
      shlib_event_cleanup_no = shlib_event_cleanup_bp->number;
    }

  if (!shlib_event_free_bp && HAS_ADDR (module_free))
    {
      CORE_ADDR addr = ADDR (module_free);
      shlib_event_free_bp =
	create_solib_event_breakpoint (target_gdbarch (), addr);

      DEBUG (MODULE, 2, "SET `event_free` @%s\n",
	     phex (shlib_event_free_bp->loc->address, 4));

      /* keep track of the number outside the bp struct, because bpno
	 is what the delete observer propagates */
      shlib_event_free_no = shlib_event_free_bp->number;
    }
}

/* Called by GDB to setup the module hooks that will inform GDB of shared
   library events.  */
static void
soops_create_inferior_hook (int from_tty)
{
  if (lkd_params.enable_module_load)
    lkd_modules_create_inferior_hook ();
}

/* not a soops callback, but a helper actually*/
static void
lkd_modules_destroy_inferior_hook (void)
{
  DEBUG (MODULE, 3, "lkd_modules_destroy_inferior_hook\n");

  if (shlib_event_load_bp)
    {
      delete_breakpoint (shlib_event_load_bp);
      DEBUG (MODULE, 2, "DEL  `event_load`\n");
      shlib_event_load_bp = NULL;
      shlib_event_load_no = 0;
    }

  if (shlib_event_cleanup_bp)
    {
      delete_breakpoint (shlib_event_cleanup_bp);
      DEBUG (MODULE, 2, "DEL  `event_cleanup`\n");
      shlib_event_cleanup_bp = NULL;
      shlib_event_cleanup_no = 0;
    }

  if (shlib_event_free_bp)
    {
      delete_breakpoint (shlib_event_free_bp);
      DEBUG (MODULE, 2, "DEL  `event_free`\n");
      shlib_event_free_bp = NULL;
      shlib_event_free_no = 0;
    }
}


/* Callback called by GDB after the symbols of a shared library have
 been read to allow the implementation to do special things. */
static void
soops_special_symbol_handling (void)
{
  struct lm_info_list *list = lm_infos;
  struct obj_section *sect;
  DEBUG (MODULE, 3, "soops_special_symbol_handling\n");

  while (list != NULL)
    {
      struct lm_info *info = list->info;

      if (!info->so_list_updated)
	{
	  if (info->needs_relocated_file && info->mod != NULL)
	    {

	      /* Here we copy the file of the original module in
	         the GDB data structure. That makes 'info modules'
	         (aka 'info sharedlibraries') display that name
	         instead of the temporary one we created. */
	      strcpy (info->mod->so_name, info->real_file);

	      if (info->computed_init_text_size && !info->init_size)
		{
		  /* This combination means that we've loaded the
		     debug information after the init step of the
		     module has happened. Can occur when the user
		     sets a correct module-search-path after the
		     module load has been notified. */

		  DEBUG (MODULE, 2,
			 "Relocating symbols for %s\n", info->module_name);

		  /* Mangle the debug information so that the
		     unmapped code seemingly disappears from the
		     symbol space. */
		  lkd_modules_objfile_relocate (info->mod->objfile,
						info->module_init,
						info->module_init
						+
						info->computed_init_text_size,
						info->module_core,
						info->module_core
						+ info->core_size);
		}

	      info->so_list_updated = 1;
	    }
	}
      
      /*See Bug 61434 - backtrace in LKD not showing source/line information for a kernel module frame with late symbol loading */	      
      if ((info->mod != NULL) && (info->mod->objfile != NULL) && (info->mod->objfile->psymtabs != NULL))
      {
	/* Force all the debug information for the module
	   to be fully read in. */
	struct partial_symtab *pst;
	for (pst =  info->mod->objfile->psymtabs;
	     pst != NULL; pst = pst->next)
	  {
	    psymtab_to_symtab (info->mod->objfile, pst);
	  }
      }

/*
  Serge CHATROUX:
  This resolution of RnDCT00013980 seems to be not complete. Remove this code and use gdb_bfd_openX functions instead of bfd_openX functions.

      if (info->mod != NULL) {
	set_objfile_per_bfd (info->mod->objfile);
	gdb_bfd_ref (info->mod->abfd);
      }
*/
    
      list = list->next;
    }
}

/* Helper for lkd_modules_objfile_relocate () to sort the line
 information according to their start address. */
/* Copied from buildsym.c:compare_line_numbers */
static int
compare_line_numbers (const void *ln1p, const void *ln2p)
{
  struct linetable_entry *ln1 = (struct linetable_entry *) ln1p;
  struct linetable_entry *ln2 = (struct linetable_entry *) ln2p;

  /* Note: this code does not assume that CORE_ADDRs can fit in ints.
     Please keep it that way.  */
  if (ln1->pc < ln2->pc)
    return -1;

  if (ln1->pc > ln2->pc)
    return 1;

  /* If pc equal, sort by line.  I'm not sure whether this is optimum
     behavior (see comment at struct linetable in symtab.h).  */
  return ln1->line - ln2->line;
}

/* This function scrambles the debug information associated to OBJFILE
 to make all the code symbols that fit into [INIT_START...INIT_END[
 disappear from the address space. This is done by placing these
 symbols at the ~(CORE_ADDR)0 address. */
/* Copy pasted from objfiles.c:lkd_modules_objfile_relocate() */
static void
lkd_modules_objfile_relocate (struct objfile *objfile,
			      CORE_ADDR init_start,
			      CORE_ADDR init_end,
			      CORE_ADDR core_start, CORE_ADDR core_end)
{
  int i;
  struct symtab *s;
  struct compunit_symtab *cust;
  struct partial_symbol **psym;
  struct partial_symtab *pst;
  struct minimal_symbol *msym;
  struct obj_section *sec;
  bfd *abfd;

  DEBUG (MODULE, 3, "lkd_modules_objfile_relocate %s init_start 0x%x init_end 0x%x core_start 0x%x core_end 0x%x\n",
		  objfile->original_name,
		  (unsigned int) init_start,
		  (unsigned int) init_end,
		  (unsigned int) core_start,
		  (unsigned int) core_end);

  /*See Bug 61434 - backtrace in LKD not showing source/line information for a kernel module frame with late symbol loading */	      
  {
    /* Force all the debug information for the module
       to be fully read in. */
    for (pst =  objfile->psymtabs;
	 pst != NULL; pst = pst->next)
      {
	psymtab_to_symtab (objfile, pst);
      }
  }

  /* OK, get all the symtabs.  */
  ALL_OBJFILE_FILETABS(objfile, cust, s)
  {
    struct linetable *l;
    int i;

    /* First the line table.  */
    l = SYMTAB_LINETABLE (s);
    if (l)
      {
	for (i = 0; i < l->nitems; ++i)
	  if (init_start <= l->item[i].pc && init_end > l->item[i].pc)
	    l->item[i].pc = ~(CORE_ADDR) 0;

	qsort (l->item,
	       l->nitems,
	       sizeof (struct linetable_entry), compare_line_numbers);
      }

  }

  ALL_OBJFILE_COMPUNITS(objfile, cust)
  {
    const struct blockvector *bv = COMPUNIT_BLOCKVECTOR (cust);

    for (i = 0; i < BLOCKVECTOR_NBLOCKS (bv); ++i)
      {
	struct block *b;
	struct symbol *sym;
	struct block_iterator iter;

	b = BLOCKVECTOR_BLOCK (bv, i);

	ALL_BLOCK_SYMBOLS (b, iter, sym)
	{
	  fixup_symbol_section (sym, objfile);

	  if (SYMBOL_BFD_SECTION (objfile, sym)
	      && !strncmp (".init.",
			   SYMBOL_BFD_SECTION (objfile, sym)->name,
			   6)
	      && (SYMBOL_CLASS (sym) == LOC_LABEL
		  || SYMBOL_CLASS (sym) == LOC_STATIC)
	      && SYMBOL_SECTION (sym) >= 0)
	    {
	      SYMBOL_VALUE_ADDRESS (sym) = ~(CORE_ADDR) 0;
	    }
	}

	if (init_start <= BLOCK_START (b) && init_end >= BLOCK_END (b))
	  {
	    BLOCK_START (b) = ~(CORE_ADDR) 0;
	    BLOCK_END (b) = ~(CORE_ADDR) 0;
	  }
	else
	  {
	    if (init_start <= BLOCK_START (b) && init_end > BLOCK_START (b))
	      {
		BLOCK_START (b) = core_start;
	      }
	    if (init_start <= BLOCK_END (b) && init_end >= BLOCK_END (b))
	      {
		BLOCK_END (b) = core_end;
	      }
	  }
      }
  }

  /* Now the psymtabs */
  for (psym = objfile->global_psymbols.list;
       psym < objfile->global_psymbols.next; psym++)
    {
      fixup_psymbol_section (*psym, objfile);
      if (SYMBOL_BFD_SECTION (objfile, *psym)
	  && !strncmp (".init.", SYMBOL_BFD_SECTION (objfile, *psym)->name, 6))
	SYMBOL_VALUE_ADDRESS (*psym) = ~(CORE_ADDR) 0;
    }

  ALL_OBJFILE_PSYMTABS (objfile, pst)
  {
    if (init_start <= pst->textlow && init_end >= pst->texthigh)
      {
	pst->textlow = ~(CORE_ADDR) 0;
	pst->texthigh = ~(CORE_ADDR) 0;
      }
    else
      {
	if (init_start <= pst->textlow && init_end > pst->textlow)
	  {
	    pst->textlow = core_start;
	  }
	if (init_start <= pst->texthigh && init_end >= pst->texthigh)
	  {
	    pst->texthigh = core_end;
	  }
      }
  }


  /* And finally the minimal symbols. */
  ALL_OBJFILE_MSYMBOLS (objfile, msym)
    if ( MSYMBOL_OBJ_SECTION (objfile, msym)
	&& !strncmp (".init.", MSYMBOL_OBJ_SECTION (objfile, msym)->the_bfd_section->name, 6))
	    msym->mginfo.value.address = ~(CORE_ADDR) 0;

  /* As a final point, eradicate the section */
  abfd = objfile->obfd;

  ALL_OBJFILE_OSECTIONS (objfile, sec)
  {
    if (!strncmp (sec->the_bfd_section->name, ".init.", 6))
      {
	/* FIXME: we were setting begin and end address of the
	   section to ~(CORE_ADDR)0 before, but know that these
	   values are computed it's not possible. Just set offset so
	   that start address is very big.  */
	/* Set the offset to 0 first, so that the next call to
	   obj_section_addr returns the real section VMA. */
	obj_section_offset (sec) = ~(CORE_ADDR) 0 - obj_section_addr (sec);

	/*See Bug 61434 - backtrace in LKD not showing source/line information 
	  for a kernel module frame with late symbol loading
    
	  The above code probably removes the '.init.*' section.
	  The comment below shows that two solutions were used before:
	  - setting begin and end address of the section to ~(CORE_ADDR)0 
	  -> This solution has been deprecated.
	  - setting  offset so that start address is very big             
	  -> Implemented above

	  The issue is that this solution modifies the address of the section 
	  and that the section is already included in a sorted list saved in the
	  program space informations, which is then no more sorted !
	  In find_pc_section function which is used to unwind the call stack, 
	  the function get the list of the sections (from the program space) and 
	  use a 'bsearch' algorithm to find the section that holds the PC.
	  The 'bsearch' algorithm fails if the section list is not properly sorted.
	  
	  We must call 'objfiles_changed' to force the section list of the program 
	  space to be sorted again !
	*/
	objfiles_changed();
      }
  }

  /* Relocate breakpoints as necessary, after things are relocated. */
  breakpoint_re_set ();
}

static int in_module_init_hook_blacklist (const char *module);

/* This function is the callback queried by GDB to get the list of the
 currently loaded modules.

 This comment holds for all the solib code in here: _Things should be
 simpler_, but some details prevent us from making it simpler. For
 example, the module init code is called before the module insertion
 in the global list. Thus we can't just reread the list, we have to
 explicitely detect the load_module end, and maintain our own
 list. Without that, no break in init code... */
static struct so_list *
soops_current_sos (void)
{
  CORE_ADDR pc;
  struct so_list *ret;

  DEBUG (MODULE, 2, "soops_current_sos => pc=0x%s\n",
	 phex (target_has_registers ?
	       regcache_read_pc (get_current_regcache ()) : 0, 4));

  if (!target_has_registers || (lkd_private.loaded != LKD_LOADED))
    return NULL;

  pc = regcache_read_pc (get_current_regcache ());

  if (IS_LOC (pc, shlib_event_load_bp))
    {
      /* We've just loaded a new module to memory. */
      CORE_ADDR ptr;
      struct breakpoint *bp;
      /* The third parameter to module_finalize should be the
         'struct module *' for the newly loaded module. */
      ptr = linux_awareness_ops->lo_third_pointer_arg_value ();

      DEBUG (MODULE, 2, "HIT `event_load` (module_finalize) mod=%s\n",
	     phex (ptr, 4));

      lm_info_add_from_struct_module (ptr, &lm_infos);
      last_loaded = lm_infos->info;

      /* Fix for RnDCT00012447 - this is a bodge and needs to be removed */
      if (lm_infos
	  && in_module_init_hook_blacklist(lm_infos->info->module_name))
	{
	  /* We are loading a blacklisted module. Disable the module free
	     breakpoint and enable the module cleanup breakpoint (to catch a
	     subsequent module unload in order to re-enable the module free
	     breakpoint).  */
	  disable_breakpoint (shlib_event_free_bp);
	  enable_breakpoint (shlib_event_cleanup_bp);
	}
      else
	{
	  /* We are loading a module after previously encountering a blacklisted
	     module. Re-enable the module free breakpoint and disable the module
	     cleanup breakpoint.  */
	  enable_breakpoint (shlib_event_free_bp);
	  disable_breakpoint (shlib_event_cleanup_bp);
	}

      return lm_info_build_so_list ();
    }
  else if (IS_LOC (pc, shlib_event_cleanup_bp))
    {
      CORE_ADDR module_ptr = linux_awareness_ops->lo_first_pointer_arg_value ();

      DEBUG (MODULE, 2,
	     "HIT `event_cleanup` (module_arch_cleanup) mod=%s\n",
	     phex (module_ptr, 4));

      /* We are unloading a module after previously encountering a blacklisted
         module. Re-enable the module free breakpoint and disable the module
	 cleanup breakpoint.  */
      enable_breakpoint (shlib_event_free_bp);
      disable_breakpoint (shlib_event_cleanup_bp);

      return lm_info_build_so_list ();
    }
  else if (IS_LOC (pc, shlib_event_free_bp))
    {
      /* A module section has been unloaded. The module is specified by its
        'struct module' MOD parameter and the section by its MODULE_REGION
	 parameter.  */
      CORE_ADDR module_ptr = linux_awareness_ops->lo_first_pointer_arg_value ();
      CORE_ADDR section_ptr = linux_awareness_ops->lo_second_pointer_arg_value ();
      struct lm_info *info = lm_info_find_by_addr (module_ptr, lm_infos);

      DEBUG (MODULE, 2,
	     "HIT `event_free` (module_free) mod=%s sec=%s\n",
	     phex (module_ptr, 4), phex (section_ptr, 4));

      if (info && info->module_init == section_ptr)
        {
	  /* A module init section is being removed, just remove all references to it.  */
	  struct bp_location *loc, **locp_tmp;

	  ALL_BP_LOCATIONS (loc, locp_tmp)
	    {
	      CORE_ADDR bp_addr = loc->address;
	      if (bp_addr >= info->module_init
		  && bp_addr < info->module_init + info->init_size)
		{
		  warning
		    ("Disabling breakpoints that are in .init section (they will be re-set\n"
		     "if you reload that module)");
		  break;
		}
	    }

	  /* ... and scramble it to make the init section 'disappear'.  */
          if (info->mod && info->mod->objfile)
	    {
	      DEBUG (MODULE, 3, "Removing module '%s' init section...\n", info->module_name);
	      lkd_modules_objfile_relocate (info->mod->objfile,
					    info->module_init,
					    info->module_init + info->init_size,
					    info->module_core,
					    info->module_core + info->core_size);
	    }
	}
      else if (info && info->module_core == section_ptr)
	{
	  /* A module is being removed, delete from the internal lm_info list.  */
	  lm_info_remove (info, 1);
	  DEBUG (MODULE, 3, "Removing done...\n");
	}

      return lm_info_build_so_list ();
    }

  /* because of the new policy in LKD, we reread the actual module list
   * from kernel memory on "sharedlibrary" or "modules" command,
   * because the lm_infos list may have been created before
   * activating solib events.
   */
  DEBUG (MODULE, 1, "Reading module list\n");

  lkd_modules_build_list ();

  return lm_info_build_so_list ();
}

/* Required but unused callback of the shared library machinery. */
static int
soops_open_symbol_file_object (void *from_ttyp)
{
  DEBUG (MODULE, 3, "soops_open_symbol_file_object\n");
  return 0;
}

/* This callback is queried by GDB to know if the passed pc is inside
 the dynamic loader code. This code is normally hidden to the
 user. We hijack this functionality to hide the code of the
 pagefault handler. */
static int
soops_in_dynsym_resolve_code (CORE_ADDR pc)
{
  DEBUG (MODULE, 3, "soops_in_dynsym_resolve_code\n");

  return (linux_awareness_ops->lo_is_tlb_miss_handler ?
	  linux_awareness_ops->lo_is_tlb_miss_handler (pc) : 0);
}

/*****************************************************************
 *   API
 *****************************************************************/

static void set_module_init_hook_blacklist (char *args, int from_tty,
					    struct cmd_list_element *c);

static void show_module_init_hook_blacklist (struct ui_file *file, int from_tty,
					     struct cmd_list_element *c,
					     const char *value);

/* Register all the module/shared library callbacks in the
 lkd_so_ops structure. */
static void
lkd_modules_init_so_ops (void)
{
  DEBUG (MODULE, 3, "init_so_ops\n");
  lkd_so_ops.relocate_section_addresses = soops_relocate_section_addresses;
  lkd_so_ops.free_so = soops_free_so;
  lkd_so_ops.clear_solib = soops_clear_solib;
  lkd_so_ops.solib_create_inferior_hook = soops_create_inferior_hook;
  lkd_so_ops.special_symbol_handling = soops_special_symbol_handling;
  lkd_so_ops.current_sos = soops_current_sos;
  lkd_so_ops.open_symbol_file_object = soops_open_symbol_file_object;
  lkd_so_ops.in_dynsym_resolve_code = soops_in_dynsym_resolve_code;
  lkd_so_ops.bfd_open = soops_bfd_open;

  memset( &lkd_modules_private, 0, sizeof(lkd_modules_private));
}

static void
observe_breakpoint_delete (struct breakpoint *b)
{
  int bpno = b->number;

  if (bpno == shlib_event_load_no)
    {
      DEBUG (MODULE, 2, "observed DEL `event_load` #%d\n", bpno);
      shlib_event_load_bp = NULL;
      shlib_event_load_no = 0;
    }
  else if (bpno == shlib_event_cleanup_no)
    {
      DEBUG (MODULE, 2, "observed DEL `event_cleanup` #%d\n", bpno);
      shlib_event_cleanup_bp = NULL;
      shlib_event_cleanup_no = 0;
    }
  else if (bpno == shlib_event_free_no)
    {
      DEBUG (MODULE, 2, "observed DEL `event_free` #%d\n", bpno);
      shlib_event_free_bp = NULL;
      shlib_event_free_no = 0;
    }
}

void
lkd_modules_init (void)
{
  extern char *solib_search_path;

  tmpdir = getenv ("TMPDIR");

  free_depmod_cache ();

  lkd_modules_init_so_ops ();

  memset (&lkd_modules_private, 0, sizeof (struct lkd_modules_private));
  observer_attach_breakpoint_deleted (observe_breakpoint_delete);

  set_solib_ops (target_gdbarch (), &lkd_so_ops);

  module_search_path = &solib_search_path;
  if (*module_search_path == NULL)
    /* mod_path will choke on it otherwise. */
    *module_search_path = xstrdup ("");

  add_com ("add-module-search-path", class_support,
	   add_module_search_path_command,
	   "Append a module search path to the current one.");

  add_setshow_optional_filename_cmd ("install-mod-path", class_support,
				     &install_mod_path,
	_("Set an alternate path matching 'modprobe --dirname'"),
	_("Show the path used to find /lib/`uname -r`/modules.dep."),
	_("If set, this path takes precedence over <target-root-path>/lib/modules/`uname -r`."),
	set_install_mod_path, show_install_mod_path, &setlist, &showlist);

  add_setshow_boolean_cmd ("enable_module_load",
			   class_stm,
			   &lkd_params.enable_module_load,
			   "Set whether module init triggers debug info loading.",
			   "Show whether module init triggers debug info loading.",
			   NULL, enable_module_events_command, NULL,
			   &set_linux_awareness_cmd_list,
			   &show_linux_awareness_cmd_list);

  add_setshow_string_noescape_cmd ("module-init-hook-blacklist",
    class_stm,
    &module_init_hook_blacklist,
    "Add a module to the blacklist preventing the monitoring of its initialization function.",
    "Show the modules in the blacklist preventing the monitoring of their initialization functions.",
    NULL, set_module_init_hook_blacklist, show_module_init_hook_blacklist,
    &set_linux_awareness_cmd_list,
    &show_linux_awareness_cmd_list);
}

/* This function fully reads the list of modules stored in the
 kernel's memory. It discards the old information. Normally our
 list is constructed incrementally without resorting to that
 function, but the user might trigger a full re-read by
 eg. changing the module-search-path. */
struct lm_info_list *
lkd_modules_build_list (void)
{
  CORE_ADDR next;
  struct lm_info_list *new_list = NULL;

  if (!HAS_ADDR (modules) || !lkd_params.enable_vm_translation)
    return NULL;

  DBG_IF (MODULE) next = read_memory_typed_address (ADDR (modules), lkd_private.target_pointer_type);
  DEBUG (MODULE, 3, " ADDR (modules) = %s\n", phex (ADDR (modules), 4));
  DEBUG (MODULE, 3, "*ADDR (modules) = %s\n", phex (next, 4));
  DBG_ENDIF (MODULE)
    for (next = read_memory_typed_address (ADDR (modules), lkd_private.target_pointer_type);
	 next != ADDR (modules);
	 next = read_memory_typed_address (next, lkd_private.target_pointer_type))
    {
      CORE_ADDR addr = next;
      if (!linux_aware_translate_address_safe (&addr, 1))
	error
	  ("The debugger can't read the module list. The linux awareness\n"
	   "layer's view of the kernel is seriously compromised.");

      lm_info_add_from_struct_module (container_of (next, module, list),
				      &new_list);
    }
  /* lm_infos will be discarded anyway. Just free the list
     containers, and not the lm_infos which will be reused. */
  while (lm_infos)
    {
      struct lm_info_list *next = lm_infos->next;
      xfree (lm_infos);
      lm_infos = next;
    }

  return lm_infos = new_list;
}

void
lkd_modules_close (void)
{
  lkd_modules_destroy_inferior_hook ();
  lm_info_free_list ();
}

/*****************************************************************
 *   COMMANDS
 *****************************************************************/

/* modules_dep_path provides a way to specify an alternate modules installation path
 * analog to the modprobe --dirname option. */
static void
show_install_mod_path (struct ui_file *file, int from_tty,
		       struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, "The lookup path for modules.dep is: %s.\n",
		    get_install_mod_path ());
}

static void
set_install_mod_path (char *args, int from_tty, struct cmd_list_element *c)
{
  if (!install_mod_path || *install_mod_path == '\0')
    install_mod_path_changed = 0;
  else
    install_mod_path_changed = 1;
}

static char *
get_install_mod_path (void)
{
  return (install_mod_path_changed == 1) ? install_mod_path : gdb_sysroot;
}

/* add-module-search-path command. */
void
add_module_search_path_command (char *args, int from_tty)
{
  mod_path (args, module_search_path);
}

/* defect 10646: set the actual bp only if debugging in init/exit is need */
void
enable_module_events_command (char *args,
			      int from_tty, struct cmd_list_element *c)
{
  DEBUG (MODULE, 3, "enable_module_events_command\n");

  set_solib_ops (target_gdbarch (), &lkd_so_ops);

  if (lkd_params.enable_module_load)
    lkd_modules_create_inferior_hook ();
  else
    lkd_modules_destroy_inferior_hook ();
}

static int
in_module_init_hook_blacklist (const char *module)
{
  int ix;
  char_ptr m;

  for (ix = 0;
       VEC_iterate (char_ptr, module_init_hook_blacklist_vec, ix, m);
       ix++)
    {
       if (strcmp (m, module) == 0)
         return 1;
    }

  return 0;
}

static void
set_module_init_hook_blacklist (char *args, int from_tty,
				struct cmd_list_element *c)
{
  if (module_init_hook_blacklist && *module_init_hook_blacklist)
    {
      int ix;
      char **argv = gdb_buildargv (module_init_hook_blacklist);

      for (ix = 0; argv[ix]; ix++)
        {
          if (!in_module_init_hook_blacklist (argv[ix]))
	    VEC_safe_push (char_ptr, module_init_hook_blacklist_vec, argv[ix]);
	}
      xfree (argv);
    }
  else if (!from_tty
           || query (_("Reinitialize kernel modules blacklist to empty? ")))
    {
      while (!VEC_empty (char_ptr, module_init_hook_blacklist_vec))
	xfree (VEC_pop (char_ptr, module_init_hook_blacklist_vec));
    }
}

static void
show_module_init_hook_blacklist (struct ui_file *file, int from_tty,
				 struct cmd_list_element *c, const char *value)
{
  if (!VEC_empty (char_ptr, module_init_hook_blacklist_vec))
    {
      int ix;
      char_ptr m;

      puts_filtered ("Kernel modules in blacklist:");
      for (ix = 0;
	   VEC_iterate (char_ptr, module_init_hook_blacklist_vec, ix, m);
	   ix++)
	printf_filtered (" \"%s\"", m);
      puts_filtered ("\n");
    }
  else
    puts_filtered ("No kernel modules in blacklist.\n");
}
