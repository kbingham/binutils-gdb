/*
  Linux Awareness extension target (Linux Kernel Debugger)
  Copyright 2011-2013 STMicroelectronics.
*/

#ifndef __LKD_MODULES_H__
#define __LKD_MODULES_H__

/* The list of tasks as cached in the debugger. */
/* The data we compute and store about a loaded module. */
struct lm_info
{
  char module_name[SO_NAME_MAX_PATH_SIZE];
  CORE_ADDR this_module;
  CORE_ADDR init;
  CORE_ADDR module_init;
  CORE_ADDR module_core;
  ULONGEST init_size;
  ULONGEST core_size;
  ULONGEST init_text_size;
  ULONGEST core_text_size;

  ULONGEST computed_core_text_size;
  ULONGEST computed_init_text_size;

  int needs_relocated_file;

  char *real_file;
  char *relocated_file;

  unsigned int shnum;
  struct
  {
    unsigned int nameidx;
    char *name;
    CORE_ADDR addr;
  } *sections;

  int so_list_updated;
  struct so_list *mod;
};

struct lm_info_list
{
  struct lm_info *info;
  struct lm_info_list *next;
};

/* The structure used to pass information to the BFD section iterators
 that are used to build the 'linked' module. */
struct module_bfd_copy_info
{
  bfd *old;
  bfd *new;
  struct lm_info *lm_info;
  asection **sec_mapping;
};

/* That macro existed and disappeared in newer GDB versions. */
#define SYMBOL_BFD_SECTION(objfile, sym) (SYMBOL_OBJ_SECTION (objfile, sym) ? \
    SYMBOL_OBJ_SECTION (objfile, sym)->the_bfd_section : NULL)

extern struct breakpoint *shlib_event_load_bp;
extern struct breakpoint *shlib_event_init_bp;
extern struct breakpoint *shlib_event_post_init_bp;
extern struct breakpoint *shlib_event_free_bp;

/*API*/
void lkd_modules_init (void);
struct lm_info_list *lkd_modules_build_list (void);
void lkd_modules_close (void);
void lkd_modules_resume (void);

/*commands*/
void add_module_search_path_command (char *args, int from_tty);
void enable_module_events_command (char *args, int from_tty,
				   struct cmd_list_element *c);

#endif /*__LKD_MODULES_H__*/
