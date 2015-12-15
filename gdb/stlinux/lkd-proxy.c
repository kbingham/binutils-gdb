/*
 *  Copyright(c) 2011-2013 ST-Microelectronics.
 *
 *  This file contains the Linux Kernel Debugger
 *  remote target proxys.
 *
 **/
#include "defs.h"
#include "command.h"
#include "exceptions.h"
#include "exec.h"
#include "gdb.h"
#include "gdb_assert.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "gdbtypes.h"
#include "objfiles.h"
#include "target.h"
#include "remote.h"
#include "value.h"

#include "lkd.h"
#include "lkd-process.h"

/* arch specific.*/
extern lkd_proxy_t lkd_arch_remotes[];
static int cur_remote = lkd_invalid;

#define CUR_LKD_REMOTE lkd_arch_remotes[cur_remote]

/**************************************************************/
/*************  INIT / AUTODETECTION / ENABLEMENT   ***********/
/**************************************************************/
static char *
local_execute_command (char *in)
{
  struct cleanup *cleanup;
  char *cmd = xstrdup (in), *output;
  LONGEST result;

  cleanup = make_cleanup (xfree, cmd);
  output = execute_command_to_string (cmd, 0);
  do_cleanups (cleanup);
  xfree (output);

  if (get_internalvar_integer (lookup_internalvar ("_"), &result))
    {
      static char *cmd_buf = NULL;

      xfree (cmd_buf);
      cmd_buf = xstrprintf ("%s", phex (result, 4));

      return cmd_buf;
    }

  return NULL;
}

/*
 * insert the remote channel and try enumerate ST-Microelectronics
 * LKD compatible remotes.
 **/
static char *
remote_execute_command (char *in)
{
  static char *cmd_buf = NULL;
  long int size = 512;

  gdb_assert (in);

  xfree (cmd_buf);
  cmd_buf = xcalloc (size, sizeof (char));

  snprintf(cmd_buf, size, "Qst %s", in);

  DEBUG (D_INIT, 1, "remote_execute_command : -> [%s] \n", cmd_buf);

  putpkt (cmd_buf);
  getpkt (&cmd_buf, &size, 1);

  DEBUG (D_INIT, 1, "remote_execute_command : <- [%s] \n", cmd_buf);

  return cmd_buf;
}

/* create a Q packet from command line*/
static void
st_qemu_command (char *args, int from_tty)
{
	char *reply;

	reply = remote_execute_command (args);
	printf_filtered("%s\n", reply);
}

/* default, command proxy.
 */
#define RD_CP15_SCR0    "cp15 c1 0 c0 0"
#define RD_CP15_TTBR0   "cp15 c2 0 c0 0"
#define WR_CP15_TTBR0   "cp15 c2 0 c0 0 0x%x"
#define RD_CP15_ASID    "cp15 c13 0 c0 1"
#define WR_CP15_ASID    "cp15 c13 0 c0 1 0x%x"

lkd_proxy_t lkd_arch_remotes[] = {
  {.id = lkd_local_stgdi,
   .name = "STARM-gdb (stgdi)",
   .exec = local_execute_command,
   .version = "",
   .rd_cp15_SCR0 = "st "RD_CP15_SCR0,
   .rd_cp15_TTBR0 = "st "RD_CP15_TTBR0,
   .wr_cp15_TTBR0 = "st "WR_CP15_TTBR0,
   .rd_cp15_ASID = "st "RD_CP15_ASID,
   .wr_cp15_ASID = "st "WR_CP15_ASID,
   }
  ,
  {.id = lkd_local_shtdi,
   .name = "SH4/ARMv7 Linux GDB (shtdi)",
   .exec = local_execute_command,
   .version = "",
   .rd_cp15_SCR0 = "st "RD_CP15_SCR0,
   .rd_cp15_TTBR0 = "st " RD_CP15_TTBR0,
   .wr_cp15_TTBR0 = "st "WR_CP15_TTBR0,
   .rd_cp15_ASID = "st "RD_CP15_ASID,
   .wr_cp15_ASID = "st " WR_CP15_ASID,
   }
  ,
  {
   .id = lkd_remote_qemu,
   .name = "ST ARMv7 Qemu",
   .exec = remote_execute_command,
   .version = "version",
   .rd_cp15_SCR0 = RD_CP15_SCR0,
   .rd_cp15_TTBR0 = RD_CP15_TTBR0,
   .wr_cp15_TTBR0 = WR_CP15_TTBR0,
   .rd_cp15_ASID = RD_CP15_ASID,
   .wr_cp15_ASID = WR_CP15_ASID,
   }
  ,
  {lkd_invalid, "", NULL, ""}
  ,
};

/*
 * Remote Target discovery and init routine.
 **/
lkd_proxy_id_t
lkd_proxy_init_target (struct target_ops * beneath)
{
  int found = 0;
  char *out = NULL;

  DEBUG (D_INIT, 1, "lkd_proxy_init_target\n");

  if (!beneath)
    return lkd_invalid;

  /* Check if we already have a beneath target we identified
   * and initialized.*/
  if (cur_remote != lkd_invalid)
    return cur_remote;

  if (!strcmp (beneath->to_shortname, "stgdi"))
    {
      cur_remote = lkd_local_stgdi;
      found = 1;
    }
  else if (!strcmp (beneath->to_shortname, "shtdi"))
    {
      cur_remote = lkd_local_shtdi;
      found = 1;
    }
  else if (strstr (beneath->to_shortname, "remote"))
    {
      /* check for ST-QEMU */
      cur_remote = lkd_remote_qemu;

      /* send "version" command */
      printf_filtered ("Testing remote: %s ", CUR_LKD_REMOTE.name);

      out = CUR_LKD_REMOTE.exec (CUR_LKD_REMOTE.version);
      if (strstr (out, "st"))
      {
	printf_filtered ("Version request return : [%s].\n", out);

	add_com ("st", class_stm, st_qemu_command, "");
	found = 1;
      }
      else
	printf_filtered ("unknown response : %s\n", out);
      found = 1;
    }

  if (!found)
    {
      DEBUG (D_INIT, 1, "Invalid remote \"%s\" (ver=%s)\n",
	     beneath->to_shortname, out);

      cur_remote = lkd_invalid;

      return lkd_invalid;	/* [EXIT] */
    }

  linux_awareness_ops->proxy = &(CUR_LKD_REMOTE);

  return CUR_LKD_REMOTE.id;
};


void
lkd_proxy_exit_target (void)
{
  cur_remote = lkd_invalid;
}

inline lkd_proxy_id_t
lkd_proxy_get_current (void)
{
  return cur_remote;
}
