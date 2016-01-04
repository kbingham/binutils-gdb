/*
 * @file usermode-dbg-app.c
 *
 * Copyright (c) 2010 STMicroelectronics (R&D) Ltd.
 *
 * @author Marc Titinger <m.titinger@amesys.fr>
 * @brief a user client app that allows triggering LKD test cases
 * @version 0.99.0
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/**/
#define DEVICE_NAME  "/dev/st-idtec/lkd-test-cdev"


/*
 * very trivial code for now.
 **/
 sub2  ()
{
 int fd = 0;
 char buf[256]="test";

 fd = open(DEVICE_NAME,	O_RDWR);

 write( fd,buf,1);
 close(fd);

 return 0;

};


int main()
{
	sub2();

  return 0;
}
