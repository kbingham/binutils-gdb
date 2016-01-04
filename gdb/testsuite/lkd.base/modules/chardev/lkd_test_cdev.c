/*
 * @file lkd_test_cdev.c
 *
 * Copyright (c) 2010 STMicroelectronics (R&D) Ltd.
 *
 * @author Marc Titinger <m.titinger@amesys.fr>
 * @brief kernel module for LKD validation and demo.
 * @version 0.99.0
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#define __NO_VERSION__

#include <linux/module.h>
#include <linux/kernel.h>

#if defined(CONFIG_MODVERSIONS) && !defined(MODVERSIONS)
	#include <linux/modversions.h>
	#define MODVERSIONS
#endif

#include <linux/kthread.h>
#include <linux/sched.h>	/*current*/
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/uaccess.h>  /*put_user */

#include "lkd_test_cdev.h"

#define SUCCESS 0
#define DEVICE_NAME "lkd-test-cdev" /*Dev name as it appears in /proc/devices*/
#define CLASS_NAME "st-idtec"	/* sysfs device class for idtec drivers */
#define BUF_LEN 80            /*Max length of the message from the device */

/* Global variables are declared as static, so are global within the file. */

static int Major;         /* Major number assigned to our device driver */
static int Device_Open;   /* Is device open?  Used to prevent multiple  */

static struct class *idtec_class; /* to register into sysfs fo udev*/


static int lkd_test_cdev_open(struct inode *, struct file *);
static int lkd_test_cdev_release(struct inode *, struct file *);
static ssize_t lkd_test_cdev_read(struct file *, char *, size_t, loff_t *);
static ssize_t lkd_test_cdev_write(struct file *, const char *, size_t, loff_t *);

//static struct cdev* my_cdev;


static const struct file_operations fops = {
	.read 	= lkd_test_cdev_read,
	.write 	= lkd_test_cdev_write,
	.open 	= lkd_test_cdev_open,
	.release 	= lkd_test_cdev_release
};

/*                   Functions
 */

int  __init lkd_test_cdev_init(void)
{
	idtec_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(idtec_class))
		return PTR_ERR(idtec_class);

	Major = register_chrdev(0, DEVICE_NAME, &fops);

	if (Major < 0) {
	class_destroy(idtec_class);
	printk(KERN_ERR "Registering lkd_test_cdev_mod device failed with %d\n",
			Major);
	return Major;
	}

	/* register the sysfs device for udev to handle the device file creation */
	//device_create(idtec_class, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME );
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29))
	class_device_create(idtec_class, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME);
#else
	device_create(idtec_class, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME);
#endif

	return 0;
}

void __exit lkd_test_cdev_exit(void)
{
	/* Unregister the device
	 **/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29))
	class_device_destroy(idtec_class, MKDEV(Major, 0));
#else
	device_destroy(idtec_class, MKDEV(Major, 0));
#endif

	unregister_chrdev(Major, DEVICE_NAME);
	class_destroy(idtec_class);
}

/* Methods
 */

/* Called when a process tries to open the device file, like
 * "cat /dev/mycharfile"
 */
static int lkd_test_cdev_open(struct inode *inode, struct file *file)
{
   if (Device_Open)
	return -EBUSY;

   Device_Open++;

  return SUCCESS;
}


/* Called when a process closes the device file.
 */
static int lkd_test_cdev_release(struct inode *inode, struct file *file)
{
   Device_Open--; /* We're now ready for our next caller */
   return 0;
}


/* Called when a process, which already opened the dev file, attempts to
   read from it.
*/
static ssize_t lkd_test_cdev_read(struct file *filp,
   char *buffer,    /* The buffer to fill with data */
   size_t length,   /* The length of the buffer     */
   loff_t *offset)  /* Our offset in the file       */
{
   /* Number of bytes actually written to the buffer */

	/*TODO */
	return -ENOTTY ;

#if 0
	int bytes_read = 0;

   /* Actually put the data into the buffer */
   while (length && *msg_Ptr)  {

	/* The buffer is in the user data segment, not the kernel segment;
	 * assignment won't work. We have to use put_user which copies
	 * data from the kernel data segment to the user data segment.
	 **/
	  put_user(*(msg_Ptr++), buffer++);

	  length--;
	  bytes_read++;
   }

   /* Most read functions return the number of bytes put into the buffer */
   return bytes_read;
#endif
}


/*  Called when a process writes to dev file: echo "hi" > /dev/hello */
static ssize_t lkd_test_cdev_write(struct file *filp,
   const char *buff,
	 size_t len,
	 loff_t *off)
{
	/*current == current_thread_info()->task

  printk("The process is \"%s\" (pid %i)\n",
	 current->comm, current->pid);*/

	printk(KERN_DEBUG "write done.\n");
	return len ;
}


module_init(lkd_test_cdev_init);
module_exit(lkd_test_cdev_exit);
MODULE_LICENSE("GPL");

