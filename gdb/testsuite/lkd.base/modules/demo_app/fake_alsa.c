/*
 * @file fake_alsa.c
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

/*"newer" way for cdev*/
#include <linux/kdev_t.h>
#include <linux/cdev.h>


#include <linux/kthread.h>
#include <linux/sched.h>	/*current*/
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/uaccess.h>  /*put_user */
#include <linux/timer.h>
#include <linux/wait.h>

#define SUCCESS 0
#define DEVICE_NAME "fake_alsa"
#define CLASS_NAME "st-idtec"	/* sysfs device class for idtec drivers */
#define BUF_LEN 80            /*Max length of the message from the device*/

/* Global variables are declared as static, so are global within the file.*/

static dev_t dev;
static struct cdev fake_cdev; /*cdev_init later*/

static int Major;         /* Major number assigned to our device driver */
static int Device_Open;   /* Is device open?  Used to prevent multiple  */

#define THIS_MINOR 0

/*to fake hardware event*/
struct timer_list fake_timer;
wait_queue_head_t wq;
wait_queue_t wait;
static int got_irq;
static int nb_irqs; /*count number of fake irqs to
		   simulate a hardware contention*/

#define DELAY  (HZ/2)


static int fake_alsa_open(struct inode *, struct file *);
static int fake_alsa_release(struct inode *, struct file *);
static ssize_t fake_alsa_read(struct file *, char *, size_t, loff_t *);
static ssize_t fake_alsa_write(struct file *, const char *, size_t, loff_t *);

static const struct file_operations fops = {
	.read 	= fake_alsa_read,
	.write 	= fake_alsa_write,
	.open 	= fake_alsa_open,
	.release = fake_alsa_release
};


/*
*/
static void fake_alsa_capture_DMA_callback(unsigned long cpu)
{
	printk(KERN_DEBUG "\t\t\tCPU%ld: dma callback.\n", cpu);
	got_irq = 1;
	wake_up_interruptible(&wq);

	if (nb_irqs++ != 3)
		mod_timer(&fake_timer, jiffies + DELAY);
	else {
	printk(KERN_DEBUG "\t\t\tCPU%ld: faking hardware contention!\n", cpu);
	/*simulate a hardware contention*/
	mod_timer(&fake_timer, jiffies + DELAY*3);
	}
}



/*                   Functions
 */
int  __init fake_alsa_init(void)
{
	int ret;

	/*alloc major*/
	ret = alloc_chrdev_region(&dev, THIS_MINOR, 1 , DEVICE_NAME);
	if (ret < 0) {
		printk(KERN_ERR "Registering fake_alsa_mod device failed\n");
		return ret;
	}

	Major = MAJOR(dev);
	printk(KERN_NOTICE "Registering fake_alsa_mod device with %d\n",
			Major);

	/*register chardev*/
	cdev_init(&fake_cdev, &fops);
	fake_cdev.owner = THIS_MODULE;
	fake_cdev.ops = &fops;
	ret = cdev_add(&fake_cdev, (unsigned int)dev, 1);
	if (ret)
		printk(KERN_NOTICE "Error %d adding fake_alsa_mod", ret);


	init_timer(&fake_timer);
	fake_timer.function = fake_alsa_capture_DMA_callback ;
	fake_timer.expires  = jiffies + DELAY;
	fake_timer.data = (unsigned long) raw_smp_processor_id();

	init_waitqueue_head(&wq);

	return 0;
}

void __exit fake_alsa_exit(void)
{
	/* Unregister the device
	 **/
	cdev_del(&fake_cdev);
	unregister_chrdev_region(dev, 1);
}

/* Methods
 */

/* Called when a process tries to open the device file, like
 * "cat /dev/mycharfile"
 */
static int fake_alsa_open(struct inode *inode, struct file *file)
{
   if (Device_Open)
	return -EBUSY;

   Device_Open++;

	printk(KERN_DEBUG "\t\t\topen timer: pid=%d on cpu %d\n",
				current->pid,
				raw_smp_processor_id());
	got_irq = 0;
	nb_irqs = 0;
	add_timer(&fake_timer);
	init_waitqueue_entry(&wait, current);
	add_wait_queue(&wq, &wait);

	printk(KERN_DEBUG "\t\t\tinit_waitqueue: pid=%d on cpu %d\n",
				current->pid,
				raw_smp_processor_id());




  return SUCCESS;
}


/* Called when a process closes the device file.
 */
static int fake_alsa_release(struct inode *inode, struct file *file)
{
	del_timer_sync(&fake_timer);
	remove_wait_queue(&wq, &wait);

	printk(KERN_DEBUG "\t\t\tclose timer: pid=%d on cpu %d\n",
				current->pid,
				raw_smp_processor_id());

   Device_Open--; /* We're now ready for our next caller */
   return 0;
}


/* Called when a process, which already opened the dev file, attempts to
   read from it.
*/
static ssize_t fake_alsa_read(struct file *filp,
   char *buffer,    /* The buffer to fill with data */
   size_t length,   /* The length of the buffer     */
   loff_t *offset)  /* Our offset in the file       */
{
   /* Number of bytes actually written to the buffer */

	int bytes_read = 1;
	
#if 0	
	int val = 2;
	int timeout = HZ*3; /*1s*/
	int i = 0;
	int j = 4;

	wait_event_interruptible_timeout(wq, got_irq, timeout);
	//wait_event_interruptible(wq, got_irq);
	got_irq = 0;
	
#endif

   /* Actually put the data into the buffer */
  /* while (length)  {

	///*The buffer is in the user data segment, not the kernel segment;
	// * assignment won't work. We have to use put_user which copies
	// * data from the kernel data segment to the user data segment.
	// **
	if (copy_to_user(buffer, &val, sizeof(val)))

	length -= sizeof(val);
	bytes_read += sizeof(val);
	buffer += sizeof(val);
   }*/

/*	for ( i = 0, i < 100, i++)
	{
		if ((bytes_read != 1)
				|| (val != 2)
				|| (timeout != HZ*3)
				|| (j != 4))
			printk("stack error\n");
	}*/

  length = 0 ; 

   /* Most read functions return the number of bytes put into the buffer */
   return length;

}


/*  write handler */
static ssize_t fake_alsa_write(struct file *filp,
   const char *buff,
	 size_t len,
	 loff_t *off)
{
	printk(KERN_DEBUG "write done.\n");
	return len ;
}


module_init(fake_alsa_init);
module_exit(fake_alsa_exit);
MODULE_LICENSE("GPL");

