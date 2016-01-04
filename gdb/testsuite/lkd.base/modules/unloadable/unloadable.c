#include <linux/module.h> 
#include <linux/kernel.h>

#include <linux/kthread.h>

int __init helloworld_init(void)
{
     return -ENODEV;
}

void __exit helloworld_finish(void)
{
	printk(KERN_ALERT "Goodbye World... \n");
}

module_init(helloworld_init);
module_exit(helloworld_finish);
MODULE_LICENSE("GPL");

