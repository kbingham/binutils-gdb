#include <linux/module.h>


static int badboy_fact(int i)
{
	int n;
	if (i == 1)
		panic("Baaaaaad boy !");

	n = i*badboy_fact(i-1);
	return n;
}

static int badboy_init(void)
{
       printk(KERN_ALERT "Starting module badboy : %i\n", badboy_fact(6));
       return 0;
}

static void badboy_exit(void)
{
	        printk(KERN_ALERT "Unloading module badboy\n");
}

module_init(badboy_init);
module_exit(badboy_exit);
MODULE_LICENSE("GPL");


