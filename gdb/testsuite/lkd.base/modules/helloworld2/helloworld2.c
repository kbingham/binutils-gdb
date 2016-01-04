#include <linux/module.h>
#include <linux/vmalloc.h>

volatile int j;

static int hello_init(void)
{
        int i = 0; 
	j = &i;
        for (i = 0 ; i < 100; i++ ) {
	   j = i*2;
           printk(KERN_ALERT "Starting module hello: %d:%x \n", i, j);
       }
	
        return 0;
}

static void  hello_exit(void)
{
	        printk(KERN_ALERT "Unloading module hello : %x %x\n", j, &j);
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");


