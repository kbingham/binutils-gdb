#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/time.h>
#include <linux/delay.h>

static int x = 666;
int y = 777;

int other_thread(void *args)
{
         int i=0;

         daemonize("other_thread");

         for (i=0;i<1000;i++) {
                 printk("In other_thread %d\n", i);
                 msleep(1000);
         }
         return 0;
}

int other_test_init(void)
{
         printk("other_test_init\n");
         kernel_thread(other_thread, NULL, CLONE_KERNEL);
         return 0;
}

void other_test_exit(void)
{
         printk("other_test_exit\n");
}

module_init(other_test_init);
module_exit(other_test_exit);
MODULE_LICENSE("GPL");
