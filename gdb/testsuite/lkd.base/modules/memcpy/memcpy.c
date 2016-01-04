#include <linux/module.h> 
#include <linux/kernel.h>

#include <linux/kthread.h>
#include <linux/sched.h>

static unsigned int greeting_value = 0;
static int bongga = 25;
int toto = 12;

static int tableA[1024];
static int tableB[1024];

static struct task_struct *thread;

int helloworld_thread(void *);

int __init helloworld_init(void)
{
     printk("<1>Hello World %x !\n", greeting_value);

     thread = kthread_create(helloworld_thread, 0, "khello");
     wake_up_process(thread);
     return 0;
}

int helloworld_thread(void* blah)
{
	while (! kthread_should_stop()) {

	    memcpy(tableA, tableB, sizeof(int) * 1024);

	    set_current_state(TASK_INTERRUPTIBLE);
	    schedule_timeout(HZ>>1);
	    //schedule();
	}
	return 0;
}


void __exit helloworld_finish(void)
{
	kthread_stop(thread);
	printk(KERN_ALERT "Goodbye World... %x :(\n", greeting_value);
}

module_init(helloworld_init);
module_exit(helloworld_finish);
MODULE_LICENSE("GPL");

