#include <linux/module.h> 
#include <linux/kernel.h>

#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/sched.h>

static struct task_struct *thread;

#define NB_PAGES 256

static void* too_much_pages[NB_PAGES];
static long long* big_array;
static __initdata unsigned int ctr = 0;
int pagefault_thread(void *);

int __init pagefault_init(void)
{
     long long* big;
	int i; 

     for (ctr=0; ctr<NB_PAGES; ++ctr) {
	     too_much_pages[ctr] = vmalloc(PAGE_SIZE);

	     for (i = 0; i<PAGE_SIZE/sizeof(int); ++i)
		     *((int*)too_much_pages[ctr] + i) = ctr;
     }

     big = big_array =  vmalloc(5*PAGE_SIZE);

     while (big != (void*)big_array+5*PAGE_SIZE) {
	     *big = (big - big_array);
	     ++big;
     }
     
     thread = kthread_create(pagefault_thread, 0, "kpagefault");
     wake_up_process(thread);
     return 0;
}

int pagefault_thread(void* blah)
{
	while (! kthread_should_stop()) {
	unsigned int i = 0, j = 0;
	printk(KERN_DEBUG "spinning\n");
	for (i=0; i<NB_PAGES; ++i) {
//		for (j = 0; j < PAGE_SIZE/sizeof(int); ++j)
			if (*((int*)too_much_pages[i]+j) != i)
				BUG();
	}	
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(2*HZ);
	}
	return 0;
}


void __exit pagefault_finish(void)
{
	kthread_stop(thread);
}

module_init(pagefault_init);
module_exit(pagefault_finish);
MODULE_LICENSE("GPL");

