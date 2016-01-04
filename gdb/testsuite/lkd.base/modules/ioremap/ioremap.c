#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/bigphysarea.h>

static void* data;
static void* greeting_value;

#define SIZE 1*1024*1024

int __init helloworld_init(void)
{
	unsigned int i;

	data = bigphysarea_alloc(SIZE);

	printk(KERN_ALERT "data %p :(\n", data);

	greeting_value = ioremap_nocache(__pa(data), SIZE);

	printk("<1>Hello World %d@%p !\n", SIZE, greeting_value);

	for (i = 0; i<SIZE; i+=sizeof(int)) {
		*(int*)(data + i) = i;
	}

	return 0;
}


void __exit helloworld_finish(void)
{
	unsigned int i = 0;
        for (i = 0; i<SIZE; i+=sizeof(int)) {
		BUG_ON(*(int*)(greeting_value + i) != i);
        }


	if (greeting_value != NULL)
		iounmap(greeting_value);
	bigphysarea_free(data, SIZE);

	printk(KERN_ALERT "Goodbye World... %p :(\n", greeting_value);
}

module_init(helloworld_init);
module_exit(helloworld_finish);
MODULE_LICENSE("GPL");

