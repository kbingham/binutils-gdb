/*
 * break.c - The traditional "Hello world!" module
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

int break_init(void) {
	printk("Hello world!\n");
	return 0;
}

void break_exit(void) {
	printk("Bye bye, cruel world...\n");
}

module_init(break_init);
module_exit(break_exit);
