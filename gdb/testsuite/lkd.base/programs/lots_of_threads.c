/* Compile line:  "sh4-linux-gcc -g -O0 simple_pthread_example.c -o simple_pthread_example -lpthread" */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>

void *grandchild_work(void *unused)
{	
	// Count to ten, that's it. Very short-lived threads need to work with the tools...
	int i = 0;
	for (i = 0; i< 10;i++) {
		
	}
}

void create_grandchild(void)
{
	pthread_t thread;
	pthread_create(&thread, NULL, &grandchild_work,NULL);
}

void *fifty_work(void* value)
{
	printf("%d\n", (int)value);
	create_grandchild();
	while (1) {
		usleep(1000 * 1000 * 500);
		value++;
		value--;
		sched_yield();
	}
}

void create_fifty_threads(void)
{
	pthread_t threads[50];
	int i=0;

	for (i=0;i<50;i++) {
		printf("Creating thread %d\n", i);
		pthread_create(&threads[i], NULL, &fifty_work, (void*)i);
	}
}

void apples(void)
{
	printf("apples\n");
}

int main ()
{
	int i=0;
/*	printf("Waiting 15 seconds to start...\n");
	for (i = 0; i< 30; i++) {
		usleep(5 * 100 * 1000);
		i++;
		i--;
		sched_yield();
		printf("test\n");
	}
	printf("done\n");*/
	
    /* Create fifty normal threads */
    create_fifty_threads();

    while (1)
    {
        usleep(100 * 1000);
	i++;
	i--;
	sched_yield();
	apples();
    }
	printf("Exiting\n");

   return 0;
}

