/*
 * @file usermode-dbg-app.c
 *
 * Copyright (c) 2010 STMicroelectronics (R&D) Ltd.
 *
 * @author Marc Titinger <m.titinger@amesys.fr>
 * @brief a ligthweight demo app for kptrace
 * @version 0.99.0
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/mman.h>
#include <asm/mman.h>
#include <sys/poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <sched.h>

#define GNU_SOURCE

#define MAX_BUFFS 10
#define BUFF_SIZE 256

static int fd = 0;

struct buffer_t {
	int valid;
	unsigned int data[BUFF_SIZE];
	};

#define DMA_BUFFERS		4
#define DMA_BUFFERS_MASK	0x3

static struct buffer_t buffers[DMA_BUFFERS]; /* dma buffers*/
static struct buffer_t *cur_buf;
static int last_valid_index;   /* index of next buffer*/
static int running;

static __thread unsigned my_cpu;
static __thread unsigned tick;

static pthread_t capture_thread;
static pthread_t processing_thread;
static pthread_mutex_t mutex;

static struct timeval a,b;
static int cpu_number;

static sem_t proc1_sem; /*use a semaphore to wake the subsequent processing*/


int count_cpus(void)
{
	DIR *cpus = opendir("/sys/devices/system/cpu");
	struct dirent *cpu;
	int num;

	if (cpus == NULL)
		return 1;

	while (1) {
		cpu = readdir(cpus);
		if (cpu == NULL)
			break;
		if (sscanf(cpu->d_name, "cpu%i", &num) == 1
		    && num >= cpu_number)
			cpu_number = num + 1;
	}
	return cpu_number;
}


/**
 *	simulates a capture thread reading from a device
 */
#define SECOND 1000000

static void *capture_thread_func(void* data)
{
	long elapsed, elapsed_prev;

	my_cpu = (unsigned long)data;
	elapsed_prev = 10*SECOND ;
	last_valid_index = 0 ;

	tick = 0 ;

	printf("capture_thread start on cpu%d.\n", my_cpu);

	gettimeofday(&a, NULL);

	/* fist read to synchonize with kernel timer*/
	read (fd,buffers[0].data,BUFF_SIZE*sizeof(int));

	/* do a blocking read on the "audio" device */
 	do {

	pthread_mutex_lock(&mutex);

	cur_buf = &buffers[last_valid_index] ;

	if (!cur_buf->valid) {

		pthread_mutex_unlock(&mutex);

		/*this buffer is free and can be read*/
		read (fd, cur_buf->data, BUFF_SIZE*sizeof(int));

		gettimeofday(&b, NULL);

		/* compute elapsed time since last irq*/
		elapsed = b.tv_usec - a.tv_usec + SECOND*(b.tv_sec - a.tv_sec) ;
		a.tv_usec  = b.tv_usec;
		a.tv_sec  = b.tv_sec;

		if (elapsed > 2*elapsed_prev)
			printf( "pipe underrun, data dropout (expected at 3rd IRQ)!\n");
		else
		    elapsed_prev = elapsed ;

		cur_buf->valid=1 ; /* feed the buffer to processing thread*/

		printf( "%d: read dma[%d], elapsed %ld ms\n", tick, last_valid_index, elapsed/1000);

		last_valid_index++ ;
		last_valid_index &= DMA_BUFFERS_MASK ;

		sem_post(&proc1_sem);

		tick++;
		}
	else {
		printf( "overrun on buffer[%d]\n", last_valid_index );
		pthread_mutex_unlock(&mutex);
		exit(0);
		}
	}
	while(tick  < MAX_BUFFS);

	running = 0;

	printf("capture_thread stop\n");

	/*post again to help stop the proc thread*/
	sem_post(&proc1_sem);

	return NULL;
}

/**
 *	simulates a processing thread, writes back to a device
 */
static void *processing_thread_func(void* data)
{
	int index;
	int cur_index = 0 ;
	int rc = 0;
	static unsigned int sk_prev; 

	tick = 0 ;

	my_cpu = (unsigned long)data;

	printf("processing_thread start on cpu%d.\n", my_cpu);

	/* do a blocking read on the "audio" device */
 	while(running && (rc != ETIMEDOUT) ) {

		/* wait for a buffer to be posted */
		sem_wait(&proc1_sem);

		for (index = 0 ; index < DMA_BUFFERS ; index++)
		{
			unsigned int k, s;
			cur_index+= index;
			cur_index &= DMA_BUFFERS_MASK;

			/* process any available dma.*/
			if (buffers[cur_index].valid) {
			 printf( "%d: calc dma[%d]...", tick, cur_index );
			/* low pass filter*/
			s = sk_prev ; 

			/*pass 1*/
			for (k = 0 ; k < BUFF_SIZE-1 ; k++) {
				s =  8*(buffers[cur_index].data[k]/10) 
				   + 2*(buffers[cur_index].data[(k+1)]/10); 
				buffers[cur_index].data[k] = s;		
			}
			/*pass 2*/
			for (k = 0 ; k < BUFF_SIZE-1 ; k++) {
				s =  7*(buffers[cur_index].data[k]/10) 
				   + 3*(buffers[cur_index].data[(k+1)]/10); 
				
				buffers[cur_index].data[k] = s;		
			}
			/*pass 3*/
			for (k = 0 ; k < BUFF_SIZE-1 ; k++) {
				s =  6*(buffers[cur_index].data[k]/10) 
				   + 4*(buffers[cur_index].data[(k+1)]/10); 
				buffers[cur_index].data[k] = s;		
			}
			sk_prev = s ; 
			printf("done.\n");	

			/* write back filtered data */
			write (fd, buffers[cur_index].data, BUFF_SIZE*sizeof(int));

			/*release the processed buffer*/
			pthread_mutex_lock(&mutex);
				buffers[cur_index].valid=0;
			pthread_mutex_unlock(&mutex);
			}
		}

		tick++;
	};

	printf("processing_thread stopped");

	if (rc) printf(" with error %d\n", rc);
	else	printf(".\n");

	return NULL;
}

/**
 *      create_thread - create consumer thread
 */
static int create_threads(void)
{
	pthread_attr_t attr;
	/*struct sched_param param;*/
	cpu_set_t cpus;
	unsigned long cur_cpu = 0;

	pthread_attr_init(&attr);

	count_cpus();

	if (cpu_number >1) {
		CPU_ZERO(&cpus);
		CPU_SET(0, &cpus);
		pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
		cur_cpu++;
		}

	if (pthread_create(&capture_thread, &attr, capture_thread_func, (void*)0) < 0) {
			printf("Couldn't capture thread\n");
			return -1;
		}

	if (cpu_number >1) {
		CPU_ZERO(&cpus);
		CPU_SET(cur_cpu, &cpus);
		pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
		}

	if (pthread_create(&processing_thread, &attr, processing_thread_func, (void*)cur_cpu) < 0) {
			printf("Couldn't capture thread\n");
			return -1;
		}

	return 0;
}





int main( int argc , char** argv)
{
last_valid_index = 0;
running = 1 ;

memset( buffers, 0 , sizeof(buffers));

pthread_mutex_init(&mutex, NULL);
sem_init(&proc1_sem, 0, 0);

/* open fake "audio" device */
fd = open("/dev/fake_alsa_dev", O_RDWR);

if (fd <=0) {
	printf("couldn't open the demo driver,\nplease check that the module is loaded,\nand the device file created.\n");
	return 0;
}
create_threads();

pthread_join(capture_thread, NULL);
pthread_join(processing_thread, NULL);

pthread_mutex_destroy(&mutex);

close(fd);

  return 0;
}


