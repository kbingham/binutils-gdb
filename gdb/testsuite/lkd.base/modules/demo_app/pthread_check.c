#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
void *thread (void *arg){

int *valeur = (int *)arg;
while (1) {
(*valeur)++;
sleep(2);
}

pthread_exit(NULL);
}

int main(){
int valeur = 0;
pthread_t tid;
pthread_create(&tid, NULL, thread, &valeur);

printf ("Tapez sur Entrée pour fermer le thread\n");
scanf("%*c");
pthread_cancel(tid);
system("clear");
printf ("Attente de la terminaison du thread\n");
pthread_join(tid, NULL);
printf ("Le valeur est %d\n", valeur);
scanf ("%*c");
return 0; 
}

