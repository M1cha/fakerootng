#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>

int global;

int main()
{
    pid_t pid=vfork();

    if( pid<0 ) {
        perror("Vfork failed");

        return 1;
    }

    if( pid==0 ) {
        printf("Child sleeping...\n");
        sleep(1);
        printf("Child running: %d\n", ++global);
        exit(0);
    }

    printf("Parent running: %d\n", global);

    if( global==1 ) {
        printf("Test has passed\n");
        return 0;
    }

    return 1;
}
