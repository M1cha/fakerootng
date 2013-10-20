#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>

/* This tests the semantics of vfork:
   Make sure that the parent does not run until the child exists (or execs)
   Make sure that the parent and child share address space.
 */
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
