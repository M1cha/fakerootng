#include "config.h"
#include <unistd.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/wait.h>

int main()
{
    if( getuid()!=0 )
        fprintf(stderr, "Not root at start of test\n");

    pid_t child = fork();

    if( child<0 ) {
        perror("Failed to fork a child");
        return 2;
    }

    if( child==0 ) {
        printf("Child about to sleep\n");
        fflush(stdout);

        // We are the child - sleep indefinitely
        sleep(50000);

        fprintf(stderr, "ERROR: child was not killed\n");
        // Should never reach this point
        return 0;
    }

    printf("Parent pid %d child %d\n", getpid(), child);
    kill(child, SIGKILL);

    int status;
    wait(&status);

    if( WIFEXITED(status) ) {
        fprintf(stderr, "Child exit normally - not good\n");

        return 1;
    }

    if( !WIFSIGNALED(status) || WTERMSIG(status)!=SIGKILL ) {
        fprintf(stderr, "Child exit with unexpected status %x\n", status);

        return 1;
    }

    if( getuid()!=0 ) {
        fprintf(stderr, "Not root at end of test\n");

        return 1;
    }

    printf("Test passed\n");

    return 0;
}
