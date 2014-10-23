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
        printf("Child about to segfault\n");
        fflush(stdout);

        // We are the child - segfault
        volatile char * volatile segfault = NULL;

        segfault[12] = 's';

        fprintf(stderr, "ERROR: child did not segfault\n");
        // Should never reach this point
        return 0;
    }

    int status;
    wait(&status);

    if( WIFEXITED(status) ) {
        fprintf(stderr, "Child exit normally - not good\n");

        return 1;
    }

    if( !WIFSIGNALED(status) || WTERMSIG(status)!=SIGSEGV ) {
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
