#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main( int argc, char *argv[] )
{
    pid_t child=fork();

    if( child==0 ) {
        // We are the child
        int exitcode=getpid()%253;
        printf("Child %d exit with code 0x%x\n", getpid(), exitcode );

        exit(exitcode);
    } else if( child==-1 ) {
        perror("Failed to fork");
    } else {
        int status;

        pid_t process=wait(&status);

        if( process<0 ) {
            perror("wait failed");
        } else {
            printf("PID %d returned 0x%x\n", process, status);
        }

        process=wait(&status);

        if( process<0 ) {
            perror("Second wait failed");
        } else {
            printf("PID %d returned 0x%x\n", process, status);
        }
    }

    return 0;
}
