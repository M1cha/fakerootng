#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>

int main()
{
    int i;
    for( i=0; i<10000; ++i ) {
        pid_t child = fork();

        if( child<0 ) {
            perror("fork failed");

            exit(1);
        }

        if( child==0 ) {
            // Cause fakeroot-ng to allocate
            int fd = open("testfile", O_CREAT|O_WRONLY, 0666);
            if( fd<0 ) {
                perror("open failed");

                exit(1);
            }
            close(fd);

            char *cmdline[] = { "touch", "testfile", NULL };
            execvp(cmdline[0], cmdline);

            perror("exec failed");
            exit(1);
        }

        int status;
        wait(&status);

        if( !WIFEXITED(status) || WEXITSTATUS(status)!=0 ) {
            fprintf( stderr, "Child exit with status %x\n", status );

            exit(2);
        }
    }

    unlink("testfile");

    return 0;
}
