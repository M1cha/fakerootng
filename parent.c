#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <stdio.h>

#include "platform.h"

int process_children(pid_t first_child)
{
    while(1) {
        int status;
        pid_t ret=wait(&status);
        printf("Wait returned with pid %d, status: 0x%08x\n", ret, status);

        if( WIFEXITED(status) ) {
            printf("Process %d exited with return code %d\n", ret, WEXITSTATUS(status) );

            return WEXITSTATUS(status);
        } else if( WIFSIGNALED(status) ) {
            printf("Process %d exited with signal %d\n", ret, WTERMSIG(status) );

            return -1;
        } else if( WIFSTOPPED(status) ) {
            int sig = WSTOPSIG(status);
            printf("Process %d halted due to signal %d\n", ret, sig );
            if( sig==SIGTRAP ) {
                printf("SYSCALL %d captured\n", ptlib_get_syscall(ret));
                sig=0;
            } else {
                printf("Process received signal %d\n", sig);
            }
            ptrace( PTRACE_SYSCALL, ret, 0, sig );
        } else {
            printf("Unknown meaning of status\n");
        }
    }

    return 0;
}
