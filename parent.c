#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <stdio.h>

#include "platform.h"

int process_children(pid_t first_child)
{
    int status;
    
    // Initialize the new trace
    //ptrace(PTRACE_SETOPTIONS, first_child, NULL,
    //    PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE );

    printf("About to wait\n");
    pid_t ret=waitpid(first_child, &status, 0);

    ptrace( PTRACE_SYSCALL, ret, 0, 0 );


    while(1) {
        printf("Wait returned with pid %d, status: 0x%08x\n", ret, status);

        if( WIFEXITED(status) ) {
            printf("Process %d exited with return code %d\n", ret, WEXITSTATUS(status) );

            return WEXITSTATUS(status);
        } else if( WIFSIGNALED(status) ) {
            printf("Process %d exited with signal %d\n", ret, WTERMSIG(status) );

            return -1;
        } else if( WIFSTOPPED(status) ) {
            printf("Process %d halted due to signal %d\n", ret, WSTOPSIG(status) );
            ptrace( PTRACE_SYSCALL, ret, 0, 0 );
        } else {
            printf("Unknown meaning of status\n");
        }

        printf("About to wait again\n");
        ret=waitpid(first_child, &status, 0);
        printf("Wait done\n");
    }

    return 0;
}
