#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "parent.h"

static FILE *debug_log;

void dlog( const char *format, ... )
{
    if( debug_log!=NULL ) {
        va_list params;

        va_start(params, format);
        vfprintf(debug_log, format, params);
        va_end(params);
    }
}

int parse_options( int argc, char *argv[] )
{
    int opt;

    while( (opt=getopt(argc, argv, "+p:d:" ))!=-1 ) {
        switch( opt ) {
        case 'p': // Persist file
            break;
        case 'd':
            if( debug_log==NULL ) {
                debug_log=fopen(optarg, "wt");

                if( debug_log==NULL ) {
                    perror("fakeroot-ng: Could not open debug log");

                    return -1;
                }
            } else {
                fprintf(stderr, "-d option given twice\n");

                return -1;
            }
            break;
        case '?':
            /* Error in parsing */
            return -1;
            break;
        default:
            fprintf(stderr, "%s: internal error: unrecognized option %c\n", argv[0], optopt);
            return -1;
            break;
        }
    }
    return optind;
}

int main(int argc, char *argv[])
{
    int opt_offset=parse_options( argc, argv );
    if( opt_offset==-1 )
        return 1;

    // We create an extra child to do the actual debugging, while the parent waits for the running child to exit.
    int child2child[2], child2parent[2];
    if( pipe(child2child)<0 ) {
        perror("child pipe failed");

        return 2;
    }

    pid_t child=fork();

    if( child<0 ) {
        perror("Failed to create child process");

        return 2;
    }

    if( child==0 ) {
        // We are the child to be debugged. Halt until the pipe tells us we can perform the exec
        if( debug_log!=NULL )
            fclose(debug_log);

        char buffer;

        close(child2child[1]); // Close the writing end of the pipe

        if( read( child2child[0], &buffer, 1 )==1 ) {
            execvp(argv[opt_offset], argv+opt_offset);

            perror("Exec failed");
        }

        return 2;
    }

    // Close the reading end of the pipe
    close( child2child[0] );

    // Create the "other" pipe
    pipe(child2parent);

    pid_t debugger=fork();
    if( debugger<0 ) {
        perror("Failed to create debugger process");

        return 2;
    }

    if( debugger==0 ) {
        /* We are the child */
        close( child2parent[0] );

        /* Detach ourselves from the signals that belong to the actual processes */
        setsid();
        dlog("Debugger started\n");

        /* Attach a debugger to the child */
        if( ptrace(PTRACE_ATTACH, child, 0, 0)!=0 ) {
            perror("Could not start trace");

            exit(2);
        }
        dlog("Debugger successfully attached to process %d\n", child );

        // Let's free the process to do the exec
        if( write( child2child[1], "a", 1 )==1 ) {
            close( child2child[1] );

            process_children(child, child2parent[1] );
        }

        // It doesn't matter what we return - no one is waiting for us anyways
        return 0;
    }

    // We are the actual parent. We only need to stick around until the debugger tells us that the child has exited. We won't know
    // that ourselves, because the child is effectively the child of the debugger, not us.

    close( child2parent[1] );
    close( child2child[1] );
    fclose( debug_log );
    debug_log=NULL;

    int buffer;

    int numret;
    if( (numret=read( child2parent[0], &buffer, sizeof(int) ))<(int)sizeof(int) ) {
        if( numret==0 ) {
            waitpid( debugger, &buffer, 0 );

            fprintf(stderr, "Debugger terminated early with status %x\n", buffer);
        } else {
            perror("Parent: read failed");
        }
        exit(1);
    }

    // Why did "child" exit?
    if( WIFEXITED(buffer) ) {
        // Child has terminated. Terminate with same return code
        return WEXITSTATUS(buffer);
    }
    if( WIFSIGNALED(buffer) ) {
        // Child has terminated with a signal.
        return WTERMSIG(buffer);
    }

    fprintf(stderr, "Child %d terminated with unknown termination status %x\n", child, buffer );

    return 3;
}
