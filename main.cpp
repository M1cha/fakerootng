/*
    Fakeroot Next Generation - run command with fake root privileges
    This program is copyrighted. Copyright information is available at the
    AUTHORS file at the root of the source tree for the fakeroot-ng project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include "arch/platform.h"
#include "parent.h"
#include "file_lie.h"

static FILE *debug_log;
int log_level;

void __dlog_( const char *format, ... )
{
    if( debug_log!=NULL ) {
        if( format!=NULL ) {
            va_list params;

            va_start(params, format);
            vfprintf(debug_log, format, params);
            va_end(params);
        } else {
            fflush( debug_log );
        }
    }
}

void print_version(void)
{
    printf(PACKAGE_NAME " version " PACKAGE_VERSION "\n");
    printf("This is free software. Please read the AUTHORS file for details on copyright\n"
        "and redistribution rights.\n");
}

static bool nodetach=false;
static char persistent_file[PATH_MAX];

int parse_options( int argc, char *argv[] )
{
    int opt;

    while( (opt=getopt(argc, argv, "+p:l:d" ))!=-1 ) {
        switch( opt ) {
        case 'p': // Persist file
            if( optarg[0]!='/' ) {
                if( getcwd( persistent_file, sizeof(persistent_file) )!=NULL ) {
                    size_t len=strlen(persistent_file);
                    if( persistent_file[len-1]!='/' )
                        persistent_file[len++]='/';

                    strncpy( persistent_file+len, optarg, sizeof(persistent_file)-len-1 );
                }
            } else {
                strncpy( persistent_file, optarg, sizeof(persistent_file)-1 );
            }
            
            // strncpy has been known to leave strings unterminated
            persistent_file[sizeof(persistent_file)-1]='\0';
            break;
        case 'l':
            if( debug_log==NULL ) {
                debug_log=fopen(optarg, "wt");

                if( debug_log==NULL ) {
                    perror("fakeroot-ng: Could not open debug log");

                    return -1;
                } else {
                    log_level=1;
                }
            } else {
                fprintf(stderr, "-l option given twice\n");

                return -1;
            }
            break;
        case 'd':
            nodetach=true;
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

static void perform_debugger( int parent_socket, pid_t child )
{
    pid_t sessid=getsid(0);

    // Daemonize ourselves
    setsid();
    dlog("Debugger started\n");

    // Fill in the file_lie database from persistent file (if relevant)
    if( persistent_file[0]!='\0' ) {
        FILE *file=fopen(persistent_file, "rt");

        if( file!=NULL ) {
            dlog("Opened persistent file %s\n", persistent_file );

            load_map( file );

            fclose(file);
        } else {
            dlog("Couldn't open persistent file %s - %s\n", persistent_file, strerror(errno) );
        }
    }

    if( !nodetach ) {
        // Close all open file descriptors except child_socket, parent_socket and the debug_log (if it exists)
        // Do not close the file handles, nor chdir to root, if in debug mode. This is so that more debug info
        // come out and that core can be dumped
        int fd=-1;
        if( debug_log!=NULL )
            fd=fileno(debug_log);

        for( int i=0; i<getdtablesize(); ++i ) {
            if( i!=parent_socket && i!=fd )
                close(i);
        }

        // Re-open the std{in,out,err}
        fd=open("/dev/null", O_RDWR);
        if( fd==0 ) { // Otherwise we somehow failed to close everything
            dup(fd);
            dup(fd);
        }

        // Chdir out of the way of everyone
        chdir("/");
    }

    // Attach a debugger to the child
    if( ptrace(PTRACE_ATTACH, child, 0, 0)!=0 ) {
        perror("Could not start trace");

        exit(2);
    }
    dlog("Debugger successfully attached to process "PID_F"\n", child );

    // We are looking for a STOP and then USR1 pattern to identify the child's position.
    kill( child, SIGCONT );

    bool sync=false;
    while( !sync ) {
        int status;
        int sig=0;
        
        pid_t process=wait(&status);
        
        if( process!=child ) {
            dlog("Irrelevant process "PID_F" sent us status %x\n", process, status);
            continue;
        }

        if( WIFSTOPPED(status) ) {
            switch( WSTOPSIG(status) ) {
            case SIGSTOP:
                dlog("Seen the STOP signal\n");
                break;
            case SIGUSR1:
                dlog("Seen the USR1 signal - we can continue\n");
                sync=true;
                break;
            case SIGTRAP:
                // Just a result of using PTRACE_SYSCALL. Ignore and let the program continue
                break;
            default:
                sig=WSTOPSIG(status);
                dlog("Seen signal %d - let it through\n", sig);
                break;
            }
        } else if( WIFEXITED(status) ) {
            dlog("Program terminated with return code %d\n", WEXITSTATUS(status) );
            exit(0);
        } else if( WIFSIGNALED(status) ) {
            dlog("Program terminated with signal %d\n", WTERMSIG(status) );
            exit(0);
        }

        ptrace(PTRACE_SYSCALL, child, 0, sig);
    }

    // From this point onwards, everything is our business
    process_children(child, parent_socket, sessid );

    if( persistent_file[0]!='\0' ) {
        FILE *file=fopen(persistent_file, "w");

        if( file!=NULL ) {
            dlog("Saving persitent state to %s\n", persistent_file );
            save_map( file );

            fclose(file);
        } else {
            dlog("Failed to open persistent file %s for saving - %s\n", persistent_file, strerror(errno) );
        }
    }

    exit(0);
}

void perform_child( char *argv[] )
{
    // We are the child to be debugged. Halt until the pipe tells us we can perform the exec
    if( debug_log!=NULL )
        fclose(debug_log);

    // Send ourselves the STOP signal, and then the USR1 signal. The debugger looks for this pattern to know when to
    // begin working the fakeroot magic
    pid_t me=getpid();
    kill( me, SIGSTOP );
    kill( me, SIGUSR1 ); // Just a marker

    // If we continued, then obviously the debugger is attached - go ahead with the exec
    execvp(argv[0], argv);

    perror("Exec failed");

    exit(2);
}

int main(int argc, char *argv[])
{
    int opt_offset=parse_options( argc, argv );
    if( opt_offset==-1 )
        return 1;

    if( opt_offset==argc ) {
        print_version();
        exit(0);
    }

#if PTLIB_PARENT_CAN_WAIT
    // A parent process can perform "wait" over its debugged child
    // Don't fork for the child - run it in our process
    pid_t child=getpid();

    pid_t debugger=fork();

    if( debugger<0 ) {
        perror("Failed to create debugger process");

        exit(1);
    }

    if( debugger==0 ) {
        // We are the child, but we want to be the grandchild
        debugger=fork();

        if( debugger<0 ) {
            perror("Failed to create debugger sub-process");

            exit(1);
        }

        if( debugger==0 ) {
            perform_debugger( -1, child );
        }

        exit(0);
    }

    // We are the parent. Wait for our child to exit
    int status;

    wait(&status);

    if( !WIFEXITED(status) || WEXITSTATUS(status)!=0 ) {
        fprintf(stderr, "Exiting without running process: %x\n", status);
    }

    perform_child( argv+opt_offset );

    return 1;
#else // PTLIB_PARENT_CAN_WAIT
    // Platform cannot "wait" on child that is being debugged.
    // We will have to span a child process, and then use tricks to find out whether it finished and with what status code

    pid_t child=fork();

    if( child<0 ) {
        perror("Failed to create child process");

        return 2;
    }

    if( child==0 ) {
        perform_child( argv+opt_offset );
    }

    int child2parent[2];
    // Create the "other" pipe
    pipe(child2parent);

    pid_t debugger=fork();
    if( debugger<0 ) {
        perror("Failed to create debugger process");

        return 2;
    }

    if( debugger==0 ) {
        perform_debugger( child2parent[1], child );
    }

    // We are the actual parent. We only need to stick around until the debugger tells us that the child has exited. We won't know
    // that ourselves, because the child is effectively the child of the debugger, not us.

    close( child2parent[1] );
    if( debug_log!=NULL ) {
        fclose( debug_log );
        debug_log=NULL;
    }

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

    fprintf(stderr, "Child "PID_F" terminated with unknown termination status %x\n", child, buffer );

    return 3;
#endif // PTLIB_PARENT_CAN_WAIT
}
