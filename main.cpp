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
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include <limits.h>
#include <string.h>

#include <memory>

#include "arch/platform.h"
#include "parent.h"
#include "file_lie.h"

static FILE *debug_log;
int log_level;
bool log_flush=false;

void __dlog_( const char *format, ... )
{
    if( debug_log!=NULL ) {
        if( format!=NULL ) {
            va_list params;

            va_start(params, format);
            vfprintf(debug_log, format, params);
            va_end(params);
        }
        if( format==NULL || log_flush ) {
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

    while( (opt=getopt(argc, argv, "+p:l:dvf" ))!=-1 ) {
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
        case 'f':
            log_flush=true;
            break;
        case 'd':
            nodetach=true;
            break;
        case 'v':
            print_version();
            return -2;
        case '?':
            /* Error in parsing */
            return -1;
            break;
        default:
            fprintf(stderr, "%s: internal error: unrecognized option '-%c'\n", argv[0], opt);
            return -1;
            break;
        }
    }
    return optind;
}

// Make sure we are running in a sane environment
static bool sanity_check()
{
    // Make sure that /tmp (or $TMPDIR, or $FAKEROOT_TMPDIR) allow us to map executable files
    const char *tmp=getenv("FAKEROOT_TMPDIR");

    if( tmp==NULL )
        tmp=getenv("TMPDIR");

    std::string tmppath;

    if( tmp!=NULL ) {
        tmppath=tmp;
    } else {
        tmppath=DEFAULT_TMPDIR;
    }

    std::auto_ptr<char> templt(new char[tmppath.length()+20]);
    sprintf( templt.get(), "%s/fakeroot-ng.XXXXXX", tmppath.c_str() );

    int file=mkstemp( templt.get() );

    if( file==-1 ) {
        perror("Couldn't create temporary file");

        return false;
    }

    // First - make sure we don't leave any junk behind
    unlink( templt.get() );

    // Write some data into the file so it's not empty
    if( write( file, templt.get(), tmppath.length() )<0 ) {
        perror("Couldn't write into temporary file");

        return false;
    }

    // Map the file into memory
    void *map=mmap( NULL, 1, PROT_EXEC|PROT_READ, MAP_SHARED, file, 0 );
    int error=errno;

    close( file );

    if( map==MAP_FAILED ) {
        if( error==EPERM ) {
            fprintf( stderr, "Temporary area points to %s, but it is mounted with \"noexec\".\n"
                    "Set either the FAKEROOT_TMPDIR or TMPDIR environment variables to point to a\n"
                    "directory from which executables can be run.\n",
                    tmppath.c_str() );
        } else {
            perror("Couldn't mmap temporary file");
        }

        return false;
    }

    munmap( map, 1 );

    return true;
}

static void perform_debugger( int child_socket, int master_socket )
{
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
            if( i!=child_socket && i!=master_socket && i!=fd )
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

    errno=0;
    pid_t child;
    if( read( child_socket, &child, sizeof(child) )==sizeof(child) ) {
        attach_debugger( child, child_socket );
        process_children( master_socket );
    } else {
        // Oops - no data?
        dlog("Process ID not sent correctly - debugger received error on read: %s\n", strerror(errno) );

        exit(2);
    }

    if( persistent_file[0]!='\0' ) {
        FILE *file=fopen(persistent_file, "w");

        if( file!=NULL ) {
            dlog("Saving persitent state to %s\n", persistent_file );
            save_map( file );

            fclose(file);
        } else {
            dlog("Failed to open persistent file %s for saving - %s\n", persistent_file, strerror(errno) );
        }

        // Remove the unix socket
        struct sockaddr_un sa;

        snprintf( sa.sun_path, sizeof(sa.sun_path), "%s.run", persistent_file );
        unlink( sa.sun_path );
    }

    exit(0);
}

static int real_perform_child( int child_socket, char *argv[], int internal_pipe )
{
    // Don't leave the log file open for the program to come
    if( debug_log!=NULL )
        fclose(debug_log);

    // Send the debugger who we are
    pid_t us=getpid();
    if( write( child_socket, &us, sizeof(us) )<0 ) {
        perror("Couldn't send the process ID to the debugger");

        return 2;
    }

    // Halt until the pipe tells us we can perform the exec
    char buffer;
    if( read( child_socket, &buffer, 1 )==1 ) {
        close( child_socket );

        // We may have a parent that also needs the socket. Mark to it that it is now ok to read from it
        if( internal_pipe>=0 ) {
            close( internal_pipe );
        }

        // Mark the fact that we are ready to the debugger
        kill( getpid(), SIGUSR1 );

        execvp(argv[0], argv);

        perror("Exec failed");
    }

    return 2;
}

#if PTLIB_PARENT_CAN_WAIT
static int perform_child( int child_socket, char *argv[] )
{
    return real_perform_child( child_socket, argv, -1 );
}
#else
// Parent cannot wait on debugged child
static int perform_child( int child_socket, char *argv[] )
{
    int pipes[2];
    pipe(pipes);

    pid_t child=fork();

    if( child<0 ) {
        perror("Failed to create child process");

        return 2;
    } else if( child==0 ) {
        // We are the child
        close( pipes[0] );
        return real_perform_child( child_socket, argv, pipes[1] );
    }

    // We are the parent.

    close( pipes[1] );

    if( debug_log!=NULL ) {
        fclose( debug_log );
        debug_log=NULL;
    }

    int buffer;
    int numret;
    // Read from pipe to know when child finished talking to the debugger
    read( pipes[0], &buffer, sizeof(buffer) );

    close( pipes[0] );

    // Cannot "wait" for child - instead listen on socket
    if( (numret=read( child_socket, &buffer, sizeof(int) ))<(int)sizeof(int) ) {
        if( numret>=0 ) {
            fprintf(stderr, "Debugger terminated early\n");
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
}
#endif

int main(int argc, char *argv[])
{
    int opt_offset=parse_options( argc, argv );
    if( opt_offset==-1 )
        return 1;
    if( opt_offset==-2 )
        return 0;

    if( opt_offset==argc ) {
        // Fakeroot-ng called with no arguments - assume it wanted to run the current shell
 
        // We have at least one spare argv to work with (argv[0]) - use that
        argv[argc-1]=getenv("SHELL");
        opt_offset--;
    }

    // Check the environment to make sure it allows us to run
    if( !sanity_check() ) {
        return 1;
    }

    int master_socket=-1; // Socket fd needs to persist outside the creation location
    bool launch_debugger=true; // Whether to start a debugger process
    sockaddr_un sa;

    if( persistent_file[0]!='\0' ) {
        // We have a state to keep
        // Another thing we do if a persistent file was specified is to create a communication socket
        master_socket=socket(PF_UNIX, SOCK_SEQPACKET, 0);
        if( master_socket==-1 ) {
            // Couldn't create a socket
            perror("Unix socket creation error");
            exit(1);
        }

        sa.sun_family=AF_UNIX;
        snprintf( sa.sun_path, sizeof(sa.sun_path), "%s.run", persistent_file );

        // For all we know, the socket may already exist, which means we need not be the debugger
        if( connect(master_socket, (const struct sockaddr *) &sa, sizeof(sa) )<0 ) {
            // The socket doesn't exist - create it
            unlink( sa.sun_path ); // Erase it if it already existed
            if( bind( master_socket, (const struct sockaddr *) &sa, sizeof(sa) )<0 ) {
                // Binding failed
                perror("Couldn't bind state socket");
                exit(1);
            }

            listen( master_socket, 10 );
        } else {
            // The socket already exist - another process is the debugger
            launch_debugger=false;
        }
    }

    // We create an extra child to do the actual debugging, while the parent waits for the running child to exit.
    // No state to keep
    int sockets[2]={-1, -1}; 

    if( launch_debugger ) {
        if( socketpair( PF_UNIX, SOCK_SEQPACKET, 0, sockets )<0 ) {
            perror("Child socket creation error");

            return 2;
        }

        pid_t debugger=fork();

        if( debugger<0 ) {
            perror("Failed to create debugger process");

            exit(1);
        }

        if( debugger==0 ) {
            close(sockets[0]);

            // We are the child, but we want to be the grandchild
            debugger=fork();

            if( debugger<0 ) {
                perror("Failed to create debugger sub-process");

                exit(1);
            }

            if( debugger==0 ) {
                perform_debugger( sockets[1], master_socket );
            }

            exit(0);
        }

        // Wait for our child to exit
        int status;

        wait(&status);

        if( !WIFEXITED(status) || WEXITSTATUS(status)!=0 ) {
            fprintf(stderr, "Exiting without running process\n");

            exit(1);
        }

        close( sockets[1] );
    } else {
        // We are not launching the debugger. master_socket contains our connected socket to the real debugger
        sockets[0]=dup(master_socket);
    }

    // We are the parent. We no longer need the listening socket
    close(master_socket);
    master_socket=-1;

    return perform_child( sockets[0], argv+opt_offset );
}
