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

// XXX Should move the generation of _BSD_SOURCE into autoconf
#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include <ext/hash_map>

#include <stdio.h>
#include <assert.h>

#include "arch/platform.h"

#include "syscalls.h"
#include "parent.h"

// forward declaration of function
static bool finish_allocation( int sc_num, pid_t pid, pid_state *state );


// Keep track of handled syscalls
static __gnu_cxx::hash_map<int, syscall_hook> syscalls;

// Keep track of the states for the various processes
static __gnu_cxx::hash_map<pid_t, pid_state> state;

static void init_handlers()
{
    syscalls[SYS_geteuid]=syscall_hook(sys_getuid, "geteuid");
#ifdef SYS_geteuid32
    syscalls[SYS_geteuid32]=syscall_hook(sys_getuid, "geteuid");
#endif
    syscalls[SYS_getuid]=syscall_hook(sys_getuid, "getuid");
#ifdef SYS_getuid32
    syscalls[SYS_getuid32]=syscall_hook(sys_getuid, "getuid");
#endif
    syscalls[SYS_getegid]=syscall_hook(sys_getuid, "getegid");
#ifdef SYS_getegid32
    syscalls[SYS_getegid32]=syscall_hook(sys_getuid, "getegid");
#endif
    syscalls[SYS_getgid]=syscall_hook(sys_getuid, "getgid");
#ifdef SYS_getgid32
    syscalls[SYS_getgid32]=syscall_hook(sys_getuid, "getgid");
#endif

//    syscalls[SYS_fork]=syscall_hook(sys_fork, "fork");
//    syscalls[SYS_vfork]=syscall_hook(sys_fork, "vfork");
//    syscalls[SYS_clone]=syscall_hook(sys_fork, "clone");
    syscalls[SYS_execve]=syscall_hook(sys_execve, "execve");
#ifdef SYS_sigreturn
    syscalls[SYS_sigreturn]=syscall_hook(sys_sigreturn, "sigreturn");
#endif
    syscalls[SYS_setsid]=syscall_hook(sys_setsid, "setsid");
#ifdef SYS_wait4
    syscalls[SYS_wait4]=syscall_hook(sys_wait4, "wait4");
#endif
    syscalls[SYS_ptrace]=syscall_hook(sys_ptrace, "ptrace");

    syscalls[SYS_stat64]=syscall_hook(sys_stat64, "stat64");
    syscalls[SYS_fstat64]=syscall_hook(sys_stat64, "fstat64");
    syscalls[SYS_lstat64]=syscall_hook(sys_stat64, "lstat64");

    syscalls[SYS_chown]=syscall_hook(sys_chown, "chown32");
#ifdef SYS_chown32
    syscalls[SYS_chown32]=syscall_hook(sys_chown, "chown32");
#endif
    syscalls[SYS_fchown]=syscall_hook(sys_chown, "fchown32");
#ifdef SYS_fchown32
    syscalls[SYS_fchown32]=syscall_hook(sys_chown, "fchown32");
#endif
    syscalls[SYS_lchown]=syscall_hook(sys_chown, "lchown32");
#ifdef SYS_lchown32
    syscalls[SYS_lchown32]=syscall_hook(sys_chown, "lchown32");
#endif

    syscalls[SYS_chmod]=syscall_hook(sys_chmod, "chmod");
    syscalls[SYS_fchmod]=syscall_hook(sys_chmod, "fchmod");

    syscalls[SYS_mknod]=syscall_hook(sys_mknod, "mknod");
    syscalls[SYS_open]=syscall_hook(sys_open, "open");
    syscalls[SYS_mkdir]=syscall_hook(sys_mkdir, "mkdir");
    syscalls[SYS_symlink]=syscall_hook(sys_symlink, "symlink");

    syscalls[SYS_mmap2]=syscall_hook(sys_mmap, "mmap2");
}

// Debug related functions
static const char *sig2str( int signum )
{
    static char buffer[64];

    switch(signum) {
#define SIGNAME(a) case a: return #a;
        SIGNAME(SIGHUP);
        SIGNAME(SIGINT);
        SIGNAME(SIGQUIT);
        SIGNAME(SIGILL);
        SIGNAME(SIGTRAP);
        SIGNAME(SIGABRT);
        SIGNAME(SIGBUS);
        SIGNAME(SIGFPE);
        SIGNAME(SIGKILL);
        SIGNAME(SIGSEGV);
        SIGNAME(SIGPIPE);
        SIGNAME(SIGALRM);
        SIGNAME(SIGTERM);
        SIGNAME(SIGCHLD);
        SIGNAME(SIGCONT);
        SIGNAME(SIGSTOP);
#undef SIGNAME
    default:
        sprintf(buffer, "signal %d", signum);
    }

    return buffer;
}

static const char *state2str( pid_state::states state )
{
    static char buffer[64];

    switch(state) {
#define STATENAME(a) case pid_state::a: return #a;
        STATENAME(INIT)
        STATENAME(NONE)
        STATENAME(RETURN)
        STATENAME(REDIRECT1)
        STATENAME(REDIRECT2)
        STATENAME(ALLOCATE)
        STATENAME(ALLOC_RETURN)
        STATENAME(WAITING)
        STATENAME(DEBUGGED1)
        STATENAME(DEBUGGED2)
#undef STATENAME
    }

    sprintf(buffer, "Unknown state %d", state);

    return buffer;
}

void dump_registers( pid_t pid )
{
    if( log_level>0 ) {
        void *state[PTLIB_STATE_SIZE];

        ptlib_save_state( pid, state );

        for( int i=0; i<PTLIB_STATE_SIZE; ++i )
            dlog("state[%d]=%p\n", i, state[i]);
    }
}

// State handling functions
static void notify_parent( pid_t parent, const pid_state::wait_state &waiting )
{
    if( parent==1 || parent==0 ) {
        // This process has no parent, or had a parent that already quit
        return;
    }
    dlog("notify_parent: "PID_F" sent a notify about "PID_F"(%x)\n", parent, waiting.pid, waiting.status);
    pid_state *proc_state=&state[parent];
    proc_state->waiting_signals.push_back( waiting );

    // Is the parent currently waiting?
    if( proc_state->state==pid_state::WAITING ) {
        // Call the original function handler, now that it has something to do
        if( syscalls[proc_state->orig_sc].func( -1, parent, proc_state ) ) {
            dlog("notify_parent: "PID_F" released from wait\n", parent);
            ptrace(PTRACE_SYSCALL, parent, 0, 0);
        }
    }
}

static void handle_exit( pid_t pid, int status, const struct rusage &usage )
{
    // Let's see if the process doing the exiting is even registered
    pid_state *proc_state=lookup_state(pid);
    dlog(NULL);
    assert(proc_state!=NULL);

    // The process was being debugged
    pid_state::wait_state waiting;

    waiting.usage=usage;
    waiting.pid=pid;
    waiting.status=status;

    if( proc_state->debugger!=0 ) {
        notify_parent( proc_state->debugger, waiting );
        state[proc_state->debugger].num_debugees--;
    }
#if PTLIB_PARENT_CAN_WAIT
    // If a parent can wait on a debugged child we need to notify it even if the child is being debugged,
    // but only if it actually has a parent (i.e. - was not reparented to init)
    // Of course, if the debugger IS the parent, there is no need to notify it twice
    if( proc_state->parent!=0 && proc_state->parent!=1 && proc_state->parent!=proc_state->debugger )
#else
    // If a parent cannot wait, we need to let it know ourselves only if it's not being debugged
    else
#endif
        notify_parent( proc_state->parent, waiting );

    // Is any process a child of this process?
    for( __gnu_cxx::hash_map<pid_t, pid_state>::iterator i=state.begin(); i!=state.end(); ++i ) {
        if( i->second.parent==pid ) {
            dlog("Reparenting process %d to init from %d\n", i->first);
            i->second.parent=1;
        }

        if( i->second.debugger==pid ) {
            dlog("Detaching process %d from recursive debugger %d\n", i->first, pid );
            i->second.debugger=0;
        }
    }
    state.erase(pid);
}

static void handle_new_process( pid_t parent, pid_t child )
{
    // The new process has the same memory allocated as the parent
    state[child].memory=state[parent].memory;
    state[child].mem_size=state[parent].mem_size;

    // Copy the session information
    state[child].parent=parent;
    state[child].session_id=state[parent].session_id;
    state[parent].num_children++;
}

static pid_t first_child; // PID of first child
static int comm_fd; // FD for communicating with the process "waiting" for the first child to exit
static int num_processes; // Number of running processes

int process_sigchld( pid_t pid, enum PTLIB_WAIT_RET wait_state, int status, long ret )
{
    long sig=0;

    //dlog("process_sigchld: "PID_F" state=%d, status=%x, ret=%d\n", pid, wait_state, status, ret );

    switch(wait_state) {
    case SYSCALL:
        {
            pid_state *proc_state=&state[pid];
            if( proc_state->state==pid_state::REDIRECT1 ) {
                // REDIRECT1 is just a filler state between the previous call, where the arguments were set up and
                // the call initiated, and the call's return (REDIRECT2). No need to actually call the handler
                dlog(PID_F": Calling syscall %d redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );
                proc_state->state=pid_state::REDIRECT2;
            } else if( proc_state->state==pid_state::REDIRECT2 ) {
                dlog(PID_F": Called syscall %d, redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );

                if( !syscalls[proc_state->orig_sc].func( ret, pid, proc_state ) )
                    sig=-1; // Mark for ptrace not to continue the process
            } else if( proc_state->state==pid_state::ALLOC_RETURN ) {
                if( !finish_allocation( ret, pid, proc_state ) )
                    sig=-1;
            } else {
                // Sanity check - returning from same syscall that got us in
                if( proc_state->state==pid_state::RETURN && ret!=proc_state->orig_sc ) {
                    dlog("process "PID_F" orig_sc=%d actual sc=%d state=%d\n", pid, proc_state->orig_sc, ret, state2str(proc_state->state));
                    dlog(NULL);
                    assert( proc_state->state!=pid_state::RETURN || ret==proc_state->orig_sc );
                }

                if( proc_state->state==pid_state::NONE && proc_state->debugger!=0 && proc_state->trace_mode==PTRACE_SYSCALL ) {
                    // Notify the debugger before the syscall
                    proc_state->context_state[0]=(void *)wait_state;
                    proc_state->context_state[1]=(void *)status;
                    proc_state->context_state[2]=(void *)ret;
                    proc_state->state=pid_state::DEBUGGED1;

                    pid_state::wait_state waiting;
                    waiting.pid=pid;
                    waiting.status=status;
                    getrusage( RUSAGE_CHILDREN, &waiting.usage ); // XXX BUG This is the wrong function!
                    notify_parent( proc_state->debugger, waiting );
                    sig=-1; // We'll halt the program until the "debugger" decides what to do with it
                } else {
                    // No debugger or otherwise we need to go ahead with this syscall
                    if( proc_state->state==pid_state::DEBUGGED1 ) {
                        proc_state->state=pid_state::NONE;

                        // The debugger may have changed the system call to execute - we will respect it
                        ret=ptlib_get_syscall( pid );
                    }

                    if( proc_state->state==pid_state::NONE )
                        // Store the syscall type here (we are not in override)
                        proc_state->orig_sc=ret;

                    if( syscalls.find(ret)!=syscalls.end() ) {
                        dlog(PID_F": Called %s(%s)\n", pid, syscalls[ret].name, state2str(proc_state->state));

                        if( !syscalls[ret].func( ret, pid, proc_state ) )
                            sig=-1; // Mark for ptrace not to continue the process
                    } else {
                        dlog(PID_F": Unknown syscall %ld(%s)\n", pid, ret, state2str(proc_state->state));
                        if( proc_state->state==pid_state::NONE )
                            proc_state->state=pid_state::RETURN;
                        else if( proc_state->state==pid_state::RETURN )
                            proc_state->state=pid_state::NONE;
                    }

                    // Check for post-syscall debugger callback
                    if( proc_state->state==pid_state::NONE && proc_state->debugger!=0 && proc_state->trace_mode==PTRACE_SYSCALL ) {
                        proc_state->state=pid_state::DEBUGGED2;

                        pid_state::wait_state waiting;
                        waiting.pid=pid;
                        waiting.status=status;
                        getrusage( RUSAGE_CHILDREN, &waiting.usage ); // XXX BUG This is the wrong function!
                        notify_parent( proc_state->debugger, waiting );
                        sig=-1; // Halt process until "debugger" decides it can keep on going
                    }
                }
            }
        }
        break;
    case SIGNAL:
        dlog(PID_F": Signal %s\n", pid, sig2str(ret));
        if( state[pid].debugger==0 )
            sig=ret;
        else {
            // Pass the signal to the debugger
            pid_state::wait_state waiting;
            waiting.pid=pid;
            waiting.status=status;
            getrusage( RUSAGE_CHILDREN, &waiting.usage ); // XXX BUG this is the wrong function!
            notify_parent( state[pid].debugger, waiting );
            sig=-1;
        }
        break;
    case EXIT:
    case SIGEXIT:
        {
            if( wait_state==EXIT ) {
                dlog(PID_F": Exit with return code %ld\n", pid, ret);
            } else {
                dlog(PID_F": Exit with %s\n", pid, sig2str(ret));
            }

            struct rusage rusage;
            getrusage( RUSAGE_CHILDREN, &rusage );
            handle_exit(pid, status, rusage );
            if( pid==first_child && comm_fd!=-1 ) {
                write( comm_fd, &status, sizeof(status) );
                close( comm_fd );
                comm_fd=-1;
            }

            num_processes--;
        }
        break;
    case NEWPROCESS:
        {
            dlog(PID_F": Created new child process %ld\n", pid, ret);
            handle_new_process( pid, ret );
            num_processes++;
        }
    }

    return sig;
}

int process_children(pid_t _first_child, int _comm_fd, pid_t session_id )
{
    // Create a state for the first child
    first_child=_first_child;
    comm_fd=_comm_fd;

    state[first_child]=pid_state();
    state[first_child].session_id=session_id; // The initial session ID
    init_handlers();

    dlog( "Begin the process loop\n" );

    num_processes=1;

    while(num_processes>0) {
        int status;
        pid_t pid;
        long ret;
        ptlib_extra_data data;
        
        enum PTLIB_WAIT_RET wait_state;
        if( !ptlib_wait( &pid, &status, &data ) ) {
            dlog("ptlib_wait failed\n");
            continue;
        }

        // If this is the first time we see this process, we need to init the ptrace options for it
        if( state[pid].state==pid_state::INIT ) {
            dlog( PID_F": Init new process\n", pid);

            ptlib_prepare(pid);
            state[pid].state=pid_state::NONE;
        }

        ret=ptlib_parse_wait( pid, status, &wait_state );

        long sig=process_sigchld( pid, wait_state, status, ret );

        // The show must go on
        if( sig>=0 )
            ptrace(PTRACE_SYSCALL, pid, 0, sig);
    }

    return 0;
}

bool allocate_process_mem( pid_t pid, pid_state *state, int sc_num )
{
    dlog("allocate_process_mem: "PID_F" running syscall %d needs process memory\n", pid, sc_num );

    // Save the old state
    ptlib_save_state( pid, state->saved_state );
    state->orig_sc=sc_num;
    state->state=pid_state::ALLOCATE;

    // Translate the whatever call into an mmap
    ptlib_set_syscall( pid, SYS_mmap2 );

    ptlib_set_argument( pid, 1, 0 ); // start pointer
    ptlib_set_argument( pid, 2, (void *)sysconf(_SC_PAGESIZE) ); // Length of page - we allocate exactly one page
    ptlib_set_argument( pid, 3, (void *)(PROT_EXEC|PROT_READ|PROT_WRITE) ); // Protection - allow execute
    ptlib_set_argument( pid, 4, (void *)(MAP_PRIVATE|MAP_ANONYMOUS) ); // Flags - anonymous memory allocation
    ptlib_set_argument( pid, 5, (void *)-1 ); // File descriptor
    ptlib_set_argument( pid, 6, 0 ); // Offset

    return true;
}

bool sys_mmap( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        dlog("mmap: "PID_F" direct call\n", pid);
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        dlog("mmap: "PID_F" direct return\n", pid);
        state->state=pid_state::NONE;
    } else if( state->state==pid_state::ALLOCATE ) {

        if( ptlib_success( pid, sc_num ) ) {
            state->memory=ptlib_get_retval( pid );
            state->mem_size=sysconf( _SC_PAGESIZE );
            dlog("mmap: "PID_F" allocated for our use %d bytes at %p\n", pid, state->mem_size, state->memory);
            
            ptlib_prepare_memory( pid, &state->memory, &state->mem_size );

            // Memory is prepared, we can now use it to restart the original system call
            state->state=pid_state::ALLOC_RETURN;
            return ptlib_generate_syscall( pid, state->orig_sc , state->memory );
        } else {
            // The allocation failed. What can you do except kill the process?
            dlog("mmap: "PID_F" our memory allocation failed with error. Kill process. %s\n", pid,
                strerror(ptlib_get_error(pid, sc_num)) );
            ptrace( PTRACE_KILL, pid, 0, 0 );
            return false;
        }
        state->state=pid_state::NONE;
    }

    return true;
}

static bool finish_allocation( int sc_num, pid_t pid, pid_state *state )
{
    ptlib_restore_state( pid, state->saved_state );
    state->state=pid_state::NONE;

    syscall_hook *sys=&syscalls[sc_num];
    dlog("finish_allocation: "PID_F" restore state and call %s handler\n", pid, sys->name );

    return sys->func( sc_num, pid, state );
}

pid_state *lookup_state( pid_t pid ) {
    __gnu_cxx::hash_map<pid_t, pid_state>::iterator process=state.find(pid);

    if( process!=state.end() ) {
        return &process->second;
    }

    return NULL;
}
