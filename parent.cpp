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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include MAP_INCLUDE

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <limits.h>
#include <string.h>

#include "arch/platform.h"

#include "syscalls.h"
#include "parent.h"
#include "shared_mem.h"
#include "process.h"

// forward declaration of function
static bool handle_memory_allocation( int sc_num, pid_t pid, pid_state *state );

// Keep track of handled syscalls
static MAP_CLASS<int, syscall_hook> syscalls;

// Keep track of the states for the various processes
static MAP_CLASS<pid_t, pid_state> state;

size_t static_mem_size, shared_mem_size;

static void init_handlers()
{
    syscalls[SYS_geteuid]=syscall_hook(sys_getuid, "geteuid");
#if defined(SYS_geteuid32)
    syscalls[SYS_geteuid32]=syscall_hook(sys_getuid, "geteuid");
#endif
    syscalls[SYS_getuid]=syscall_hook(sys_getuid, "getuid");
#if defined(SYS_getuid32)
    syscalls[SYS_getuid32]=syscall_hook(sys_getuid, "getuid");
#endif
    syscalls[SYS_getegid]=syscall_hook(sys_getuid, "getegid");
#if defined(SYS_getegid32)
    syscalls[SYS_getegid32]=syscall_hook(sys_getuid, "getegid");
#endif
    syscalls[SYS_getgid]=syscall_hook(sys_getuid, "getgid");
#if defined(SYS_getgid32)
    syscalls[SYS_getgid32]=syscall_hook(sys_getuid, "getgid");
#endif

    syscalls[SYS_fork]=syscall_hook(sys_fork, "fork");
    syscalls[SYS_vfork]=syscall_hook(sys_fork, "vfork");
#if defined(SYS_clone)
    syscalls[SYS_clone]=syscall_hook(sys_clone, "clone");
#endif

//    Execve is special cased
//    syscalls[SYS_execve]=syscall_hook(sys_execve, "execve");
#if defined(SYS_sigreturn)
    syscalls[SYS_sigreturn]=syscall_hook(sys_sigreturn, "sigreturn");
#endif
#if defined(SYS_rt_sigreturn)
    syscalls[SYS_rt_sigreturn]=syscall_hook(sys_sigreturn, "sigreturn");
#endif
    syscalls[SYS_setsid]=syscall_hook(sys_setsid, "setsid");
#if defined(SYS_wait4)
    syscalls[SYS_wait4]=syscall_hook(sys_wait4, "wait4");
#endif
#if defined(SYS_waitpid)
    syscalls[SYS_waitpid]=syscall_hook(sys_waitpid, "waitpid");
#endif
    syscalls[SYS_ptrace]=syscall_hook(sys_ptrace, "ptrace");
    syscalls[SYS_kill]=syscall_hook(sys_kill, "kill");

    syscalls[SYS_stat]=syscall_hook(sys_stat, "stat");
#ifdef SYS_stat64
    syscalls[SYS_stat64]=syscall_hook(sys_stat, "stat64");
#endif
    syscalls[SYS_fstat]=syscall_hook(sys_stat, "fstat");
#ifdef SYS_fstat64
    syscalls[SYS_fstat64]=syscall_hook(sys_stat, "fstat64");
#endif
    syscalls[SYS_lstat]=syscall_hook(sys_stat, "lstat");
#ifdef SYS_lstat64
    syscalls[SYS_lstat64]=syscall_hook(sys_stat, "lstat64");
#endif
#if defined(SYS_fstatat64) && HAVE_OPENAT
    syscalls[SYS_fstatat64]=syscall_hook(sys_fstatat64, "fstatat64");
#endif

    syscalls[SYS_chown]=syscall_hook(sys_chown, "chown");
#if defined(SYS_chown32)
    syscalls[SYS_chown32]=syscall_hook(sys_chown, "chown32");
#endif
    syscalls[SYS_fchown]=syscall_hook(sys_fchown, "fchown");
#if defined(SYS_fchown32)
    syscalls[SYS_fchown32]=syscall_hook(sys_fchown, "fchown32");
#endif
    syscalls[SYS_lchown]=syscall_hook(sys_lchown, "lchown");
#if defined(SYS_lchown32)
    syscalls[SYS_lchown32]=syscall_hook(sys_lchown, "lchown32");
#endif
#if defined(SYS_fchownat) && HAVE_OPENAT
    syscalls[SYS_fchownat]=syscall_hook(sys_fchownat, "fchownat");
#endif

    syscalls[SYS_chmod]=syscall_hook(sys_chmod, "chmod");
    syscalls[SYS_fchmod]=syscall_hook(sys_fchmod, "fchmod");
#if defined(SYS_fchmodat) && HAVE_OPENAT
    syscalls[SYS_fchmodat]=syscall_hook(sys_fchmodat, "fchmodat");
#endif

    syscalls[SYS_mknod]=syscall_hook(sys_mknod, "mknod");
#if defined(SYS_mknodat) && HAVE_OPENAT
    syscalls[SYS_mknodat]=syscall_hook(sys_mknodat, "mknodat");
#endif
    syscalls[SYS_open]=syscall_hook(sys_open, "open");
#if defined(SYS_openat) && HAVE_OPENAT
    syscalls[SYS_openat]=syscall_hook(sys_openat, "openat");
#endif
    syscalls[SYS_mkdir]=syscall_hook(sys_mkdir, "mkdir");
#if defined(SYS_mkdirat) && HAVE_OPENAT
    syscalls[SYS_mkdirat]=syscall_hook(sys_mkdirat, "mkdirat");
#endif
    syscalls[SYS_symlink]=syscall_hook(sys_symlink, "symlink");
#if defined(SYS_mkdirat) && HAVE_OPENAT
    syscalls[SYS_symlinkat]=syscall_hook(sys_symlinkat, "symlinkat");
#endif

    syscalls[SYS_chroot]=syscall_hook(sys_chroot, "chroot");
    syscalls[SYS_chdir]=syscall_hook(sys_chdir, "chdir");
    syscalls[SYS_getcwd]=syscall_hook(sys_getcwd, "getcwd");

    syscalls[SYS_mmap]=syscall_hook(sys_mmap, "mmap");
#ifdef SYS_mmap2
    syscalls[SYS_mmap2]=syscall_hook(sys_mmap, "mmap2");
#endif
    syscalls[SYS_munmap]=syscall_hook(sys_munmap, "munmap");
}

void init_globals()
{
    size_t page_size=sysconf(_SC_PAGESIZE);

    static_mem_size=page_size;
    shared_mem_size=2*PATH_MAX+ptlib_prepare_memory_len();
    // Round this to the higher page size
    shared_mem_size+=page_size-1;
    shared_mem_size-=shared_mem_size%page_size;

    shared_mem::init_size( shared_mem_size );
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
        STATENAME(REDIRECT3)
        STATENAME(ALLOCATE)
        STATENAME(ALLOC_RETURN)
        STATENAME(WAITING)
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

        for( unsigned int i=0; i<PTLIB_STATE_SIZE; ++i )
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
    dlog("notify_parent: "PID_F" sent a notify about "PID_F"(%x)\n", parent, waiting.pid(), waiting.status());
    pid_state *proc_state=&state[parent];
    proc_state->waiting_signals.push_back( waiting );

    // Is the parent currently waiting?
    if( proc_state->state==pid_state::WAITING ) {
        // Call the original function handler, now that it has something to do
        if( syscalls[proc_state->orig_sc].func( -1, parent, proc_state ) ) {
            dlog("notify_parent: "PID_F" released from wait\n", parent);
            ptlib_continue(PTRACE_SYSCALL, parent, 0);
        }
    }
}

static void handle_exit( pid_t pid, int status, const struct rusage &usage )
{
    // Let's see if the process doing the exiting is even registered
    pid_state *proc_state=lookup_state(pid);
    dlog(NULL);
    assert(proc_state!=NULL);

    // First thing first - notify the parent
#if PTLIB_PARENT_CAN_WAIT
    // If a parent can wait on a debugged child we need to notify it even if the child is being debugged,
    // but only if it actually has a parent (i.e. - was not reparented to init)
    // Of course, if the debugger IS the parent, there is no need to notify it twice
    if( proc_state->parent!=0 && proc_state->parent!=1 )
#else
    // If a parent cannot wait, we need to let it know ourselves only if it's not being debugged
    if( (proc_state->debugger==0 || proc_state->debugger==proc_state->parent) && proc_state->parent!=0 && proc_state->parent!=1 )
#endif
        notify_parent( proc_state->parent, pid_state::wait_state( pid, status, &usage, false ) );

    if( proc_state->debugger!=0 && proc_state->debugger!=proc_state->parent ) {
        // The process was being debugged - notify the debugger as well
        notify_parent( proc_state->parent, pid_state::wait_state( pid, status, &usage, true ) );
        state[proc_state->debugger].num_debugees--;
    }

    pid_state *parent_state;
    // Regardless of whether it is being notified or not, the parent's child num needs to be decreased
    if( proc_state->parent!=0 && proc_state->parent!=1 && (parent_state=lookup_state(proc_state->parent))!=NULL ) {
        parent_state->num_children--;
    }

    // Is any process a child of this process?
    for( MAP_CLASS<pid_t, pid_state>::iterator i=state.begin(); i!=state.end(); ++i ) {
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
    // Copy the session information
    int_ptr process_type=state[parent].context_state[0];

    if( (process_type&NEW_PROCESS_SAME_PARENT)==0 )
        state[child].parent=parent;
    else
        state[child].parent=state[parent].parent;

    state[child].session_id=state[parent].session_id;
    state[state[child].parent].num_children++;

    // if( (process_type&NEW_PROCESS_SAME_ROOT)==0 )
        // XXX Need to contrast deep copy with shallow copy of root
    state[child].root=state[parent].root;

    // Whether the VM was copied or shared, the new process has the same static and shared memory
    state[child].memory=state[parent].memory;
    state[child].shared_memory=state[parent].shared_memory;
    // If the VM is not shared, setting shared_memory but not shared_mem_local is an indication that the
    // old memory needs to be freed
    if( (process_type&NEW_PROCESS_SAME_VM)!=0 ) {
        // The processes share the same VM - have them share the same shared memory
        state[child].shared_mem_local=state[parent].shared_mem_local;
    }
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
            bool posttrap_always=false;

            pid_state *proc_state=&state[pid];
            if( proc_state->state==pid_state::REDIRECT1 ) {
                // REDIRECT1 is just a filler state between the previous call, where the arguments were set up and
                // the call initiated, and the call's return (REDIRECT2). No need to actually call the handler
                dlog(PID_F": Calling syscall %d redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );
                proc_state->state=pid_state::REDIRECT2;
            } else if( proc_state->state==pid_state::REDIRECT2 || proc_state->state==pid_state::REDIRECT3 ) {
                // REDIRECT2 means a return from a syscall generated by us.
                // REDIRECT3 means entering a syscall generated by us, but for which the handler function would like
                // to be notified (unlike REDIRECT1 above, which is short circuited)
                if( proc_state->orig_sc!=SYS_execve ) {
                    dlog(PID_F": Called syscall %d, redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );

                    if( !syscalls[proc_state->orig_sc].func( ret, pid, proc_state ) )
                        sig=-1; // Mark for ptrace not to continue the process
                } else {
                    // Special handling of the execve case
                    dlog(PID_F": Called syscall %d, redirected from execve\n", pid, ret );

                    if( !sys_execve( ret, pid, proc_state, posttrap_always ) )
                        sig=-1;
                }
            } else {
                if( proc_state->state==pid_state::ALLOCATE ) {
                    if( !handle_memory_allocation( ret, pid, proc_state ) )
                        sig=-1;
                }

                if( proc_state->state!=pid_state::ALLOCATE ) {
                    // Sanity check - returning from same syscall that got us in
                    if( proc_state->state==pid_state::RETURN && ret!=proc_state->orig_sc ) {
                        dlog("process "PID_F" orig_sc=%d actual sc=%d state=%d\n", pid, proc_state->orig_sc, ret,
                                state2str(proc_state->state));
                        dlog(NULL);
                        assert( proc_state->state!=pid_state::RETURN || ret==proc_state->orig_sc );
                    }

                    if( proc_state->state==pid_state::NONE && proc_state->debugger!=0 && proc_state->trace_mode==TRACE_SYSCALL ) {
                        dlog(PID_F": pre-syscall hook called for debugger "PID_F"\n", pid, proc_state->debugger );

                        // Notify the debugger before the syscall
                        proc_state->context_state[0]=wait_state;
                        proc_state->context_state[1]=status;
                        proc_state->context_state[2]=ret;
                        proc_state->trace_mode=TRACE_STOPPED1;

                        pid_state::wait_state waiting;
                        waiting.pid()=pid;
                        waiting.status()=status;
                        getrusage( RUSAGE_CHILDREN, &waiting.usage() ); // XXX BUG This is the wrong function!
                        waiting.debugonly()=true;
                        notify_parent( proc_state->debugger, waiting );
                        sig=-1; // We'll halt the program until the "debugger" decides what to do with it
                    } else if( !proc_state->shared_mem_local && proc_state->state==pid_state::NONE && ret!=SYS_execve && ret!=SYS_exit ) {
                        // We need to allocate memory
                        // No point in allocating memory when we are just entering an execve that will get rid of it
                        if( !allocate_process_mem( pid, proc_state, ret ) )
                            sig=-1;
                    } else {
                        // No debugger or otherwise we need to go ahead with this syscall
                        if( (proc_state->trace_mode&TRACE_MASK2)==TRACE_STOPPED1 ) {
                            proc_state->trace_mode&=TRACE_MASK1;

                            // The debugger may have changed the system call to execute - we will respect it
                            ret=ptlib_get_syscall( pid );
                        }

                        if( proc_state->state==pid_state::NONE )
                            // Store the syscall type here (we are not in override)
                            proc_state->orig_sc=ret;

                        if( syscalls.find(ret)!=syscalls.end() ) {
                            dlog(PID_F": Called %s(%s)\n", pid, syscalls[ret].name, state2str(proc_state->state));

                            if( !syscalls[ret].func( ret, pid, proc_state ) ) {
                                sig=-1; // Mark for ptrace not to continue the process
                            }
                        } else if( ret==SYS_execve ) {
                            dlog(PID_F": Called execve(%s)\n", pid, state2str(proc_state->state));

                            if( !sys_execve(ret, pid, proc_state, posttrap_always ) )
                                sig=-1;
                        } else {
                            dlog(PID_F": Unknown syscall %ld(%s)\n", pid, ret, state2str(proc_state->state));
                            if( proc_state->state==pid_state::NONE ) {
                                proc_state->state=pid_state::RETURN;
                            } else if( proc_state->state==pid_state::RETURN ) {
                                proc_state->state=pid_state::NONE;
                            }
                        }
                    }
                }
            }

            // Check for post-syscall debugger callback
            // If the system sends a SIGTRAP after a successful execve, the logic is entirely different
            if( proc_state->debugger!=0 && (
                    (proc_state->state==pid_state::NONE && proc_state->trace_mode==TRACE_SYSCALL) ||
                    posttrap_always )
              )
            {
                dlog(PID_F": notify debugger "PID_F" about post-syscall hook\n", pid, proc_state->debugger );
                proc_state->trace_mode=TRACE_STOPPED2;

                pid_state::wait_state waiting;
                waiting.pid()=pid;
                waiting.status()=status;
                getrusage( RUSAGE_CHILDREN, &waiting.usage() ); // XXX BUG This is the wrong function!
                waiting.debugonly()=true;
                notify_parent( proc_state->debugger, waiting );
                sig=-1; // Halt process until "debugger" decides it can keep on going
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
            waiting.pid()=pid;
            waiting.status()=status;
            getrusage( RUSAGE_CHILDREN, &waiting.usage() ); // XXX BUG this is the wrong function!
            waiting.debugonly()=true;
            state[pid].trace_mode=TRACE_STOPPED2;
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

    // Initialize the ptlib library
    ptlib_init();

    state[first_child]=pid_state();
    state[first_child].session_id=session_id; // The initial session ID
    init_handlers();
    init_globals();

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
            ptlib_continue(PTRACE_SYSCALL, pid, sig);
    }

    return 0;
}

bool allocate_process_mem( pid_t pid, pid_state *state, int sc_num )
{
    dlog("allocate_process_mem: "PID_F" running syscall %d needs process memory\n", pid, sc_num );

    state->orig_sc=sc_num;

    // Save the old state
    ptlib_save_state( pid, state->saved_state );
    state->state=pid_state::ALLOCATE;
    if( state->shared_memory!=NULL )
        state->context_state[0]=20; // Internal allocation state
    else
        state->context_state[0]=0; // Internal allocation state

    return handle_memory_allocation( sc_num, pid, state );
}

static bool allocate_shared_mem( pid_t pid, pid_state *state )
{
    char filename[PATH_MAX];

    const char *tmpdir=getenv("TMPDIR");
    if( tmpdir==NULL || strlen(tmpdir)>=PATH_MAX-sizeof("/fakeroot-ng.XXXXXX") )
        tmpdir="/tmp";

    sprintf(filename, "%s/fakeroot-ng.XXXXXX", tmpdir);

    int fd=mkstemp(filename);

    if( fd==-1 ) {
        dlog("allocate_shared_mem: "PID_F" Failed to create file %s: %s\n", pid, filename, strerror(errno) );

        // We'll kill the process
        ptlib_continue( PTRACE_KILL, pid, 0 );
        return false; // Freeze the process until the signal arrives
    }

    // Make sure that the file is big enough, but create it sparse
    lseek( fd, shared_mem_size-1, SEEK_SET );
    write( fd, filename, 1 );

    // Map the file into the local address space
    char *memory=(char *)mmap( NULL, shared_mem_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0 );

    if( memory==MAP_FAILED ) {
        dlog("allocate_shared_mem: "PID_F" filed to map file %s into memory: %s\n", pid, filename, strerror(errno) );

        // Cleanup
        close(fd);
        unlink(filename);

        ptlib_continue( PTRACE_KILL, pid, 0 );
        return false;
    }

    // Fill in the memory with necessary commands and adjust the pointer
    memcpy( memory, ptlib_prepare_memory(), ptlib_prepare_memory_len() );

    // We need to remember the name of the temporary file so we can unlink it
    strcpy(memory+ptlib_prepare_memory_len(), filename);

    // Cleanup
    close(fd);

    // Set the shared memory class to know who we are
    state->shared_mem_local=shared_mem(memory);
    state->shared_mem_local.set_pid(pid);

    // The local shared memory is mapped. Now we need to map the remote end
    // Generate a new system call
    // Copy the instructions for generating a syscall to the newly created memory
    ptlib_set_mem( pid, ptlib_prepare_memory(), state->memory, ptlib_prepare_memory_len() );

    // Fill in the parameters to open the same file
    ptlib_set_argument( pid, 1, ((int_ptr)state->memory)+ptlib_prepare_memory_len() );
    ptlib_set_string( pid, (char *)state->shared_mem_local.get(), ((char *)state->memory)+ptlib_prepare_memory_len() );
    ptlib_set_argument( pid, 2, O_RDONLY );

    return true;
}

// Table of states:
// Start states - if have nothing - 0
// if have static buffer and old shared buffer - 20
static bool handle_memory_allocation( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->context_state[0]++ ) {
    case 0:
        // Translate the whatever call into an mmap to allocate the process local memory
        ptlib_set_syscall( pid, PREF_MMAP );

        ptlib_set_argument( pid, 1, 0 ); // start pointer
        ptlib_set_argument( pid, 2, static_mem_size ); // Length of page(s)
        ptlib_set_argument( pid, 3, (PROT_EXEC|PROT_READ|PROT_WRITE) ); // Protection - allow execute
        ptlib_set_argument( pid, 4, (MAP_PRIVATE|MAP_ANONYMOUS) ); // Flags - anonymous memory allocation
        ptlib_set_argument( pid, 5, -1 ); // File descriptor
        ptlib_set_argument( pid, 6, 0 ); // Offset
        break;
    case 1:
        // First step - mmap just returned
        if( ptlib_success( pid, sc_num ) ) {
            state->memory=(void *)ptlib_get_retval( pid );
            dlog("handle_memory_allocation: "PID_F" allocated for our use %d bytes at %p\n", pid, static_mem_size, state->memory);

            // "All" we need now is the shared memory. First, let's generate the local version for it.
            if(allocate_shared_mem( pid, state ))
                return ptlib_generate_syscall( pid, SYS_open, ((char *)state->memory)+ptlib_prepare_memory_len() );
            else
                return false;
        } else {
            // The allocation failed. What can you do except kill the process?
            dlog("handle_memory_allocation: "PID_F" our memory allocation failed with error. Kill process. %s\n", pid,
                    strerror(ptlib_get_error(pid, sc_num)) );
            ptlib_continue( PTRACE_KILL, pid, 0 );
            return false;
        }
        break;
    case 20:
        // Start state for the case where there is already an allocated shared mem

        // Save the remote pointer to the old memory, so we can free it later
        state->context_state[2]=(int_ptr)state->shared_memory;

        // Need to reallocate the shared memory
        if(allocate_shared_mem( pid, state ) ) {
            return ptlib_set_syscall( pid, SYS_open )==0;
        } else {
            return false;
        }
    case 2:
        // The entrance to the "open" syscall on the shared file
        break;
    case 3:
    case 21:
        // The "open" syscall returned

        // Whether it failed or succeeded, we no longer need the file
        unlink( (char *)state->shared_mem_local.get() );

        if( ptlib_success( pid, sc_num ) ) {
            // Store the fd for our own future use
            state->context_state[1]=ptlib_get_retval( pid );

            // Perform the mmap
            ptlib_set_argument( pid, 1, NULL );
            ptlib_set_argument( pid, 2, shared_mem_size );
            ptlib_set_argument( pid, 3, PROT_READ|PROT_EXEC );
            ptlib_set_argument( pid, 4, MAP_SHARED );
            ptlib_set_argument( pid, 5, state->context_state[1] );
            ptlib_set_argument( pid, 6, 0 );

            ptlib_generate_syscall( pid, PREF_MMAP, (char *)state->memory+ptlib_prepare_memory_len() );
        } else {
            // open failed
            dlog( "handle_memory_allocation: "PID_F" process failed to open %s: %s\n", pid, state->shared_mem_local.get(),
                strerror(ptlib_get_error(pid, sc_num)) );
            ptlib_continue( PTRACE_KILL, pid, 0 );
            return false;
        }
        break;
    case 4:
    case 22:
        // The mmap call entry
        break;
    case 5:
    case 23:
        // mmap call return

        if( ptlib_success( pid, sc_num ) ) {
            // mmap succeeded
            state->shared_memory=(void *)(ptlib_get_retval( pid )+ptlib_prepare_memory_len());
            dlog("handle_memory_allocation: "PID_F" allocated for our use %d shared bytes at %p\n", pid, shared_mem_size,
                (char *)state->shared_memory-ptlib_prepare_memory_len());

            // We now need to close the file descriptor
            ptlib_set_argument( pid, 1, state->context_state[1] );

            return ptlib_generate_syscall( pid, SYS_close, state->shared_memory );
        } else {
            dlog( "handle_memory_allocation: "PID_F" process failed to mmap memory: %s\n", pid, strerror(ptlib_get_error(pid, sc_num) ) );

            ptlib_continue( PTRACE_KILL, pid, 0 );
            return false;
        }
        break;
    case 6:
    case 24:
        // Close call entry
        break;
    // The first time and repeat allocations diverge again - case 25 is handled further on
    case 7:
        // Close done - we can revert to whatever we were previously doing
        if( !ptlib_success( pid, sc_num ) ) {
            // If close failed, we'll log the error and leak the file descriptor, but otherwise do nothing about it
            dlog( "handle_memory_allocation: "PID_F" procss close failed: %s\n", pid, strerror(ptlib_get_error(pid, sc_num) ) );
        }
        return ptlib_generate_syscall( pid, state->orig_sc , state->shared_memory );
    case 8:
        // The syscall to restart is entering the kernel
        {
            ptlib_restore_state( pid, state->saved_state );
            state->state=pid_state::NONE;

            dlog("handle_memory_allocation: "PID_F" restore state and call handler for syscall %d\n", pid, sc_num );
        }
        break;
    case 25:
        // Close done - we now need to deallocate the previous shared mem
        if( !ptlib_success( pid, sc_num ) ) {
            // If close failed, we'll log the error and leak the file descriptor, but otherwise do nothing about it
            dlog( "handle_memory_allocation: "PID_F" procss close failed: %s\n", pid, strerror(ptlib_get_error(pid, sc_num) ) );
        }

        ptlib_set_argument( pid, 1, state->context_state[2]-ptlib_prepare_memory_len() );
        ptlib_set_argument( pid, 2, shared_mem_size );

        ptlib_generate_syscall( pid, SYS_munmap, state->shared_memory );
        break;
    case 26:
        // Syscall enter for munmap
        break;
    case 27:
        // Munmap done
        if( !ptlib_success( pid, sc_num ) ) {
            // Again, if the unmap failed, we'll log it but otherwise continue
            dlog( "handle_memory_allocation: "PID_F" process munmap failed: %s\n", pid, strerror( ptlib_get_error(pid, sc_num) ) );
        }

        // Restart the original system call
        state->context_state[0]=8; // Merge with the original code
        return ptlib_generate_syscall( pid, state->orig_sc, state->shared_memory );
    }

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
    }

    return true;
}

pid_state *lookup_state( pid_t pid ) {
    MAP_CLASS<pid_t, pid_state>::iterator process=state.find(pid);

    if( process!=state.end() ) {
        return &process->second;
    }

    return NULL;
}
