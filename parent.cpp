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
#include <sys/socket.h>

#include MAP_INCLUDE
#include <set>

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <limits.h>
#include <string.h>
#include <stdlib.h>

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
template <class key, class data> class map_class : public  MAP_CLASS<key, data> 
{
    // Inherit everything, just disable the dangerous operator[]
public:
    data &operator[] (const key &k)
    {
        return MAP_CLASS<key,data>::operator[] (k);
    }
    const data &operator[] ( const key &k) const
    {
        return MAP_CLASS<key,data>::operator[] (k);
    }
};

static map_class<pid_t, pid_state> state;

size_t static_mem_size, shared_mem_size;

static MAP_CLASS<pid_t, int> root_children; // Map of all root children

static int num_processes; // Number of running processes

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
    syscalls[SYS_vfork]=syscall_hook(sys_vfork, "vfork");
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
    syscalls[SYS_link]=syscall_hook(sys_link, "link");
#if defined(SYS_linkat) && HAVE_OPENAT
    syscalls[SYS_linkat]=syscall_hook(sys_linkat, "linkat");
#endif
    syscalls[SYS_unlink]=syscall_hook(sys_unlink, "unlink");
#if defined(SYS_unlinkat) && HAVE_OPENAT
    syscalls[SYS_unlinkat]=syscall_hook(sys_unlinkat, "unlinkat");
#endif
    syscalls[SYS_rename]=syscall_hook(sys_rename, "rename");
#if defined(SYS_renameat) && HAVE_OPENAT
    syscalls[SYS_renameat]=syscall_hook(sys_renameat, "renameat");
#endif
    syscalls[SYS_rmdir]=syscall_hook(sys_rmdir, "rmdir");
    syscalls[SYS_readlink]=syscall_hook(sys_generic_chroot_support_link_param1, "readlink");
#if defined(SYS_renameat) && HAVE_OPENAT
    syscalls[SYS_readlinkat]=syscall_hook(sys_generic_chroot_link_at, "readlinkat");
#endif
    syscalls[SYS_truncate]=syscall_hook(sys_generic_chroot_support_param1, "truncate");
#ifdef SYS_truncate64
    syscalls[SYS_truncate64]=syscall_hook(sys_generic_chroot_support_param1, "truncate64");
#endif
    syscalls[SYS_statfs]=syscall_hook(sys_generic_chroot_support_param1, "statfs"); // XXX Should last link be resolved?
#ifdef SYS_statfs64
    syscalls[SYS_statfs64]=syscall_hook(sys_generic_chroot_support_param1, "statfs64"); // XXX Should last link be resolved?
#endif
    syscalls[SYS_chdir]=syscall_hook(sys_generic_chroot_support_param1, "chdir");
    syscalls[SYS_access]=syscall_hook(sys_generic_chroot_support_param1, "access");
#if defined(SYS_faccessat) && HAVE_OPENAT
    syscalls[SYS_faccessat]=syscall_hook(sys_generic_chroot_at_link4, "faccessat");
#endif
    syscalls[SYS_utime]=syscall_hook(sys_generic_chroot_support_param1, "utime");
    syscalls[SYS_utimes]=syscall_hook(sys_generic_chroot_support_param1, "utimes");
#ifdef SYS_setxattr
    syscalls[SYS_setxattr]=syscall_hook(sys_generic_chroot_support_param1, "setxattr");
    syscalls[SYS_getxattr]=syscall_hook(sys_generic_chroot_support_param1, "getxattr");
    syscalls[SYS_listxattr]=syscall_hook(sys_generic_chroot_support_param1, "listxattr");
    syscalls[SYS_removexattr]=syscall_hook(sys_generic_chroot_support_param1, "removexattr");
#endif
#ifdef SYS_lsetxattr
    syscalls[SYS_lsetxattr]=syscall_hook(sys_generic_chroot_support_link_param1, "lsetxattr");
    syscalls[SYS_lgetxattr]=syscall_hook(sys_generic_chroot_support_link_param1, "lgetxattr");
    syscalls[SYS_llistxattr]=syscall_hook(sys_generic_chroot_support_link_param1, "llistxattr");
    syscalls[SYS_lremovexattr]=syscall_hook(sys_generic_chroot_support_link_param1, "lremovexattr");
#endif
#ifdef SYS_uselib
    syscalls[SYS_uselib]=syscall_hook(sys_generic_chroot_support_param1, "uselib");
#endif
#ifdef SYS_inotify_add_watch
    syscalls[SYS_inotify_add_watch]=syscall_hook(sys_generic_chroot_support_param1, "inotify_add_watch");
#endif
#if defined(SYS_futimesat) && HAVE_OPENAT
    syscalls[SYS_futimesat]=syscall_hook(sys_generic_chroot_at, "futimesat");
#endif
#if defined(SYS_utimensat) && HAVE_OPENAT
    syscalls[SYS_utimensat]=syscall_hook(sys_generic_chroot_at_link4, "utimensat");
#endif

    syscalls[SYS_chroot]=syscall_hook(sys_chroot, "chroot");
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
        STATENAME(ZOMBIE)
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
    pid_state *proc_state=lookup_state(parent);
    assert(proc_state!=NULL);

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

    // Set the process state to ZOMBIE with usage count of 1
    proc_state->state=pid_state::ZOMBIE;
    proc_state->context_state[0]=1;
    dlog("%s: "PID_F" is now a zombie\n", __func__, pid );

    pid_state *parent_state=lookup_state(proc_state->parent);

    // Notify the parent
#if PTLIB_PARENT_CAN_WAIT
    // If a parent can wait on a debugged child we need to notify it even if the child is being debugged,
    // but only if it actually has a parent (i.e. - was not reparented to init)
    // Of course, if the debugger IS the parent, there is no need to notify it twice
    if( proc_state->parent!=0 && proc_state->parent!=1 )
#else
    // If a parent cannot wait, we need to let it know ourselves only if it's not being debugged
    if( (proc_state->debugger==0 || proc_state->debugger==proc_state->parent) && proc_state->parent!=0 && proc_state->parent!=1 )
#endif
    {
        proc_state->context_state[0]++; // Update use count
        notify_parent( proc_state->parent, pid_state::wait_state( pid, status, &usage, false ) );
    }

    // Regardless of whether it is being notified or not, the parent's child num needs to be decreased
    if( parent_state!=NULL ) {
        parent_state->num_children--;
    }

    if( proc_state->debugger!=0 && proc_state->debugger!=proc_state->parent ) {
        // The process was being debugged - notify the debugger as well
        proc_state->context_state[0]++; // Update use count
        notify_parent( proc_state->parent, pid_state::wait_state( pid, status, &usage, true ) );
        state[proc_state->debugger].num_debugees--;
    }

    // Is any process a child of this process?
    // We need to delete all child zombie processes. This means changing the list while scanning it.
    // Instead, create a list of pids to delete
    std::set<pid_t> need_delete;
    for( MAP_CLASS<pid_t, pid_state>::iterator i=state.begin(); i!=state.end(); ++i ) {
        if( i->second.parent==pid ) {
            dlog("Reparenting process %d to init from %d\n", i->first, pid);
            i->second.parent=1;

            if( i->second.state==pid_state::ZOMBIE ) {
                // "init" should release it
                need_delete.insert(i->first);
            }
        } 
        
        if( i->second.debugger==pid ) {
            dlog("Detaching process %d from recursive debugger %d\n", i->first, pid );
            i->second.debugger=0;

            if( i->second.state==pid_state::ZOMBIE && i->second.parent!=pid ) {
                // The process is in zombie state, pid is its debugger but not parent
                need_delete.insert(i->first);
            }
        }
    }

    for( std::set<pid_t>::iterator i=need_delete.begin(); i!=need_delete.end(); ++i ) {
        delete_state(*i);
    }

    // Delete the state from our end. The state is reference counted, so it may not actually be deleted just yet
    delete_state(pid);
}

void handle_new_process( pid_t parent_id, pid_t child_id )
{
    // Copy the session information
    pid_state *child=&state[child_id]; // We actually want to create the state if it did not already exist

    if( child->state!=pid_state::INIT ) {
        // Due to platform incompatibilities and other issues, we may be called several times over the same
        // child. Don't make a fuss - just return.

        dlog("%s: Process "PID_F" already registered - not performing any operation\n", __FUNCTION__, child_id );

        return;
    }

    dlog("%s: Registering "PID_F" with parent "PID_F"\n", __FUNCTION__, child_id, parent_id );

    // The platform may want to init the process in some way
    ptlib_prepare(child_id);
    child->state=pid_state::NONE;

    pid_state *parent=lookup_state(parent_id);
    if( parent!=NULL ) {
        // If this assert fails, we somehow created a -1 process - not good
        dlog(NULL);
        assert(parent_id!=-1);

        // This process is not a root process - it has a parent

        int_ptr process_type=parent->context_state[0];

        if( (process_type&NEW_PROCESS_SAME_PARENT)==0 )
            child->parent=parent_id;
        else
            child->parent=parent->parent;

        pid_state *child_parent=lookup_state(child->parent);
        if( child_parent!=NULL ) {
            child_parent->num_children++;
        }

        child->session_id=parent->session_id;

        // if( (process_type&NEW_PROCESS_SAME_ROOT)==0 )
        // XXX Need to contrast deep copy with shallow copy of root
        child->root=parent->root;

        // Whether the VM was copied or shared, the new process has the same static and shared memory
        child->memory=parent->memory;
        child->shared_memory=parent->shared_memory;
        // If the VM is not shared, setting shared_memory but not shared_mem_local is an indication that the
        // old memory needs to be freed
        if( (process_type&NEW_PROCESS_SAME_VM)!=0 ) {
            // The processes share the same VM - have them share the same shared memory
            child->shared_mem_local=parent->shared_mem_local;
        }

        if( (process_type&NEW_PROCESS_SAME_DEBUGGER)!=0 ) {
            // The process inherits the debugger from the parent
            child->debugger=parent->debugger;
        }

        // Both parent and child need to call ptlib_fork_exit. We may need to copy the state
        // from one to the other.
        // XXX Need to figure out precise details.
        // ptlib_fork_state_copy( parent_id, parent->
        child->orig_sc=parent->orig_sc;
        child->state=parent->state;
    } else {
        // This is a root process - no parent. Set it with the real session ID
        child->session_id=getsid(child_id);
    }

    num_processes++;
}

int process_sigchld( pid_t pid, enum PTLIB_WAIT_RET wait_state, int status, long ret )
{
    long sig=0;

    pid_state *proc_state=lookup_state(pid);
    if( wait_state!=NEWPROCESS && proc_state==NULL ) {
        // The process does not exist!
        // Register it
        dlog("Caught unknown new process %lu, detected parent "PID_F"\n", ret, pid);
        dlog(NULL);
        pid_t parent_pid=ptlib_get_parent(pid);
        assert( parent_pid==0 || parent_pid==1 || state.find(parent_pid)!=state.end() ); // Make sure the parent is, indeed, ours

        // Handle the process creation before handling the syscall return
        process_sigchld( parent_pid, NEWPROCESS, status, pid );

        // Handle the rest of the syscall as a return from a syscall
        wait_state=SYSCALL;
        proc_state=lookup_state(pid);
        assert(proc_state!=NULL);
        ret=proc_state->orig_sc;
    }

    switch(wait_state) {
    case SYSCALL:
        {
            bool posttrap_always=false;

            if( proc_state->state==pid_state::REDIRECT1 ) {
                // REDIRECT1 is just a filler state between the previous call, where the arguments were set up and
                // the call initiated, and the call's return (REDIRECT2). No need to actually call the handler
                dlog(PID_F": Calling syscall %ld redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );
                proc_state->state=pid_state::REDIRECT2;
            } else if( proc_state->state==pid_state::REDIRECT2 || proc_state->state==pid_state::REDIRECT3 ) {
                // REDIRECT2 means a return from a syscall generated by us.
                // REDIRECT3 means entering a syscall generated by us, but for which the handler function would like
                // to be notified (unlike REDIRECT1 above, which is short circuited)
                if( proc_state->orig_sc!=SYS_execve ) {
                    dlog(PID_F": Called syscall %ld, redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );

                    if( !syscalls[proc_state->orig_sc].func( ret, pid, proc_state ) )
                        sig=-1; // Mark for ptrace not to continue the process
                } else {
                    // Special handling of the execve case
                    dlog(PID_F": Called syscall %ld, redirected from execve\n", pid, ret );

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
                        dlog("process "PID_F" orig_sc=%d actual sc=%ld state=%s\n", pid, proc_state->orig_sc, ret,
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
        if( proc_state->debugger==0 )
            sig=ret;
        else {
            // Pass the signal to the debugger
            pid_state::wait_state waiting;
            waiting.pid()=pid;
            waiting.status()=status;
            getrusage( RUSAGE_CHILDREN, &waiting.usage() ); // XXX BUG this is the wrong function!
            waiting.debugonly()=true;
            proc_state->trace_mode=TRACE_STOPPED2;
            notify_parent( proc_state->debugger, waiting );
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
            
            // If this was a root child, we may need to perform notification of exit status
            MAP_CLASS<pid_t, int>::iterator root_child=root_children.find(pid);
            if( root_child!=root_children.end() ) {
                if( root_child->second!=-1 ) {
                    write( root_child->second, &status, sizeof(status) );
                    close( root_child->second );
                }

                root_children.erase(root_child);
            }

            num_processes--;
        }
        break;
    case NEWPROCESS:
        {
            dlog(PID_F": Created new child process %ld\n", pid, ret);
            handle_new_process( pid, ret );
        }
    }

    return sig;
}

bool attach_debugger( pid_t child, int socket )
{
    dlog(NULL);

    // Attach a debugger to the child
    if( ptrace(PTRACE_ATTACH, child, 0, 0)!=0 ) {
        dlog("Could not start trace of process "PID_F": %s\n", child, strerror(errno) );

        return false;
    }
    dlog("Debugger successfully attached to process "PID_F"\n", child );

    // Let's free the process to do the exec
    errno=0;
    if( write( socket, "a", 1 )!=1 ) {
        dlog("Couldn't free child process - write failed: %s\n", strerror(errno) );

        return false;
    }

#if PTLIB_PARENT_CAN_WAIT
    close( socket );
    socket=-1;
#endif

    // If we start the processing loop too early, we might accidentally cath the "wait" where the master process (our grandparent)
    // is waiting for our parent to terminate.
    // In order to avoid that race, we wait until we notice that the process is sending itself a "USR1" signal to indicate it
    // is ready.

    bool sync=false;
    while( !sync ) {
        int status;

        waitpid( child, &status, 0 );

        if( WIFSTOPPED(status) ) {
            switch( WSTOPSIG(status) ) {
            case SIGUSR1:
                // SIGUSR1 - that's our signal
                dlog("Caught SIGUSR1 by child - start special handling\n");
                ptrace( PTRACE_SYSCALL, child, 0, 0 );
                sync=true;
                break;
            case SIGSTOP:
                dlog("Caught SIGSTOP\n");
                ptrace( PTRACE_CONT, child, 0, 0 ); // Continue the child in systrace mode
                break;
            case SIGTRAP:
                dlog("Caught SIGTRAP\n");
                ptrace( PTRACE_CONT, child, 0, 0 ); // Continue the child in systrace mode
                break;
            default:
                dlog("Caught signal %d\n", WSTOPSIG(status) );
                ptrace( PTRACE_CONT, child, 0, WSTOPSIG(status) );
                break;
            }
        } else {
            // Stopped for whatever other reason - just continue it
            dlog("Another stop %x\n", status );
            ptrace( PTRACE_CONT, child, 0, 0 );
        }
    }

    // Child has started, and is debugged
    root_children[child]=socket; // Mark this as a root child

    handle_new_process( -1, child ); // No parent - a root process

    return true;
}

// Do nothing signal handler for sigchld
static void sigchld_handler(int signum)
{
}

// Signify whether an alarm was received while we were waiting
static bool alarm_happened=false;

static void sigalrm_handler(int signum)
{
    alarm_happened=true;
}

int process_children( int master_socket )
{
    // Initialize the ptlib library
    ptlib_init();

    init_handlers();
    init_globals();

    dlog( "Begin the process loop\n" );

    // Prepare the signal masks so we do not lose SIGCHLD while we wait

    struct sigaction action;
    memset( &action, 0, sizeof( action ) );

    action.sa_handler=sigchld_handler;
    sigemptyset( &action.sa_mask );
    action.sa_flags=0;

    sigaction( SIGCHLD, &action, NULL );

    action.sa_handler=sigalrm_handler;
    sigaction( SIGALRM, &action, NULL );

    sigset_t orig_signals, child_signals;

    sigemptyset( &child_signals );
    sigaddset( &child_signals, SIGCHLD );
    sigaddset( &child_signals, SIGALRM );
    sigprocmask( SIG_BLOCK, &child_signals, &orig_signals );

    sigdelset( &orig_signals, SIGCHLD );
    sigdelset( &orig_signals, SIGALRM );

    // Prepare the file descriptors
    fd_set file_set;

    FD_ZERO(&file_set);
    if( master_socket>0 )
        FD_SET(master_socket, &file_set);

    while(num_processes>0) {
        int status;
        pid_t pid;
        long ret;
        ptlib_extra_data data;

        enum PTLIB_WAIT_RET wait_state;
        if( !ptlib_wait( &pid, &status, &data, true ) ) {
            if( errno==EAGAIN ) {
                // No process is waiting - halt until one exists or until the socket has something to say
                fd_set read_set=file_set;
                fd_set except_set=file_set;

                if( pselect( master_socket+1, &read_set, NULL, &except_set, NULL, &orig_signals )>=0 ) {
                    // Something happened on the socket - new root process?
                    int session_socket=accept( master_socket, NULL, 0 );
                    if( session_socket>=0 ) {
                        pid_t child=-1;

                        if( read( session_socket, &child, sizeof(child))>0 && child>0 ) {
                            dlog("Got asynchronous request to attach to process "PID_F"\n", child);

                            attach_debugger(child, session_socket);
                        }
                    }
                }

                // Did an alarm signal arrive?
                if( alarm_happened ) {
                    alarm_happened=false;

                    dump_states();
                }

            } else if( errno==ECHILD ) {
                // We should never get here. If we have no more children, we should have known about it already
                dlog( "BUG - ptlib_wait failed with %s while numchildren is still %d\n", strerror(errno), num_processes );
                dlog(NULL);
                num_processes=0;
            } else {
                dlog("ptlib_wait failed %d: %s\n", errno, strerror(errno) );
            }

            continue;
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

    const char *tmpdir=getenv("FAKEROOT_TMPDIR");

    if( tmpdir==NULL )
        tmpdir=getenv("TMPDIR");

    if( tmpdir==NULL || strlen(tmpdir)>=PATH_MAX-sizeof("/fakeroot-ng.XXXXXX") )
        tmpdir=DEFAULT_TMPDIR;

    sprintf(filename, "%s/fakeroot-ng.XXXXXX", tmpdir);

    int fd=mkstemp(filename);

    if( fd==-1 ) {
        dlog("allocate_shared_mem: "PID_F" Failed to create file %s: %s\n", pid, filename, strerror(errno) );

        // We'll kill the process
        ptlib_continue( PTRACE_KILL, pid, 0 );
        return false; // Freeze the process until the signal arrives
    }

    // Make sure that the file is big enough, but create it sparse
    ftruncate( fd, shared_mem_size );

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
            dlog("handle_memory_allocation: "PID_F" allocated for our use %lu bytes at %p\n", pid,
                    (unsigned long)static_mem_size, state->memory);

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
            ptlib_set_argument( pid, 1, (int_ptr)NULL );
            ptlib_set_argument( pid, 2, shared_mem_size );
            ptlib_set_argument( pid, 3, PROT_READ|PROT_EXEC );
            ptlib_set_argument( pid, 4, MAP_SHARED );
            ptlib_set_argument( pid, 5, state->context_state[1] );
            ptlib_set_argument( pid, 6, 0 );

            ptlib_generate_syscall( pid, PREF_MMAP, (char *)state->memory+ptlib_prepare_memory_len() );
        } else {
            // open failed
            dlog( "handle_memory_allocation: "PID_F" process failed to open %s: %s\n", pid, state->shared_mem_local.getc(),
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
            dlog("handle_memory_allocation: "PID_F" allocated for our use %lu shared bytes at %p\n", pid,
                    (unsigned long)shared_mem_size, (char *)state->shared_memory-ptlib_prepare_memory_len());

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

void delete_state( pid_t pid )
{
    pid_state *proc_state=lookup_state(pid);
    assert(proc_state!=NULL);
    assert(proc_state->state==pid_state::ZOMBIE);

    if( (--proc_state->context_state[0])==0 )
        state.erase(pid);
}

void dump_states()
{
    // Print the header
    dlog("PID\tParent\tState\n");

    for( map_class<pid_t, pid_state>::const_iterator i=state.begin(); i!=state.end(); ++i ) {
        dlog(PID_F"\t"PID_F"\t%s", i->first, i->second.parent, state2str(i->second.state) );

        if( i->second.state==pid_state::ZOMBIE ) {
            dlog("(%d)", (int)i->second.context_state[0]);
        }

        dlog("\n");
    }

    dlog(NULL);
}
