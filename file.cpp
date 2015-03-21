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
#include <sys/stat.h>
#include <fcntl.h>

#include "syscalls.h"
#include "timespec.h"
#include "log.h"
#include "file_lie.h"

#include "parent.h"

void sys_fchownat( int sc_num, pid_t pid, pid_state *state )
{
    auto shared_mem_guard = state->uses_buffers();

    uid_t owner = ptlib::get_argument( pid, 3 );
    uid_t group = ptlib::get_argument( pid, 4 );

    // Turn this into a call to fstatat, so we know what dev:inode to change
    ptlib::set_syscall( pid, ptlib::preferred::FSTATAT );
    // First two arguments are the same for both syscalls
    ptlib::set_argument( pid, 3, state->m_proc_mem->non_shared_addr );

    // The flags argument is 5 on fchownat, 4 on fstatat
    int flags = ptlib::get_argument( pid, 5 );
    ptlib::set_argument( pid, 4, flags );

    state->ptrace_syscall_wait(pid, 0);

    if( !ptlib::success( pid, ptlib::preferred::FSTATAT ) ) {
        shared_mem_guard.unlock();
        // If we failed the fstatat, our error is, most likely, the same as we would for fchownat for root
        state->end_handling();

        return;
    }

    struct stat stat = ptlib::get_stat_result( state->m_pid, state->m_tid, ptlib::preferred::FSTATAT,
            state->m_proc_mem->non_shared_addr );
    shared_mem_guard.unlock();

    auto file_list_lock = file_list::lock();
    file_list::stat_override *override = file_list::get_map( stat );

    if( owner!=uid_t(-1L) )
        override->uid = owner;
    if( group!=gid_t(-1L) )
        override->gid = group;

    // Clear SUID and SGID of file due to ownership change
    override->mode &= ~06000;

    file_list_lock.unlock();

    LOG_D() << "Changing ownership of file "<<override->dev<<":"<<override->inode<<
            " to "<<override->uid<<"."<<override->gid;

    state->end_handling();
}

static void real_stat( int sc_num, pid_t pid, pid_state *state, unsigned int buf_arg )
{
    int_ptr stat_addr = ptlib::get_argument( pid, buf_arg );

    state->ptrace_syscall_wait(pid, 0);

    if( ptlib::success( pid, sc_num ) ) {
        // Check the result to see if we need to lie about this file
        struct stat stat = ptlib::get_stat_result( state->m_pid, state->m_tid, sc_num, stat_addr );
        auto file_list_lock = file_list::lock();
        file_list::stat_override *override = file_list::get_map( stat, false );

        if( override ) {
            file_list::apply( stat, *override );

            ptlib::set_stat_result( state->m_pid, state->m_tid, sc_num, stat_addr, &stat );

            LOG_D() << "Reported false info for stat " << *override;
        }
    }

    state->end_handling();
}

void sys_fstatat( int sc_num, pid_t pid, pid_state *state )
{
    real_stat( sc_num, pid, state, 3 );
}

void sys_stat( int sc_num, pid_t pid, pid_state *state )
{
    real_stat( sc_num, pid, state, 2 );
}

static bool newly_created_timestamps( const struct stat &stat, struct timespec start_marker )
{
    static const long FS_TIMESTAMP_INTERVAL_NS = 100000000; // 100,000,000 nano, or 0.1 seconds

    if( stat.st_mtim != stat.st_ctim || stat.st_atim != stat.st_ctim ) {
        // A newly created file will have all timestamps the same
        return false;
    }

    struct timespec end_marker;
    clock_gettime( CLOCK_REALTIME, &end_marker );

    if( stat.st_ctim >= end_marker ) {
        return false;
    }

    if( stat.st_ctim.tv_nsec==0 ) {
        // The file system does not support nanoseconds percision
        return stat.st_ctim.tv_sec <= start_marker.tv_sec;
    } else {
        start_marker -= FS_TIMESTAMP_INTERVAL_NS;
        return stat.st_ctim >= start_marker;
    }
}

static void real_open( int sc_num, pid_t pid, pid_state *state, unsigned int offset )
{
    int_ptr flags = ptlib::get_argument( pid, offset+1 );
    mode_t requested_permissions, real_permissions;
    struct timespec start_marker;

    if( (flags&O_CREAT)!=0 ) {
        // Possibly creating a new file: make sure we don't deny ourselves read/write permissions on it
        requested_permissions = ptlib::get_argument( pid, offset+2 );

        real_permissions = requested_permissions;
        real_permissions &= ~07000; // Remove suid/sgid
        real_permissions |=  00600; // Add user read/write

        ptlib::set_argument( pid, offset+2, real_permissions );

        // Clock in before possible file creation so we can later compare times
        clock_gettime( CLOCK_REALTIME, &start_marker );
    }

    auto shared_mem_guard = state->uses_buffers();

    state->ptrace_syscall_wait(pid, 0);

    if( !ptlib::success( pid, sc_num ) || (flags&O_CREAT)==0 ) {
        state->end_handling();

        return;
    }

    // Syscall succeeded and it is possible we created a new file

    int fd = ptlib::get_retval( pid );

    auto saved_state = ptlib::save_state( pid );

    state->generate_syscall( pid );
    state->ptrace_syscall_wait( pid, 0 );

    ptlib::set_syscall( pid, ptlib::preferred::FSTAT );
    ptlib::set_argument( pid, 1, fd );
    ptlib::set_argument( pid, 2, state->m_proc_mem->non_shared_addr );
    state->ptrace_syscall_wait(pid, 0);

    // Fstat on a valid file descriptor should succeed
    // XXX What if a different thread closed it?
    ASSERT( ptlib::success( pid, ptlib::preferred::FSTAT ) );

    struct stat stat = ptlib::get_stat_result( state->m_pid, state->m_tid, ptlib::preferred::FSTAT,
            state->m_proc_mem->non_shared_addr );

    {
        auto file_list_lock = file_list::lock();
        file_list::stat_override *override = file_list::get_map( stat, false );

        if( (!override || override->transient) && S_ISREG(stat.st_mode) &&
                newly_created_timestamps( stat, start_marker ) )
        {
            // We did not already have the file in our database, and its creation time is after this function started
            // Yep, we created it :-)
            stat.st_uid = state->m_fsuid;
            stat.st_gid = state->m_fsgid;
            // TODO: Take umask into consideration. umask 222 doesn't currently work.
            stat.st_mode = S_IFREG | (stat.st_mode&00177) | (requested_permissions&07600);

            if( override ) {
                file_list::remove_map( stat.st_dev, stat.st_ino );
            }

            file_list::get_map( stat, true );

            LOG_D() << "Added mapping of new file inode " << stat.st_ino;
        }
    }

    ptlib::restore_state( pid, &saved_state );
    state->end_handling();
}

void sys_open( int sc_num, pid_t pid, pid_state *state )
{
    real_open( sc_num, pid, state, 1 );
}

void sys_openat( int sc_num, pid_t pid, pid_state *state )
{
    real_open( sc_num, pid, state, 2 );
}
