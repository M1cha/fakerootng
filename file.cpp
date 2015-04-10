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

static struct stat proxy_stat( pid_state *state, unsigned int num_path_args, bool follow_links )
{
    int syscall;

    switch( num_path_args ) {
    case 1:
        syscall = follow_links ? ptlib::preferred::STAT : ptlib::preferred::LSTAT;
        break;
    case 2:
        syscall = ptlib::preferred::FSTATAT;
        state->set_argument( 3, follow_links ? 0 : AT_SYMLINK_NOFOLLOW );
        break;
    default:
        LOG_F() << "proxy_stat called with num_path_args set to " << num_path_args << " pid " << state->m_pid;
        ASSERT(false);
    }

    state->set_syscall( syscall );
    state->set_argument( num_path_args, state->m_proc_mem->non_shared_addr );

    state->ptrace_syscall_wait(0);

    if( !state->success( syscall ) ) {
        throw debugee_exception( state->get_error( syscall ), "generated stat call" );
    }

    return state->get_stat_result( syscall, state->m_proc_mem->non_shared_addr );
}

static void real_chown( int sc_num, pid_state *state, unsigned offset, int stat_sc )
{
    auto shared_mem_guard = state->uses_buffers();

    uid_t owner = state->get_argument( offset );
    uid_t group = state->get_argument( offset+1 );

    // Turn this into a call to fstatat, so we know what dev:inode to change
    state->set_syscall( stat_sc );
    // First arguments are the same for both syscalls
    state->set_argument( offset, state->m_proc_mem->non_shared_addr );

    if( stat_sc==ptlib::preferred::FSTATAT ) {
        // The flags argument is 5 on fchownat, 4 on fstatat
        int flags = state->get_argument( offset+2 );
        state->set_argument( offset+1, flags );
    }

    state->ptrace_syscall_wait(0);

    if( !state->success( stat_sc ) ) {
        shared_mem_guard.unlock();
        // If we failed the fstatat, our error is, most likely, the same as we would for fchownat for root
        state->end_handling();

        return;
    }

    struct stat stat = state->get_stat_result( stat_sc, state->m_proc_mem->non_shared_addr );
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

void sys_fchownat( int sc_num, pid_state *state )
{
    real_chown( sc_num, state, 2, ptlib::preferred::FSTATAT );
}

void sys_fchown( int sc_num, pid_state *state )
{
    real_chown( sc_num, state, 1, ptlib::preferred::FSTAT );
}

void sys_chown( int sc_num, pid_state *state )
{
    real_chown( sc_num, state, 1, ptlib::preferred::STAT );
}

void sys_lchown( int sc_num, pid_state *state )
{
    real_chown( sc_num, state, 1, ptlib::preferred::LSTAT );
}

static void real_stat( int sc_num, pid_state *state, unsigned int buf_arg )
{
    int_ptr stat_addr = state->get_argument( buf_arg );

    state->ptrace_syscall_wait(0);

    if( state->success( sc_num ) ) {
        // Check the result to see if we need to lie about this file
        struct stat stat = state->get_stat_result( sc_num, stat_addr );
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

void sys_fstatat( int sc_num, pid_state *state )
{
    real_stat( sc_num, state, 2 );
}

void sys_stat( int sc_num, pid_state *state )
{
    real_stat( sc_num, state, 1 );
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

static void real_real_open( int sc_num, pid_state *state, unsigned int offset, int flags );
static void real_open( int sc_num, pid_state *state, unsigned int offset )
{
    int_ptr flags = state->get_argument( offset );

    real_real_open( sc_num, state, offset, flags );
}

static void real_real_open( int sc_num, pid_state *state, unsigned int offset, int flags )
{
    mode_t requested_permissions, real_permissions;
    struct timespec start_marker;

    if( (flags&O_CREAT)!=0 ) {
        // Possibly creating a new file: make sure we don't deny ourselves read/write permissions on it
        requested_permissions = state->get_argument( offset+1 );
        requested_permissions &= ~state->m_umask;

        real_permissions = requested_permissions;
        real_permissions &= ~07000; // Remove suid/sgid
        real_permissions |=  00600; // Add user read/write
        if( (requested_permissions & 0011) != 0 )
            real_permissions |=  00100; // Add user execute

        state->set_argument( offset+1, real_permissions );

        // Clock in before possible file creation so we can later compare times
        clock_gettime( CLOCK_REALTIME, &start_marker );
    }

    auto shared_mem_guard = state->uses_buffers();

    state->ptrace_syscall_wait(0);

    if( (flags&O_CREAT)==0 || !state->success( sc_num ) ) {
        state->end_handling();

        return;
    }

    // Syscall succeeded and it is possible we created a new file

    int fd = state->get_retval();

    auto saved_state = state->save_state();

    state->generate_syscall();
    state->ptrace_syscall_wait( 0 );

    state->set_syscall( ptlib::preferred::FSTAT );
    state->set_argument( 0, fd );
    state->set_argument( 1, state->m_proc_mem->non_shared_addr );
    state->ptrace_syscall_wait(0);

    // Fstat on a valid file descriptor should succeed
    // XXX What if a different thread closed it?
    ASSERT( state->success( ptlib::preferred::FSTAT ) );

    struct stat stat = state->get_stat_result( ptlib::preferred::FSTAT, state->m_proc_mem->non_shared_addr );

    {
        auto file_list_lock = file_list::lock();
        file_list::stat_override *override = file_list::get_map( stat, false );

        if( (!override || override->transient) && S_ISREG(stat.st_mode) &&
                newly_created_timestamps( stat, start_marker ) )
        {
            // We did not already have the file in our database, and its creation time is after this function started
            // Yep, we created it :-)
            stat.st_uid = state->m_euid;
            stat.st_gid = state->m_egid;
            // TODO: Take umask into consideration. umask 222 doesn't currently work.
            stat.st_mode = S_IFREG | (stat.st_mode&00077) | (requested_permissions&07700);

            if( override ) {
                file_list::remove_map( stat.st_dev, stat.st_ino );
            }

            file_list::get_map( stat, true );

            LOG_D() << "Added mapping of new file inode " << stat.st_ino;
        }
    }

    state->restore_state( &saved_state );
    state->end_handling();
}

void sys_open( int sc_num, pid_state *state )
{
    real_open( sc_num, state, 1 );
}

void sys_creat( int sc_num, pid_state *state )
{
    real_real_open( sc_num, state, 1, O_CREAT|O_WRONLY|O_TRUNC );
}

void sys_openat( int sc_num, pid_state *state )
{
    real_open( sc_num, state, 2 );
}

static void real_unlink( int sc_num, pid_state *state, unsigned int num_path_args )
{
    // We need to know whether the file was, indeed, deleted. Possible methods:
    // First method:
    // First, open the file. Next, unlink the file. Then, fstat the file.
    // Problem - cannot do that for symbolic links. Also, what if we do not have open permissions?
    //
    // Second method:
    // lstat the file before, unlink. If link count before was 1, inode is no more.
    // Problem - someone else may have linked it while between the lstat and the unlink.
    //
    // Third method:
    // link the file to a temporary name, unlink the original, check link count on temporary name.
    // Problem - not easy to translate relative name to one that can be used from another process. Also, yeach!

    // For now, implement the second method
    auto shared_mem_guard = state->uses_buffers();
    auto saved_state = state->save_state();

    try {
        struct stat stat = proxy_stat( state, num_path_args, false );

        state->generate_syscall();
        state->ptrace_syscall_wait( 0 );
        state->restore_state( &saved_state );
        state->ptrace_syscall_wait( 0 );

        if( ( stat.st_nlink==1 || S_ISDIR(stat.st_mode) ) && state->success( sc_num ) ) {
            file_list::mark_map_stale( stat.st_dev, stat.st_ino );
        }
    } catch(const debugee_exception &ex) {
        LOG_D() << state << " failed during unlink: " << ex.what();
    }

    state->end_handling();
}

void sys_unlink( int sc_num, pid_state *state )
{
    real_unlink( sc_num, state, 1 );
}

void sys_unlinkat( int sc_num, pid_state *state )
{
    real_unlink( sc_num, state, 2 );
}

void sys_umask( int sc_num, pid_state *state )
{
    mode_t old_mask = state->m_umask;

    mode_t real_mask = state->get_argument( 0 ) & 0777;
    state->m_umask = real_mask;

    real_mask &= 0077;
    state->set_argument( 0, real_mask );

    state->ptrace_syscall_wait( 0 );

    old_mask |= state->get_retval();

    state->set_retval( old_mask );
    LOG_D() << state << "setting thread umask from " << OCT_FORMAT(old_mask, 3) << " to " <<
            OCT_FORMAT( state->m_umask, 3 );

    state->end_handling();
}

static void real_mkdir( int sc_num, pid_state *state, unsigned int offset )
{
    auto shared_mem_guard = state->uses_buffers();

    auto saved_state = state->save_state();

    mode_t requested_permissions = state->get_argument( offset );
    requested_permissions &= ~state->m_umask;

    mode_t real_permissions = requested_permissions;
    real_permissions &= ~07000; // Remove suid/sgid
    real_permissions |=  00700; // Add user read/write/execute
    state->set_argument( offset, real_permissions );

    state->ptrace_syscall_wait( 0 );

    if( state->success( sc_num ) ) {
        // Need to find out the new directory's inode number
        state->generate_syscall();
        state->ptrace_syscall_wait( 0 );

        state->restore_state( &saved_state );
        int stat_syscall;
        switch( offset ) {
        case 1:
            stat_syscall = ptlib::preferred::STAT;
            break;
        case 2:
            stat_syscall = ptlib::preferred::FSTATAT;
            state->set_argument( offset+1, 0 ); // No flags - follow symlink
            break;
        default:
            ASSERT(offset==1 || offset==2);
        }
        state->set_syscall( stat_syscall );

        state->set_argument( offset, state->m_proc_mem->non_shared_addr );
        state->ptrace_syscall_wait(0);

        if( !state->success( stat_syscall ) ) {
            LOG_E() << state << " mkdir succeeded followed by failed stat with errno " <<
                    state->get_error( stat_syscall );
        } else {
            struct stat stat = state->get_stat_result( stat_syscall, state->m_proc_mem->non_shared_addr );

            if( !S_ISDIR(stat.st_mode) ) {
                LOG_E() << state << " mkdir succeeded, but did not create directory. Inode: " << stat.st_dev << ":" <<
                        stat.st_ino;
            } else {
                auto file_list_lock = file_list::lock();
                file_list::remove_map( stat.st_dev, stat.st_ino );

                stat.st_mode = S_IFDIR | (stat.st_mode & 00077) | (requested_permissions & 07700);
                stat.st_uid = state->m_euid;
                stat.st_gid = state->m_egid;
                file_list::stat_override *override = file_list::get_map( stat, true );
                ASSERT( override );

                LOG_D() << "Added mapping of new dir inode " << stat.st_ino;
            }
        }

        state->set_retval( 0 );
    }

    state->end_handling();
}

void sys_mkdir( int sc_num, pid_state *state )
{
    real_mkdir( sc_num, state, 1 );
}

void sys_mkdirat( int sc_num, pid_state *state )
{
    real_mkdir( sc_num, state, 2 );
}

static void real_chmod( int sc_num, pid_state *state, int stat_sc, unsigned int offset )
{
    mode_t requested_permissions = state->get_argument( offset );
    auto saved_state = state->save_state();
    auto shared_mem_guard = state->uses_buffers();

    // First perform a stat to see who and/or what we're dealing with
    state->set_syscall( stat_sc );
    state->set_argument( offset, state->m_proc_mem->non_shared_addr );
    state->ptrace_syscall_wait( 0 );

    if( state->success( stat_sc ) ) {
        struct stat stat = state->get_stat_result( stat_sc, state->m_proc_mem->non_shared_addr );

        state->generate_syscall();
        state->ptrace_syscall_wait( 0 );

        mode_t real_permissions = requested_permissions;
        real_permissions &= ~07000; // Remove suid/sgid
        real_permissions |=  00600; // Add user read/write/execute
        if( S_ISDIR(stat.st_mode) || (requested_permissions & 0011) != 0 )
            real_permissions |= 00100;

        state->restore_state( &saved_state );
        state->set_argument( offset, real_permissions );
        state->ptrace_syscall_wait( 0 );

        if( state->success( sc_num ) ) {
            auto file_list_lock = file_list::lock();
            file_list::stat_override *override = file_list::get_map( stat, true );

            override->mode = (override->mode & S_IFMT) | (requested_permissions & 07777);
            LOG_D() << state << " Set mode of inode " << override->inode << " to " << OCT_FORMAT(override->mode, 4);
        }
    }
}

void sys_chmod( int sc_num, pid_state *state )
{
    real_chmod( sc_num, state, ptlib::preferred::STAT, 1 );
    state->end_handling();
}

void sys_fchmod( int sc_num, pid_state *state )
{
    real_chmod( sc_num, state, ptlib::preferred::FSTAT, 1 );
    state->end_handling();
}

void sys_fchmodat( int sc_num, pid_state *state )
{
    // We need a flags argument for the real_chmod, but we need to restore it to its original value upon return
    int_ptr saved_flags = state->get_argument( 3 );
    state->set_argument( 3, 0 );

    real_chmod( sc_num, state, ptlib::preferred::FSTATAT, 2 );

    state->set_argument( 3, saved_flags );
    state->end_handling();
}

static void real_mknod( int sc_num, pid_state *state, unsigned offset, int stat_sc, int stat_flags )
{
    auto shared_mem_guard = state->uses_buffers();
    auto saved_state = state->save_state();

    mode_t requested_mode = state->get_argument( offset );
    dev_t dev = state->get_argument( offset+1 );

    requested_mode &= ~state->m_umask;
    mode_t real_mode = (requested_mode & S_IFMT) | 00600 | (requested_mode & 00066);
    if( (requested_mode & 0111) != 0 ) {
        real_mode |= 00100;
    }
    
    if( S_ISCHR(requested_mode) || S_ISBLK(requested_mode) ) {
        LOG_D() << state << " squashing request for creating a device";
        real_mode = S_IFREG | (real_mode & 00666);
    }

    state->set_argument( offset, real_mode );

    state->ptrace_syscall_wait( 0 );

    if( state->success( sc_num ) ) {
        state->generate_syscall();
        state->ptrace_syscall_wait( 0 );

        state->restore_state( &saved_state );
        state->set_syscall( stat_sc );
        state->set_argument( offset, state->m_proc_mem->non_shared_addr );
        if( stat_flags != -1 ) {
            state->set_argument( offset+1, stat_flags );
        }
        state->ptrace_syscall_wait( 0 );

        if( state->success( stat_sc ) ) {
            struct stat stat = state->get_stat_result( stat_sc, state->m_proc_mem->non_shared_addr );

            if( (stat.st_mode & S_IFMT) != (real_mode & S_IFMT) ) {
                LOG_W() << state << " inode " << stat.st_dev << ":" << stat.st_ino << " returned inconsistent type. "
                        "Expected " << HEX_FORMAT( real_mode, 0 ) << ", got " << HEX_FORMAT( stat.st_mode, 0 );

                state->set_retval( 0 );
                state->end_handling();
                return;
            }

            stat.st_mode = (requested_mode & (S_IFMT | 07700)) | (stat.st_mode & 00066);
            stat.st_uid = state->m_euid;
            stat.st_gid = state->m_egid;
            stat.st_rdev = dev;

            auto file_list_lock = file_list::lock();
            file_list::remove_map( stat.st_dev, stat.st_ino );
            file_list::get_map( stat, true );
        }

        state->set_retval( 0 );
    }

    state->end_handling();
}

void sys_mknod( int sc_num, pid_state *state )
{
    real_mknod( sc_num, state, 1, ptlib::preferred::LSTAT, -1 );
}

void sys_mknodat( int sc_num, pid_state *state )
{
    real_mknod( sc_num, state, 2, ptlib::preferred::FSTATAT, AT_SYMLINK_NOFOLLOW );
}
