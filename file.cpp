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

#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>

#include <assert.h>

#include "syscalls.h"
#include "file_lie.h"
#include "arch/platform.h"

// "stat" structure size and layout too greatly depends on the precise syscall used. We define it here, just in case

// Same function for stat64, lstat64 and fstat64
bool sys_stat64( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Entering the syscall
        state->state=pid_state::RETURN;
        state->saved_state[0]=ptlib_get_argument( pid, 2 ); // Store the pointer to the stat struct
        dlog("stat64: %d stored pointer at %p\n", pid, state->saved_state[0] );
    } else if( state->state==pid_state::RETURN ) {
        // Returning from the syscall
        void *returncode=ptlib_get_retval( pid );
        dlog("stat64: %d returned %x\n", pid, returncode);
        if( ptlib_success( pid, sc_num ) ) {
            struct ptlib_stat64 ret;
            struct stat_override override;

            ptlib_get_mem( pid, state->saved_state[0], &ret, sizeof(ret) );

            // Copy the current mode into the override struct
            override.mode=ret.mode;

            if( get_map( ret.dev, ret.ino, &override ) ) {
                ret.mode=override.mode;
                ret.uid=override.uid;
                ret.gid=override.gid;
                if( S_ISBLK(ret.mode) || S_ISCHR(ret.mode) )
                    ret.rdev=override.dev_id;

                // XXX the dlog may actually be platform dependent, based on the size of dev and inode
                dlog("stat64: %d dev=%llx inode=%lld mode=%o uid=%d gid=%d\n", pid, ret.dev, ret.ino, ret.mode, ret.uid, ret.gid );
                ptlib_set_mem( pid, &ret, state->saved_state[0], sizeof(struct stat) );
            }
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_chmod( int sc_num, pid_t pid, pid_state *state )
{
    dlog("chmod: %d started\n", pid);
    if( state->state==pid_state::NONE ) {
        if( state->memory==NULL ) {
            return allocate_process_mem( pid, state, sc_num );
        }

        state->saved_state[0]=ptlib_get_argument( pid, 1 ); // Store the filename/filedes
        mode_t mode=(mode_t)ptlib_get_argument( pid, 2 ); // Store the requested mode
        state->saved_state[1]=(void *)mode;

        mode=mode&0777;
        ptlib_set_argument( pid, 2, (void *) mode ); // Zero out the S* field

        dlog("chmod: %d mode %o changed to %o\n", pid, state->saved_state[1], mode );
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        if( ptlib_success( pid, sc_num ) ) {
            dlog("chmod: %d chmod successful, performing stat so we can update the map\n", pid);

            // We need to call "stat/fstat" so we can know the dev/inode
            state->state=pid_state::REDIRECT1;
            ptlib_save_state( pid, state->saved_state+2 );
            state->orig_sc=sc_num;

            ptlib_set_argument( pid, 1, state->saved_state[0] );
            ptlib_set_argument( pid, 2, state->memory );
            switch( sc_num ) {
            case SYS_fchmod:
                return ptlib_generate_syscall( pid, SYS_fstat64, state->memory );
                break;
            case SYS_chmod:
                return ptlib_generate_syscall( pid, SYS_lstat64, state->memory );
                break;
            default:
                dlog("chmod: %d Oops! Unhandled syscall %d\n", pid, sc_num );
                abort();
                ptlib_restore_state( pid, state->saved_state+2 );
                ptlib_set_error( pid, sc_num, EFAULT );
                state->state=pid_state::NONE;
                break;
            }
        } else {
            state->state=pid_state::NONE;
            dlog("chmod: %d chmod failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)));
        }
    } else if( state->state==pid_state::REDIRECT1 ) {
        state->state=pid_state::REDIRECT2;
        dlog("chmod: %d REDIRECT1\n", pid );
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Update our lies database
        struct stat_override override;
        struct ptlib_stat64 stat;

        ptlib_get_mem( pid, state->memory, &stat, sizeof( stat ) );

        if( !get_map( stat.dev, stat.ino, &override ) ) {
            override.dev=stat.dev;
            override.inode=stat.ino;
            override.uid=stat.uid;
            override.gid=stat.uid;
            override.dev_id=stat.rdev;
        }
        override.mode=(stat.mode&~07000)|(((mode_t)state->saved_state[1])&07000);

        dlog("chmod: %d Setting override mode %o\n", pid, override.mode );
        set_map( &override );

        state->state=pid_state::NONE;
        ptlib_restore_state( pid, state->saved_state+2 );
    } else {
        dlog("chmod: %d unknown state %d\n", pid, state->state );
    }

    return true;
}
