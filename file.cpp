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

// Helper function - fill in an override structure from a stat structure
static void stat_override_copy( const ptlib_stat64 *stat, stat_override *override )
{
    override->dev=stat->dev;
    override->inode=stat->ino;
    override->uid=stat->uid;
    override->gid=stat->uid;
    override->dev_id=stat->rdev;
    override->mode=stat->mode;
}

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

            if( get_map( ret.dev, ret.ino, &override ) ) {
                bool ok=true;

                ret.uid=override.uid;
                ret.gid=override.gid;
                if( S_ISBLK(override.mode) || S_ISCHR(override.mode) ) {
                    // Only turn regular files into devices
                    if( !S_ISREG( ret.mode ) )
                        ok=false;
                    ret.rdev=override.dev_id;
                } else {
                    // If the override is not a device, and the types do not match, this is not a valid entry
                    ok=(S_IFMT&ret.mode)==(S_IFMT&override.mode);
                }
                ret.mode=ret.mode&(~(07000|S_IFMT)) | override.mode&(07000|S_IFMT);

                // XXX the dlog may actually be platform dependent, based on the size of dev and inode
                if( ok ) {
                    dlog("stat64: %d dev=%llx inode=%lld mode=%o uid=%d gid=%d\n", pid, ret.dev, ret.ino, ret.mode, ret.uid, ret.gid );
                    ptlib_set_mem( pid, &ret, state->saved_state[0], sizeof(struct stat) );
                } else {
                    dlog("stat64: %d dev=%llx inode=%lld entry corrupt - removed\n", pid, ret.dev, ret.ino );
                    remove_map( ret.dev, ret.ino );
                }
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

        mode=mode&~07000;
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
            stat_override_copy( &stat, &override );
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

bool sys_chown( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // We're going to need memory
        if( state->memory==NULL ) {
            return allocate_process_mem( pid, state, sc_num );
        }

        // Map this to a stat operation
        state->saved_state[0]=ptlib_get_argument(pid, 2);
        state->saved_state[1]=ptlib_get_argument(pid, 3);

        ptlib_set_argument( pid, 2, state->memory );

        switch( sc_num ) {
        case SYS_chown32:
            ptlib_set_syscall( pid, SYS_stat64 );
            dlog("chown: %d redirected chown call to stat\n", pid );
            break;
        case SYS_fchown32:
            ptlib_set_syscall( pid, SYS_fstat64 );
            dlog("chown: %d redirected fchown call to fstat\n", pid );
            break;
        case SYS_lchown32:
            ptlib_set_syscall( pid, SYS_lstat64 );
            dlog("chown: %d redirected lchown call to lstat\n", pid );
            break;
        default:
            dlog("chown: %d called unsupported syscall %d\n", pid, sc_num );
            abort();
            break;
        }

        state->state=pid_state::REDIRECT2;
        state->orig_sc=sc_num;
    } else if( state->state==pid_state::REDIRECT2 ) {
        dlog("point %d\n", sc_num );
        if( ptlib_success( pid, sc_num ) ) {
            dlog("point2\n");
            struct ptlib_stat64 stat;
            struct stat_override override;

            ptlib_get_mem( pid, state->memory, &stat, sizeof( stat ) );

            if( !get_map( stat.dev, stat.ino, &override ) )
                stat_override_copy( &stat, &override );

            if( ((int)state->saved_state[0])!=-1 )
                override.uid=(int)state->saved_state[0];
            if( ((int)state->saved_state[1])!=-1 )
                override.gid=(int)state->saved_state[1];

            set_map( &override );
        } else {
            dlog("chown: %d stat call failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)) );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_mknod( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Will need memory
        if( state->memory==NULL ) {
            return allocate_process_mem(pid, state, sc_num);
        }

        state->saved_state[0]=ptlib_get_argument( pid, 1 ); // File name
        state->saved_state[1]=ptlib_get_argument( pid, 2 ); // Mode
        state->saved_state[2]=ptlib_get_argument( pid, 3 ); // Device ID
        mode_t mode=(mode_t)state->saved_state[1];

        if( S_ISCHR(mode) || S_ISBLK(mode) ) {
            dlog("mknod: %d tried to create %s device, turn to regular file\n", pid, S_ISCHR(mode) ? "character" : "block" );
            mode=mode&~S_IFMT | S_IFREG;

            ptlib_set_argument( pid, 2, (void *)mode );
        }

        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        mode_t mode=(mode_t)state->saved_state[1];

        if( ptlib_success( pid, sc_num ) && (S_ISCHR(mode) || S_ISBLK(mode) ) ) {
            // Need to call "stat" on the file to see what inode number it got
            ptlib_set_argument( pid, 1, state->saved_state[0] ); // File name
            ptlib_set_argument( pid, 2, state->memory ); // Struct stat

            state->orig_sc=sc_num;
            state->state=pid_state::REDIRECT1;
            ptlib_save_state( pid, state->saved_state+3 );

            dlog("mknod: %d Actual node creation successful. Calling stat\n", pid );
            return ptlib_generate_syscall( pid, SYS_stat64, state->memory );
        } else {
            // Nothing to do if the call failed
            dlog("mknod: %d call failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num) ) );
        }
    } else if( state->state==pid_state::REDIRECT1 ) {
        dlog("mknod: %d REDIRECT1\n", pid );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            dlog("mknod: %d registering the new device in the override DB\n", pid);

            ptlib_stat64 stat;
            stat_override override;

            ptlib_get_mem( pid, state->memory, &stat, sizeof(stat) );

            // This file was, supposedly, just created. Even if it has an entry in the override DB, that entry is obsolete
            stat_override_copy( &stat, &override );

            // We created the file, it should have our uid/gid
            override.uid=0;
            override.gid=0;

            mode_t mode=(mode_t)state->saved_state[1];
            if( S_ISCHR(mode) || S_ISBLK(mode) ) {
                dlog("mknod: %d overriding the file type\n", pid );
                override.mode=override.mode&~S_IFMT | mode&S_IFMT;
                override.dev_id=(dev_t)state->saved_state[2];
            }

            set_map( &override );
        } else {
            // mknod succeeded, but stat failed?
            dlog("mknod: %d stat failed. Leave override DB non-updated\n", pid );
        }

        ptlib_restore_state( pid, state->saved_state+3 );
        state->state=pid_state::NONE;
    }

    return true;
}
