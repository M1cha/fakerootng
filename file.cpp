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
#include <fcntl.h>

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
        state->context_state[0]=ptlib_get_argument( pid, 2 ); // Store the pointer to the stat struct
        dlog("stat64: "PID_F" stored pointer at %p\n", pid, state->context_state[0] );
    } else if( state->state==pid_state::RETURN ) {
        // Returning from the syscall
        void *returncode=ptlib_get_retval( pid );
        dlog("stat64: "PID_F" returned %x\n", pid, returncode);
        if( ptlib_success( pid, sc_num ) ) {
            struct ptlib_stat64 ret;
            struct stat_override override;

            ptlib_get_mem( pid, state->context_state[0], &ret, sizeof(ret) );

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

                if( ok ) {
                    dlog("stat64: "PID_F" override dev="DEV_F" inode="INODE_F" mode=%o uid=%d gid=%d\n", pid, ret.dev, ret.ino, ret.mode, ret.uid, ret.gid );
                    ptlib_set_mem( pid, &ret, state->context_state[0], sizeof(struct stat) );
                } else {
                    dlog("stat64: "PID_F" dev="DEV_F" inode="INODE_F" override entry corrupt - removed\n", pid, ret.dev, ret.ino );
                    remove_map( ret.dev, ret.ino );
                }
            }
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_statat64( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Entering the syscall
        state->state=pid_state::RETURN;
        state->context_state[0]=ptlib_get_argument( pid, 3 ); // Store the pointer to the stat struct
        dlog("statat64: "PID_F" stored pointer at %p\n", pid, state->context_state[0] );

        return true;
    } else {
        return sys_stat64( sc_num, pid, state ); // Return code handling is the same as for the regular stat
    }
}

static bool real_chmod( int sc_num, pid_t pid, pid_state *state, int mode_offset, int stat_function, int extra_flags=-1 )
{
    if( state->state==pid_state::NONE ) {
        if( state->memory==NULL ) {
            return allocate_process_mem( pid, state, sc_num );
        }

        mode_t mode=(mode_t)ptlib_get_argument( pid, mode_offset+1 ); // Store the requested mode
        state->context_state[0]=(void *)mode;

        mode=mode&~07000;
        ptlib_set_argument( pid, mode_offset+1, (void *) mode ); // Zero out the S* field

        dlog("chmod: "PID_F" mode %o changed to %o\n", pid, state->context_state[1], mode );
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        if( ptlib_success( pid, sc_num ) ) {
            dlog("chmod: "PID_F" chmod successful, performing stat so we can update the map\n", pid);

            // We need to call "stat/fstat" so we can know the dev/inode
            state->state=pid_state::REDIRECT1;
            ptlib_save_state( pid, state->saved_state );
            state->orig_sc=sc_num;

            for( int i=1; i<=mode_offset; ++i )
                ptlib_set_argument( pid, i, state->context_state[i] );

            ptlib_set_argument( pid, mode_offset+1, state->memory ); // Where to store the stat result

            // One anomaly handled with special case. Ugly, but not worth the interface complication
            if( extra_flags!=-1 ) {
                // Some of the functions require an extra flag after the usual parameters
                ptlib_set_argument( pid, mode_offset+2, (void *)extra_flags );
            }

            return ptlib_generate_syscall( pid, stat_function, state->memory );
        } else {
            state->state=pid_state::NONE;
            dlog("chmod: "PID_F" chmod failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)));
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Update our lies database
        struct stat_override override;
        struct ptlib_stat64 stat;

        ptlib_get_mem( pid, state->memory, &stat, sizeof( stat ) );

        if( !get_map( stat.dev, stat.ino, &override ) ) {
            stat_override_copy( &stat, &override );
        }
        override.mode=(override.mode&~07777)|(((mode_t)state->context_state[0])&07777);

        dlog("chmod: "PID_F" Setting override mode %o dev "DEV_F" inode "INODE_F"\n", pid, override.mode, override.dev,
            override.inode );
        set_map( &override );

        state->state=pid_state::NONE;
        ptlib_restore_state( pid, state->saved_state );
    } else {
        dlog("chmod: "PID_F" unknown state %d\n", pid, state->state );
    }

    return true;
}

// The actual work is done by "real_chmod".
bool sys_chmod( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[1]=ptlib_get_argument( pid, 1 ); // Store the file name
    }

    return real_chmod( sc_num, pid, state, 1, PREF_STAT );
}

bool sys_fchmod( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[1]=ptlib_get_argument( pid, 1 ); // Store the file descriptor
    }

    return real_chmod( sc_num, pid, state, 1, PREF_FSTAT );
}

bool sys_fchmodat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[1]=ptlib_get_argument( pid, 1 ); // Store the base dir fd
        state->context_state[2]=ptlib_get_argument( pid, 2 ); // Store the file name
        state->context_state[3]=ptlib_get_argument( pid, 4 ); // Store the flags
    }

    return real_chmod( sc_num, pid, state, 2, PREF_FSTATAT, (int)state->context_state[3] );
}

// context_state[0] and 1 should contain the desired uid and gid respectively
static bool real_chown( int sc_num, pid_t pid, pid_state *state, int own_offset, int stat_function, int extra_flags=-1 )
{
    // XXX Do we handle the mode change following a chown (file and directory) correctly?
    if( state->state==pid_state::NONE ) {
        // We're going to need memory
        if( state->memory==NULL ) {
            return allocate_process_mem( pid, state, sc_num );
        }

        // Map this to a stat operation
        ptlib_set_argument( pid, own_offset+1, state->memory );

        if( extra_flags!=-1 ) {
            ptlib_set_argument( pid, own_offset+2, (void *)extra_flags );
        }

        ptlib_set_syscall( pid, stat_function );
        dlog("chown: "PID_F" redirected chown call to stat\n", pid );

        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            struct ptlib_stat64 stat;
            struct stat_override override;

            ptlib_get_mem( pid, state->memory, &stat, sizeof( stat ) );

            if( !get_map( stat.dev, stat.ino, &override ) ) {
                dlog("chown: "PID_F" no override for file - create a new one\n", pid );
                stat_override_copy( &stat, &override );
            }

            if( ((int)state->context_state[0])!=-1 )
                override.uid=(int)state->context_state[0];
            if( ((int)state->context_state[1])!=-1 )
                override.gid=(int)state->context_state[1];

            dlog("chown: "PID_F" changing owner of dev "DEV_F" inode "INODE_F"\n", pid, override.dev, override.inode );
            set_map( &override );
        } else {
            dlog("chown: "PID_F" stat call failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)) );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_chown( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument(pid, 2);
        state->context_state[1]=ptlib_get_argument(pid, 3);
    }
    
    return real_chown( sc_num, pid, state, 1, PREF_STAT );
}

bool sys_fchown( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument(pid, 2);
        state->context_state[1]=ptlib_get_argument(pid, 3);
    }
    
    return real_chown( sc_num, pid, state, 1, PREF_FSTAT );
}

bool sys_lchown( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument(pid, 2);
        state->context_state[1]=ptlib_get_argument(pid, 3);
    }
    
    return real_chown( sc_num, pid, state, 1, PREF_LSTAT );
}

bool sys_fchownat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument(pid, 3);
        state->context_state[1]=ptlib_get_argument(pid, 4);
        state->context_state[2]=ptlib_get_argument(pid, 5);
    }
    
    return real_chown( sc_num, pid, state, 2, PREF_FSTATAT, (int)state->context_state[2] );
}

static bool real_mknod( int sc_num, pid_t pid, pid_state *state, int mode_offset, int stat_function, int extra_flags=-1 )
{
    if( state->state==pid_state::NONE ) {
        // Will need memory
        if( state->memory==NULL ) {
            return allocate_process_mem(pid, state, sc_num);
        }

        mode_t mode=(mode_t)state->context_state[0];

        if( (mode&07000)!=0 ) {
            // Mode has a SUID set
            mode&=~(07000);
        }
        if( S_ISCHR(mode) || S_ISBLK(mode) ) {
            dlog("mknod: "PID_F" tried to create %s device, turn to regular file\n", pid, S_ISCHR(mode) ? "character" : "block" );
            mode=mode&~S_IFMT | S_IFREG;
        }
        ptlib_set_argument( pid, mode_offset+1, (void *)mode );

        dlog("mknod: %d mode %o\n", pid, state->context_state[1] );
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        if( ptlib_success( pid, sc_num ) ) {
            // Need to call "stat" on the file to see what inode number it got
            ptlib_save_state( pid, state->saved_state );

            for( int i=0; i<mode_offset; ++i ) {
                ptlib_set_argument( pid, i+1, state->context_state[2+i] ); // File name etc.
            }
            ptlib_set_argument( pid, mode_offset+1, state->memory ); // Struct stat

            if( extra_flags!=-1 ) {
                ptlib_set_argument( pid, mode_offset+2, (void *)extra_flags );
            }

            state->state=pid_state::REDIRECT1;

            dlog("mknod: "PID_F" Actual node creation successful. Calling stat\n", pid );
            return ptlib_generate_syscall( pid, stat_function, state->memory );
        } else {
            // Nothing to do if the call failed
            dlog("mknod: "PID_F" call failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num) ) );
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            ptlib_stat64 stat;
            stat_override override;

            ptlib_get_mem( pid, state->memory, &stat, sizeof(stat) );

            // This file was, supposedly, just created. Even if it has an entry in the override DB, that entry is obsolete
            stat_override_copy( &stat, &override );

            // We created the file, it should have our uid/gid
            override.uid=0;
            override.gid=0;

            dlog("mknod: "PID_F" registering the new device in the override DB dev "DEV_F" inode "INODE_F"\n", pid,
                stat.dev, stat.ino );

            mode_t mode=(mode_t)state->context_state[0];
            if( S_ISCHR(mode) || S_ISBLK(mode) || (mode&07000)!=0) {
                dlog("mknod: "PID_F" overriding the file type and/or mode\n", pid );
                override.mode=override.mode&~(S_IFMT|07000) | mode&(S_IFMT|07000);
                override.dev_id=(dev_t)state->context_state[1];
            }

            set_map( &override );
        } else {
            // mknod succeeded, but stat failed?
            dlog("mknod: "PID_F" stat failed. Leave override DB non-updated\n", pid );
        }

        ptlib_restore_state( pid, state->saved_state );
        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_mknod( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 2 ); // Mode
        state->context_state[1]=ptlib_get_argument( pid, 3 ); // Device ID
        state->context_state[2]=ptlib_get_argument( pid, 1 ); // File name
    }

    return real_mknod( sc_num, pid, state, 1, PREF_STAT );
}

bool sys_mknodat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 3 ); // Mode
        state->context_state[1]=ptlib_get_argument( pid, 4 ); // Device ID
        state->context_state[2]=ptlib_get_argument( pid, 1 ); // Base fd
        state->context_state[3]=ptlib_get_argument( pid, 2 ); // File name
    }

    return real_mknod( sc_num, pid, state, 1, PREF_FSTATAT, 0 );
}

static bool real_open( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Will need memory
        if( state->memory==NULL )
            return allocate_process_mem( pid, state, sc_num );

        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        // Did we request to create a new file?
        if( (((int)state->context_state[0])&O_CREAT)!=0 && ptlib_success(pid, sc_num) ) {
            int fd=(int)ptlib_get_retval(pid);
            dlog("open: "PID_F" opened fd %d, assume we actually created it\n", pid, fd );

            ptlib_save_state( pid, state->saved_state );
            state->state=pid_state::REDIRECT1;

            // Call fstat to find out what we have
            ptlib_set_argument( pid, 1, (void *)fd );
            ptlib_set_argument( pid, 2, state->memory );
            return ptlib_generate_syscall( pid, PREF_FSTAT, state->memory );
        } else
            state->state=pid_state::NONE;
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            ptlib_stat64 stat;
            stat_override override;

            ptlib_get_mem( pid, state->memory, &stat, sizeof( stat ) );

            // XXX The test whether we just created a new file is not the most accurate in the world
            // In particular, if the previous instance was deleted, this will misbehave
            if( !get_map( stat.dev, stat.ino, &override ) ) {
                // If the map already exists, assume we did not create a new file and don't touch the owners
                stat_override_copy( &stat, &override );

                override.uid=0;
                override.gid=0;

                set_map( &override );
                dlog("open: "PID_F" creating override for dev "DEV_F" inode "INODE_F"\n", pid, override.dev, override.inode);
            } else {
                dlog("open: "PID_F" map for dev "DEV_F" inode "INODE_F" already exists - doing nothing\n", pid, stat.dev, stat.ino );
            }
        } else {
            dlog("open: "PID_F" fstat failed %s\n", pid, strerror( ptlib_get_error( pid, sc_num ) ) );
        }

        state->state=pid_state::NONE;
        ptlib_restore_state( pid, state->saved_state );
    }

    return true;
}

bool sys_open( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 2 ); //flags
    }

    return real_open( sc_num, pid, state );
}

bool sys_openat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 3 ); //flags
    }

    return real_open( sc_num, pid, state );
}

static bool real_mkdir( int sc_num, pid_t pid, pid_state *state, int mode_offset, int stat_function, int extra_flags=-1 )
{
    if( state->state==pid_state::NONE ) {
        // Will need memory
        if( state->memory==NULL )
            return allocate_process_mem( pid, state, sc_num );

        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;

        if( ptlib_success( pid, sc_num ) ) {
            dlog("mkdir: "PID_F" succeeded. Call stat\n", pid );
            ptlib_save_state( pid, state->saved_state );

            // Perform a stat operation so we can know the directory's dev and inode
            for( int i=0; i<mode_offset; ++i )
                ptlib_set_argument( pid, i+1, state->context_state[i] ); // Name
            ptlib_set_argument( pid, mode_offset+1, state->memory ); // stat structure

            if( extra_flags!=-1 ) {
                ptlib_set_argument( pid, mode_offset+2, (void *)extra_flags );
            }

            state->orig_sc=sc_num;
            state->state=pid_state::REDIRECT1;

            return ptlib_generate_syscall( pid, stat_function, state->memory );
        } else {
            // If mkdir failed, we don't have anything else to do.
            dlog("mkdir: "PID_F" failed with error %s\n", pid, strerror(ptlib_get_error( pid, sc_num ) ) );
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            ptlib_stat64 stat;
            stat_override override;

            ptlib_get_mem( pid, state->memory, &stat, sizeof( stat ) );

            // Since mkdir fails if the directory already exists, there is no point to check whether the override already exists
            stat_override_copy( &stat, &override );
            override.uid=0;
            override.gid=0;

            dlog("mkdir: "PID_F" storing override for dev "DEV_F" inode "INODE_F"\n", pid, override.dev, override.inode);
            set_map( &override );
        } else {
            dlog("mkdir: "PID_F" stat failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)));
        }

        ptlib_restore_state( pid, state->saved_state );
        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_mkdir( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 1 ); // Directory name

        if( log_level>0  ) {
            char name[PATH_MAX];

            ptlib_get_string( pid, state->context_state[0], name, sizeof(name) );

            dlog("mkdir: %d creates %s\n", pid, name );
        }
    }

    return real_mkdir( sc_num, pid, state, 1, PREF_STAT );
}

bool sys_mkdirat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 1 ); // Directory name

        if( log_level>0  ) {
            char name[PATH_MAX];

            ptlib_get_string( pid, state->context_state[0], name, sizeof(name) );
            int fd=(int)ptlib_get_argument( pid, 1 );

            dlog("mkdirat: %d creates %s at %x\n", pid, name, fd );
        }
    }

    return real_mkdir( sc_num, pid, state, 2, PREF_FSTATAT, 0 );
}

bool sys_symlink( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Will need memory
        if( state->memory==NULL )
            return allocate_process_mem( pid, state, sc_num );

        state->context_state[0]=ptlib_get_argument( pid, 2 ); // new path

        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        if( ptlib_success( pid, sc_num ) ) {
            dlog("symlink: "PID_F" success. Call stat to mark uid/gid override\n", pid );

            state->orig_sc=sc_num;
            state->state=pid_state::REDIRECT1;
            ptlib_save_state( pid, state->saved_state );

            ptlib_set_argument( pid, 1, state->context_state[0] ); // File name
            ptlib_set_argument( pid, 2, state->memory ); // stat structure

            return ptlib_generate_syscall( pid, SYS_lstat64, state->memory );
        } else {
            dlog("symlink: "PID_F" failed with error %s\n", pid, strerror( ptlib_get_error(pid, sc_num) ) );
            state->state=pid_state::NONE;
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            ptlib_stat64 stat;
            stat_override override;

            ptlib_get_mem( pid, state->memory, &stat, sizeof( stat ) );

            // Make sure we got the right file
            if( S_ISLNK(stat.mode) ) {
                // No need to check the DB as we just created the file
                stat_override_copy( &stat, &override );

                override.uid=0;
                override.gid=0;

                dlog("symlink: "PID_F" set uid/gid override for dev "DEV_F" inode "INODE_F"\n", pid, override.dev, override.inode );
                set_map( &override );
            } else {
                dlog("symlink: "PID_F" acutal file on disk is not a symlink. Type %o dev "DEV_F" inode "INODE_F"\n", pid, stat.mode, stat.dev,
                    stat.ino );
            }
        } else {
            dlog("symlink: "PID_F" symlink succeeded, but stat failed with %s\n", pid, strerror(ptlib_get_error(pid, sc_num)));
        }

        ptlib_restore_state( pid, state->saved_state );
        state->state=pid_state::NONE;
    }

    return true;
}

