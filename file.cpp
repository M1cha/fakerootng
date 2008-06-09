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
#include <sys/ptrace.h>
#include <errno.h>
#include <fcntl.h>

#include <assert.h>
#include <limits.h>

#include <string.h>

#include "syscalls.h"
#include "file_lie.h"
#include "chroot.h"
#include "arch/platform.h"

// Helper function - fill in an override structure from a stat structure
static void stat_override_copy( const ptlib_stat *stat, stat_override *override )
{
    override->dev=stat->dev;
    override->inode=stat->ino;
    override->uid=stat->uid;
    override->gid=stat->uid;
    override->dev_id=stat->rdev;
    override->mode=stat->mode;
}

// Same function for stat, lstat and fstat
bool sys_stat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Entering the syscall
        state->state=pid_state::RETURN;
        state->context_state[0]=ptlib_get_argument( pid, 2 ); // Store the pointer to the stat struct
        dlog("stat64: "PID_F" stored pointer at %p\n", pid, state->context_state[0] );

        // If the process is chrooted, we need to translate the file name
        int real_sc=ptlib_get_syscall( pid );
        if( ( real_sc==PREF_STAT || real_sc==PREF_LSTAT ) ) {
            chroot_translate_param( pid, state, 1, real_sc!=PREF_LSTAT );
        }
    } else if( state->state==pid_state::RETURN ) {
        // Returning from the syscall
        int returncode=ptlib_get_retval( pid );
        dlog("stat64: "PID_F" returned %x\n", pid, returncode);
        if( ptlib_success( pid, sc_num ) ) {
            struct ptlib_stat ret;
            struct stat_override override;

            ptlib_get_mem( pid, (void *)state->context_state[0], &ret, sizeof(ret) );

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
                ret.mode=(ret.mode&(~(07000|S_IFMT))) | (override.mode&(07000|S_IFMT));

                if( ok ) {
                    dlog("stat64: "PID_F" override dev="DEV_F" inode="INODE_F" mode=%o uid=%d gid=%d\n", pid, ret.dev, ret.ino, ret.mode, ret.uid, ret.gid );
                    ptlib_set_mem( pid, &ret, (void *)state->context_state[0], sizeof(struct stat) );
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

#if HAVE_OPENAT
bool sys_fstatat64( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Entering the syscall
        state->state=pid_state::RETURN;
        state->context_state[0]=ptlib_get_argument( pid, 3 ); // Store the pointer to the stat struct
        dlog("statat64: "PID_F" stored pointer at %p\n", pid, state->context_state[0] );

        return true;
    } else {
        return sys_stat( sc_num, pid, state ); // Return code handling is the same as for the regular stat
    }
}
#endif

static bool real_chmod( int sc_num, pid_t pid, pid_state *state, int mode_offset, int stat_function, int extra_flags=-1 )
{
    if( state->state==pid_state::NONE ) {
        if( state->memory==NULL ) {
            return allocate_process_mem( pid, state, sc_num );
        }

        mode_t mode=(mode_t)ptlib_get_argument( pid, mode_offset+1 ); // Store the requested mode
        state->context_state[0]=mode;

        mode=mode&~07000;
        ptlib_set_argument( pid, mode_offset+1, mode ); // Zero out the S* field

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

            ptlib_set_argument( pid, mode_offset+1, (int_ptr)state->memory ); // Where to store the stat result

            // One anomaly handled with special case. Ugly, but not worth the interface complication
            if( extra_flags!=-1 ) {
                // Some of the functions require an extra flag after the usual parameters
                ptlib_set_argument( pid, mode_offset+2, extra_flags );
            }

            return ptlib_generate_syscall( pid, stat_function, state->shared_memory );
        } else {
            state->state=pid_state::NONE;
            dlog("chmod: "PID_F" chmod failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)));
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Update our lies database
        struct stat_override override;
        struct ptlib_stat stat;

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
        chroot_translate_param( pid, state, 1, true );

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

#if HAVE_OPENAT
bool sys_fchmodat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[1]=ptlib_get_argument( pid, 1 ); // Store the base dir fd
        state->context_state[2]=ptlib_get_argument( pid, 2 ); // Store the file name
        state->context_state[3]=ptlib_get_argument( pid, 4 ); // Store the flags
    }

    return real_chmod( sc_num, pid, state, 2, PREF_FSTATAT, state->context_state[3] );
}
#endif

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
        ptlib_set_argument( pid, own_offset+1, (int_ptr)state->memory );

        if( extra_flags!=-1 ) {
            ptlib_set_argument( pid, own_offset+2, extra_flags );
        }

        ptlib_set_syscall( pid, stat_function );
        dlog("chown: "PID_F" redirected chown call to stat\n", pid );

        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            struct ptlib_stat stat;
            struct stat_override override;

            ptlib_get_mem( pid, state->memory, &stat, sizeof( stat ) );

            if( !get_map( stat.dev, stat.ino, &override ) ) {
                dlog("chown: "PID_F" no override for file - create a new one\n", pid );
                stat_override_copy( &stat, &override );
            }

            if( ((int)state->context_state[0])!=-1 )
                override.uid=state->context_state[0];
            if( ((int)state->context_state[1])!=-1 )
                override.gid=state->context_state[1];

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
    if( state->state==pid_state::NONE && state->memory!=NULL ) {
        state->context_state[0]=ptlib_get_argument(pid, 2);
        state->context_state[1]=ptlib_get_argument(pid, 3);

        chroot_translate_param( pid, state, 1, true );
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
    if( state->state==pid_state::NONE && state->memory!=NULL ) {
        state->context_state[0]=ptlib_get_argument(pid, 2);
        state->context_state[1]=ptlib_get_argument(pid, 3);

        chroot_translate_param( pid, state, 1, false );
    }
    
    return real_chown( sc_num, pid, state, 1, PREF_LSTAT );
}

#if HAVE_OPENAT
bool sys_fchownat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument(pid, 3);
        state->context_state[1]=ptlib_get_argument(pid, 4);
        state->context_state[2]=ptlib_get_argument(pid, 5);
    }
    
    return real_chown( sc_num, pid, state, 2, PREF_FSTATAT, state->context_state[2] );
}
#endif

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
            mode=(mode&~S_IFMT) | S_IFREG;
        }
        ptlib_set_argument( pid, mode_offset+1, mode );

        dlog("mknod: %d mode %o\n", pid, state->context_state[1] );
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        if( ptlib_success( pid, sc_num ) ) {
            // Need to call "stat" on the file to see what inode number it got
            ptlib_save_state( pid, state->saved_state );

            for( int i=0; i<mode_offset; ++i ) {
                ptlib_set_argument( pid, i+1, state->context_state[2+i] ); // File name etc.
            }
            ptlib_set_argument( pid, mode_offset+1, (int_ptr)state->memory ); // Struct stat

            if( extra_flags!=-1 ) {
                ptlib_set_argument( pid, mode_offset+2, extra_flags );
            }

            state->state=pid_state::REDIRECT1;

            dlog("mknod: "PID_F" Actual node creation successful. Calling stat\n", pid );
            return ptlib_generate_syscall( pid, stat_function, state->shared_memory );
        } else {
            // Nothing to do if the call failed
            dlog("mknod: "PID_F" call failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num) ) );
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            ptlib_stat stat;
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
                override.mode=(override.mode&~(S_IFMT|07000)) | (mode&(S_IFMT|07000));
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
        chroot_translate_param( pid, state, 1, false );

        state->context_state[0]=ptlib_get_argument( pid, 2 ); // Mode
        state->context_state[1]=ptlib_get_argument( pid, 3 ); // Device ID
        state->context_state[2]=ptlib_get_argument( pid, 1 ); // File name
    }

    return real_mknod( sc_num, pid, state, 1, PREF_STAT );
}

#if HAVE_OPENAT
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
#endif

static bool real_open( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        // Did we request to create a new file?
        if( (state->context_state[0]&O_CREAT)!=0 && ptlib_success(pid, sc_num) ) {
            int fd=(long)ptlib_get_retval(pid);
            dlog("open: "PID_F" opened fd %d, assume we actually created it\n", pid, fd );

            ptlib_save_state( pid, state->saved_state );
            state->state=pid_state::REDIRECT1;

            // Call fstat to find out what we have
            ptlib_set_argument( pid, 1, fd );
            ptlib_set_argument( pid, 2, (int_ptr)state->memory );
            return ptlib_generate_syscall( pid, PREF_FSTAT, state->shared_memory );
        } else
            state->state=pid_state::NONE;
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            ptlib_stat stat;
            stat_override override;

            ptlib_get_mem( pid, state->memory, &stat, sizeof( stat ) );

            // XXX The test whether we just created a new file is not the most accurate in the world
            // In particular, if the previous instance was deleted, this will misbehave
            // Fixed: if the previous instance was deleted BY US, this should now be ok
            // Still, /dev/null is routinely found in the map for no good reason due to this code
            if( !get_map( stat.dev, stat.ino, &override ) || override.transient ) {
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
        chroot_translate_param( pid, state, 1, true );

        state->context_state[0]=ptlib_get_argument( pid, 2 ); //flags
    }

    return real_open( sc_num, pid, state );
}

#if HAVE_OPENAT
bool sys_openat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Will need memory
        if( state->memory==NULL )
            return allocate_process_mem( pid, state, sc_num );

        state->context_state[0]=ptlib_get_argument( pid, 3 ); //flags
    }

    return real_open( sc_num, pid, state );
}
#endif

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
            ptlib_set_argument( pid, mode_offset+1, (int_ptr)state->memory ); // stat structure

            if( extra_flags!=-1 ) {
                ptlib_set_argument( pid, mode_offset+2, extra_flags );
            }

            state->orig_sc=sc_num;
            state->state=pid_state::REDIRECT1;

            return ptlib_generate_syscall( pid, stat_function, state->shared_memory );
        } else {
            // If mkdir failed, we don't have anything else to do.
            dlog("mkdir: "PID_F" failed with error %s\n", pid, strerror(ptlib_get_error( pid, sc_num ) ) );
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            ptlib_stat stat;
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
    if( state->state==pid_state::NONE && state->memory!=NULL ) {
        chroot_translate_param( pid, state, 1, true );

        state->context_state[0]=ptlib_get_argument( pid, 1 ); // Directory name

        if( log_level>0  ) {
            char name[PATH_MAX];

            ptlib_get_string( pid, (void *)state->context_state[0], name, sizeof(name) );

            dlog("mkdir: %d creates %s\n", pid, name );
        }
    }

    return real_mkdir( sc_num, pid, state, 1, PREF_STAT );
}

#if HAVE_OPENAT
bool sys_mkdirat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 1 ); // Directory name

        if( log_level>0  ) {
            char name[PATH_MAX];

            ptlib_get_string( pid, (void *)state->context_state[0], name, sizeof(name) );
            int fd=(int)ptlib_get_argument( pid, 1 );

            dlog("mkdirat: %d creates %s at %x\n", pid, name, fd );
        }
    }

    return real_mkdir( sc_num, pid, state, 2, PREF_FSTATAT, 0 );
}
#endif

static bool real_symlink( int sc_num, pid_t pid, pid_state *state, int mode_offset, int stat_function, int extra_flags=-1 )
{
    if( state->state==pid_state::NONE ) {
        // Will need memory
        if( state->memory==NULL )
            return allocate_process_mem( pid, state, sc_num );

        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        if( ptlib_success( pid, sc_num ) ) {
            dlog("symlink: "PID_F" success. Call stat to mark uid/gid override\n", pid );
            ptlib_save_state( pid, state->saved_state );

            for( int i=0; i<mode_offset; ++i ) {
                ptlib_set_argument( pid, i+1, state->context_state[i] ); // File name
            }
            ptlib_set_argument( pid, mode_offset+1, (int_ptr)state->memory ); // stat structure

            if( extra_flags!=-1 ) {
                ptlib_set_argument( pid, mode_offset+2, extra_flags );
            }

            state->state=pid_state::REDIRECT1;

            return ptlib_generate_syscall( pid, stat_function, state->shared_memory );
        } else {
            dlog("symlink: "PID_F" failed with error %s\n", pid, strerror( ptlib_get_error(pid, sc_num) ) );
            state->state=pid_state::NONE;
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( ptlib_success( pid, sc_num ) ) {
            ptlib_stat stat;
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

bool sys_symlink( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE && state->memory!=NULL ) {
        chroot_translate_param( pid, state, 2, true );

        state->context_state[0]=ptlib_get_argument( pid, 2 ); // new path
    }

    return real_symlink( sc_num, pid, state, 1, PREF_LSTAT );
}

#if HAVE_OPENAT
bool sys_symlinkat( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 2 ); // dirfd
        state->context_state[1]=ptlib_get_argument( pid, 3 ); // new path
    }

    return real_symlink( sc_num, pid, state, 2, PREF_FSTATAT, AT_SYMLINK_NOFOLLOW );
}
#endif

bool sys_getcwd( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Will need memory
        if( state->memory==NULL )
            return allocate_process_mem( pid, state, sc_num );

        state->state=pid_state::RETURN;

        // If the process is chrooted, we need to translate the directory name
        if( chroot_is_chrooted(state) ) {
            // We don't want to report the real current directory, of course!
            state->context_state[0]=ptlib_get_argument( pid, 1 ); // Buffer
            state->context_state[1]=ptlib_get_argument( pid, 2 ); // Buffer len

            // Perform the actual call into our buffer
            ptlib_set_argument( pid, 1, (int_ptr)state->memory );
            ptlib_set_argument( pid, 2, PATH_MAX );
        }
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;

        if( ptlib_success( pid, sc_num ) && chroot_is_chrooted(state) ) {
            // We are inside a chroot, and the call was successful
            char buffer[PATH_MAX];
            ptlib_get_string( pid, state->memory, buffer, sizeof(buffer) );
            char tmp=buffer[state->root.length()];
            buffer[state->root.length()]='\0';
            char *ptr=buffer;

            if( ( tmp=='/' || tmp=='\0' ) && state->root==buffer ) {
                // Current directory is inside the chroot jail - need to truncate the prefix
                if( tmp=='/' ) {
                    ptr+=state->root.length();
                    *ptr=tmp;
                } else {
                    // The current directory is the new root
                    strcpy( buffer, "/" );
                }
            } else {
                // Current directory is outside of the jail - pass it to the program as is
                buffer[state->root.length()]=tmp;
            }

            // Emulate the actual call
            size_t len=strlen(ptr);

            if( len<state->context_state[1] ) {
                // Buffer is large enough
                ptlib_set_string( pid, ptr, (void *)state->context_state[0] );
                ptlib_set_retval( pid, len+1 );
            } else {
                // The buffer is not large enough
                ptlib_set_error( pid, sc_num, ERANGE );
            }
        }
    }

    return true;
}

bool sys_munmap( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE || state->state==pid_state::REDIRECT1 ) {
        if( state->state==pid_state::NONE ) {
            // This is our first time entering this munmap
            state->context_state[2]=0; // No state to restore
        }

        state->state=pid_state::RETURN;
        state->context_state[0]=0; // 0 is the next start address to unmap, 1 is the new length
        state->context_state[1]=0; // len=0 means we have no more mmaps to perform

        // Is this an attempt to release one of the memory areas we own?
        int_ptr start=ptlib_get_argument( pid, 1 );
        int_ptr end=start+ptlib_get_argument( pid, 2 );

        // If end wraps around then the kernel will fail this anyways
        // Same goes if the page size is not aligned or the length is zero
        if( start>end || (start%sysconf(_SC_PAGESIZE))!=0 || start==end )
            return true;

        // Put the lower of the two addreses in addr1
        int_ptr addr1=(int_ptr)state->shared_memory, addr2=(int_ptr)state->memory;
        size_t len1=static_mem_size, len2=shared_mem_size-ptlib_prepare_memory_len();
        const char *name1="static", *name2="shared";

        if( addr1>addr2 ) {
            int_ptr tmp=addr1;
            addr1=addr2;
            addr2=tmp;

            size_t tmplen=len1;
            len1=len2;
            len2=tmplen;

            const char *tmpname=name1;
            name1=name2;
            name2=tmpname;
        }

        state->state=pid_state::REDIRECT2;
        if( start<addr1 && end>addr1 ) {
            // The unmap range covers the lower range
            dlog("sys_munmap: "PID_F" tried to unmap range %p-%p, which conflicts with our %s range %p-%p\n",
                pid, start, end, name1, addr1, addr1+len1 );

            if( end>addr1+len1 ) {
                // There is an area to unmap above the lower range - mark it for a second syscall
                state->context_state[0]=addr1+len1;
                state->context_state[1]=end-state->context_state[0];
            }

            end=addr1;
        } else if( start>=addr1 && start<addr1+len1 ) {
            // The start pointer is inside the lower memory range
            dlog("sys_munmap: "PID_F" tried to unmap range %p-%p, which conflicts with our %s range %p-%p\n",
                pid, start, end, name1, addr1, addr1+len1 );

            start=addr1+len1;
        } else if( start<addr2 && end>addr2 ) {
            // The unmap area covers the upper memory range
            dlog("sys_munmap: "PID_F" tried to unmap range %p-%p, which conflicts with our %s range %p-%p\n",
                pid, start, end, name2, addr2, addr2+len2 );

            if( end>addr2+len2 ) {
                // There is an area to unmap above the upper range - mark it for a second (third?) syscall
                state->context_state[0]=addr2+len2;
                state->context_state[1]=end-state->context_state[0];
            }
            
            end=addr2;
        } else if( start>=addr2 && start<addr2+len2 ) {
            // The start pointer is inside the upper memory range
            dlog("sys_munmap: "PID_F" tried to unmap range %p-%p, which conflicts with our %s range %p-%p\n",
                pid, start, end, name2, addr2, addr2+len2 );

            start=addr2+len2;
        } else {
            // The unmap range was a-ok. No need to touch the syscall at all
            state->state=pid_state::RETURN;
            return true;
        }

        // We had to change the parameters because of an overlap
        ptlib_set_argument( pid, 1, start );
        ptlib_set_argument( pid, 2, end-start );
    } else if( state->state==pid_state::RETURN || state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;

        if( ptlib_success( pid, sc_num ) ) {
            bool last=(state->context_state[1]==0);

            // If we are not done yet, we will need to store this position and come back to it
            if( state->context_state[2]==0 && !last ) {
                ptlib_save_state( pid, state->saved_state );
                state->context_state[2]=1;
            }

            if( !last ) {
                // We split the munmap into several calls - there are more calls to perform
                // Use REDIRECT3 rather than NONE so that strace won't see the extra call
                state->state=pid_state::REDIRECT3;

                ptlib_set_argument( pid, 1, state->context_state[0] );
                ptlib_set_argument( pid, 2, state->context_state[1] );
                return ptlib_generate_syscall( pid, sc_num, state->shared_memory );
            }
        } else {
            // The syscall failed - we will end it here even if we thought we had something more to do
            dlog("sys_munmap: "PID_F" failed: %s\n", pid, strerror(ptlib_get_error(pid, sc_num)));
        }

        if( state->context_state[2]==1 ) {
            ptlib_restore_state( pid, state->saved_state );
        }
    }

    return true;
}

bool sys_link( int sc_num, pid_t pid, pid_state *state )
{
    // XXX lock memory
    if( state->state==pid_state::NONE ) {
        state->state=pid_state::RETURN;

        if( chroot_is_chrooted( state ) ) {
            // Translate the "oldpath"
            chroot_translate_param( pid, state, 1, true, false, 0 );

            // Translate the "newpath"
            chroot_translate_param( pid, state, 2, true, false, PATH_MAX );
        }
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;
    }

    return true;
}

// In this function, context_state holds:
// 0 - state machine for redirected syscalls
// 1 - forced error number
// 2 - pointer to file name
// 
// after the lstat stage:
// 2 - 0: just delete. 1: need to mark for deletion from the override db as well
bool sys_unlink( int sc_num, pid_t pid, pid_state *state )
{
    // XXX lock memory
    if( state->state==pid_state::NONE ) {

        state->context_state[0]=0; // Beginning of syscall
        state->context_state[1]=0; // No forced error

        if( chroot_is_chrooted( state ) ) {
            // Translate the filename. If the last path component is a symlink, that is what we want deleted
            if( !chroot_translate_param( pid, state, 1, false, true ) ) {
                // We had an error translating the file name - pass the error on
                state->state=pid_state::REDIRECT2;
                state->context_state[1]=errno;
                ptlib_set_syscall(pid, PREF_NOP);

                return true;
            }
        }

        // Keep a copy of the file name
        state->context_state[2]=ptlib_get_argument( pid, 1 );

        // We need to know whether the file was, indeed, deleted. One method goes like this
        // First, open the file. Next, unlink the file. Then, fstat the file.
        // Problem - cannot do that for symbolic links.
        //
        // Second method - lstat the file before, unlink. If link count before was 1, inode
        // is no more.
        // Problem - someone else may have linked it while between the lstat and the unlink.
        //
        // Third method - link the file to a temporary name, unlink the original, check link
        // count on temporary name.
        // Problem - not easy to translate relative name to one that can be used from another
        // process. On Linux, we do that using "linkat"

        // We now implement the second method
        ptlib_set_syscall( pid, PREF_LSTAT );
        ptlib_set_argument( pid, 2, (int_ptr)state->memory );

        state->state=pid_state::REDIRECT2;

    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;

        if( state->context_state[1]!=0 ) {
            // We need to force an error
            ptlib_set_error( pid, state->orig_sc, state->context_state[1] );
            state->state=pid_state::NONE;

            return true;
        }

        // Handle the actual state machine
        switch( state->context_state[0] ) {
        case 0:
            // lstat returned
            {
                if( ptlib_success( pid, sc_num ) ) {
                    ptlib_stat stat;

                    ptlib_get_mem( pid, state->memory, &stat, sizeof(stat) );

                    if( stat.nlink==1 ) {
                        // Store the relevant data in the shared memory
                        struct override_key *key=reinterpret_cast<override_key *>(state->shared_mem_local.getc()+PATH_MAX);
                        key->dev=stat.dev;
                        key->inode=stat.ino;

                        state->context_state[2]=1;
                    } else {
                        state->context_state[2]=0;
                    }

                    // Perform the actual unlink operation
                    ptlib_save_state( pid, state->saved_state );
                    ptlib_generate_syscall( pid, state->orig_sc, state->shared_memory );
                    state->state=pid_state::REDIRECT1;
                    state->context_state[0]=1;
                } else {
                    // lstat syscall failed - pass the error along
                    state->state=pid_state::NONE;
                }
            }
            break;
        case 1:
            // unlink returned
            {
                bool success=ptlib_success( pid, sc_num );
                int error=success?0:ptlib_get_error( pid, sc_num );

                ptlib_restore_state( pid, state->saved_state );

                if( success ) {
                    if( state->context_state[2]==1 ) {
                        // Need to erase the override from our database
                        struct override_key *key=reinterpret_cast<override_key *>(state->shared_mem_local.getc()+PATH_MAX);
                        stat_override map;

                        if( get_map( key->dev, key->inode, &map ) ) {
                            map.transient=true;
                            set_map( &map );
                            dlog("sys_unlink: "PID_F" inode "INODE_F" in override mapping marked transient\n", pid, key->inode );
                        }
                    }
                } else {
                    // The "restore state" command overwrote the error
                    ptlib_set_error( pid, sc_num, error );
                }
            }
            break;
        }
    }

    return true;
}

// XXX BUG Since it is possible that the file is renamed across a device boundry, we really need to make sure we properly copy
// the override attributes with the file. We also possibly need to erase the old override entry
bool sys_rename( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->state=pid_state::RETURN;

        chroot_translate_param( pid, state, 1, false, false, 0 );
        chroot_translate_param( pid, state, 2, false, false, PATH_MAX );
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_rmdir( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        chroot_translate_param( pid, state, 1, false );

        // Keep a copy of the directory name to erase
        state->context_state[0]=0; // Internal state
        state->context_state[1]=ptlib_get_argument( pid, 1 );

        // We need to stat the directory before we erase it
        ptlib_set_argument( pid, 2, (int_ptr)state->memory );
        ptlib_set_syscall( pid, PREF_LSTAT );

        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( state->context_state[0]==0 ) {
            // lstat returned
            if( ptlib_success( pid, sc_num ) ) {
                ptlib_stat stat;

                ptlib_get_mem( pid, state->memory, &stat, sizeof(stat) );

                struct override_key *key=reinterpret_cast<override_key *>(state->shared_mem_local.getc()+PATH_MAX);
                key->dev=stat.dev;
                key->inode=stat.ino;

                state->context_state[0]=1;

                // Run the original syscall
                ptlib_save_state( pid, state->saved_state );
                ptlib_generate_syscall( pid, state->orig_sc, state->shared_memory );
                state->state=pid_state::REDIRECT1;
            } else {
                // Pass the lstat error as if it were the rmdir error
                state->state=pid_state::NONE;
            }
        } else if( state->context_state[0]==1 ) {
            bool success=ptlib_success( pid, sc_num );
            int error=success?0:ptlib_get_error( pid, sc_num );

            ptlib_restore_state( pid, state->saved_state );

            if( success ) {
                // Need to erase the override from our database
                struct override_key *key=reinterpret_cast<override_key *>(state->shared_mem_local.getc()+PATH_MAX);
                stat_override map;

                if( get_map( key->dev, key->inode, &map ) ) {
                    map.transient=true;
                    set_map( &map );
                    dlog("sys_rmdir: "PID_F" inode "INODE_F" in override mapping marked transient\n", pid, key->inode );
                }
            } else {
                // Need to copy the error number (overwritten by the state restore)
                ptlib_set_error( pid, sc_num, error );
            }

            state->state=pid_state::NONE;
        }
    }

    return true;
}

// This function handles the generic case where the function is one that does not need fake root
// special handling, except we need to translate the first parameter in case we are chrooted
bool sys_generic_chroot_support_param1( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->state=pid_state::RETURN;

        chroot_translate_param( pid, state, 1, false );
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;
    }

    return true;
}
