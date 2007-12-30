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
    if( state->state==pid_state::NONE ) {
        if( state->memory==NULL ) {
            return allocate_process_mem( pid, state, sc_num );
        }

        state->saved_state[0]=ptlib_get_argument( pid, 1 ); // Store the filename/filedes
        state->saved_state[1]=ptlib_get_argument( pid, 2 ); // Store the requested mode
        ptlib_set_argument( pid, 2,
            reinterpret_cast<void *>(reinterpret_cast<unsigned long>(state->saved_state[0])&0777) ); // Zero out the S* field
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        if( ptlib_success( pid, sc_num ) ) {
            // We need to call "stat/fstat" so we can know the dev/inode
            state->state=pid_state::REDIRECT;
            ptlib_save_state( pid, state->saved_state+2 );
            state->orig_sc=sc_num;

            ptlib_set_argument( pid, 1, state->saved_state[0] );
            ptlib_set_argument( pid, 2, state->memory );
            switch( sc_num ) {
            case SYS_fchmod:
                ptlib_generate_syscall( pid, SYS_fstat64, state->memory );
                break;
            case SYS_chmod:
                ptlib_generate_syscall( pid, SYS_lstat64, state->memory );
                break;
            default:
                dlog("chmod: %d Oops! Unhandled syscall %d\n", pid, sc_num );
                assert(0);
                ptlib_restore_state( pid, state->saved_state+2 );
                ptlib_set_error( pid, sc_num, EFAULT );
                state->state=pid_state::NONE;
                break;
            }
        } else {
            state->state=pid_state::NONE;
        }
    } else if( state->state==pid_state::REDIRECT ) {
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
        override.mode=(stat.mode&~07777)|(((mode_t)state->saved_state[1])&07777);

        set_map( &override );

        state->state=pid_state::NONE;
    }
}
