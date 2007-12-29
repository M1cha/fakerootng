#include "config.h"

#include <sys/stat.h>

#include "syscalls.h"
#include "file_lie.h"
#include "arch/platform.h"

// "stat" structure size and layout too greatly depends on the precise syscall used. We define it here, just in case

bool sys_stat64( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Entering the syscall
        state->state=pid_state::RETURN;
        state->saved_state[0]=ptlib_get_argument( pid, 2 ); // Store the pointer to the stat struct
        dlog("stat: %d stored pointer at %p\n", pid, state->saved_state[0] );
    } else if( state->state==pid_state::RETURN ) {
        // Returning from the syscall
        void *returncode=ptlib_get_retval( pid );
        dlog("stat: %d returned %x\n", pid, returncode);
        if( ptlib_success( pid, sc_num ) ) {
            struct ptlib_stat64 ret;
            struct stat_override override;

            ptlib_get_mem( pid, state->saved_state[0], &ret, sizeof(ret) );
            // XXX the dlog may actually be platform dependent, based on the size of dev and inode
            dlog("stat: %d dev=%llx inode=%lld mode=%o uid=%d gid=%d\n", pid, ret.dev, ret.ino, ret.mode, ret.uid, ret.gid );

            if( get_map( ret.dev, ret.ino, &override ) ) {
                ret.mode=override.mode;
                ret.uid=override.uid;
                ret.gid=override.gid;
                if( S_ISBLK(ret.mode) || S_ISCHR(ret.mode) )
                    ret.rdev=override.dev_id;

                ptlib_set_mem( pid, &ret, state->saved_state[0], sizeof(struct stat) );
            }
        }

        state->state=pid_state::NONE;
    }

    return true;
}
