#include "config.h"
#include "lockless_event.h"

#include <linux/futex.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <sys/syscall.h>

#include "exceptions.h"

#include <iostream>
static int futex(std::atomic_int *uaddr, int op, int val)
{
    return syscall(SYS_futex, uaddr, op, val, nullptr, nullptr, nullptr);
}

lockless_event::lockless_event() : m_sync_var(UNSIGNALLED)
{
    // The lockless event cannot work if atomic is not, well, lockless
    assert(m_sync_var.is_lock_free());
    static_assert( sizeof(m_sync_var) == sizeof(int),
            "an atomic_int is not really an int, so the pointers will not match" );
}

void lockless_event::wait()
{
    if( m_sync_var==UNSIGNALLED ) {
        int oldstate = m_sync_var.exchange(WAITING);
        if( oldstate==UNSIGNALLED ) {
            if( futex(&m_sync_var, FUTEX_WAIT_PRIVATE, WAITING )<0 )
            {
                if( errno!=EINTR && errno!=EAGAIN ) {
                    throw errno_exception("futex wait failed");
                }
            }
        }
    }

    m_sync_var = UNSIGNALLED;
}


void lockless_event::signal()
{
    int oldstate = m_sync_var.exchange(SIGNALLED);

    if( oldstate==WAITING )
        futex( &m_sync_var, FUTEX_WAKE_PRIVATE, 1 );
}

void lockless_event::signal_from_sighandler()
{
    m_sync_var = SIGNALLED;
}
