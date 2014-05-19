#ifndef LOCKLESS_EVENT_H
#define LOCKLESS_EVENT_H

#include <atomic>

/* lockless event implements an event (similar to a condition variable) without a corresponding mutex.
   Obviously, such an event might suffer from spurious wakeups, so it should only be used when such wakeups
   are an acceptable tradeoff (obviously resulting in better performance).

   This class is designed for single waiter, multiple signallers.
 */

class lockless_event {
    enum STATES {
        WAITING, UNSIGNALLED, SIGNALLED
    };

    std::atomic_int m_sync_var;
    unsigned spurious_wakeup_count = 0;

    lockless_event( const lockless_event &rhs ) = delete;
    lockless_event &operator=( const lockless_event &rhs ) = delete;
public:
    lockless_event();

    void wait();

    // Do not call this function from a signal handler
    void signal();

    // Only call the following function from a signal handler on the same thread as the waiter
    void signal_from_sighandler();
};

#endif // LOCKLESS_EVENT_H
