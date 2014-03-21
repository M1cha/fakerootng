#ifndef PLATFORM_H
#define PLATFORM_H

/** 
 * \file platform.h
 * ptlib interface definitions.
 *
 * Here all interfaces for ptlib are defined in a platform independent way.
 */

/** \defgroup ptlib ptlib - PTrace wrapper LIBrary
 *
 * Sort-of stand alone library for abstracting the ugly ptrace details from the library's user.
 * @{
 */

#include <sys/types.h>
#include <functional>
#include <iostream>

/* Platform specific definitinos go in a special file */
#include "platform_specific.h"

/**
  @brief Namespace for the ptlib functions
 */
namespace ptlib {

/* Functions for abstracting the details of registers and memory layout for interpreting ptrace stacks and memory */

typedef std::function < void( const std::function< void () > &thread_callback ) > callback_initiator;
/* Called once before any other call to ptlib functions.
   callback - a function returning void. It is used to proxy execute arbitrary code inside the debugger thread
        callback has the following parameters:
            thread_callback - the callback function to be called in the debugger thread
 */

/**
  @brief Initialize the ptlib library.

  This function should be called precisely once before use of the ptlib library.
  @param callback Callback function for trampoline code - should execute provided code in main thread
  @see callback_initiator
 */
void init( const callback_initiator &callback );

/**
  @brief Continue (or detach) a halted process.

  @param request PTRACE request type.
  @param pid the pid of the process to restart.
  @param signal the signal to send the process with the ptrace command.
  @return the same value as the corresponding ptrace command
 */
int cont( int request, pid_t pid, int signal );

/**
  @brief Call once per each new process created.

  Call this function once for each new process for which we attach as a debugger.
  This function should be called after we have already attached to it as a debugger.
  @param pid the pid of the process to which we attached.
 */
void prepare( pid_t pid );

/**
  @brief legal return values from ptlib::wait.
  @see ptlib::parse_wait

  @note
  ptlib::NEWPROCESS can only be returned only if SUPPORTS_{FORK,VFORK,CLONE} is defined for the platform.

  @see ptlib::parse_wait
 */
enum class WAIT_RET {
    SIGNAL,     ///< The process was halted with a signal.
    EXIT,       ///< The process performed a normal exit.
    SIGEXIT,    ///< The process quit due to a signal.
    SYSCALL,    ///< The process performed a system call.
    NEWPROCESS  ///< This is a notification of a new process (but see the note above).
};

static inline std::ostream &operator<< (std::ostream &strm, WAIT_RET wait_ret)
{
#define PRODUCE_CASE(state) case WAIT_RET::state: strm<<#state; break
    switch( wait_ret ) {
        PRODUCE_CASE(SIGNAL);
        PRODUCE_CASE(EXIT);
        PRODUCE_CASE(SIGEXIT);
        PRODUCE_CASE(SYSCALL);
        PRODUCE_CASE(NEWPROCESS);
    }
#undef PRODUCE_CASE

    return strm;
}

/**
 @brief Wait for next event. Returns some data about the event.

 If async is true and there is nothing to report, the function exits immediately, returning false. If async is false,
 the function blocks until there is something to report.

 @param[out] pid        the pid of the process on which we are reporting.
 @param[out] status     the status returned by "wait" (integer).
 @param[out] data       extra data returned by wait (such as rusage).
 @param[in]  async      whether to block if we have nothing to report.
 @returns               whether the function succeeded.
 @see ptlib::parse_wait
 */
bool wait( pid_t *pid, int *status, extra_data *data, int async );
/**
 @brief parses the info returned by ptlib::wait.
 
 @param[in]  pid        the pid of the process to parse.
 @param[in]  status     the status as returned by ptlib::wait.
 @param[out] type       type of event that happened.
 @returns               meaning depends on value of type.

 Parses the event that ptlib::wait reported, and gives more specific information about it. Return type depends on the
 type of event that happened:

 - ptlib::SIGNAL - ret is the signal number.
 - ptlib::EXIT - ret is the exit code of the program.
 - ptlib::SIGEXIT - ret is the signal number that killed the program.
 - ptlib::SYSCALL - ret is the syscall number that triggered the event.
 - ptlib::NEWPROCESS - ret is the new PID.

 @see   ptlib::wait
 @see   ptlib::WAIT_RET
 */
long parse_wait( pid_t pid, int status, WAIT_RET *type );

/* If we get a trace before we run prepare, we might mis-interpret the signals */
// TODO Is this function even needed?
WAIT_RET reinterpret( WAIT_RET prestate, pid_t pid, int status, long *ret );

/**
  @brief get process' program counter

  @param pid pid of process to query.
  @returns address of current program counter.
 */
int_ptr get_pc( pid_t pid );
/**
  @brief set process' program counter

  @param pid pid of process to alter.
  @param location new address to set PC to.
  @returns 0 on success, -1 on failure.
 */
int set_pc( pid_t pid, int_ptr location );

/* Syscall analysis functions - call only when stopped process just invoked a syscall */

/* Report the syscall number being invoked */
int get_syscall( pid_t pid );
int set_syscall( pid_t pid, int sc_num ); /* Change the meaning of a just started system call */
int generate_syscall( pid_t pid, int sc_num, int_ptr base_memory ); /* Generate a new system call */

/* Return the nth argument passed */
int_ptr get_argument( pid_t pid, int argnum );
int set_argument( pid_t pid, int argnum, int_ptr value );

int_ptr get_retval( pid_t pid );
int success( pid_t pid, int sc_num ); /* Report whether the syscall succeeded */
void set_retval( pid_t pid, int_ptr val );
void set_error( pid_t pid, int sc_num, int error );
int get_error( pid_t pid, int sc_num );

/* Copy memory in and out of the process
 * Return TRUE on success */
int get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len );
int set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len );

/* Copy a NULL terminated string. "get" returns the number of bytes copied, including the NULL */
int get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen );
int set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr );

/* Get a process' current directory and open fds */
/* Return value is as for "readlink" */
ssize_t get_cwd( pid_t pid, char *buffer, size_t buff_size );
ssize_t get_fd( pid_t pid, int fd, char *buffer, size_t buff_size );

/* Save/restore the process state */
void save_state( pid_t pid, void *buffer );
void restore_state( pid_t pid, const void *buffer );

/* Initialize debugger controled memory inside debuggee address space */
const void *prepare_memory( ); /* Returns pointer to static buffer with the desired opcods, of prepare_memory_len length */
size_t prepare_memory_len(); /* How much memory does the platform need beyond how much the process needs */

/* Process relationship - return the parent of a process */
pid_t get_parent( pid_t pid );

/**
 * @brief Handle process creation with debugger attached
 *
 * Keep in mind that child process might start running (traced) before the parent
 * process returns from the fork, or after. It is also possible that child or parent
 * will run to completion before the other one returns from the fork. Caller must be
 * prepared to handle them in arbitrary order.
 * 
 * @param pid the pid of the process executing the call
 * @param sc_num the actual system call number performed
 * @param waiter a callback to be called whenever the handler needs to release the original process
 * @return the PID of the new process created
 */
pid_t fork_handler( pid_t pid, int orig_sc, std::function<void ()> waiter );

}; // End of namespace ptlib

/**
 * @}
 */

#endif /* PLATFORM_H */
