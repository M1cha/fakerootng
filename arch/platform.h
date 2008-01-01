#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Platform specific definitinos go in a special file */
#include "platform_specific.h"

/* Functions for abstracting the details of registers and memory layout for interpreting ptrace stacks and memory */

/* Called once per new process created */
void ptlib_prepare( pid_t pid );

/* Wait for next event.
 * Reports whether it was a signal delivered at the process (ret gets the signal number)
 * "status" is the status returned by "wait"
 * A process stopped due to signal (ret is the signal number)
 * A process terminated (ret is the return code)
 * A process terminated (ret is the signal that killed it)
 * A SYSCALL took place (ret is the syscall number)
 * A new process being created (only if PTLIB_SUPPORTS_{FORK,VFORK,CLONE} is defined for the platform) - ret is the new PID */
enum PTLIB_WAIT_RET { SIGNAL, EXIT, SIGEXIT, SYSCALL, NEWPROCESS };
int ptlib_wait( pid_t *pid, int *status, long *ret );
/* If we get a trace before we run ptlib_prepare, we might mis-interpret the signals */
int ptlib_reinterpret( enum PTLIB_WAIT_RET prestate, pid_t pid, int status, long *ret );

/* Returns/sets the Program Counter (EIP on Intel) for the traced program */
void *ptlib_get_pc( pid_t pid );
void *ptlib_set_pc( pid_t pid );

/* Syscall analysis functions - call only when stopped process just invoked a syscall */

/* Report the syscall number being invoked */
int ptlib_get_syscall( pid_t pid );
int ptlib_set_syscall( pid_t pid, int sc_num ); /* Change the meaning of a just started system call */
int ptlib_generate_syscall( pid_t pid, int sc_num, void *base_memory ); /* Generate a new system call */

/* Return the nth argument passed */
void *ptlib_get_argument( pid_t pid, int argnum );
int ptlib_set_argument( pid_t pid, int argnum, void *value );

void *ptlib_get_retval( pid_t pid );
int ptlib_success( pid_t pid, int sc_num ); /* Report whether the syscall succeeded */
void ptlib_set_retval( pid_t pid, void *val );
void ptlib_set_error( pid_t pid, int sc_num, int error );
int ptlib_get_error( pid_t pid, int sc_num );

/* Copy memory in and out of the process
 * Return TRUE on success */
int ptlib_get_mem( pid_t pid, void *process_ptr, void *local_ptr, size_t len );
int ptlib_set_mem( pid_t pid, const void *local_ptr, void *process_ptr, size_t len );

/* Copy a NULL terminated string. "get" returns the number of bytes copied, including the NULL */
int ptlib_get_string( pid_t pid, void *process_ptr, char *local_ptr, size_t maxlen );
int ptlib_set_string( pid_t pid, const char *local_ptr, void *process_ptr );

/* Save/restore the process state */
void ptlib_save_state( pid_t pid, void *buffer );
void ptlib_restore_state( pid_t pid, const void *buffer );

/* Initialize debugger controled memory inside debuggee address space */
void ptlib_prepare_memory( pid_t pid, void **memory, size_t *size );

/* This is a function that must be provided by the user of the library */
void dlog( const char *format, ... );

#ifdef __cplusplus
};
#endif

#endif /* PLATFORM_H */
