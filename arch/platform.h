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

/* Return the nth argument passed */
void *ptlib_get_argument( pid_t pid, int argnum );

void *ptlib_get_retval( pid_t pid );
void ptlib_set_retval( pid_t pid, void *val );

#ifdef __cplusplus
};
#endif

#endif /* PLATFORM_H */
