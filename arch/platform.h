#ifndef PLATFORM_H
#define PLATFORM_H

/* Functions for abstracting the details of registers and memory layout for interpreting ptrace stacks and memory */

/* Returns the Program Counter (EIP on Intel) for the traced program */
void *ptlib_get_pc( pid_t pid );

/* Syscall analysis functions - call only when stopped process just invoked a syscall */

/* Report the syscall number being invoked */
void *ptlib_get_syscall( pid_t pid );

/* Return the nth argument passed */
void *ptlib_get_argument( pid_t pid, int argnum );

#endif /* PLATFORM_H */
