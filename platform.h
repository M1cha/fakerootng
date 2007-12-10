#ifndef PLATFORM_H
#define PLATFORM_H

/* Functions for abstracting the details of registers and memory layout for interpreting ptrace stacks and memory */

/* Returns the Program Counter (EIP on Intel) for the traced program */
void *getpc( pid_t pid );

#endif /* PLATFORM_H */
