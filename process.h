#ifndef PROCESS_H
#define PROCESS_H

// Bitmasks to be stored in context_state[0] by all functions handling new process creation
#define NEW_PROCESS_SAME_PARENT 1
#define NEW_PROCESS_SAME_VM 2
#define NEW_PROCESS_SAME_FD 4
#define NEW_PROCESS_SAME_ROOT 8

#endif // PROCESS_H
