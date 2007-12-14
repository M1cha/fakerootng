#include "config.h"

#include <sys/types.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

#include "../platform.h"

void ptlib_prepare( pid_t pid )
{
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE);
}


