/*
    Fakeroot Next Generation - run command with fake root privileges
    This program is copyrighted. Copyright information is available at the
    AUTHORS file at the root of the source tree for the fakeroot-ng project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "config.h"

#include <asm/unistd.h>
#include <sys/ptrace.h>
#define __FRAME_OFFSETS
#include <asm/ptrace.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>

#include "../../../log.h"
#include "../../platform.h"
#include "../os.h"
#include "platform_specific_internal.h"

namespace ptlib {

typedef platform::process_state::types cpu_types;

static const unsigned char memory_image[prepare_memory_len]=
{
    0xcd, 0x80, /* int 0x80 - syscall for 32 bit */
    0x00, 0x00, /* Pad */
    0x0f, 0x05, /* syscall - 64 bit */
    0x00, 0x00, /* Pad */
};

static int syscall_instr64_offset=4;

/* All entries stating "-1" mean unimplemented (32bit) function
 * All entries stating SYS_ instead of __NR_ mean a function unimplemented in 64bit, which we allocate a (fictive) syscall number for
 */
static int syscall_32_to_64[]={
    __NR_restart_syscall,       /* 0 */
    __NR_exit,          /* 1 */
    __NR_fork,          /* 2 */
    __NR_read,          /* 3 */
    __NR_write,         /* 4 */
    __NR_open,		/* 5 */
    __NR_close,         /* 6 */
    SYS_waitpid,        /* 7 */
    __NR_creat,         /* 8 */
    __NR_link,          /* 9 */
    __NR_unlink,	/* 10 */
    __NR_execve,	/* 11 */
    __NR_chdir,		/* 12 */
    __NR_time,		/* 13 */
    __NR_mknod,		/* 14 */
    __NR_chmod,		/* 15 */
    __NR_lchown,	/* 16 */
    -1, /* __NR_break,		17 */
    SYS_oldstat,	/* 18 */
    __NR_lseek,		/* 19 */
    __NR_getpid,	/* 20 */
    __NR_mount,		/* 21 */
    -1, /* __NR_umount,	 22 */
    __NR_setuid,	/* 23 */
    __NR_getuid,	/* 24 */
    -1, /* __NR_stime,		 25 */
    __NR_ptrace,	/* 26 */
    __NR_alarm,		/* 27 */
    SYS_oldfstat,	/* 28 */
    __NR_pause,		/* 29 */
    __NR_utime,		/* 30 */
    -1, /* __NR_stty,		 31 */
    -1, /* __NR_gtty,		32 */
    __NR_access,	/* 33 */
    -1, /* __NR_nice,	34 */
    -1, /* __NR_ftime,		35 */
    __NR_sync,		/* 36 */
    __NR_kill,		/* 37 */
    __NR_rename,	/* 38 */
    __NR_mkdir,		/* 39 */
    __NR_rmdir,		/* 40 */
    __NR_dup,		/* 41 */
    __NR_pipe,		/* 42 */
    __NR_times,		/* 43 */
    -1, /* prof,		 44 */
    __NR_brk,		/* 45 */
    __NR_setgid,	/* 46 */
    __NR_getgid,	/* 47 */
    -1, /* signal,	 48 */
    __NR_geteuid,	/* 49 */
    __NR_getegid,	/* 50 */
    __NR_acct,		/* 51 */
    __NR_umount2,	/* 52 */
    -1, /* lock,		53 */
    __NR_ioctl,		/* 54 */
    __NR_fcntl,		/* 55 */
    -1, /* mpx,		 56 */
    __NR_setpgid,	/* 57 */
    -1, /* ulimit,	 58 */
    -1, /* oldolduname,	 59 */
    __NR_umask,		/* 60 */
    __NR_chroot,	/* 61 */
    __NR_ustat,		/* 62 */
    __NR_dup2,		/* 63 */
    __NR_getppid,	/* 64 */
    __NR_getpgrp,	/* 65 */
    __NR_setsid,	/* 66 */
    -1, /* sigaction,	 67 */
    -1, /* sgetmask,	 68 */
    -1, /* ssetmask,	 69 */
    __NR_setreuid,	/* 70 */
    __NR_setregid,	/* 71 */
    -1, /* sigsuspend,	 72 */
    -1, /* sigpending,	 73 */
    __NR_sethostname,	/* 74 */
    __NR_setrlimit,	/* 75 */
    __NR_getrlimit,	/* 76 */	/* Back compatible 2Gig limited rlimit */
    __NR_getrusage,	/* 77 */
    __NR_gettimeofday,	/* 78 */
    __NR_settimeofday,	/* 79 */
    __NR_getgroups,	/* 80 */
    __NR_setgroups,	/* 81 */
    __NR_select,	/* 82 */
    __NR_symlink,	/* 83 */
    SYS_oldlstat,	/* 84 */
    __NR_readlink,	/* 85 */
    __NR_uselib,	/* 86 */
    __NR_swapon,	/* 87 */
    __NR_reboot,	/* 88 */
    -1, /* readdir,	 89 */
    SYS_mmap2,		/* 90 */ /* See comment for __NR_mmap (192) */
    __NR_munmap,	/* 91 */
    __NR_truncate,	/* 92 */
    __NR_ftruncate,	/* 93 */
    __NR_fchmod,	/* 94 */
    __NR_fchown,	/* 95 */
    __NR_getpriority,	/* 96 */
    __NR_setpriority,	/* 97 */
    -1, /* profil,	 98 */
    __NR_statfs,	/* 99 */
    __NR_fstatfs,	/* 100 */
    __NR_ioperm,	/* 101 */
    -1, /* socketcall,	 102 */
    __NR_syslog,	/* 103 */
    __NR_setitimer,	/* 104 */
    __NR_getitimer,	/* 105 */
    __NR_stat,		/* 106 */
    __NR_lstat,		/* 107 */
    __NR_fstat,		/* 108 */
    -1, /* olduname,	 109 */
    __NR_iopl,		/* 110 */
    __NR_vhangup,	/* 111 */
    -1, /* idle,		112 */
    -1, /* vm86old,	 113 */
    __NR_wait4,		/* 114 */
    __NR_swapoff,	/* 115 */
    __NR_sysinfo,	/* 116 */
    -1, /* ipc,		 117 */
    __NR_fsync,		/* 118 */
    SYS_sigreturn,	/* 119 */
    __NR_clone,		/* 120 */
    __NR_setdomainname,	/* 121 */
    __NR_uname,		/* 122 */
    __NR_modify_ldt,		/* 123 */
    __NR_adjtimex,		/* 124 */
    __NR_mprotect,		/* 125 */
    -1, /* sigprocmask,		 126 */
    __NR_create_module,		/* 127 */
    __NR_init_module,		/* 128 */
    __NR_delete_module,		/* 129 */
    __NR_get_kernel_syms,	/* 130 */
    __NR_quotactl,		/* 131 */
    __NR_getpgid,		/* 132 */
    __NR_fchdir,		/* 133 */
    -1, /* bdflush,		 134 */
    __NR_sysfs,	        	/* 135 */
    __NR_personality,		/* 136 */
    __NR_afs_syscall,		/* 137 */ /* Syscall for Andrew File System */
    __NR_setfsuid,		/* 138 */
    __NR_setfsgid,		/* 139 */
    -1, /* _llseek,		 140 */
    __NR_getdents,		/* 141 */
    -1, /* _newselect,		 142 */
    __NR_flock,	        	/* 143 */
    __NR_msync,	        	/* 144 */
    __NR_readv,	        	/* 145 */
    __NR_writev,		/* 146 */
    __NR_getsid,		/* 147 */
    __NR_fdatasync,		/* 148 */
    __NR__sysctl,		/* 149 */
    __NR_mlock,		        /* 150 */
    __NR_munlock,		/* 151 */
    __NR_mlockall,		/* 152 */
    __NR_munlockall,		/* 153 */
    __NR_sched_setparam,	/* 154 */
    __NR_sched_getparam,	/* 155 */
    __NR_sched_setscheduler,	/* 156 */
    __NR_sched_getscheduler,	/* 157 */
    __NR_sched_yield,		/* 158 */
    __NR_sched_get_priority_max,		/* 159 */
    __NR_sched_get_priority_min,		/* 160 */
    __NR_sched_rr_get_interval,	        	/* 161 */
    __NR_nanosleep,		/* 162 */
    __NR_mremap,		/* 163 */
    __NR_setresuid,		/* 164 */
    __NR_getresuid,		/* 165 */
    -1, /* vm86,	        	 166 */
    __NR_query_module,		/* 167 */
    __NR_poll,		        /* 168 */
    __NR_nfsservctl,		/* 169 */
    __NR_setresgid,		/* 170 */
    __NR_getresgid,		/* 171 */
    __NR_prctl,		        /* 172 */
    __NR_rt_sigreturn,		/* 173 */
    __NR_rt_sigaction,		/* 174 */
    __NR_rt_sigprocmask,	/* 175 */
    __NR_rt_sigpending,		/* 176 */
    __NR_rt_sigtimedwait,	/* 177 */
    __NR_rt_sigqueueinfo,	/* 178 */
    __NR_rt_sigsuspend,		/* 179 */
    __NR_pread64,		/* 180 */
    __NR_pwrite64,		/* 181 */
    __NR_chown,		        /* 182 */
    __NR_getcwd,		/* 183 */
    __NR_capget,		/* 184 */
    __NR_capset,		/* 185 */
    __NR_sigaltstack,		/* 186 */
    __NR_sendfile,		/* 187 */
    __NR_getpmsg,		/* 188 */	/* some people actually want streams */
    __NR_putpmsg,		/* 189 */	/* some people actually want streams */
    __NR_vfork,		        /* 190 */
    -1, /* ugetrlimit,		191 */	/* SuS compliant getrlimit */
    __NR_mmap,                  /* 192 */
    /* Technically, this is mmap2. However, it is much more reasonable as far as arguments are handled to map it this way. */
    -1, /* truncate64,		 193 */
    -1, /* ftruncate64,		 194 */
    SYS_stat64,		/* 195 */
    SYS_lstat64,		/* 196 */
    SYS_fstat64,		/* 197 */
    SYS_lchown32,		/* 198 */
    SYS_getuid32,		/* 199 */
    SYS_getgid32,		/* 200 */
    SYS_geteuid32,		/* 201 */
    SYS_getegid32,		/* 202 */
    SYS_setreuid32,		/* 203 */
    SYS_setregid32,		/* 204 */
    SYS_getgroups32,		/* 205 */
    SYS_setgroups32,		/* 206 */
    SYS_fchown32,		/* 207 */
    SYS_setresuid32,		/* 208 */
    SYS_getresuid32,		/* 209 */
    SYS_setresgid32,		/* 210 */
    SYS_getresgid32,		/* 211 */
    SYS_chown32,		/* 212 */
    SYS_setuid32,		/* 213 */
    SYS_setgid32,		/* 214 */
    SYS_setfsuid32,		/* 215 */
    SYS_setfsgid32,		/* 216 */
    __NR_pivot_root,		/* 217 */
    __NR_mincore,		/* 218 */
    __NR_madvise,		/* 219 */
    -1, /* __NR_madvise1,	         219 */
    __NR_getdents64,		/* 220 */
    -1, /* __NR_fcntl64,		 221 */
    -1,                         /* 223 is unused */
    __NR_gettid,		/* 224 */
    __NR_readahead,		/* 225 */
    __NR_setxattr,		/* 226 */
    __NR_lsetxattr,		/* 227 */
    __NR_fsetxattr,		/* 228 */
    __NR_getxattr,		/* 229 */
    __NR_lgetxattr,		/* 230 */
    __NR_fgetxattr,		/* 231 */
    __NR_listxattr,		/* 232 */
    __NR_llistxattr,		/* 233 */
    __NR_flistxattr,		/* 234 */
    __NR_removexattr,		/* 235 */
    __NR_lremovexattr,		/* 236 */
    __NR_fremovexattr,		/* 237 */
    __NR_tkill,		        /* 238 */
    -1, /* __NR_sendfile64,		 239 */
    __NR_futex,		        /* 240 */
    __NR_sched_setaffinity,	/* 241 */
    __NR_sched_getaffinity,	/* 242 */
    __NR_set_thread_area,	/* 243 */
    __NR_get_thread_area,	/* 244 */
    __NR_io_setup,		/* 245 */
    __NR_io_destroy,		/* 246 */
    __NR_io_getevents,		/* 247 */
    __NR_io_submit,		/* 248 */
    __NR_io_cancel,		/* 249 */
    __NR_fadvise64,		/* 250 */
    -1,                         /* 251 is available for reuse (was briefly sys_set_zone_reclaim) */
    __NR_exit_group,		/* 252 */
    __NR_lookup_dcookie,	/* 253 */
    __NR_epoll_create,		/* 254 */
    __NR_epoll_ctl,		/* 255 */
    __NR_epoll_wait,		/* 256 */
    __NR_remap_file_pages,	/* 257 */
    __NR_set_tid_address,	/* 258 */
    __NR_timer_create,		/* 259 */
    __NR_timer_settime,		/* 260 */
    __NR_timer_gettime,		/* 261 */
    __NR_timer_getoverrun,	/* 262 */
    __NR_timer_delete,		/* 263 */
    __NR_clock_settime,		/* 264 */
    __NR_clock_gettime,		/* 265 */
    __NR_clock_getres,		/* 266 */
    __NR_clock_nanosleep,	/* 267 */
    -1, /* statfs64,		 268 */
    -1, /* fstatfs64,		269 */
    __NR_tgkill,		/* 270 */
    __NR_utimes,		/* 271 */
    -1, /* fadvise64_64,		 272 */
    __NR_vserver,		/* 273 */
    __NR_mbind,	        	/* 274 */
    __NR_get_mempolicy,		/* 275 */
    __NR_set_mempolicy,		/* 276 */
    __NR_mq_open,		/* 277 */
    __NR_mq_unlink,		/* 278 */
    __NR_mq_timedsend,		/* 279 */
    __NR_mq_timedreceive,	/* 280 */
    __NR_mq_notify,		/* 281 */
    __NR_mq_getsetattr,		/* 282 */
    __NR_kexec_load,		/* 283 */
    __NR_waitid,		/* 284 */
    -1,                         /* __NR_sys_setaltroot	285 */
    __NR_add_key,		/* 286 */
    __NR_request_key,		/* 287 */
    __NR_keyctl,		/* 288 */
    __NR_ioprio_set,		/* 289 */
    __NR_ioprio_get,		/* 290 */
    __NR_inotify_init,		/* 291 */
    __NR_inotify_add_watch,	/* 292 */
    __NR_inotify_rm_watch,	/* 293 */
    __NR_migrate_pages,		/* 294 */
    __NR_openat,		/* 295 */
    __NR_mkdirat,		/* 296 */
    __NR_mknodat,		/* 297 */
    __NR_fchownat,		/* 298 */
    __NR_futimesat,		/* 299 */
    SYS_fstatat64,		/* 300 */
    __NR_unlinkat,		/* 301 */
    __NR_renameat,		/* 302 */
    __NR_linkat,		/* 303 */
    __NR_symlinkat,		/* 304 */
    __NR_readlinkat,		/* 305 */
    __NR_fchmodat,		/* 306 */
    __NR_faccessat,		/* 307 */
    __NR_pselect6,		/* 308 */
    __NR_ppoll,	        	/* 309 */
    __NR_unshare,		/* 310 */
    __NR_set_robust_list,	/* 311 */
    __NR_get_robust_list,	/* 312 */
    __NR_splice,		/* 313 */
    __NR_sync_file_range,	/* 314 */
    __NR_tee,		        /* 315 */
    __NR_vmsplice,		/* 316 */
    __NR_move_pages,		/* 317 */
    -1, /* getcpu,		 318 */
    -1, /* epoll_pwait,		 319 */
    -1, /* utimensat,		320 */
    -1, /* __NR_signalfd,		 321 */
    -1, /* __NR_timerfd,		 322 */
    -1, /* __NR_eventfd,		 323 */
};

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
static constexpr size_t MAP_SIZE_32_64 = ARRAY_SIZE(syscall_32_to_64)+SYS_X86_32_OFFSET;
static int syscall_64_to_32[MAP_SIZE_32_64];

/* We init the reverse map when the library loads */
void init( callback_initiator callback )
{
    unsigned int i;
    for( i=0; i<ARRAY_SIZE(syscall_64_to_32); ++i )
        syscall_64_to_32[i]=-1;

    for( i=0; i<ARRAY_SIZE(syscall_32_to_64); ++i ) {
        if( syscall_32_to_64[i]!=-1 && syscall_32_to_64[i]>=(-SYS_X86_32_OFFSET) &&
                syscall_32_to_64[i]<(int)ARRAY_SIZE(syscall_32_to_64) )
        {
            syscall_64_to_32[syscall_32_to_64[i]+SYS_X86_32_OFFSET]=i;
        }
    }

    linux::init( callback );
}

void cont( int request, pid_t pid, int signal )
{
    linux::cont( __ptrace_request(request), pid, signal );
}

void prepare( pid_t pid )
{
    linux::prepare(pid);
}

bool wait( pid_t *pid, int *status, extra_data *data, int async )
{
    return linux::wait( pid, status, data, async );
}

long parse_wait( pid_t pid, int status, WAIT_RET *type )
{
    return linux::parse_wait( pid, status, type );
}

WAIT_RET reinterpret( WAIT_RET prestate, pid_t pid, int status, long *ret )
{
    return linux::reinterpret( prestate, pid, status, ret );
}

int_ptr get_pc( pid_t pid )
{
    platform::process_state *state = linux::get_process_state(pid);
    return state->registers.rip;
}

int set_pc( pid_t pid, int_ptr location )
{
    platform::process_state *state = linux::get_process_state(pid);
    state->registers.rip = location;
    state->dirty = true;
    return 0;
}

int get_syscall( pid_t pid )
{
    platform::process_state *state = linux::get_process_state(pid);

    int syscall;

    switch( state->type )
    {
    case cpu_types::amd64:
        syscall = state->registers.orig_rax;
        break;
    case cpu_types::i386:
        // Need to translate the 32 bit syscalls to 64 bit ones
        syscall = state->registers.orig_rax;
        ASSERT(syscall>=0);
        if( (unsigned long)syscall < ARRAY_SIZE(syscall_32_to_64) ) {
            syscall=syscall_32_to_64[syscall];
        } else {
            LOG_W() << "ptlib_get_syscall: " << pid << " syscall out of range " << syscall;

            syscall=-1;
        }
        break;
    case cpu_types::x32:
        LOG_F()<<"Unhandled platform type x32";
        abort();
        break;
    default:
        LOG_F()<<"Unknown platform type!";
        abort();
        break;
    }

    return syscall;
}

static int translate_syscall( pid_t pid, int sc_num )
{
    platform::process_state *state = linux::get_process_state(pid);

    if( state->type == cpu_types::amd64 )
        return sc_num;

    ASSERT( state->type == cpu_types::i386 );
    int sc=sc_num+SYS_X86_32_OFFSET;

    if( (sc-SYS_X86_32_OFFSET)!=-1 && sc>=0 && (unsigned int)sc<ARRAY_SIZE(syscall_64_to_32) ) {
        sc=syscall_64_to_32[sc];
    } else {
        sc=-1;
        LOG_E() << "ptlib_set_syscall: " << pid <<
                " invalid 64 to 32 bit translation for syscall " << sc_num;
    }

    return sc;
}

int set_syscall( pid_t pid, int sc_num )
{
    sc_num=translate_syscall( pid, sc_num );

    if( sc_num==-1 ) {
        errno=EINVAL;
        return -1;
    }

    platform::process_state *state = linux::get_process_state(pid);
    state->registers.orig_rax = sc_num;
    state->dirty = true;

    return 0;
}

void generate_syscall( pid_t pid, int_ptr base_memory )
{
    platform::process_state *state = linux::get_process_state(pid);

    switch( state->type ) {
    case cpu_types::amd64:
        /* 64 bit syscall instruction */
        set_pc( pid, base_memory-prepare_memory_len+syscall_instr64_offset );
        break;
    case cpu_types::i386:
        /* 32 bit syscall instruction */
        set_pc( pid, base_memory-prepare_memory_len );
        break;
    default:
        LOG_F() << "Unsupported CPU platform";
        abort();
    }
}

static decltype(user_regs_struct::rax) user_regs_struct::*arg_offset_32bit[]={
    &user_regs_struct::rbx,
    &user_regs_struct::rcx,
    &user_regs_struct::rdx,
    &user_regs_struct::rsi,
    &user_regs_struct::rdi,
    &user_regs_struct::rbp
};

static decltype(user_regs_struct::rax) user_regs_struct::*arg_offset_64bit[]={
    &user_regs_struct::rdi,
    &user_regs_struct::rsi,
    &user_regs_struct::rdx,
    &user_regs_struct::r10,
    &user_regs_struct::r8,
    &user_regs_struct::r9
};

int_ptr get_argument( pid_t pid, int argnum )
{
    /* Check for error condition */
    if( argnum<1 || argnum>6 ) {
        LOG_E() << "ptlib_get_argument: " << pid << " invalid argument number " << argnum;
        errno=EINVAL;

        return -1;
    }

    platform::process_state *state = linux::get_process_state(pid);

    int_ptr ret;

    switch( state->type ) {
    case cpu_types::amd64:
        ret = state->registers.*arg_offset_64bit[argnum-1];
        break;
    case cpu_types::i386:
        ret = state->registers.*arg_offset_32bit[argnum-1];
        break;

        ret &= 0xffffffff;
        break;
    default:
        LOG_F() << "Unsupported CPU platform";
        abort();
    }

    return ret;
}

int set_argument( pid_t pid, int argnum, int_ptr value )
{
    if( argnum<1 || argnum>6 ) {
        LOG_E() << "ptlib_set_argument: " << pid << " invalid argument number " << argnum;
        errno=EINVAL;

        return -1;
    }

    platform::process_state *state = linux::get_process_state(pid);
    state->dirty = true;

    switch( state->type ) {
    case cpu_types::amd64:
        state->registers.*arg_offset_64bit[argnum-1] = value;
        break;
    case cpu_types::i386:
        state->registers.*arg_offset_32bit[argnum-1] = value;
        break;
    default:
        LOG_F() << "Unsupported CPU platform";
        abort();
    }

    return 0;
}

int_ptr get_retval( pid_t pid )
{
    platform::process_state *state = linux::get_process_state(pid);
    return state->registers.rax;
}

bool success( pid_t pid, int sc_num )
{
    unsigned long ret=get_retval( pid );

    /* This heuristic is good for all syscalls we found. It may not be good for all of them */
    return ret<0xfffffffffffff000u;
}

void set_retval( pid_t pid, int_ptr val )
{
    platform::process_state *state = linux::get_process_state(pid);

    state->registers.rax = val;
    state->dirty = true;
}

void set_error( pid_t pid, int sc_num, int error )
{
    set_retval( pid, -error );
}

int get_error( pid_t pid, int sc_num )
{
    return -(long)get_retval( pid );
}

int get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len )
{
    return linux::get_mem( pid, process_ptr, local_ptr, len );
}

int set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len )
{
    return linux::set_mem( pid, local_ptr, process_ptr, len );
}

int get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen )
{
    return linux::get_string( pid, process_ptr, local_ptr, maxlen );
}

int set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr )
{
    return linux::set_string( pid, local_ptr, process_ptr );
}

struct stat get_stat_result( pid_t pid, int sc_num, int_ptr stat_addr )
{
    platform::process_state *state = linux::get_process_state(pid);

    struct stat stat;

    if( state->type == cpu_types::amd64 ) {
        ASSERT( sc_num==SYS_stat || sc_num==SYS_fstat || sc_num==SYS_lstat || sc_num==SYS_newfstatat );

        get_mem( pid, stat_addr, &stat, sizeof(stat) );
    } else {
        abort();
    }

    return stat;
}

void set_stat_result( pid_t pid, int sc_num, int_ptr stat_addr, struct stat *stat )
{
    platform::process_state *state = linux::get_process_state(pid);

    if( state->type == cpu_types::amd64 ) {
        ASSERT( sc_num==SYS_stat || sc_num==SYS_fstat || sc_num==SYS_lstat || sc_num==SYS_newfstatat );

        set_mem( pid, stat, stat_addr, sizeof(*stat) );
    } else {
        abort();
    }
}

ssize_t get_cwd( pid_t pid, char *buffer, size_t buff_size )
{
    return linux::get_cwd( pid, buffer, buff_size );
}

ssize_t get_fd( pid_t pid, int fd, char *buffer, size_t buff_size )
{
    return linux::get_fd( pid, fd, buffer, buff_size );
}

cpu_state save_state( pid_t pid )
{
    platform::process_state *state = linux::get_process_state(pid);

    return state->registers;
}

void restore_state( pid_t pid, const cpu_state *saved_state )
{
    platform::process_state *state = linux::get_process_state(pid);

    state->registers = *saved_state;
    state->dirty = true;
}

const void *prepare_memory( )
{
    return memory_image;
}

pid_t get_parent( pid_t pid )
{
    return linux::get_parent(pid);
}

namespace platform {

void process_state::post_load(pid_t pid)
{
    switch(registers.cs) {
    case 0x33:
        type = cpu_types::amd64;
        break;
    case 0x23:
        type = cpu_types::i386;
        break;
    default:
        LOG_F() << "Unknown code segment " << HEX_FORMAT(registers.cs, 2);
        abort();
        break;
    }
}

}; // End namespace platform

}; // End of namespace ptlib
