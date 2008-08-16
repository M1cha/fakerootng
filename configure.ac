#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([fakeroot-ng], [0.13], [shachar@debian.org])
AC_CANONICAL_TARGET()
AM_INIT_AUTOMAKE([no-dist])
AC_CONFIG_SRCDIR([parent.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_RANLIB

AC_LANG(C)

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

dnl Check whether we have PTRACE_GETREGS
AC_MSG_CHECKING([for PTRACE_GETREGS])
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
        #include <sys/ptrace.h>
        ],
        [ptrace(PTRACE_GETREGS, 0, 0, 0);])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_PTRACE_GETREGS], [1], [Ptrace defines a single syscall for getting all registers])
    ],
    [AC_MSG_RESULT([no])])

dnl Check whether we have PTRACE_PEEKUSER
AC_MSG_CHECKING([for PTRACE_PEEKUSER])
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
        #include <sys/ptrace.h>
        ],
        [ptrace(PTRACE_PEEKUSER, 0, 0, 0);])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_PTRACE_PEEKUSER], [1], [Ptrace defines a syscall for getting a single register])
    ],
    [AC_MSG_RESULT([no])])

dnl Check which std::map variant to use
AC_LANG_PUSH(C++)
AC_LANG_WERROR

AC_MSG_CHECKING([whether compiler supports the upcoming ISO C++ standard])
saved_CXXFLAGS=$CXXFLAGS
CXXFLAGS="$CXXFLAGS -std=c++0x"
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
        #include <stdio.h>
        ],
        [ printf("Hello, world\n"); ])],
    [
        AC_MSG_RESULT([yes])
    ],
    [
        AC_MSG_RESULT([no])
        CXXFLAGS="$saved_CXXFLAGS"
    ]
)

AC_MSG_CHECKING([for std::map])
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
        #include <unordered_map>
        ],
        [ std::unordered_map<int, int> test; ])],
    [
        AC_MSG_RESULT([std::unordered_map])
        AC_DEFINE([MAP_INCLUDE], [<unordered_map>], [The file to include in order to get the map class])
        AC_DEFINE([MAP_CLASS], [std::unordered_map], [The type for the map class])
    ],
    [
        AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
            #include <ext/hash_map>
        ],
        [ __gnu_cxx::hash_map<int,int> test ])],
    [
        AC_MSG_RESULT([__gnu_cxx::hash_map])
        AC_DEFINE([MAP_INCLUDE], [<ext/hash_map>])
        AC_DEFINE([MAP_CLASS], [__gnu_cxx::hash_map])
    ],
    [
        AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
            #include <map>
        ],
        [ std::map<int,int> test ])],
    [
        AC_MSG_RESULT([std::map])
        AC_DEFINE([MAP_INCLUDE], [<map>])
        AC_DEFINE([MAP_CLASS], [std::map])
    ],
    [
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([Without a working map class this program cannot be compiled!])
    ])])]
)

dnl gcc supports indicating that a function is a printf style function. It then has protections against format string
dnl mismatches
AC_MSG_CHECKING([whether compiler supports custom printf style protection])
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([int dummy( const char *format, ... ) __attribute__ ((format(printf, 1, 2)));],[] )],
        [
                AC_MSG_RESULT([__attribute__ ((format(...)))])
                AC_DEFINE([COMPHINT_PRINTF( f, c )], [__attribute__ (( format ( printf, f, c )))],
                        [How to tell the compiler that this is a printf style function])
        ],
        [
                AC_MSG_RESULT([no])
                AC_MSG_ERROR([Compiler does not support format string checking on custom functions])
        ]
)

AC_LANG_POP

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getcwd mkdir strchr strerror])

AC_MSG_CHECKING([whether openat class functions are supported])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([
    #include <sys/stat.h>
    #include <sys/fcntl.h>
    ], [struct stat stat; fstatat(AT_FDCWD, "/etc/passwd", &stat, AT_SYMLINK_NOFOLLOW);])],
    [ AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_OPENAT], [1], [Supports the openat class of functions])],
    [
        dnl Let's try again, this time with _ATFILE_SOURCE at the beginning
        AC_COMPILE_IFELSE(
            [ AC_LANG_PROGRAM([
                #define _ATFILE_SOURCE
                #include <sys/stat.h>
                #include <sys/fcntl.h>
                ], [struct stat stat; fstatat(AT_FDCWD, "/etc/passwd", &stat, AT_SYMLINK_NOFOLLOW);])],
            [
                AC_MSG_RESULT([_ATFILE_SOURCE])
                AC_DEFINE([HAVE_OPENAT], [1])
                AC_DEFINE([_ATFILE_SOURCE],[], [Enable openat functions])
            ],
            [ AC_MSG_RESULT([no]) ]
        )
    ] )

# Custom steps

dnl Canoninize the canonical system names
[
if [ "$target_os" = "linux-gnu" ]
then
    target_os=linux
fi

case "$target_cpu" in
i686|i586|i486)
    target_cpu=i386
    ;;
esac
]

# Check whether we are ported to this platform
AC_MSG_CHECKING([whether platform $target_os/$target_cpu is supported])

[
if [ ! -f "$srcdir/arch/$target_os/$target_cpu/platform_specific.h" ]
then
]
    AC_MSG_RESULT(no)
    echo "$srcdir"
    AC_MSG_ERROR(Platform detected is not yet supported.)
[
else
]    AC_MSG_RESULT([yes]) [
fi
]

dnl We generate all Makefiles for all platforms, and then only invoke those for the platforms we need
AC_CONFIG_FILES([Makefile tests/Makefile arch/Makefile arch/$target_os/Makefile.template arch/$target_os/$target_cpu/Makefile])
AC_OUTPUT
