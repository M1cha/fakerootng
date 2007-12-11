#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([fakeroot-ng], [0.00], [shachar@debian.org])
AC_CANONICAL_TARGET()
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([parent.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([stdlib.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK

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
if [ ! -f "$srcdir/arch/$target_os/$target_cpu/platform.c" ]
then
]
    AC_MSG_RESULT(no)
    echo "$srcdir"
    AC_MSG_ERROR(Platform detected is yet supported.)
[
else
]    AC_MSG_RESULT([yes]) [
fi
]

AC_CONFIG_FILES([Makefile arch/linux/i386/Makefile])
AC_OUTPUT
