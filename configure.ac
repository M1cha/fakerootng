#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([fakeroot-ng], [0.00], [shachar@debian.org])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([platform.h.in])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_MKDIR_P

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([stdlib.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK

AC_CONFIG_FILES([Makefile platform.h])
AC_OUTPUT
