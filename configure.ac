dnl Process this file with Autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([pam-krb5], [2.4], [rra@stanford.edu])

m4_include([m4/krb5.m4])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CANONICAL_HOST
RRA_LIB_KRB5

dnl Crank up the warnings if we're using GCC.
if test "$GCC" = "yes" ; then
    CFLAGS="$CFLAGS -Wall"
fi

dnl If and only if we're on Linux, make sure that all the symbols in the
dnl module are resolved.  More platforms could be handled here.
case "$host" in
*-linux*)
    LDFLAGS="-Wl,-z,defs $LDFLAGS"
    ;;
esac

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
