dnl Process this file with Autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([pam-krb5], [2.5], [rra@stanford.edu])

m4_include([m4/krb5.m4])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CANONICAL_HOST
RRA_LIB_KRB5

dnl Crank up the warnings if we're using GCC.
if test "$GCC" = "yes" ; then
    CFLAGS="-Wall $CFLAGS"
fi

dnl Try to add the compiler flags for position-independent code and try to
dnl specify the binding so that any references within the PAM module are
dnl resolved to the functions in that module in preference to any external
dnl function.  Also, if and only if we're on Linux, make sure that all the
dnl symbols in the module are resolved.
dnl
dnl More platforms could be handled here.  Contributions welcome.
case "$host" in
*-linux*)
    CFLAGS="-fPIC $CFLAGS"
    LDFLAGS="-Wl,-z,defs -Wl,-Bsymbolic $LDFLAGS"
    ;;
*-solaris2*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
        LDFLAGS="-Wl,-Bsymbolic $LDFLAGS"
    else
        CFLAGS="-KPIC $CFLAGS"
        LDFLAGS="-G -xldscope=symbolic $LDFLAGS"
    fi
    ;;
*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
    fi
    ;;
esac

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
