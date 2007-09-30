dnl Process this file with Autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([pam-krb5], [3.8], [rra@stanford.edu])

m4_include([m4/krb5.m4])
m4_include([m4/pam-const.m4])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CANONICAL_HOST
RRA_LIB_KRB5
AC_SEARCH_LIBS([pam_set_data], [pam])
AC_CHECK_FUNCS([pam_modutil_getpwnam])
RRA_HEADER_PAM_CONST
AC_CHECK_HEADERS([security/pam_modutil.h])

dnl Mac OS X calls its PAM headers something different than everyone else.
AC_CHECK_HEADERS([security/pam_appl.h], ,
    [AC_CHECK_HEADERS([pam/pam_appl.h], ,
        [AC_MSG_ERROR([No PAM header files found])])])

dnl Crank up the warnings if we're using GCC.
if test "$GCC" = "yes" ; then
    CFLAGS="-Wall $CFLAGS"
fi

dnl Try to add the compiler flags for position-independent code and try to
dnl specify the binding so that any references within the PAM module are
dnl resolved to the functions in that module in preference to any external
dnl function.
dnl
dnl Also, if and only if we're on Linux, make sure that all the symbols in the
dnl module are resolved and try to adjust for the 32-bit vs. 64-bit library
dnl paths.
dnl
dnl More platforms could be handled here.  Contributions welcome.
case "$host" in
*-darwin*)
    if test "$GCC" = "yes" ; then
        LD="$CC"
        LDFLAGS="-bundle $LDFLAGS"
    else
        AC_MSG_ERROR([Only know compiler flags for gcc on this platform])
    fi
    ;;
*-hpux*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
        LD="$CC"
        LDFLAGS="-fPIC -shared -Wl,-Bsymbolic $LDFLAGS"
    else
        CFLAGS="+z $CFLAGS"
        LD="ld"
        LDFLAGS="+vshlibunsats -b $LDFLAGS"
    fi
    ;;
x86_64-*-linux*)
    CFLAGS="-fPIC $CFLAGS"
    LD="$CC"
    LDFLAGS="-fPIC -shared -Wl,-z,defs -Wl,-Bsymbolic $LDFLAGS"
    if test x"$libdir" = x'${exec_prefix}/lib' ; then
        libdir='${exec_prefix}/lib64'
    fi
    ;;
*-linux*)
    CFLAGS="-fPIC $CFLAGS"
    LD="$CC"
    LDFLAGS="-fPIC -shared -Wl,-z,defs -Wl,-Bsymbolic $LDFLAGS"
    ;;
*-solaris2*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
        LDFLAGS="-fPIC -shared -Wl,-Bsymbolic $LDFLAGS"
    else
        CFLAGS="-KPIC $CFLAGS"
        LDFLAGS="-G -xldscope=symbolic $LDFLAGS"
    fi
    LD="$CC"
    ;;
*)
    if test "$GCC" = "yes" ; then
        CFLAGS="-fPIC $CFLAGS"
        LD="$CC"
        LDFLAGS="-fPIC -shared $LDFLAGS"
    else
        AC_MSG_ERROR([Only know compiler flags for gcc on this platform])
    fi
    ;;
esac
AC_SUBST([LD])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
