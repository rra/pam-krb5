dnl Process this file with Autoconf to produce a configure script.
dnl
dnl Copyright 2005, 2006, 2007, 2008, 2009 Russ Allbery <rra@debian.org>
dnl Copyright 2005 Andres Salomon <dilinger@debian.org>
dnl Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.63])
AC_INIT([pam-krb5], [3.14], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

m4_include([m4/krb5.m4])
m4_include([m4/krb5-pkinit.m4])
m4_include([m4/lib-depends.m4])
m4_include([m4/lib-pathname.m4])
m4_include([m4/pam-const.m4])

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CANONICAL_HOST

dnl Check for the Solaris issetugid function, which is nicer than comparing
dnl real and effective UIDs and GIDs.
AC_CHECK_FUNCS([issetugid])

dnl Probe for the functionality of the PAM libraries and their include file
dnl naming.  Mac OS X puts them in pam/* instead of security/*.
AC_SEARCH_LIBS([pam_set_data], [pam])
AC_CHECK_FUNCS([pam_modutil_getpwnam])
AC_CHECK_HEADERS([security/pam_modutil.h])
AC_CHECK_HEADERS([security/pam_appl.h], ,
    [AC_CHECK_HEADERS([pam/pam_appl.h], ,
        [AC_MSG_ERROR([No PAM header files found])])])
RRA_HEADER_PAM_CONST

dnl Probe for the location and functionality of the Kerberos libraries.
RRA_LIB_KRB5
RRA_LIB_KRB5_SET
AC_CHECK_HEADERS([hx509_err.h k5profile.h])
AC_CHECK_MEMBER([krb5_creds.session],
    [AC_DEFINE([HAVE_KRB5_HEIMDAL], [1],
        [Define if your Kerberos implementation is Heimdal.])],
    [AC_DEFINE([HAVE_KRB5_MIT], [1],
        [Define if your Kerberos implementation is MIT.])],
    [#include <krb5.h>])
AC_CHECK_FUNCS([krb5_appdefault_string \
    krb5_get_init_creds_opt_alloc \
    krb5_get_init_creds_opt_set_change_password_prompt \
    krb5_get_init_creds_opt_set_default_flags \
    krb5_get_init_creds_opt_set_pa \
    krb5_init_secure_context \
    krb5_verify_init_creds_opt_init])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_set_pkinit],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_ARGS])
AC_CHECK_FUNC([krb5_get_init_creds_opt_free],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS])

dnl Crank up the warnings if we're using GCC.
AS_IF([test x"$GCC" = x"yes"], [CFLAGS="-Wall $CFLAGS"])

dnl Try to add the compiler flags for position-independent code and try to
dnl specify the binding so that any references within the PAM module are
dnl resolved to the functions in that module in preference to any external
dnl function.
dnl
dnl Also, if and only if we're on Linux, make sure that all the symbols in the
dnl module are resolved, try to adjust for the 32-bit vs. 64-bit library
dnl paths, install into /lib or /lib64 instead of /usr/lib or /usr/lib64 if
dnl the prefix is /usr, and use a version script to be sure that we hide
dnl internal functions.  The version script could also be used on Solaris and
dnl probably other ELF platforms, but the option is only valid with the GNU ld
dnl and I don't know how to probe for that.
dnl
dnl More platforms could be handled here.  Contributions welcome.
MAP='-Wl,--version-script=${srcdir}/pam_krb5.map'
LD="$CC"
AS_CASE([$host],
    [*-darwin*],
    [AS_IF([test x"$GCC" = x"yes"],
        [LDFLAGS="-bundle $LDFLAGS"],
        [AC_MSG_ERROR([Only know compiler flags for gcc on this platform])])],

    [*-hpux*],
    [AS_IF([test x"$GCC" = x"yes"],
        [CFLAGS="-fPIC $CFLAGS"
         LDFLAGS="-fPIC -shared -Wl,-Bsymbolic $LDFLAGS"],
        [CFLAGS="+z $CFLAGS"
         LD="ld"
         LDFLAGS="+vshlibunsats -b $LDFLAGS"])],

    [*-linux*],
    [CFLAGS="-fPIC $CFLAGS"
     LDFLAGS="-fPIC -shared -Wl,-z,defs -Wl,-Bsymbolic $MAP $LDFLAGS"
     AS_IF([test x"${prefix}" = x"/usr"],
        [AS_IF([test x"${libdir}" = x'${exec_prefix}/lib'],
            [AS_CASE(["$host"],
                [x86_64-*|powerpc64-*|s390x-*|sparc64-*], [libdir="/lib64"],
                [*], [libdir="/lib"])])])],

    [*-solaris2*],
    [AS_IF([test x"$GCC" = x"yes"],
        [CFLAGS="-fPIC $CFLAGS"
         LDFLAGS="-fPIC -shared -Wl,-Bsymbolic $LDFLAGS"],
        [CFLAGS="-KPIC $CFLAGS"
         LDFLAGS="-G -xldscope=symbolic $LDFLAGS"])],

    [*],
    [AS_IF([test x"$GCC" = x"yes"],
        [CFLAGS="-fPIC $CFLAGS"
         LDFLAGS="-fPIC -shared $LDFLAGS"],
        [AC_MSG_ERROR([Only know compiler flags for gcc on this platform])])])

AC_SUBST([LD])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
