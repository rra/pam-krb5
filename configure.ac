dnl Autoconf configuration for pam-krb5.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2009 Board of Trustees, Leland Stanford Jr. University
dnl Copyright 2005, 2006, 2007, 2008, 2009 Russ Allbery <rra@stanford.edu>
dnl Copyright 2005 Andres Salomon <dilinger@debian.org>
dnl Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.64])
AC_INIT([pam-krb5], [4.3], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news silent-rules])
AM_MAINTAINER_MODE

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AM_PROG_CC_C_O
AC_PROG_INSTALL
LT_INIT([disable-static])

dnl Check for the Solaris issetugid function, which is nicer than comparing
dnl real and effective UIDs and GIDs.
AC_CHECK_FUNCS([issetugid])

dnl Probe for the functionality of the PAM libraries and their include file
dnl naming.  Mac OS X puts them in pam/* instead of security/*.
AC_SEARCH_LIBS([pam_set_data], [pam])
AC_CHECK_FUNCS([pam_modutil_getpwnam])
AC_REPLACE_FUNCS([pam_syslog pam_vsyslog])
AC_CHECK_HEADERS([security/pam_modutil.h], ,
    [AC_CHECK_HEADERS([pam/pam_modutil.h])])
AC_CHECK_HEADERS([security/pam_appl.h], ,
    [AC_CHECK_HEADERS([pam/pam_appl.h], ,
        [AC_MSG_ERROR([No PAM header files found])])])
AC_CHECK_HEADERS([security/pam_ext.h], ,
    [AC_CHECK_HEADERS([pam/pam_ext.h])])
RRA_HEADER_PAM_CONST

dnl Needed for the pam_vsyslog replacement function.
AC_DEFINE([MODULE_NAME], ["pam_krb5"],
    [The name of the PAM module, used by the pam_vsyslog replacement.])

dnl Probe for the location and functionality of the Kerberos libraries.
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
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
    krb5_get_init_creds_opt_set_fast_ccache_name \
    krb5_get_init_creds_opt_set_pa \
    krb5_init_secure_context \
    krb5_verify_init_creds_opt_init])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_set_pkinit],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_ARGS])
AC_CHECK_FUNC([krb5_get_init_creds_opt_free],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS])
RRA_LIB_KRB5_RESTORE

dnl Other probes of the system libraries.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bittypes.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
AC_TYPE_LONG_LONG_INT
RRA_FUNC_SNPRINTF
AC_REPLACE_FUNCS([asprintf mkstemp])

dnl Everything we build needs the Kerberos libraries.
AM_CPPFLAGS="$KRB5_CPPFLAGS"
AM_LDFLAGS="$KRB5_LDFLAGS"
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_LDFLAGS])

dnl Try to specify the binding so that any references within the PAM module
dnl are resolved to the functions in that module in preference to any external
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
    [*-hpux*],
    [AS_IF([test x"$GCC" = x"yes"],
        [AM_LDFLAGS="-Wl,-Bsymbolic $AM_LDFLAGS"],
        [AM_LDFLAGS="-Wl,+vshlibunsats $AM_LDFLAGS"])],

    [*-linux*],
    [AM_LDFLAGS="-Wl,-z,defs -Wl,-Bsymbolic $MAP $AM_LDFLAGS"
     AS_IF([test x"${prefix}" = x"/usr"],
        [AS_IF([test x"${libdir}" = x'${exec_prefix}/lib'],
            [RRA_SET_LIBDIR])])],

    [*-solaris2*],
    [AM_LDFLAGS="-Wl,-Bsymbolic $AM_LDFLAGS"])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
