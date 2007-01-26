dnl krb5.m4 -- Find the compiler and linker flags for Kerberos v5.
dnl $Id: krb5.m4 2417 2006-02-03 23:35:46Z rra $
dnl
dnl Finds the compiler and linker flags and adds them to CPPFLAGS and LIBS.
dnl Provides --with-kerberos and --enable-reduced-depends configure options to
dnl control how linking with Kerberos is done.  Uses krb5-config where
dnl available unless reduced dependencies is requested.  Provides the macro
dnl RRA_LIB_KRB5.

dnl Check whether krb5_get_init_creds_opt_free takes one argument or two.
dnl Early Heimdal used to take a single argument.  Defines
dnl HAVE_KRB5_GET_INIT_CREDS_OPT_FREE_2_ARGS if it takes two arguments.
AC_DEFUN([RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS],
[AC_CACHE_CHECK([if krb5_get_init_creds_opt_free takes two arguments],
    [rra_cv_func_krb5_get_init_creds_opt_free_args],
[AC_TRY_COMPILE(
    [#include <krb5.h>],
    [krb5_get_init_creds_opt *opts; krb5_context c;
     krb5_get_init_creds_opt_free(c, opts);],
    [rra_cv_func_krb5_get_init_creds_opt_free_args=yes],
    [rra_cv_func_krb5_get_init_creds_opt_free_args=no])])
if test $rra_cv_func_krb5_get_init_creds_opt_free_args = yes ; then
    AC_DEFINE([HAVE_KRB5_GET_INIT_CREDS_OPT_FREE_2_ARGS], 1,
        [Define if krb5_get_init_creds_opt_free takes two arguments.])
fi])

dnl Check whether krb5_get_init_creds_opt_set_pkinit takes eleven arguments
dnl (0.8 release candidates and later) or only nine (0.7).  Defines
dnl HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_11_ARGS if it takes eleven
dnl arguments.
AC_DEFUN([RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_ARGS],
[AC_CACHE_CHECK([if krb5_get_init_creds_opt_set_pkinit takes 11 arguments],
    [rra_cv_func_krb5_get_init_creds_opt_set_pkinit_args],
[AC_TRY_COMPILE(
    [#include <krb5.h>],
    [krb5_context c; krb5_get_init_creds_opt *o; krb5_principal p;
     krb5_get_init_creds_opt_set_pkinit(c, o, p, NULL, NULL, NULL, NULL, 0,
                                        NULL, NULL, NULL);],
    [rra_cv_func_krb5_get_init_creds_opt_set_pkinit_args=yes],
    [rra_cv_func_krb5_get_init_creds_opt_set_pkinit_args=no])])
if test $rra_cv_func_krb5_get_init_creds_opt_set_pkinit_args = yes ; then
    AC_DEFINE([HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_11_ARGS], 1,
        [Define if krb5_get_init_creds_opt_set_pkinit takes 11 arguments.])
fi])

dnl Does the appropriate library checks for reduced-dependency krb5 linkage.
AC_DEFUN([_RRA_LIB_KRB5_KRB5_REDUCED],
[AC_CHECK_LIB([krb5], [krb5_init_context], [KRB5_LIBS="-lkrb5"],
    [AC_MSG_ERROR([cannot find usable Kerberos v5 library])])
AC_CHECK_LIB([com_err], [com_err], [KRB5_LIBS="$KRB5_LIBS -lcom_err"],
    [AC_MSG_ERROR([cannot find usable com_err library])])])

dnl Does the appropriate library checks for krb5 linkage.  Note that we have
dnl to check for a different function the second time since the Heimdal and
dnl MIT libraries have the same name.
AC_DEFUN([_RRA_LIB_KRB5_KRB5],
[AC_CHECK_LIB([krb5], [krb5_init_context],
    [KRB5_LIBS="-lkrb5 -lasn1 -lroken -lcrypto -lcom_err"],
    [KRB5EXTRA="-lk5crypto -lcom_err"
     AC_CHECK_LIB([krb5support], [krb5int_getspecific],
        [KRB5EXTRA="$KRB5EXTRA -lkrb5support"],
        [AC_SEARCH_LIBS([pthread_setspecific], [pthreads pthread])
         AC_CHECK_LIB([krb5support], [krb5int_setspecific],
            [KRB5EXTRA="$KRB5EXTRA -lkrb5support"])])
     AC_CHECK_LIB([krb5], [krb5_cc_default],
        [KRB5_LIBS="-lkrb5 $KRB5EXTRA"],
        [AC_MSG_ERROR([cannot find usable Kerberos v5 library])],
        [$KRB5EXTRA])],
    [-lasn1 -lroken -lcrypto -lcom_err])])

dnl Additional checks for portability between MIT and Heimdal if krb5
dnl libraries were requested.
AC_DEFUN([_RRA_LIB_KRB5_KRB5_EXTRA],
[AC_CHECK_HEADERS([et/com_err.h hx509_err.h])
AC_CHECK_MEMBER([krb5_creds.session],
    [AC_DEFINE([HAVE_KRB5_HEIMDAL], [1],
        [Define if your Kerberos implementation is Heimdal.])],
    [AC_DEFINE([HAVE_KRB5_MIT], [1],
        [Define if your Kerberos implementation is MIT.])],
    [#include <krb5.h>])
AC_CHECK_FUNCS([krb5_get_error_message \
    krb5_get_init_creds_opt_alloc \
    krb5_get_init_creds_opt_set_default_flags \
    krb5_get_init_creds_opt_set_pa])
AC_CHECK_FUNCS([krb5_get_init_creds_set_pkinit],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_ARGS])
AC_CHECK_FUNC([krb5_get_init_creds_opt_free],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS])])

dnl The main macro.
AC_DEFUN([RRA_LIB_KRB5],
[KRBROOT=
AC_ARG_WITH([kerberos],
    AC_HELP_STRING([--with-kerberos=DIR],
        [Location of Kerberos headers and libraries]),
    [if test x"$withval" != xno ; then
        KRBROOT="$withval"
     fi])

dnl Handle the reduced depends case, which is much simpler.
reduced_depends=false
AC_ARG_ENABLE([reduced-depends],
    AC_HELP_STRING([--enable-reduced-depends],
        [Try to minimize shared library dependencies]),
    [if test x"$enableval" = xyes ; then
        if test x"$KRBROOT" != x ; then
            if test x"$KRBROOT" != x/usr ; then
                CPPFLAGS="$CPPFLAGS -I$KRBROOT/include"
            fi
            LDFLAGS="$LDFLAGS -L$KRBROOT/lib"
        fi
        _RRA_LIB_KRB5_KRB5_REDUCED
        reduced_depends=true
    fi])

dnl Checking for the neworking libraries shouldn't be necessary for the
dnl krb5-config case, but apparently it is at least for MIT Kerberos 1.2.
dnl This will unfortunately mean multiple -lsocket -lnsl references when
dnl building with current versions of Kerberos, but this shouldn't cause
dnl any practical problems.
if test x"$reduced_depends" != xtrue ; then
    AC_SEARCH_LIBS([gethostbyname], [nsl])
    AC_SEARCH_LIBS([socket], [socket], ,
        [AC_CHECK_LIB([nsl], [socket],
            [LIBS="-lnsl -lsocket $LIBS"], , [-lsocket])])
    AC_ARG_VAR([KRB5_CONFIG], [Path to krb5-config])
    if test x"$KRBROOT" != x ; then
        if test -x "$KRBROOT/bin/krb5-config" ; then
            KRB5_CONFIG="$KRBROOT/bin/krb5-config"
        fi
    else
        AC_PATH_PROG([KRB5_CONFIG], [krb5-config])
    fi

    if test x"$KRB5_CONFIG" != x ; then
        AC_MSG_CHECKING([for krb5 support in krb5-config])
        if "$KRB5_CONFIG" | grep krb5 > /dev/null 2>&1 ; then
            AC_MSG_RESULT([yes])
            KRB5_CPPFLAGS=`"$KRB5_CONFIG" --cflags krb5`
            KRB5_LIBS=`"$KRB5_CONFIG" --libs krb5`
        else
            AC_MSG_RESULT([no])
            KRB5_CPPFLAGS=`"$KRB5_CONFIG" --cflags`
            KRB5_LIBS=`"$KRB5_CONFIG" --libs`
        fi
        KRB5_CPPFLAGS=`echo "$KRB5_CPPFLAGS" | sed 's%-I/usr/include ?%%'`
    else
        if test x"$KRBROOT" != x ; then
            if test x"$KRBROOT" != x/usr ; then
                KRB5_CPPFLAGS="-I$KRBROOT/include"
            fi
            LDFLAGS="$LDFLAGS -L$KRBROOT/lib"
        fi
        AC_SEARCH_LIBS([res_search], [resolv], ,
            [AC_SEARCH_LIBS([__res_search], [resolv])])
        AC_SEARCH_LIBS([crypt], [crypt])
        _RRA_LIB_KRB5_KRB5
    fi
    if test x"$KRB5_CPPFLAGS" != x ; then
        CPPFLAGS="$CPPFLAGS $KRB5_CPPFLAGS"
    fi
fi

dnl Generate the final library list and put it into the standard variables.
LIBS="$KRB5_LIBS $LIBS"
CPPFLAGS=`echo "$CPPFLAGS" | sed 's/^  *//'`
LDFLAGS=`echo "$LDFLAGS" | sed 's/^  *//'`

dnl Run any extra checks for the desired libraries.
_RRA_LIB_KRB5_KRB5_EXTRA])
