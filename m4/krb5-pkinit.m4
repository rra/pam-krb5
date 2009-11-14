dnl Find the compiler and linker flags for Kerberos v5.
dnl
dnl Additonal Kerberos v5 library probes that check behavior of the library
dnl relevant to PKINIT support.  Provides the macros:
dnl
dnl     RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS
dnl     RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_ARGS
dnl
dnl Copyright 2007 Russ Allbery <rra@stanford.edu>
dnl
dnl See LICENSE for licensing terms.

dnl Check whether krb5_get_init_creds_opt_free takes one argument or two.
dnl Early Heimdal used to take a single argument.  Defines
dnl HAVE_KRB5_GET_INIT_CREDS_OPT_FREE_2_ARGS if it takes two arguments.
AC_DEFUN([RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS],
[AC_CACHE_CHECK([if krb5_get_init_creds_opt_free takes two arguments],
    [rra_cv_func_krb5_get_init_creds_opt_free_args],
[AC_TRY_COMPILE([#include <krb5.h>],
    [krb5_get_init_creds_opt *opts; krb5_context c;
     krb5_get_init_creds_opt_free(c, opts);],
    [rra_cv_func_krb5_get_init_creds_opt_free_args=yes],
    [rra_cv_func_krb5_get_init_creds_opt_free_args=no])])
AS_IF([test $rra_cv_func_krb5_get_init_creds_opt_free_args = yes],
    [AC_DEFINE([HAVE_KRB5_GET_INIT_CREDS_OPT_FREE_2_ARGS], 1,
        [Define if krb5_get_init_creds_opt_free takes two arguments.])])])

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
AS_IF([test $rra_cv_func_krb5_get_init_creds_opt_set_pkinit_args = yes],
    [AC_DEFINE([HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT_11_ARGS], 1,
        [Define if krb5_get_init_creds_opt_set_pkinit takes 11 arguments.])])])
