dnl Use krb5-config to get link paths for Kerberos libraries.
dnl
dnl Provides one macro, RRA_KRB5_CONFIG, which attempts to get compiler and
dnl linker flags for a library via krb5-config and sets the appropriate shell
dnl variables.  Defines the Autoconf variable PATH_KRB5_CONFIG, which can be
dnl used to find the default path to krb5-config.
dnl
dnl The canonical version of this file is maintained in the rra-c-util
dnl package, available at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2011
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Check for krb5-config in the user's path and set PATH_KRB5_CONFIG.  This
dnl is moved into a separate macro so that it can be loaded via AC_REQUIRE,
dnl meaning it will only be run once even if we link with multiple krb5-config
dnl libraries.
AC_DEFUN([_RRA_KRB5_CONFIG_PATH],
[AC_ARG_VAR([PATH_KRB5_CONFIG], [Path to krb5-config])
 AC_PATH_PROG([PATH_KRB5_CONFIG], [krb5-config], [],
    [${PATH}:/usr/kerberos/bin])])

dnl Attempt to find the flags for a library using krb5-config.  Takes the
dnl following arguments (in order):
dnl
dnl 1. The root directory for the library in question, generally from an
dnl    Autoconf --with flag.  Used by preference as the path to krb5-config.
dnl
dnl 2. The argument to krb5-config to retrieve flags for this particular
dnl    library.
dnl
dnl 3. The variable prefix to use when setting CPPFLAGS and LIBS variables
dnl    based on the result of krb5-config.
dnl
dnl 4. Further actions to take if krb5-config was found and supported that
dnl    library type.
dnl
dnl 5. Further actions to take if krb5-config could not be used to get flags
dnl    for that library type.
AC_DEFUN([RRA_KRB5_CONFIG],
[AC_REQUIRE([_RRA_KRB5_CONFIG_PATH])
 rra_krb5_config_$3=
 AS_IF([test x"$1" != x && test -x "$1/bin/krb5-config"],
    [rra_krb5_config_$3="$1/bin/krb5-config"],
    [rra_krb5_config_$3="$PATH_KRB5_CONFIG"])
 AS_IF([test x"$rra_krb5_config_$3" != x && test -x "$rra_krb5_config_$3"],
    [AC_CACHE_CHECK([for $2 support in krb5-config], [rra_cv_lib_$3[]_config],
         [AS_IF(["$rra_krb5_config_$3" 2>&1 | grep $2 >/dev/null 2>&1],
             [rra_cv_lib_$3[]_config=yes],
             [rra_cv_lib_$3[]_config=no])])
     AS_IF([test "$rra_cv_lib_$3[]_config" = yes],
        [$3[]_CPPFLAGS=`"$rra_krb5_config_$3" --cflags $2 2>/dev/null`
         $3[]_LIBS=`"$rra_krb5_config_$3" --libs $2 2>/dev/null`
         $3[]_CPPFLAGS=`echo "$$3[]_CPPFLAGS" | sed 's%-I/usr/include %%'`
         $3[]_CPPFLAGS=`echo "$$3[]_CPPFLAGS" | sed 's%-I/usr/include$%%'`
         $4])])
 AS_IF([test x"$rra_cv_lib_$3[]_config" != xyes], [$5])])
