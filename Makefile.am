# Automake makefile for pam-krb5.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2009, 2011, 2012
#     The Board of Trustees of the Leland Stanford Junior University
# Copyright 2005, 2006, 2007, 2014 Russ Allbery <eagle@eyrie.org>
# Copyright 2005 Andres Salomon <dilinger@debian.org>
# Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
#
# See LICENSE for licensing terms.

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore LICENSE autogen pam_krb5.map pam_krb5.pod	 \
	pam_krb5.sym tests/README tests/TESTS tests/config/README	 \
	tests/data/generate-krb5-conf tests/data/krb5-pam.conf		 \
	tests/data/krb5.conf tests/data/scripts tests/data/valgrind.supp \
	tests/docs/pod-spelling-t tests/docs/pod-t tests/fakepam/README	 \
	tests/tap/libtap.sh

# Everything we build needs the Kerbeors headers and library flags.
AM_CPPFLAGS = $(KRB5_CPPFLAGS)
AM_LDFLAGS  = $(KRB5_LDFLAGS)

noinst_LTLIBRARIES = pam-util/libpamutil.la portable/libportable.la
portable_libportable_la_SOURCES = portable/dummy.c portable/kadmin.h	    \
        portable/krb5.h portable/macros.h portable/pam.h portable/stdbool.h \
        portable/system.h
portable_libportable_la_LIBADD = $(LTLIBOBJS)
pam_util_libpamutil_la_SOURCES = pam-util/args.c pam-util/args.h	\
	pam-util/logging.c pam-util/logging.h pam-util/options.c	\
	pam-util/options.h pam-util/vector.c pam-util/vector.h

if HAVE_LD_VERSION_SCRIPT
    VERSION_LDFLAGS = -Wl,--version-script=${srcdir}/pam_krb5.map
else
    VERSION_LDFLAGS = -export-symbols ${srcdir}/pam_krb5.sym
endif

pamdir = $(libdir)/security
pam_LTLIBRARIES = pam_krb5.la
pam_krb5_la_SOURCES = account.c alt-auth.c auth.c cache.c context.c fast.c \
	internal.h options.c password.c prompting.c public.c setcred.c	   \
	support.c
pam_krb5_la_LDFLAGS = -module -shared -avoid-version $(VERSION_LDFLAGS) \
	$(AM_LDFLAGS)
pam_krb5_la_LIBADD = pam-util/libpamutil.la portable/libportable.la \
	$(KRB5_LIBS)
dist_man_MANS = pam_krb5.5

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile		 \
	build-aux/config.guess build-aux/config.sub build-aux/depcomp	 \
	build-aux/install-sh build-aux/ltmain.sh build-aux/missing	 \
	config.h.in config.h.in~ configure m4/libtool.m4 m4/ltoptions.m4 \
	m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4 pam_krb5.5

# A set of flags for warnings.	Add -O because gcc won't find some warnings
# without optimization turned on.  Desirable warnings that can't be turned
# on due to other problems:
#
#     -Wconversion	http://bugs.debian.org/488884 (htons warnings)
#
# Last checked against gcc 4.8.2 (2014-04-12).	-D_FORTIFY_SOURCE=2 enables
# warn_unused_result attribute markings on glibc functions on Linux, which
# catches a few more issues.
WARNINGS = -g -O -fstrict-overflow -fstrict-aliasing -D_FORTIFY_SOURCE=2    \
	-Wall -Wextra -Wendif-labels -Wformat=2 -Winit-self -Wswitch-enum   \
	-Wstrict-overflow=5 -Wfloat-equal -Wdeclaration-after-statement	    \
	-Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align	    \
	-Wwrite-strings -Wjump-misses-init -Wlogical-op -Wstrict-prototypes \
	-Wold-style-definition -Wmissing-prototypes -Wnormalized=nfc	    \
	-Wpacked -Wredundant-decls -Wnested-externs -Winline -Wvla -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' \
	    KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/module/alt-auth-t			    \
	tests/module/bad-authtok-t tests/module/basic-t			    \
	tests/module/cache-cleanup-t tests/module/cache-t		    \
	tests/module/expired-t tests/module/fast-t tests/module/no-cache-t  \
	tests/module/pam-user-t tests/module/password-t			    \
	tests/module/pkinit-t tests/module/realm-t tests/module/stacked-t   \
	tests/module/trace-t tests/pam-util/args-t tests/pam-util/fakepam-t \
	tests/pam-util/logging-t tests/pam-util/options-t		    \
	tests/pam-util/vector-t tests/portable/asprintf-t		    \
	tests/portable/mkstemp-t tests/portable/snprintf-t		    \
	tests/portable/strlcat-t tests/portable/strlcpy-t		    \
	tests/portable/strndup-t
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/fakepam/libfakepam.a tests/tap/libtap.a
tests_fakepam_libfakepam_a_SOURCES = tests/fakepam/config.c		   \
	tests/fakepam/data.c tests/fakepam/general.c			   \
	tests/fakepam/internal.h tests/fakepam/kuserok.c		   \
	tests/fakepam/logging.c tests/fakepam/pam.h tests/fakepam/script.c \
	tests/fakepam/script.h
tests_tap_libtap_a_CPPFLAGS = $(KADM5CLNT_CPPFLAGS) $(AM_CPPFLAGS)
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h	\
	tests/tap/kadmin.c tests/tap/kadmin.h tests/tap/kerberos.c	\
	tests/tap/kerberos.h tests/tap/macros.h tests/tap/process.c	\
	tests/tap/process.h tests/tap/string.c tests/tap/string.h

# The list of objects and libraries used for module testing by programs that
# link with the fake PAM library or with both it and the module.
MODULE_OBJECTS = account.lo alt-auth.lo auth.lo cache.lo context.lo fast.lo \
	options.lo password.lo prompting.lo public.lo setcred.lo support.lo \
	pam-util/libpamutil.la tests/fakepam/libfakepam.a

# The test programs themselves.
tests_module_alt_auth_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_bad_authtok_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_basic_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_cache_cleanup_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_cache_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_expired_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a	\
	portable/libportable.la $(KADM5CLNT_LDFLAGS) $(KADM5CLNT_LIBS)	\
	$(KRB5_LIBS)
tests_module_fast_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_no_cache_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_pam_user_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_password_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_pkinit_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_realm_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_stacked_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_module_trace_t_LDADD = $(MODULE_OBJECTS) tests/tap/libtap.a \
	portable/libportable.la $(KRB5_LIBS)
tests_pam_util_args_t_LDADD = pam-util/libpamutil.la	\
	tests/fakepam/libfakepam.a tests/tap/libtap.a	\
	portable/libportable.la $(KRB5_LIBS)
tests_pam_util_fakepam_t_LDADD = tests/fakepam/libfakepam.a	\
	tests/tap/libtap.a portable/libportable.la
tests_pam_util_logging_t_LDADD = pam-util/libpamutil.la	\
	tests/fakepam/libfakepam.a tests/tap/libtap.a	\
	portable/libportable.la $(KRB5_LIBS)
tests_pam_util_options_t_LDADD = pam-util/libpamutil.la	\
	tests/fakepam/libfakepam.a tests/tap/libtap.a	\
	portable/libportable.la $(KRB5_LIBS)
tests_pam_util_vector_t_LDADD = pam-util/libpamutil.la	\
	tests/fakepam/libfakepam.a tests/tap/libtap.a	\
	portable/libportable.la
tests_portable_asprintf_t_SOURCES = tests/portable/asprintf-t.c \
	tests/portable/asprintf.c
tests_portable_asprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_mkstemp_t_SOURCES = tests/portable/mkstemp-t.c \
	tests/portable/mkstemp.c
tests_portable_mkstemp_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_snprintf_t_SOURCES = tests/portable/snprintf-t.c \
	tests/portable/snprintf.c
tests_portable_snprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strlcat_t_SOURCES = tests/portable/strlcat-t.c \
        tests/portable/strlcat.c
tests_portable_strlcat_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strlcpy_t_SOURCES = tests/portable/strlcpy-t.c \
        tests/portable/strlcpy.c
tests_portable_strlcpy_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strndup_t_SOURCES = tests/portable/strndup-t.c \
	tests/portable/strndup.c
tests_portable_strndup_t_LDADD = tests/tap/libtap.a portable/libportable.la

check-local: $(check_PROGRAMS)
	cd tests && ./runtests -l $(abs_top_srcdir)/tests/TESTS

# Used by maintainers to run the test suite under valgrind.
check-valgrind: $(check_PROGRAMS)
	rm -rf $(abs_top_builddir)/tmp-valgrind
	mkdir $(abs_top_builddir)/tmp-valgrind
	valgrind --leak-check=full --leak-check=full			\
	    --show-reachable=yes --trace-children=yes			\
	    --log-file=$(abs_top_builddir)/tmp-valgrind/log.%p		\
	    --suppressions=$(abs_top_srcdir)/tests/data/valgrind.supp	\
	    --trace-children-skip="/bin/sh,*/cat,*/cut,*/expr,*/getopt,*/kinit,*/ls,*/mkdir,*/rm,*/rmdir,*/sed,*/sleep,*/wc,*/data/generate-krb5-conf,*/docs/*-t" \
	    tests/runtests -l $(abs_top_srcdir)/tests/TESTS
