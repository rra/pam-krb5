# Automake makefile for pam-krb5.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2009, 2011
#     The Board of Trustees of the Leland Stanford Junior University
# Copyright 2005, 2006, 2007 Russ Allbery <rra@stanford.edu>
# Copyright 2005 Andres Salomon <dilinger@debian.org>
# Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
#
# See LICENSE for licensing terms.

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore LICENSE autogen pam_krb5.map pam_krb5.pod	  \
	tests/README tests/TESTS tests/fakepam/README tests/tap/libtap.sh

# Everything we build needs the Kerbeors headers and library flags.
AM_CPPFLAGS = $(KRB5_CPPFLAGS)
AM_LDFLAGS  = $(KRB5_LDFLAGS)

noinst_LTLIBRARIES = pam-util/libpamutil.la portable/libportable.la
portable_libportable_la_SOURCES = portable/dummy.c portable/krb5.h	\
        portable/macros.h portable/pam.h portable/stdbool.h		\
        portable/system.h
portable_libportable_la_LIBADD = $(LTLIBOBJS)
pam_util_libpamutil_la_SOURCES = pam-util/args.c pam-util/args.h	\
	pam-util/logging.c pam-util/logging.h pam-util/options.c	\
	pam-util/options.h pam-util/vector.c pam-util/vector.h

pamdir = $(libdir)/security
pam_LTLIBRARIES = pam_krb5.la
pam_krb5_la_SOURCES = api-account.c api-auth.c api-password.c api-session.c \
	auth.c cache.c context.c internal.h options.c password.c	    \
	prompting.c setcred.c support.c
pam_krb5_la_LDFLAGS = -module -shared -avoid-version $(AM_LDFLAGS)
pam_krb5_la_LIBADD = pam-util/libpamutil.la portable/libportable.la \
	$(KRB5_LIBS)
dist_man_MANS = pam_krb5.5

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile		 \
	build-aux/config.guess build-aux/config.sub build-aux/depcomp	 \
	build-aux/install-sh build-aux/ltmain.sh build-aux/missing	 \
	config.h.in config.h.in~ configure m4/libtool.m4 m4/ltoptions.m4 \
	m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4 pam_krb5.5

# A set of flags for warnings.	Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/pam-util/args-t tests/pam-util/fakepam-t		 \
	tests/pam-util/logging-t tests/pam-util/options-t		 \
	tests/pam-util/vector-t tests/runtests tests/portable/asprintf-t \
	tests/portable/mkstemp-t tests/portable/snprintf-t		 \
	tests/portable/strlcat-t tests/portable/strlcpy-t		 \
	tests/portable/strndup-t
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/fakepam/libfakepam.a tests/tap/libtap.a
tests_fakepam_libfakepam_a_SOURCES = tests/fakepam/data.c	\
	tests/fakepam/logging.c tests/fakepam/testing.c		\
	tests/fakepam/testing.h
tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests $(AM_CPPFLAGS)
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h

# The test programs themselves.
tests_pam_util_args_t_LDADD = pam-util/libpamutil.la	\
	tests/fakepam/libfakepam.a tests/tap/libtap.a	\
	portable/libportable.la $(KRB5_LIBS)
tests_pam_util_fakepam_t_LDADD = tests/fakepam/libfakepam.a \
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
	cd tests && ./runtests $(abs_top_srcdir)/tests/TESTS
