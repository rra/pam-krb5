# Automake makefile for pam-krb5.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2009 Board of Trustees, Leland Stanford Jr. University
# Copyright 2005, 2006, 2007 Russ Allbery <rra@stanford.edu>
# Copyright 2005 Andres Salomon <dilinger@debian.org>
# Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
#
# See LICENSE for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore LICENSE autogen compat-aix.c compat-heimdal.c	\
	compat-mit.c pam_krb5.map pam_krb5.pod

noinst_LTLIBRARIES = portable/libportable.la
portable_libportable_la_SOURCES = portable/dummy.c portable/macros.h \
        portable/pam.h portable/stdbool.h portable/system.h
portable_libportable_la_LIBADD = $(LTLIBOBJS)

pamdir = $(libdir)/security
pam_LTLIBRARIES = pam_krb5.la
pam_krb5_la_SOURCES = api-account.c api-auth.c api-password.c api-session.c \
	auth.c cache.c compat.c context.c internal.h logging.c options.c    \
	password.c prompting.c setcred.c support.c
pam_krb5_la_LDFLAGS = -module -shared -avoid-version $(AM_LDFLAGS)
pam_krb5_la_LIBADD = portable/libportable.la $(KRB5_LIBS)
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
