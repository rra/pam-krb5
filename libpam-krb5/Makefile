#
# Makefile for pam_krb5
#
KRB5BASE = /usr
KRB5_IMPL = mit
PAMPREFIX = $(DESTDIR)/lib/security
MANPREFIX = $(DESTDIR)/usr/share/man
BINOWN = root
BINGRP = root
MANOWN = root
MANGRP = root
INSTALL = install

CC = gcc
CFLAGS = -O2 -fPIC -Wall
LDFLAGS = -shared -Xlinker -x


OSLIBS = -lpam -lresolv -ldb

# HEIMDAL
#LIBS_heimdal = ${KRB5BASE}/lib/libkrb5.a ${KRB5BASE}/lib/libasn1.a   \
#	${KRB5BASE}/lib/libcom_err.a ${KRB5BASE}/lib/libroken.a  \
#	${KRB5BASE}/lib/libgssapi.a ${KRB5BASE}/lib/libdes.a 

LIBS_heimdal = -lkrb5 -lasn1 -lcom_err -lroken -lgssapi -ldes 


# MIT
LIBS_mit = -lkrb5 -lk5crypto -lcom_err
LIBS = $(OSLIBS) ${LIBS_${KRB5_IMPL}}
COMPAT = compat_${KRB5_IMPL}.c

INC = -I${KRB5BASE}/include


####################################################################
# No changes below this line

SRCS = pam_krb5_auth.c pam_krb5_pass.c pam_krb5_acct.c pam_krb5_sess.c \
	support.c ${COMPAT}

OBJS = pam_krb5_auth.o pam_krb5_pass.o pam_krb5_acct.o pam_krb5_sess.o \
	support.o ${COMPAT:.c=.o}

all: pam_krb5.so

pam_krb5.so: $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

install: pam_krb5.so
	${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m 0644 pam_krb5.so \
	    ${PAMPREFIX}/pam_krb5.so
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 0644 pam_krb5.5 \
	    ${MANPREFIX}/man8/pam_krb5.8

clean:
	rm -f *.so *.o

pam_krb5_auth.o: pam_krb5_auth.c pam_krb5.h
	$(CC) -c $(CFLAGS) $(INC) $<

pam_krb5_pass.o: pam_krb5_pass.c pam_krb5.h
	$(CC) -c $(CFLAGS) $(INC) $<

pam_krb5_acct.o: pam_krb5_acct.c pam_krb5.h
	$(CC) -c $(CFLAGS) $(INC) $<

pam_krb5_sess.o: pam_krb5_sess.c pam_krb5.h
	$(CC) -c $(CFLAGS) $(INC) $<

support.o: support.c pam_krb5.h
	$(CC) -c $(CFLAGS) $(INC) $<

compat_heimdal.o: compat_heimdal.c
	$(CC) -c $(CFLAGS) $(INC) $<

compat_mit.o: compat_mit.c
	$(CC) -c $(CFLAGS) $(INC) $<

