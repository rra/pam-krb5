#
# Makefile for pam_krb5
#

CC = gcc
CFLAGS = -O2 -fPIC
#LDFLAGS = -shared
LDFLAGS = -G

DESTDIR = /usr/lib/security
MANDIR = /opt/local/man/man5

OSLIBS = -lpam -lnsl -lsocket
KRB5LIBS = -L/opt/local/lib -lkrb5 -lk5crypto -lcom_err

LIBS = $(OSLIBS) $(KRB5LIBS)

INC = -I/opt/local/include


####################################################################
# No changes below this line

SRCS = pam_krb5_auth.c pam_krb5_pass.c pam_krb5_acct.c pam_krb5_sess.c \
	support.c

OBJS = pam_krb5_auth.o pam_krb5_pass.o pam_krb5_acct.o pam_krb5_sess.o \
	support.o

all: pam_krb5.so.1

pam_krb5.so.1: $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

install:
	cp pam_krb5.so.1 $(DESTDIR)
	chown root:sys $(DESTDIR)/pam_krb5.so.1
	ln -s ./pam_krb5.so.1 $(DESTDIR)/pam_krb5.so
	cp pam_krb5.5 $(MANDIR)
	chown root:sys $(MANDIR)/pam_krb5.5

clean:
	rm -f *.so.1 *.o

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

