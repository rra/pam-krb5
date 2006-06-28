/*
 * pam_krb5.h
 *
 * $Id: pam_krb5.h,v 1.3 2000/12/19 22:53:11 hartmans Exp $
 */

#ifndef PAM_KRB5_H_
#define PAM_KRB5_H_

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <krb5.h>
#include <stdarg.h>
#include <stdio.h>
#include "credlist.h"
#include "context.h"

struct pam_args
{
	int debug;
	int try_first_pass;
	int use_first_pass;
	int forwardable;
	int reuse_ccache;
	int no_ccache;
	int ignore_root;
	char *ccache_dir;
	char *ccache;
	int search_k5login;
	int quiet; /* not really an arg, but it may as well be */
};
extern struct pam_args pam_args;
void parse_args(struct context *, int flags, int argc, const char **argv);

int init_ccache(struct context *, const char *, struct credlist *,
		krb5_ccache *);

int password_auth(struct context *, char *in_tkt_service,
		struct credlist **);

int get_user_info(pam_handle_t *, const char *, int, char **);
int validate_auth(struct context *);

krb5_prompter_fct pam_prompter;

const char	*compat_princ_component(krb5_context, krb5_principal, int);
void		 compat_free_data_contents(krb5_context, krb5_data *);
krb5_error_code	 compat_cc_next_cred(krb5_context, const krb5_ccache, 
				     krb5_cc_cursor *, krb5_creds *);

#ifndef ENCTYPE_DES_CBC_MD5
#define ENCTYPE_DES_CBC_MD5	ETYPE_DES_CBC_MD5
#endif

/*#define DEBUG_TO_FILE*/
#define LOGFILE "/tmp/krb5.log"
static void _dlog_to_file(const char *name, const char *msg)
{
#ifdef DEBUG_TO_FILE
	static FILE *fp = NULL;
	if (!fp) {
		if ((fp = fopen(LOGFILE, "a")) != NULL)
			fprintf(fp, "  ---\n");
	}
	if (fp) {
		fprintf(fp, "(pam_krb5): %s: %s\n", name, msg);
		fflush(fp);
	}
#endif
}

#define DEBUG_TO_SYSLOG
static void _dlog_to_syslog(const char *name, const char *msg)
{
#ifdef DEBUG_TO_SYSLOG
	syslog(LOG_DEBUG, "(pam_krb5): %s: %s", name, msg);
#endif
}

/*#define DEBUG_TO_STDERR*/
static void _dlog_to_stderr(const char *name, const char *msg)
{
#ifdef DEBUG_TO_STDERR
	fprintf(stderr, "(pam_krb5): %s: %s\n", name, msg);
#endif
}

/* A useful logging macro */
static inline void dlog(struct context *ctx, const char *fmt, ...)
{
	if (pam_args.debug) {
		const char *name;
		char msg[256];
		va_list args;

		va_start(args, fmt);
		vsnprintf(msg, sizeof(msg), fmt, args);
		va_end(args);

		name = ctx && ctx->name ? ctx->name : "none";
		_dlog_to_syslog(name, msg);
		_dlog_to_stderr(name, msg);
		_dlog_to_file(name, msg);
	}
}

#endif /* PAM_KRB5_H_ */
