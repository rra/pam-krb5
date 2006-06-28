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

/*
 * The global structure holding our arguments, both from krb5.conf and from
 * the PAM configuration.  Filled in by parse_args.
 */
struct pam_args {
    char *ccache;               /* Path to write ticket cache to. */
    char *ccache_dir;           /* Directory for ticket cache. */
    int debug;                  /* Log debugging information. */
    int forwardable;            /* Obtain forwardable tickets. */
    int ignore_root;            /* Skip authentication for root. */
    int ignore_k5login;         /* Don't check .k5login files. */
    int no_ccache;              /* Don't create a ticket cache. */
    char *renew_lifetime;       /* Renewable lifetime of credentials. */
    int search_k5login;         /* Try password with each line of .k5login. */
    int try_first_pass;         /* Try the previously entered password. */
    int use_first_pass;         /* Always use the previous password. */

    /*
     * This isn't really an arg, but instead flags whether PAM_SILENT was
     * included in the flags.  If set, don't report some messages back to the
     * user (currently only error messages from password changing).
     */
    int quiet;
};

/* Parse the PAM flags, arguments, and krb5.conf and fill out pam_args. */
struct pam_args *parse_args(struct context *, int flags, int argc,
                            const char **argv);

/* Free the pam_args struct when we're done. */
void free_args(struct pam_args *);


int init_ccache(struct context *, struct pam_args *, const char *,
                struct credlist *, krb5_ccache *);

int password_auth(struct context *, struct pam_args *, char *in_tkt_service,
                  struct credlist **);

int get_user_info(pam_handle_t *, const char *, int, char **);
int validate_auth(struct context *, struct pam_args *);

krb5_prompter_fct pam_prompter;

const char	*compat_princ_component(krb5_context, krb5_principal, int);
void		 compat_free_data_contents(krb5_context, krb5_data *);
krb5_error_code	 compat_cc_next_cred(krb5_context, const krb5_ccache, 
				     krb5_cc_cursor *, krb5_creds *);

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
static inline void
dlog(struct context *ctx, struct pam_args *args, const char *fmt, ...)
{
	if (args->debug) {
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

/* The same, but not optional based on the debug setting. */
static inline void
error(struct context *ctx, const char *fmt, ...)
{
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

#endif /* PAM_KRB5_H_ */
