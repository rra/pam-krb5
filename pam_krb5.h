/*
 * pam_krb5.h
 *
 * $Id: pam_krb5.h,v 1.3 2000/12/19 22:53:11 hartmans Exp $
 */

#ifndef PAM_KRB5_H_
#define PAM_KRB5_H_

#include <krb5.h>
#include <security/pam_modules.h>
#include <stdarg.h>

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
    int minimum_uid;            /* Ignore users below this UID. */
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

/*
 * The global structure that holds the context, including all the data we want
 * to preserve across calls to the public entry points.  This context is
 * stored in the PAM state and passed as the first argument to most internal
 * functions.
 */
struct context {
    pam_handle_t *pamh;         /* Pointer back to the PAM handle. */
    const char *name;           /* Username being authenticated. */
    const char *service;        /* PAM service to which to authenticate. */
    krb5_context context;       /* Kerberos context. */
    krb5_ccache cache;          /* Active credential cache, if any. */
    krb5_principal princ;       /* Principal being authenticated. */
    int dont_destroy_cache;     /* If set, don't destroy cache on shutdown. */
    int initialized;            /* If set, ticket cache initialized. */
};

/* Stores a simple list of credentials. */
struct credlist {
    krb5_creds creds;
    struct credlist *next;
};

/* Parse the PAM flags, arguments, and krb5.conf and fill out pam_args. */
struct pam_args *parse_args(struct context *, int flags, int argc,
                            const char **argv);

/* Free the pam_args struct when we're done. */
void free_args(struct pam_args *);

/* Initialize a ticket cache from a credlist containing credentials. */
int init_ccache(struct context *, struct pam_args *, const char *,
                struct credlist *, krb5_ccache *);

/*
 * Authenticate the user.  Prompts for the password as needed and obtains
 * tickets for in_tkt_service, krbtgt/<realm> by default.  Stores the initial
 * credentials in the final argument.  If possible, the initial credentials
 * are verified by checking them against the local system key.
 */
int password_auth(struct context *, struct pam_args *, char *in_tkt_service,
                  struct credlist **);

/* Generic prompting function to get information from the user. */
int get_user_info(pam_handle_t *, const char *, int, char **);

/* Prompting function for the Kerberos libraries. */
krb5_error_code prompter_krb5(krb5_context, void *data, const char *name,
                              const char *banner, int, krb5_prompt *);

/* Check the user with krb5_kuserok or the configured equivalent. */
int validate_auth(struct context *, struct pam_args *);

/* Returns true if we should ignore this user (root or low UID). */
int should_ignore_user(struct context *, struct pam_args *, const char *);

/*
 * Compatibility functions.  Depending on whether pam_krb5 is built with MIT
 * Kerberos or Heimdal, appropriate implementations for the Kerberos
 * implementation will be provided.
 */
const char *compat_princ_component(krb5_context, krb5_principal, int);
void compat_free_data_contents(krb5_context, krb5_data *);
krb5_error_code compat_cc_next_cred(krb5_context, const krb5_ccache, 
                                    krb5_cc_cursor *, krb5_creds *);

/*
 * Set to the function to use to prompt for the user's password from inside
 * the Kerberos libraries.
 */
krb5_prompter_fct pam_prompter;

/* Context management. */
int new_context(pam_handle_t *pamh, struct context **ctx);
int fetch_context(pam_handle_t *pamh, struct context **ctx);
void free_context(struct context *ctx);
void destroy_context(pam_handle_t *pamh, void *data, int pam_end_status);

/* Credential list handling. */
int new_credlist(struct context *, struct credlist **);
int append_to_credlist(struct context *, struct credlist **, krb5_creds);
int copy_credlist(struct context *, struct credlist **, krb5_ccache);
void free_credlist(struct context *, struct credlist *);

/* Error reporting and debugging functions. */
void error(struct context *, const char *, ...);
void debug(struct context *, struct pam_args *, const char *, ...);
void debug_pam(struct context *, struct pam_args *, const char *, int);
void debug_krb5(struct context *, struct pam_args *, const char *, int);

/* Macros to record entry and exit from the main PAM functions. */
#define ENTRY(ctx, args, flags) \
    debug((ctx), (args), "%s: entry (0x%x)", __FUNCTION__, (flags))
#define EXIT(ctx, args, pamret) \
    debug((ctx), (args), "%s: exit (%s)", __FUNCTION__, \
          ((pamret) == PAM_SUCCESS) ? "success" : "failure")

#endif /* PAM_KRB5_H_ */
