/*
 * pam_krb5.h
 *
 * $Id: pam_krb5.h,v 1.3 2000/12/19 22:53:11 hartmans Exp $
 */

#ifndef PAM_KRB5_H_
#define PAM_KRB5_H_

#include "config.h"

#include <krb5.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdarg.h>

/*
 * The global structure holding our arguments, both from krb5.conf and from
 * the PAM configuration.  Filled in by pamk5_args_parse.
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
    char *realm;                /* Default realm. */
    krb5_deltat renew_lifetime; /* Renewable lifetime of credentials. */
    int retain;                 /* Don't destroy the cache on session end. */
    int search_k5login;         /* Try password with each line of .k5login. */
    int try_first_pass;         /* Try the previously entered password. */
    int use_authtok;            /* Require a previous password be used. */
    int use_first_pass;         /* Always use the previous password. */

    /*
     * The default realm, used mostly in option parsing but also for
     * initializing krb5_get_init_creds_opt.  Unfortunately, the storage type
     * varies between Heimdal and MIT.
     */
#ifdef HAVE_KRB5_HEIMDAL
    krb5_realm realm_data;
#else
    krb5_data *realm_data;
#endif

    /*
     * This isn't really an arg, but instead flags whether PAM_SILENT was
     * included in the flags.  If set, don't report some messages back to the
     * user (currently only error messages from password changing).
     */
    int quiet;
};

/* Stores a simple list of credentials. */
struct credlist {
    krb5_creds creds;
    struct credlist *next;
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
    struct credlist *creds;     /* Credentials for password changing. */
};

/* Parse the PAM flags, arguments, and krb5.conf and fill out pam_args. */
struct pam_args *pamk5_args_parse(int flags, int argc, const char **argv);

/* Free the pam_args struct when we're done. */
void pamk5_args_free(struct pam_args *);

/* Initialize a ticket cache from a credlist containing credentials. */
int pamk5_ccache_init(struct context *, struct pam_args *, const char *,
                      struct credlist *, krb5_ccache *);

/*
 * Authenticate the user.  Prompts for the password as needed and obtains
 * tickets for in_tkt_service, krbtgt/<realm> by default.  Stores the initial
 * credentials in the final argument.  If possible, the initial credentials
 * are verified by checking them against the local system key.
 */
int pamk5_password_auth(struct context *, struct pam_args *,
                        char *in_tkt_service, struct credlist **);

/* Generic prompting function to get information from the user. */
int pamk5_prompt(pam_handle_t *, const char *, int, char **);

/* Prompting function for the Kerberos libraries. */
krb5_error_code pamk5_prompter_krb5(krb5_context, void *data,
                                    const char *name, const char *banner,
                                    int, krb5_prompt *);

/* Check the user with krb5_kuserok or the configured equivalent. */
int pamk5_validate_auth(struct context *, struct pam_args *);

/* Returns true if we should ignore this user (root or low UID). */
int pamk5_should_ignore(struct context *, struct pam_args *,
                             const char *);

/*
 * Compatibility functions.  Depending on whether pam_krb5 is built with MIT
 * Kerberos or Heimdal, appropriate implementations for the Kerberos
 * implementation will be provided.
 */
void pamk5_compat_free_data_contents(krb5_context, krb5_data *);
const char *pamk5_compat_get_err_text(krb5_context, krb5_error_code);
krb5_error_code pamk5_compat_set_realm(struct pam_args *, const char *);
void pamk5_compat_free_realm(struct pam_args *);

/* Context management. */
int pamk5_context_new(pam_handle_t *, struct pam_args *, struct context **);
int pamk5_context_fetch(pam_handle_t *, struct context **);
void pamk5_context_free(struct context *);
void pamk5_context_destroy(pam_handle_t *, void *data, int pam_end_status);

/* Credential list handling. */
int pamk5_credlist_new(struct context *, struct credlist **);
int pamk5_credlist_append(struct context *, struct credlist **, krb5_creds);
int pamk5_credlist_copy(struct context *, struct credlist **, krb5_ccache);
void pamk5_credlist_free(struct context *, struct credlist *);

/* Error reporting and debugging functions. */
void pamk5_error(struct context *, const char *, ...);
void pamk5_debug(struct context *, struct pam_args *, const char *, ...);
void pamk5_debug_pam(struct context *, struct pam_args *, const char *, int);
void pamk5_debug_krb5(struct context *, struct pam_args *, const char *, int);

/* Macros to record entry and exit from the main PAM functions. */
#define ENTRY(ctx, args, flags) \
    pamk5_debug((ctx), (args), "%s: entry (0x%x)", __FUNCTION__, (flags))
#define EXIT(ctx, args, pamret) \
    pamk5_debug((ctx), (args), "%s: exit (%s)", __FUNCTION__, \
                ((pamret) == PAM_SUCCESS) ? "success" : "failure")

#endif /* PAM_KRB5_H_ */
