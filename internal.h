/*
 * Internal prototypes and structures for pam-krb5.
 *
 * Copyright 2005, 2006, 2007, 2008, 2009 Russ Allbery <rra@stanford.edu>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 * See LICENSE for licensing terms.
 */

#ifndef INTERNAL_H
#define INTERNAL_H 1

#include <config.h>
#include <portable/pam.h>

#include <krb5.h>
#include <stdarg.h>
#include <syslog.h>

/* Forward declarations to avoid unnecessary includes. */
struct passwd;

/*
 *__attribute__ is available in gcc 2.5 and later, but only with gcc 2.7
 * could you use the __format__ form of the attributes, which is what we use
 * (to avoid confusion with other macros).
 */
#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#  define __attribute__(spec)   /* empty */
# endif
#endif

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED  __attribute__((__unused__))

/*
 * An authentication context, including all the data we want to preserve
 * across calls to the public entry points.  This context is stored in the PAM
 * state and a pointer to it is stored in the pam_args struct that is passed
 * as the first argument to most internal functions.
 */
struct context {
    char *name;                 /* Username being authenticated. */
    krb5_context context;       /* Kerberos context. */
    krb5_ccache cache;          /* Active credential cache, if any. */
    krb5_principal princ;       /* Principal being authenticated. */
    int expired;                /* If set, account was expired. */
    int dont_destroy_cache;     /* If set, don't destroy cache on shutdown. */
    int initialized;            /* If set, ticket cache initialized. */
    krb5_creds *creds;          /* Credentials for password changing. */
};

/*
 * The global structure holding our arguments, both from krb5.conf and from
 * the PAM configuration, and a pointer to our state.  Filled in by
 * pamk5_args_parse and passed as a first argument to most internal
 * functions.
 */
struct pam_args {
    char *banner;               /* Addition to password changing prompts. */
    char *ccache;               /* Path to write ticket cache to. */
    char *ccache_dir;           /* Directory for ticket cache. */
    int clear_on_fail;          /* Delete saved password on change failure. */
    int debug;                  /* Log debugging information. */
    int defer_pwchange;         /* Defer expired account fail to account. */
    int expose_account;         /* Display principal in password prompts. */
    int fail_pwchange;          /* Treat expired password as auth failure. */
    char *fast_ccache;          /* Cache containing armor ticket. */
    int force_first_pass;       /* Require a previous password be stored. */
    int force_pwchange;         /* Change expired passwords in auth. */
    int forwardable;            /* Obtain forwardable tickets. */
    int ignore_root;            /* Skip authentication for root. */
    int ignore_k5login;         /* Don't check .k5login files. */
    char *keytab;               /* Keytab for credential validation. */
    krb5_deltat lifetime;       /* Lifetime of credentials. */
    int minimum_uid;            /* Ignore users below this UID. */
    int no_ccache;              /* Don't create a ticket cache. */
    int prompt_princ;           /* Prompt for the Kerberos principal. */
    char *realm;                /* Default realm. */
    krb5_deltat renew_lifetime; /* Renewable lifetime of credentials. */
    int retain;                 /* Don't destroy the cache on session end. */
    int search_k5login;         /* Try password with each line of .k5login. */
    int try_first_pass;         /* Try the previously entered password. */
    int use_authtok;            /* Use the stored new password for changes. */
    int use_first_pass;         /* Always use the previous password. */

    /* Options used for the optional PKINIT support. */
    char *pkinit_anchors;       /* Trusted certificates, usually per realm. */
    int pkinit_prompt;          /* Prompt user to insert smart card. */
    char *pkinit_user;          /* User ID to pass to PKINIT. */
    int try_pkinit;             /* Attempt PKINIT, fall back to password. */
    int use_pkinit;             /* Require PKINIT. */

    /* Options used for MIT Kerberos preauth plugins. */
    char **preauth_opt;         /* Preauth options. */
    int preauth_opt_count;      /* Number of preauth options set. */

    /* Options for use of alternate identities */
    char *alt_auth_map;         /* An sprintf pattern to map principals. */
    int force_alt_auth;         /* Alt principal must be used if it exists. */
    int only_alt_auth;          /* Alt principal must be used. */

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
     * This isn't really an arg but instead records whether PAM_SILENT was
     * included in the flags.  If set, only call the conversation function for
     * prompts, not informational messages or errors.
     */
    int silent;

    /* Pointers to our state so that we can pass around only one struct. */
    pam_handle_t *pamh;         /* Pointer back to the PAM handle. */
    struct context *ctx;        /* Pointer to our authentication context. */
};

/* Default to a hidden visibility for all internal functions. */
#pragma GCC visibility push(hidden)

/* Parse the PAM flags, arguments, and krb5.conf and fill out pam_args. */
struct pam_args *pamk5_args_parse(pam_handle_t *pamh, int flags, int argc,
                                  const char **argv);

/* Free the pam_args struct when we're done. */
void pamk5_args_free(struct pam_args *);

/*
 * Authenticate the user.  Prompts for the password as needed and obtains
 * tickets for in_tkt_service, krbtgt/<realm> by default.  Stores the initial
 * credentials in the final argument, allocating a new krb5_creds structure.
 * If possible, the initial credentials are verified by checking them against
 * the local system key.
 */
int pamk5_password_auth(struct pam_args *, const char *service,
                        krb5_creds **);

/*
 * Create or refresh the user's ticket cache.  This is the underlying function
 * beneath pam_sm_setcred and pam_sm_open_session.
 */
int pamk5_setcred(struct pam_args *, int refresh);

/*
 * Prompt the user for a new password, twice so that they can confirm.  Sets
 * PAM_AUTHTOK and puts the new password in newly allocated memory in pass if
 * it's not NULL.
 */
int pamk5_password_prompt(struct pam_args *, char **pass);

/*
 * Change the user's password.  Prompts for the current password as needed and
 * the new password.  If the second argument is true, only obtains the
 * necessary credentials without changing anything.
 */
int pamk5_password_change(struct pam_args *, int only_auth);

/*
 * Generic conversation function to display messages or get information from
 * the user.  Takes the message, the message type, and a place to put the
 * result of a prompt.
 */
int pamk5_conv(struct pam_args *, const char *, int, char **);

/*
 * Function specifically for getting a password.  Takes a prefix (if non-NULL,
 * args->banner will also be prepended) and a pointer into which to store the
 * password.  The password must be freed by the caller.
 */
int pamk5_get_password(struct pam_args *, const char *, char **);

/* Prompting function for the Kerberos libraries. */
krb5_error_code pamk5_prompter_krb5(krb5_context, void *data,
                                    const char *name, const char *banner,
                                    int, krb5_prompt *);

/* Check the user with krb5_kuserok or the configured equivalent. */
int pamk5_authorized(struct pam_args *);

/* Map username to principal using alt_auth_map. */
int pamk5_map_principal(struct pam_args *args, const char *, char **);

/* Returns true if we should ignore this user (root or low UID). */
int pamk5_should_ignore(struct pam_args *, PAM_CONST char *);

/* Context management. */
int pamk5_context_new(struct pam_args *);
int pamk5_context_fetch(struct pam_args *);
void pamk5_context_free(struct context *);
void pamk5_context_destroy(pam_handle_t *, void *data, int pam_end_status);

/* Get and set environment variables for the ticket cache. */
const char *pamk5_get_krb5ccname(struct pam_args *, const char *key);
int pamk5_set_krb5ccname(struct pam_args *, const char *, const char *key);

/*
 * Create a ticket cache file securely given a mkstemp template.  Modifies
 * template in place to store the name of the created file.
 */
int pamk5_cache_mkstemp(struct pam_args *, char *template);

/*
 * Create a ticket cache and initialize it with the provided credentials,
 * returning the new cache in the last argument
 */
int pamk5_cache_init(struct pam_args *, const char *ccname, krb5_creds *,
                     krb5_ccache *);

/*
 * Create a ticket cache with a random path, initialize it with the provided
 * credentials, store it in the context, and put the path into PAM_KRB5CCNAME.
 */
int pamk5_cache_init_random(struct pam_args *, krb5_creds *);

/*
 * Compatibility functions.  Depending on whether pam_krb5 is built with MIT
 * Kerberos or Heimdal, appropriate implementations for the Kerberos
 * implementation will be provided.
 */
void pamk5_compat_free_data_contents(krb5_context, krb5_data *);
void pamk5_compat_free_keytab_contents(krb5_context, krb5_keytab_entry *);
const char *pamk5_compat_get_error(krb5_context, krb5_error_code);
void pamk5_compat_free_error(krb5_context, const char *);
krb5_error_code pamk5_compat_opt_alloc(krb5_context,
                                       krb5_get_init_creds_opt **);
void pamk5_compat_opt_free(krb5_context, krb5_get_init_creds_opt *);
krb5_error_code pamk5_compat_set_realm(struct pam_args *, const char *);
void pamk5_compat_free_realm(struct pam_args *);
krb5_error_code pamk5_compat_secure_context(krb5_context *);

/* Calls issetugid if available, otherwise checks effective IDs. */
int pamk5_compat_issetugid(void);

/*
 * Error reporting and debugging functions.  For each log level, there are
 * three functions.  The _log function just prints out the message it's given.
 * The _log_pam function reports a PAM error using pam_strerror.  The
 * _log_krb5 function reports a Kerberos error.
 */
void pamk5_crit(struct pam_args *, const char *, ...)
    __attribute__((__format__(printf, 2, 3)));
void pamk5_crit_pam(struct pam_args *, int, const char *, ...)
    __attribute__((__format__(printf, 3, 4)));
void pamk5_crit_krb5(struct pam_args *, int, const char *, ...)
    __attribute__((__format__(printf, 3, 4)));
void pamk5_err(struct pam_args *, const char *, ...)
    __attribute__((__format__(printf, 2, 3)));
void pamk5_err_pam(struct pam_args *, int, const char *, ...)
    __attribute__((__format__(printf, 3, 4)));
void pamk5_err_krb5(struct pam_args *, int, const char *, ...)
    __attribute__((__format__(printf, 3, 4)));
void pamk5_debug(struct pam_args *, const char *, ...)
    __attribute__((__format__(printf, 2, 3)));
void pamk5_debug_pam(struct pam_args *, int, const char *, ...)
    __attribute__((__format__(printf, 3, 4)));
void pamk5_debug_krb5(struct pam_args *, int, const char *, ...)
    __attribute__((__format__(printf, 3, 4)));

/* Log an authentication failure. */
void pamk5_log_failure(struct pam_args *, const char *, ...)
    __attribute__((__format__(printf, 2, 3)));

/* Undo default visibility change. */
#pragma GCC visibility pop

/* __func__ is C99, but not provided by all implementations. */
#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

/* Macros to record entry and exit from the main PAM functions. */
#define ENTRY(args, flags)                                              \
    if (args->debug)                                                    \
        pam_syslog((args)->pamh, LOG_DEBUG,                             \
                   "%s: entry (0x%x)", __func__, (flags))
#define EXIT(args, pamret)                                              \
    if (args->debug)                                                    \
        pam_syslog((args)->pamh, LOG_DEBUG, "%s: exit (%s)", __func__,  \
                   ((pamret) == PAM_SUCCESS) ? "success"                \
                   : (((pamret) == PAM_IGNORE) ? "ignore" : "failure"))

#endif /* !INTERNAL_H */
