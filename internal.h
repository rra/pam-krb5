/*
 * Internal prototypes and structures for pam-krb5.
 *
 * Copyright 2005, 2006, 2007 Russ Allbery <rra@debian.org>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 * See LICENSE for licensing terms.
 */

#ifndef INTERNAL_H
#define INTERNAL_H 1

#include "config.h"

#include <krb5.h>
#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#elif HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
# include <pam/pam_modules.h>
#endif
#include <stdarg.h>

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
    int expose_account;         /* Display principal in password prompts. */
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
    int use_authtok;            /* Require a previous password be used. */
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
int pamk5_password_auth(struct pam_args *, const char *service, krb5_creds **);

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

/* Returns true if we should ignore this user (root or low UID). */
int pamk5_should_ignore(struct pam_args *, PAM_CONST char *);

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

/* Calls pam_modutil_getpwnam if available, otherwise getpwnam. */
struct passwd *pamk5_compat_getpwnam(struct pam_args *, const char *);

/* Context management. */
int pamk5_context_new(struct pam_args *);
int pamk5_context_fetch(struct pam_args *);
void pamk5_context_free(struct context *);
void pamk5_context_destroy(pam_handle_t *, void *data, int pam_end_status);

/* Error reporting and debugging functions. */
void pamk5_error(struct pam_args *, const char *, ...);
void pamk5_error_krb5(struct pam_args *, const char *, int);
void pamk5_debug(struct pam_args *, const char *, ...);
void pamk5_debug_pam(struct pam_args *, const char *, int);
void pamk5_debug_krb5(struct pam_args *, const char *, int);

/* __func__ is C99, but not provided by all implementations. */
#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

/* Macros to record entry and exit from the main PAM functions. */
#define ENTRY(args, flags) \
    pamk5_debug((args), "%s: entry (0x%x)", __func__, (flags))
#define EXIT(args, pamret) \
    pamk5_debug((args), "%s: exit (%s)", __func__, \
                ((pamret) == PAM_SUCCESS) ? "success" : "failure")

#endif /* !INTERNAL_H */
