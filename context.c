/*
 * context.c
 *
 * Manage context structure.
 *
 * The context structure is the internal state maintained by the pam_krb5
 * module between calls to the various public interfaces.
 */

#include "config.h"

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pam_krb5.h"

/* Solaris doesn't have these. */
#ifndef PAM_CONV_AGAIN
# define PAM_CONV_AGAIN 0
# define PAM_INCOMPLETE PAM_SERVICE_ERR
#endif

/* Heimdal doesn't need krb5_init_secure_context. */
#if HAVE_KRB5_HEIMDAL
# define krb5_init_secure_context(c) krb5_init_context(c)
#endif

/*
 * Create a new context and populate it with the user from PAM and a new
 * Kerberos context.  Set the default realm if one was configured.
 */
int
pamk5_context_new(pam_handle_t *pamh, struct pam_args *args,
                  struct context **ctx)
{
    struct context *c;
    int retval;
    const char *name;

    c = calloc(1, sizeof(*c));
    if (c == NULL) {
        retval = PAM_BUF_ERR;
        goto done;
    }
    *ctx = c;
    c->pamh = pamh;
    c->creds = NULL;

    /*
     * This will prompt for the username if it's not already set (generally it
     * will be).  Otherwise, grab the saved username.
     */
    retval = pam_get_user(c->pamh, &name, NULL);
    if (retval != PAM_SUCCESS || name == NULL) {
        if (retval == PAM_CONV_AGAIN)
            retval = PAM_INCOMPLETE;
        else
            retval = PAM_SERVICE_ERR;
        goto done;
    }
    c->name = strdup(name);
    if (getuid() != geteuid() || getgid() != getegid())
        retval = krb5_init_secure_context(&c->context);
    else
        retval = krb5_init_context(&c->context);
    if (retval != 0) {
        pamk5_error(c, "krb5_init_context: %s",
                    pamk5_compat_get_err_text(c->context, retval));
        retval = PAM_SERVICE_ERR;
        goto done;
    }

    /* Set a default realm if one was configured. */
    if (args->realm != NULL) {
        retval = krb5_set_default_realm(c->context, args->realm);
        if (retval != 0) {
            pamk5_error(c, "cannot set default realm: %s",
                        pamk5_compat_get_err_text(c->context, retval));
            retval = PAM_SERVICE_ERR;
            goto done;
        }
    }

done:
    if (c != NULL && retval != PAM_SUCCESS) {
        pamk5_context_free(c);
        *ctx = NULL;
    }
    return retval;
}


/*
 * Retrieve a context from the PAM data structures, returning failure if no
 * context was present.  Note that OpenSSH loses contexts between authenticate
 * and setcred, so failure shouldn't always be fatal.
 */
int
pamk5_context_fetch(pam_handle_t *pamh, struct context **ctx)
{
    int pamret;

    pamret = pam_get_data(pamh, "ctx", (void *) ctx);
    if (pamret != PAM_SUCCESS)
        *ctx = NULL;
    return (pamret == 0 && *ctx == NULL) ? PAM_SERVICE_ERR : pamret;
}


/*
 * Free a context and all of the data that's stored in it.  Normally this also
 * includes destroying the ticket cache, but don't do this (just close it) if
 * a flag was set to preserve it.
 */
void
pamk5_context_free(struct context *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->context != NULL) {
        if (ctx->name != NULL)
            free(ctx->name);
        if (ctx->princ != NULL)
            krb5_free_principal(ctx->context, ctx->princ);
        if (ctx->cache != NULL) {
            if (ctx->dont_destroy_cache)
                krb5_cc_close(ctx->context, ctx->cache);
            else
                krb5_cc_destroy(ctx->context, ctx->cache);
        }
        if (ctx->creds != NULL)
            pamk5_credlist_free(ctx, ctx->creds);
        krb5_free_context(ctx->context);
    }
    free(ctx);
}


/*
 * The PAM callback to destroy the context stored in the PAM data structures.
 * Just does the necessary conversion of arguments and calls
 * pamk5_context_free.
 */
void
pamk5_context_destroy(pam_handle_t *pamh, void *data, int pam_end_status)
{
    struct context *ctx = (struct context *) data;

    if (ctx != NULL)
        pamk5_context_free(ctx);
}
