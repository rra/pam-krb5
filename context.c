/*
 * context.c
 *
 * Manage context structure.
 *
 * The context structure is the internal state maintained by the pam_krb5
 * module between calls to the various public interfaces.
 */

#include "config.h"

#include <security/pam_modules.h>
#include <string.h>

#include "pam_krb5.h"

/*
 * Create a new context and populate it with the user and service from PAM and
 * a new Kerberos context.
 */
int
pamk5_context_new(pam_handle_t *pamh, struct context **ctx)
{
    struct context *c;
    int retval;

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
    retval = pam_get_user(c->pamh, &c->name, NULL);
    if (retval != PAM_SUCCESS || c->name == NULL) {
        if (retval == PAM_CONV_AGAIN)
            retval = PAM_INCOMPLETE;
        else
            retval = PAM_SERVICE_ERR;
        goto done;
    }
    pam_get_item(c->pamh, PAM_SERVICE, (void *) &c->service);
    if (c->service == NULL)
        c->service = "unknown";
    retval = krb5_init_context(&c->context);
    if (retval != 0) {
        pamk5_error(c, "krb5_init_context: %s", error_message(retval));
        retval = PAM_SERVICE_ERR;
        goto done;
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
