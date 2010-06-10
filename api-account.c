/*
 * Implements the PAM account group API (pam_sm_acct_mgmt).
 *
 * We don't have much to do for account management, but we do recheck the
 * user's authorization against .k5login (or whatever equivalent we've been
 * configured for).
 *
 * Copyright 2005, 2006, 2007, 2008, 2009 Russ Allbery <rra@stanford.edu>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

/* Get prototypes for the account management functions. */
#define PAM_SM_ACCOUNT

#include <config.h>
#include <portable/pam.h>

#include <errno.h>
#include <krb5.h>
#include <stdlib.h>
#include <string.h>

#include <internal.h>

/*
 * Check the authorization of the user.  It's not entirely clear what this
 * function is supposed to do, but rechecking .k5login and friends makes the
 * most sense.
 */
int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct pam_args *args;
    struct context *ctx;
    int pamret, retval;
    const char *name;

    args = pamk5_args_parse(pamh, flags, argc, argv);
    if (args == NULL) {
        pamk5_crit(NULL, "cannot allocate memory: %s", strerror(errno));
        pamret = PAM_AUTH_ERR;
        goto done;
    }
    pamret = pamk5_context_fetch(args);
    ENTRY(args, flags);

    /*
     * Succeed if the user did not use krb5 to login.  Ideally, we should
     * probably fail and require that the user set up policy properly in their
     * PAM configuration, but it's not common for the user to do so and that's
     * not how other krb5 PAM modules work.  If we don't do this, root logins
     * with the system root password fail, which is a bad failure mode.
     */
    if (pamret != PAM_SUCCESS || args->ctx == NULL) {
        pamret = PAM_IGNORE;
        pamk5_debug(args, "skipping non-Kerberos login");
        goto done;
    }
    ctx = args->ctx;

    /* If the account was expired, here's where we actually fail. */
    if (ctx->expired) {
        pamk5_debug(args, "account password is expired");
        pamret = PAM_NEW_AUTHTOK_REQD;
        goto done;
    }

    /*
     * Re-retrieve the user rather than trusting our context; it's conceivable
     * the application could have changed it.  We have to cast &name to void *
     * due to C's broken type system.
     *
     * Use pam_get_item rather than pam_get_user here since the user should be
     * set by the time we get to this point.  If we would have to prompt for a
     * user, something is definitely broken and we should fail.
     */
    retval = pam_get_item(pamh, PAM_USER, (PAM_CONST void **) &name);
    if (retval != PAM_SUCCESS || name == NULL) {
        pamk5_err_pam(args, retval, "unable to retrieve user");
        pamret = PAM_AUTH_ERR;
        goto done;
    }
    if (ctx->name != NULL)
        free(ctx->name);
    ctx->name = strdup(name);

    /*
     * If we have a ticket cache, then we can apply an additional bit of
     * paranoia.  Rather than trusting princ in the context, extract the
     * principal from the Kerberos ticket cache we actually received and then
     * validate that.  This should make no difference in practice, but it's a
     * bit more thorough.
     */
    if (ctx->cache != NULL) {
        pamk5_debug(args, "retrieving principal from cache");
        if (ctx->princ != NULL)
            krb5_free_principal(ctx->context, ctx->princ);
        retval = krb5_cc_get_principal(ctx->context, ctx->cache, &ctx->princ);
        if (retval != 0) {
            pamk5_err_krb5(args, retval, "cannot get principal from cache");
            pamret = PAM_AUTH_ERR;
            goto done;
        }
    }
    pamret = pamk5_authorized(args);

done:
    EXIT(args, pamret);
    pamk5_args_free(args);
    return pamret;
}
