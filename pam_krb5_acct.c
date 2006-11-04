/*
 * pam_krb5_acct.c
 *
 * PAM account management functions for pam_krb5
 *
 */

/* Get prototypes for the account management functions. */
#define PAM_SM_ACCOUNT

#include "config.h"

#include <errno.h>
#include <krb5.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string.h>

#include "pam_krb5.h"

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

    args = pamk5_args_parse(flags, argc, argv);
    if (args == NULL) {
        pamk5_error(ctx, "cannot allocate memory: %s", strerror(errno));
        pamret = PAM_AUTH_ERR;
        goto done;
    }
    pamret = pamk5_context_fetch(pamh, &ctx);
    ENTRY(ctx, args, flags);

    /*
     * Succeed if the user did not use krb5 to login.  Yes, ideally we should
     * probably fail and require that the user set up policy properly in their
     * PAM configuration, but it's not common for the user to do so and that's
     * not how other krb5 PAM modules work.  If we don't do this, root logins
     * with the system root password fail, which is a bad failure mode.
     */
    if (pamret != PAM_SUCCESS || ctx == NULL) {
        pamret = PAM_SUCCESS;
        ctx = NULL;
        pamk5_debug(ctx, args, "skipping non-Kerberos login");
        goto done;
    }

    /*
     * Re-retrieve the user rather than trusting our context; it's conceivable
     * the application could have changed it.  We have to cast &ctx->name to
     * void * due to C's broken type system.
     *
     * Use pam_get_item rather than pam_get_user here since the user should be
     * set by the time we get to this point.  If we would have to prompt for a
     * user, something is definitely broken and we should fail.
     */
    retval = pam_get_item(pamh, PAM_USER, (void *) &ctx->name);
    if (retval != PAM_SUCCESS || ctx->name == NULL) {
        retval = PAM_AUTH_ERR;
        goto done;
    }

    /*
     * If we have a ticket cache, then we can apply an additional bit of
     * paranoia.  Rather than trusting princ in the context, extract the
     * principal from the Kerberos ticket cache we actually received and then
     * validate that.  This should make no difference in practice, but it's a
     * bit more thorough.
     */
    if (ctx->cache != NULL) {
        pamk5_debug(ctx, args, "retrieving principal from cache");
        if (ctx->princ != NULL)
            krb5_free_principal(ctx->context, ctx->princ);
        retval = krb5_cc_get_principal(ctx->context, ctx->cache, &ctx->princ);
        if (retval != 0) {
            pamk5_error(ctx, "cannot retrieve principal from cache: %s",
                        pamk5_compat_get_err_text(ctx->context, retval));
            pamret = PAM_AUTH_ERR;
            goto done;
        }
    }
    pamret = pamk5_validate_auth(ctx, args);

done:
    EXIT(ctx, args, pamret);
    pamk5_args_free(args);
    return pamret;
}
