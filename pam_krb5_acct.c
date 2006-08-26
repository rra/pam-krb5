/*
 * pam_krb5_acct.c
 *
 * PAM account management functions for pam_krb5
 *
 */

/* Get prototypes for the account management functions. */
#define PAM_SM_ACCOUNT

#include "config.h"

#include <security/pam_modules.h>

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
    int	pamret = PAM_AUTH_ERR;

    pamret = pamk5_context_fetch(pamh, &ctx);
    args = pamk5_args_parse(ctx, flags, argc, argv);
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
    pamret = pamk5_validate_auth(ctx, args);

done:
    EXIT(ctx, args, pamret);
    pamk5_args_free(args);
    return pamret;
}
