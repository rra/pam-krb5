/*
 * pam_krb5_acct.c
 *
 * PAM account management functions for pam_krb5
 *
 */

#define PAM_SM_ACCOUNT

#include <syslog.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <krb5.h>
#include <com_err.h>
#include "pam_krb5.h"
#include "context.h"

/* Check authorization of user */
int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct context *ctx = NULL;
    int	pamret = PAM_AUTH_ERR;

    parse_args(flags, argc, argv);
    dlog(ctx, "%s: entry", __FUNCTION__);

    /* Succeed if the user did not use krb5 to login.  Yes, ideally we should
       probably fail and require that the user set up policy properly in their
       PAM configuration, but it's not common for the user to do so and that's
       not how other krb5 PAM modules work.  If we don't do this, root logins
       with the system root password fail, which is a bad failure mode. */
    pamret = pam_get_data(pamh, "ctx", (void *) &ctx);
    if (pamret != PAM_SUCCESS || ctx == NULL) {
        pamret = PAM_SUCCESS;
        ctx = NULL;
        dlog(ctx, "%s: skipping non-Kerberos login", __FUNCTION__);
        goto done;
    }
    pamret = fetch_context(pamh, &ctx);
    if (pamret == PAM_SUCCESS)
        pamret = validate_auth(ctx);

    /* XXX: we could be a bit more thorough here; see what krb5_kuserok
     * *doesn't* check for, and check that here. */

done:
    dlog(ctx, "%s: exit (%s)", __FUNCTION__, pamret ? "failure" : "success");
    return pamret;
}

