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

    if (fetch_context(pamh, &ctx) != PAM_SUCCESS) {
	/* User did not use krb5 to login */
	/* pamret = PAM_SUCCESS;	// I don't think we want to do this.
	 * 				// This policy should be in pam.conf,
	 *				// not here.  Fail, instead.  Admin can
	 *				// override w/ 'sufficient' */
	goto done;
    }

    /* XXX: we could be a bit more thorough here; see what krb5_kuserok
     * *doesn't* check for, and check that here. */

done:
    dlog(ctx, "%s: exit (%s)", __FUNCTION__, pamret ? "failure" : "success");
    return pamret;
}

