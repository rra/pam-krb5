/*
 * Implements the PAM password group API (pam_sm_chauthtok).
 *
 * Copyright 2005, 2006, 2007, 2008 Russ Allbery <rra@debian.org>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 * See LICENSE for licensing terms.
 */

/* Get declarations for the password functions. */
#define PAM_SM_PASSWORD

#include "config.h"

#include <errno.h>
#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#elif HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
# include <pam/pam_modules.h>
#endif
#include <string.h>

#include "internal.h"


/*
 * The main PAM interface for password changing.
 */
int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct context *ctx = NULL;
    struct pam_args *args;
    int pamret = PAM_SUCCESS;
    int status;
    PAM_CONST char *user;
    char *pass = NULL;

    args = pamk5_args_parse(pamh, flags, argc, argv);
    if (args == NULL) {
        pamk5_error(NULL, "cannot allocate memory: %s", strerror(errno));
        pamret = PAM_AUTHTOK_ERR;
        goto done;
    }
    pamret = pamk5_context_fetch(args);
    ENTRY(args, flags);

    /* We only support password changes. */
    if (!(flags & PAM_UPDATE_AUTHTOK) && !(flags & PAM_PRELIM_CHECK)) {
        pamret = PAM_AUTHTOK_ERR;
        goto done;
    }

    /*
     * Skip root password changes on the assumption that they'll be handled by
     * some other module.  Don't tromp on pamret here unless we're failing.
     */
    if (args->ignore_root || args->minimum_uid > 0) {
        status = pam_get_user(pamh, &user, NULL);
        if (status == PAM_SUCCESS && pamk5_should_ignore(args, user)) {
            pamret = PAM_PERM_DENIED;
            goto done;
        }
    }

    /*
     * If we weren't able to find an existing context to use, we're going
     * into this fresh and need to create a new context.
     */
    if (args->ctx == NULL) {
        pamret = pamk5_context_new(args);
        if (pamret != PAM_SUCCESS) {
            pamk5_debug_pam(args, "creating context failed", pamret);
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
        pamret = pam_set_data(pamh, "pam_krb5", args->ctx,
                              pamk5_context_destroy);
        if (pamret != PAM_SUCCESS) {
            pamk5_debug_pam(args, "cannot set context data", pamret);
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
    }
    ctx = args->ctx;

    /* Tell the user what's going on if we're handling an expiration. */
    if (ctx->expired && ctx->creds == NULL)
        pamk5_conv(args, "Password expired.  You must change it now.",
                   PAM_TEXT_INFO, NULL);

    /* Do the password change. */
    pamret = pamk5_password_change(args, !(flags & PAM_UPDATE_AUTHTOK));

    /*
     * If we were handling a password change for an expired password, now
     * try to get a ticket cache with the new password.
     */
    if (pamret == PAM_SUCCESS && ctx->expired) {
        krb5_creds *creds = NULL;

        pamk5_debug(args, "obtaining credentials with new password");
        args->use_authtok = 1;
        pamret = pamk5_password_auth(args, NULL, &creds);
        if (pamret != PAM_SUCCESS)
            goto done;
        pamret = pamk5_cache_init_random(args, creds);
    }

done:
    if (pamret != PAM_SUCCESS) {
        if (pamret == PAM_SERVICE_ERR || pamret == PAM_AUTH_ERR)
            pamret = PAM_AUTHTOK_ERR;
        if (pamret == PAM_AUTHINFO_UNAVAIL)
            pamret = PAM_AUTHTOK_ERR;
    }
    EXIT(args, pamret);
    if (pass != NULL) {
        memset(pass, 0, strlen(pass));
        free(pass);
    }
    pamk5_args_free(args);
    return pamret;
}
