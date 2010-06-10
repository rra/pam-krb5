/*
 * Implements the PAM auth group API (pam_sm_authenticate and pam_sm_setcred).
 *
 * The former does and checks the authentication, and the latter creates the
 * final ticket cache and sets its permissions appropriately.  pam_sm_setcred
 * can also refresh an existing ticket cache or destroy a ticket cache,
 * depending on the flags passed in.
 *
 * Copyright 2005, 2006, 2007, 2008, 2009 Russ Allbery <rra@stanford.edu>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

/* Get the prototypes for the authentication functions. */
#define PAM_SM_AUTH

#include <config.h>
#include <portable/pam.h>

#include <errno.h>
#include <krb5.h>
#include <string.h>
#include <syslog.h>

#include <internal.h>

/*
 * Authenticate a user via Kerberos 5.
 *
 * It would be nice to be able to save the ticket cache temporarily as a
 * memory cache and then only write it out to disk during the session
 * initialization.  Unfortunately, OpenSSH 4.2 does PAM authentication in a
 * subprocess and therefore has no saved module-specific data available once
 * it opens a session, so we have to save the ticket cache to disk and store
 * in the environment where it is.
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                    const char **argv)
{
    struct context *ctx = NULL;
    struct pam_args *args;
    krb5_creds *creds = NULL;
    char *pass = NULL;
    char *principal;
    int pamret;
    int set_context = 0;
    krb5_error_code retval;

    args = pamk5_args_parse(pamh, flags, argc, argv);
    if (args == NULL) {
        pamk5_crit(NULL, "cannot allocate memory: %s", strerror(errno));
        pamret = PAM_SERVICE_ERR;
        goto done;
    }
    ENTRY(args, flags);

    /* Temporary backward compatibility. */
    if (args->use_authtok && !args->force_first_pass) {
        pamk5_err(args, "use_authtok option in authentication group should"
                  " be changed to force_first_pass");
        args->force_first_pass = 1;
    }

    /* Create a context and obtain the user. */
    pamret = pamk5_context_new(args);
    if (pamret != PAM_SUCCESS)
        goto done;
    ctx = args->ctx;

    /* Check whether we should ignore this user. */
    if (pamk5_should_ignore(args, ctx->name)) {
        pamret = PAM_USER_UNKNOWN;
        goto done;
    }

    /*
     * Do the actual authentication.  Expiration, if we're handling this using
     * the formally correct method (defer_pwchange), is handled specially: we
     * set a flag in the context and return success.  That flag will later be
     * checked by pam_sm_acct_mgmt.  If we're not handling it in the formally
     * correct method, we try to do the password change directly now.
     *
     * We need to set the context as PAM data in the defer_pwchange case, but
     * we don't want to set the PAM data until we've checked .k5login since if
     * we've stacked multiple pam-krb5 invocations in different realms with
     * optional, we don't want to override a previous successful
     * authentication.
     *
     * This means that if authentication succeeds in one realm and is then
     * expired in a later realm, the expiration in the latter realm wins.
     * This isn't ideal, but avoiding that case is more complicated than it's
     * worth.
     *
     * In the force_pwchange case, try to use the password the user just
     * entered to authenticate to the password changing service, but don't
     * throw an error if that doesn't work.  We have to move it from
     * PAM_AUTHTOK to PAM_OLDAUTHTOK to be in the place where password
     * changing expects, and have to unset PAM_AUTHTOK or we'll just change
     * the password to the same thing it was.
     */
    pamret = pamk5_password_auth(args, NULL, &creds);
    if (pamret == PAM_NEW_AUTHTOK_REQD) {
        if (args->fail_pwchange)
            pamret = PAM_AUTH_ERR;
        else if (args->defer_pwchange) {
            pamk5_debug(args, "expired account, deferring failure");
            ctx->expired = 1;
            pamret = PAM_SUCCESS;
        } else if (args->force_pwchange) {
            pam_syslog(args->pamh, LOG_INFO, "user %s password expired,"
                       " forcing password change", ctx->name);
            pamk5_conv(args, "Password expired.  You must change it now.",
                       PAM_TEXT_INFO, NULL);
            pamret = pam_get_item(args->pamh, PAM_AUTHTOK,
                                  (PAM_CONST void **) &pass);
            if (pamret == PAM_SUCCESS && pass != NULL)
                pam_set_item(args->pamh, PAM_OLDAUTHTOK, pass);
            pam_set_item(args->pamh, PAM_AUTHTOK, NULL);
            args->use_first_pass = 1;
            pamret = pamk5_password_change(args, 0);
            if (pamret == PAM_SUCCESS) {
                pamk5_debug(args, "successfully changed expired password");
                args->force_first_pass = 1;
                pamret = pamk5_password_auth(args, NULL, &creds);
            }
        }
    }
    if (pamret != PAM_SUCCESS) {
        pamk5_log_failure(args, "authentication failure");
        goto done;
    }

    /* Check .k5login and alt_auth_map. */
    if (!ctx->expired) {
        pamret = pamk5_authorized(args);
        if (pamret != PAM_SUCCESS) {
            pamk5_log_failure(args, "failed authorization check");
            goto done;
        }
    }

    /* Reset PAM_USER in case we canonicalized, but ignore errors. */
    if (!ctx->expired) {
        pamret = pam_set_item(args->pamh, PAM_USER, ctx->name);
        if (pamret != PAM_SUCCESS)
            pamk5_err_pam(args, pamret, "cannot set PAM_USER");
    }

    /* Log the successful authentication. */
    retval = krb5_unparse_name(ctx->context, ctx->princ, &principal);
    if (retval != 0) {
        pamk5_err_krb5(args, retval, "krb5_unparse_name failed");
        pam_syslog(args->pamh, LOG_INFO, "user %s authenticated as UNKNOWN",
                   ctx->name);
    } else {
        pam_syslog(args->pamh, LOG_INFO, "user %s authenticated as %s",
                   ctx->name, principal);
        free(principal);
    }

    /* Now that we know we're successful, we can store the context. */
    pamret = pam_set_data(pamh, "pam_krb5", ctx, pamk5_context_destroy);
    if (pamret != PAM_SUCCESS) {
        pamk5_err_pam(args, pamret, "cannot set context data");
        pamk5_context_free(ctx);
        pamret = PAM_SERVICE_ERR;
        goto done;
    }
    set_context = 1;

    /*
     * If we have an expired account or if we're not creating a ticket cache,
     * we're done.  Otherwise, store the obtained credentials in a temporary
     * cache.
     */
    if (!args->no_ccache && !ctx->expired)
        pamret = pamk5_cache_init_random(args, creds);

done:
    if (creds != NULL) {
        krb5_free_cred_contents(ctx->context, creds);
        free(creds);
    }
    EXIT(args, pamret);

    /*
     * Clear the context on failure so that the account management module
     * knows that we didn't authenticate with Kerberos.  Only clear the
     * context if we set it.  Otherwise, we may be blowing away the context of
     * a previous successful authentication.
     */
    if (pamret != PAM_SUCCESS) {
        if (set_context)
            pam_set_data(pamh, "pam_krb5", NULL, NULL);
        else
            pamk5_context_free(ctx);
    }
    pamk5_args_free(args);
    return pamret;
}


/*
 * Should be called after a successful authentication.  Sets user credentials
 * by creating the permanent ticket cache and setting the proper ownership.
 */
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct pam_args *args;
    int refresh = 0;
    int pamret, allow;

    args = pamk5_args_parse(pamh, flags, argc, argv);
    if (args == NULL) {
        pamk5_crit(NULL, "cannot allocate memory: %s", strerror(errno));
        pamret = PAM_SERVICE_ERR;
        goto done;
    }
    ENTRY(args, flags);

    /*
     * Special case.  Just free the context data, which will destroy the
     * ticket cache as well.
     */
    if (flags & PAM_DELETE_CRED) {
        pamret = pam_set_data(pamh, "pam_krb5", NULL, NULL);
        if (pamret != PAM_SUCCESS)
            pamk5_err_pam(args, pamret, "cannot clear context data");
        args->ctx = NULL;
        goto done;
    }

    /*
     * Reinitialization requested, which means that rather than creating a new
     * ticket cache and setting KRB5CCNAME, we should figure out the existing
     * ticket cache and just refresh its tickets.
     */
    if (flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED))
        refresh = 1;
    if (refresh && (flags & PAM_ESTABLISH_CRED)) {
        pamk5_err(args, "requested establish and refresh at the same time");
        pamret = PAM_SERVICE_ERR;
        goto done;
    }
    allow = PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED | PAM_ESTABLISH_CRED;
    if (!(flags & allow)) {
        pamk5_err(args, "invalid pam_setcred flags %d", flags);
        pamret = PAM_SERVICE_ERR;
        goto done;
    }

    /* Do the work. */
    pamret = pamk5_setcred(args, refresh);

    /*
     * Never return PAM_IGNORE from pam_setcred since this can confuse the
     * Linux PAM library, at least for applications that call pam_setcred
     * without pam_authenticate (possibly because authentication was done
     * some other way), when used with jumps with the [] syntax.  Since we
     * do nothing in this case, and since the stack is already frozen from
     * the auth group, success makes sense.
     *
     * Don't return an error here or the PAM stack will fail if pam-krb5 is
     * used with [success=ok default=1], since jumps are treated as required
     * during the second pass with pam_setcred.
     */
    if (pamret == PAM_IGNORE)
        pamret = PAM_SUCCESS;

done:
    EXIT(args, pamret);
    pamk5_args_free(args);
    return pamret;
}
