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
#include <krb5.h>
#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#elif HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
# include <pam/pam_modules.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include "internal.h"

/* Solaris 8 has deficient PAM. */
#ifndef PAM_AUTHTOK_RECOVER_ERR
# define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_ERR
#endif


/*
 * Get the new password.  Store it in PAM_AUTHTOK if we obtain it and verify
 * it successfully.
 */
static int
get_new_password(struct pam_args *args, char **pass)
{
    int pamret = PAM_AUTHTOK_ERR;
    char *pass2;
    PAM_CONST void *tmp;

    /*
     * Try to use the password from a previous module, if so configured.  Note
     * that try_first_pass and use_first_pass are equivalent for the new
     * password; we don't reprompt even if the password was rejected.
     */
    *pass = NULL;
    if (args->try_first_pass || args->use_first_pass || args->use_authtok) {
        pamret = pam_get_item(args->pamh, PAM_AUTHTOK, &tmp);
        if (tmp != NULL)
            *pass = strdup((const char *) tmp);
    }
    if (args->use_authtok && (pamret != PAM_SUCCESS || *pass == NULL)) {
        pamk5_debug_pam(args, "no stored password", pamret);
        pamret = PAM_AUTHTOK_ERR;
        goto done;
    }

    /* Prompt for the new password if necessary. */
    if (*pass == NULL) {
        pamret = pamk5_get_password(args, "Enter new", pass);
        if (pamret != PAM_SUCCESS) {
            pamk5_debug_pam(args, "error getting new password", pamret);
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
        pamret = pamk5_get_password(args, "Retype new", &pass2);
        if (pamret != PAM_SUCCESS) {
            pamk5_debug_pam(args, "error getting new password", pamret);
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
        if (strcmp(*pass, pass2) != 0) {
            pamk5_debug(args, "new passwords don't match");
            pamk5_conv(args, "Passwords don't match", PAM_ERROR_MSG, NULL);
            memset(pass2, 0, strlen(pass2));
            free(pass2);
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
        memset(pass2, 0, strlen(pass2));
        free(pass2);

        /* Save the new password for other modules. */
        pamret = pam_set_item(args->pamh, PAM_AUTHTOK, *pass);
        if (pamret != PAM_SUCCESS) {
            pamk5_debug_pam(args, "error storing password", pamret);
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
    }

done:
    return pamret;
}


/*
 * We've obtained credentials for the password changing interface and gotten
 * the new password, so do the work of actually changing the password.
 */
static int
password_change(struct pam_args *args, const char *pass)
{
    struct context *ctx;
    int retval = PAM_SUCCESS;
    int result_code;
    krb5_data result_code_string, result_string;
    const char *message;

    /* Sanity check. */
    if (args == NULL || args->ctx == NULL || args->ctx->creds == NULL)
        return PAM_AUTHTOK_ERR;
    ctx = args->ctx;

    /* The actual change. */
    retval = krb5_change_password(ctx->context, ctx->creds, (char *) pass,
                 &result_code, &result_code_string, &result_string);

    /* Everything from here on is just handling diagnostics and output. */
    if (retval != 0) {
        pamk5_debug_krb5(args, "krb5_change_password", retval);
        message = pamk5_compat_get_error(ctx->context, retval);
        pamk5_conv(args, message, PAM_ERROR_MSG, NULL);
        pamk5_compat_free_error(ctx->context, message);
        retval = PAM_AUTHTOK_ERR;
        goto done;
    }
    if (result_code != 0) {
        char *message;

        pamk5_debug(args, "krb5_change_password: %s", result_code_string.data);
        retval = PAM_AUTHTOK_ERR;
        message = malloc(result_string.length + result_code_string.length + 3);
        if (message == NULL)
            pamk5_error(args, "malloc failure: %s", strerror(errno));
        else {
            sprintf(message, "%.*s%s%.*s",
                    (int) result_code_string.length,
                    (char *) result_code_string.data,
                    result_string.length == 0 ? "" : ": ",
                    (int) result_string.length, (char *) result_string.data);
            pamk5_conv(args, message, PAM_ERROR_MSG, NULL);
            free(message);
        }
    }
    krb5_free_data_contents(ctx->context, &result_string);
    krb5_free_data_contents(ctx->context, &result_code_string);

done:
    /*
     * On failure, when clear_on_fail is set, we set the new password to NULL
     * so that subsequent password change PAM modules configured with
     * use_authtok will also fail.  Otherwise, since the order of the stack is
     * fixed once the pre-check function runs, subsequent modules would
     * continue even when we failed.
     */
    if (retval != PAM_SUCCESS && args->clear_on_fail) {
        if (pam_set_item(args->pamh, PAM_AUTHTOK, NULL))
            pamk5_error(args, "error clearing password");
    }
    return retval;
}


/* The main PAM interface for password changing. */
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

    /* Authenticate to the password changing service using the old password. */
    if (ctx->creds == NULL) {
        pamret = pamk5_password_auth(args, "kadmin/changepw", &ctx->creds);
        if (pamret == PAM_SERVICE_ERR || pamret == PAM_AUTH_ERR)
            pamret = PAM_AUTHTOK_RECOVER_ERR;
        if (pamret != PAM_SUCCESS)
            goto done;
    }

    /*
     * Now, get the new password and change it unless we're just doing the
     * first check.
     */
    if (!(flags & PAM_UPDATE_AUTHTOK))
        goto done;
    pamret = get_new_password(args, &pass);
    if (pamret != PAM_SUCCESS)
        goto done;
    pamret = password_change(args, pass);

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
