/*
 * Kerberos password changing.
 *
 * Copyright 2005, 2006, 2007, 2008, 2009 Russ Allbery <rra@stanford.edu>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/pam.h>

#include <errno.h>
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal.h>

/* Solaris 8 has deficient PAM. */
#ifndef PAM_AUTHTOK_RECOVER_ERR
# define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_ERR
#endif


/*
 * Get the new password.  Store it in PAM_AUTHTOK if we obtain it and verify
 * it successfully and return it in the pass parameter.  If pass is set to
 * NULL, only store the new password in PAM_AUTHTOK.
 *
 * Returns a PAM error code, usually either PAM_AUTHTOK_ERR or PAM_SUCCESS.
 */
int
pamk5_password_prompt(struct pam_args *args, char **pass)
{
    int pamret = PAM_AUTHTOK_ERR;
    char *pass1 = NULL;
    char *pass2;
    PAM_CONST void *tmp;

    /* Use the password from a previous module, if so configured. */
    if (pass != NULL)
        *pass = NULL;
    if (args->use_authtok) {
        pamret = pam_get_item(args->pamh, PAM_AUTHTOK, &tmp);
        if (tmp == NULL) {
            pamk5_debug_pam(args, pamret, "no stored password");
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
        pass1 = strdup((const char *) tmp);
    }

    /* Prompt for the new password if necessary. */
    if (pass1 == NULL) {
        pamret = pamk5_get_password(args, "Enter new", &pass1);
        if (pamret != PAM_SUCCESS) {
            pamk5_debug_pam(args, pamret, "error getting new password");
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
        pamret = pamk5_get_password(args, "Retype new", &pass2);
        if (pamret != PAM_SUCCESS) {
            pamk5_debug_pam(args, pamret, "error getting new password");
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
        if (strcmp(pass1, pass2) != 0) {
            pamk5_debug(args, "new passwords don't match");
            pamk5_conv(args, "Passwords don't match", PAM_ERROR_MSG, NULL);
            memset(pass1, 0, strlen(pass1));
            free(pass1);
            memset(pass2, 0, strlen(pass2));
            free(pass2);
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
        memset(pass2, 0, strlen(pass2));
        free(pass2);

        /* Save the new password for other modules. */
        pamret = pam_set_item(args->pamh, PAM_AUTHTOK, pass1);
        if (pamret != PAM_SUCCESS) {
            pamk5_err_pam(args, pamret, "error storing password");
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
    }
    if (pass != NULL)
        *pass = pass1;

done:
    return pamret;
}


/*
 * We've obtained credentials for the password changing interface and gotten
 * the new password, so do the work of actually changing the password.
 */
static int
change_password(struct pam_args *args, const char *pass)
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
        pamk5_debug_krb5(args, retval, "krb5_change_password failed");
        message = pamk5_compat_get_error(ctx->context, retval);
        pamk5_conv(args, message, PAM_ERROR_MSG, NULL);
        pamk5_compat_free_error(ctx->context, message);
        retval = PAM_AUTHTOK_ERR;
        goto done;
    }
    if (result_code != 0) {
        char *message;
        int status;

        pamk5_debug(args, "krb5_change_password: %s",
                    (char *) result_code_string.data);
        retval = PAM_AUTHTOK_ERR;
        status = asprintf(&message, "%.*s%s%.*s",
                          (int) result_code_string.length,
                          (char *) result_code_string.data,
                          result_string.length == 0 ? "" : ": ",
                          (int) result_string.length,
                          (char *) result_string.data);
        if (status < 0)
            pamk5_crit(args, "asprintf failed: %s", strerror(errno));
        else {
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
            pamk5_err(args, "error clearing password");
    }
    return retval;
}


/*
 * Change a user's password.  Returns a PAM status code for success or
 * failure.  This does the work of pam_sm_chauthtok, but also needs to be
 * called from pam_sm_authenticate if we're working around a library that
 * can't handle password change during authentication.
 *
 * If the second argument is true, only do the authentication without actually
 * doing the password change (PAM_PRELIM_CHECK).
 */
int
pamk5_password_change(struct pam_args *args, int only_auth)
{
    struct context *ctx = args->ctx;
    int pamret = PAM_SUCCESS;
    char *pass = NULL;

    /*
     * Authenticate to the password changing service using the old password.
     */
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
    if (only_auth)
        goto done;
    pamret = pamk5_password_prompt(args, &pass);
    if (pamret != PAM_SUCCESS)
        goto done;
    pamret = change_password(args, pass);
    if (pamret == PAM_SUCCESS)
        pam_syslog(args->pamh, LOG_INFO, "user %s changed Kerberos password",
                   ctx->name);

done:
    if (pass != NULL) {
        memset(pass, 0, strlen(pass));
        free(pass);
    }
    return pamret;
}
