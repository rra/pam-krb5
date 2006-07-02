/*
 * pam_krb5_pass.c
 *
 * PAM password management functions for pam_krb5.
 *
 * Handles prompting for a new password and changing passwords, including the
 * implementation of pam_sm_chauthtok.
 */

/* Get declarations for the password functions. */
#define PAM_SM_PASSWORD

#include <com_err.h>
#include <errno.h>
#include <krb5.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include "pam_krb5.h"
#include "credlist.h"
#include "context.h"


/*
 * Utter an error message to the user that doesn't require a response.  If
 * quiet is set to true, return without doing anything.
 */
static void
krb_pass_utter(pam_handle_t *pamh, int quiet, const char *text)
{
    struct pam_message msg[1], *pmsg[1];
    struct pam_response *resp;
    struct pam_conv *conv;
    int retval;

    if (quiet)
        return;

    pmsg[0] = &msg[0];
    msg[0].msg = text;
    msg[0].msg_style = PAM_ERROR_MSG;
    retval = pam_get_item(pamh, PAM_CONV, (void *) &conv);
    if (retval == PAM_SUCCESS) {
        resp = NULL;
        retval = conv->conv(1, (const struct pam_message **) pmsg, &resp,
                            conv->appdata_ptr);
        if (resp) {
            if (resp->resp)
                free(resp->resp);
            free(resp);
        }
    }
}


/*
 * Get the new password.  Memory allocation is annoying here since we may get
 * the password from a conversation function and it's unclear whether we're
 * allowed to free that memory.  Don't do so, which may create memory leaks.
 */
static int
get_new_password(struct context *ctx, struct pam_args *args, char **pass)
{
    int pamret = PAM_SUCCESS;
    char *pass2;

    /*
     * Try to use the password from a previous module, if so configured.  Note
     * that try_first_pass and use_first_pass are equivalent for the new
     * password; we don't reprompt even if the password was rejected.
     */
    *pass = NULL;
    if (args->try_first_pass || args->use_first_pass)
        pam_get_item(ctx->pamh, PAM_AUTHTOK, (const void **) pass);

    /* Prompt for the new password if necessary. */
    if (!*pass) {
        pamret = get_user_info(ctx->pamh, "Enter new password: ",
                               PAM_PROMPT_ECHO_OFF, pass);
        if (pamret != PAM_SUCCESS) {
            debug_pam(ctx, args, "error getting new password", pamret);
            pamret = PAM_SERVICE_ERR;
            goto done;
        }
        pamret = get_user_info(ctx->pamh, "Enter it again: ",
                               PAM_PROMPT_ECHO_OFF, &pass2);
        if (pamret != PAM_SUCCESS) {
            debug_pam(ctx, args, "error getting new password", pamret);
            pamret = PAM_SERVICE_ERR;
            goto done;
        }
        if (strcmp(*pass, pass2) != 0) {
            debug(ctx, args, "new passwords don't match");
            krb_pass_utter(ctx->pamh, args->quiet, "Passwords don't match");
            *pass = NULL;
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
password_change(struct context *ctx, struct pam_args *args,
                struct credlist *clist, const char *pass)
{
    int retval = PAM_SUCCESS;
    int result_code;
    krb5_data result_code_string, result_string;

    /* Sanity check. */
    if (clist == NULL) {
        retval = PAM_AUTHTOK_ERR;
        goto done;
    }

    /* The actual change. */
    retval = krb5_change_password(ctx->context, &clist->creds, (char *) pass,
                                  &result_code, &result_code_string,
                                  &result_string);

    /* Everything from here on is just handling diagnostics and output. */
    if (retval != 0) {
        debug_krb5(ctx, args, "krb5_change_password", retval);
        krb_pass_utter(ctx->pamh, args->quiet, error_message(retval));
        retval = PAM_AUTHTOK_ERR;
        goto done;
    }
    if (result_code != 0) {
        char *message;

        debug(ctx, args, "krb5_change_password: %s", result_code_string.data);
        retval = PAM_AUTHTOK_ERR;
        message = malloc(result_string.length + result_code_string.length + 3);
        if (message == NULL)
            error(ctx, "malloc failure: %s", strerror(errno));
        else {
            sprintf(message, "%.*s%s%.*s",
                    result_code_string.length, result_code_string.data,
                    result_string.length == 0 ? "" : ": ",
                    result_string.length, result_string.data);
            krb_pass_utter(ctx->pamh, args->quiet, message);
            free(message);
        }
    }
    krb5_free_data(ctx->context, &result_string);
    krb5_free_data(ctx->context, &result_code_string);

done:
    return retval;
}


/* The main PAM interface for password changing. */
int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct context *ctx;
    struct pam_args *args;
    struct credlist *clist = NULL;
    int pamret = PAM_SUCCESS;
    int status;
    const char *tmpname;
    char *pass = NULL;

    pamret = fetch_context(pamh, &ctx);
    args = parse_args(ctx, flags, argc, argv);
    ENTRY(ctx, args, flags);

    /*
     * We don't do anything useful for the preliminary check.
     * FIXME: It would be nice to check connectivity to the KDC somehow.
     */
    if (flags & PAM_PRELIM_CHECK)
        goto done;

    /* We only support password changes. */
    if (!(flags & PAM_UPDATE_AUTHTOK)) {
        pamret = PAM_AUTHTOK_ERR;
        goto done;
    }

    /*
     * Skip root password changes on the assumption that they'll be handled by
     * some other module.  Don't tromp on pamret here.
     */
    if (args->ignore_root || args->minimum_uid > 0) {
        status = pam_get_user(pamh, &tmpname, NULL);
        if (status == PAM_SUCCESS && should_ignore_user(ctx, args, tmpname)) {
            pamret = PAM_SUCCESS;
            goto done;
        }
    }

    /*
     * pamret holds the result of fetch_context from above.  If set to
     * PAM_SUCCESS, we were able to find an existing context that we could
     * use; otherwise, we're going into this fresh and need to create a new
     * context.
     */
    if (pamret != PAM_SUCCESS) {
        pamret = new_context(pamh, &ctx);
        if (pamret != PAM_SUCCESS) {
            debug_pam(ctx, args, "creating context failed", pamret);
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
        pamret = pam_set_data(pamh, "ctx", ctx, destroy_context);
        if (pamret != PAM_SUCCESS) {
            debug_pam(ctx, args, "cannot set context data", pamret);
            pamret = PAM_AUTHTOK_ERR;
            goto done;
        }
    }

    /* Authenticate to the password changing service using the old password. */
    pamret = password_auth(ctx, args, "kadmin/changepw", &clist);
    if (pamret != PAM_SUCCESS) {
        pamret = PAM_AUTHTOK_ERR;
        goto done;
    }

    /* Now, get the new password. */
    pamret = get_new_password(ctx, args, &pass);
    if (pamret != PAM_SUCCESS)
        goto cleanup;

    /* Change it. */
    pamret = password_change(ctx, args, clist, pass);

cleanup:
    free_credlist(ctx, clist);

done:
    EXIT(ctx, args, pamret);
    free_args(args);
    return pamret;
}
