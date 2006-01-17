/*
 * pam_krb5_pass.c
 *
 * PAM password management functions for pam_krb5
 *
 */

#define PAM_SM_PASSWORD

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <krb5.h>
#include <com_err.h>
#include "pam_krb5.h"
#include "credlist.h"
#include "context.h"

/* Utter a message to the user */
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

/* Get a new password */
static int
get_new_password(struct context *ctx, char **pass)
{
	int pamret = PAM_SUCCESS;
	char *pass2;

	*pass = NULL;
	if (pam_args.try_first_pass || pam_args.use_first_pass)
		pam_get_item(ctx->pamh, PAM_AUTHTOK, (const void **) pass);

	if (!pass) {
		if ((pamret = get_user_info(ctx->pamh, "Enter new password: ", PAM_PROMPT_ECHO_OFF, pass) != PAM_SUCCESS)) { 
			dlog(ctx, "get_user_info(): %s", pam_strerror(ctx->pamh, pamret));
			pamret = PAM_SERVICE_ERR;
			goto done;
		}
		if ((pamret = get_user_info(ctx->pamh, "Enter it again: ", PAM_PROMPT_ECHO_OFF, &pass2)) != PAM_SUCCESS) {
			dlog(ctx, "get_user_info(): %s", pam_strerror(ctx->pamh, pamret));
			pamret = PAM_SERVICE_ERR;
			goto done;
		}

		if (strcmp(*pass, pass2) != 0) {
			dlog(ctx, "strcmp(): passwords not equal!");
			krb_pass_utter(ctx->pamh, pam_args.quiet, "Passwords don't match");
			*pass = NULL;
			pamret = PAM_AUTHTOK_ERR;
			goto done;
		}
	}
done:
	return pamret;
}

static int
password_change(struct context *ctx, struct credlist *clist,
		const char *pass)
{
	int retval = PAM_SUCCESS;
	int result_code;
	krb5_data result_code_string, result_string;

	if (!clist) {
		retval = PAM_AUTHTOK_ERR;
		goto done;
	}
	if ((retval = krb5_change_password(ctx->context, &clist->creds,
				       	(char *) pass, &result_code,
				       	&result_code_string, &result_string)) != 0) {
		dlog(ctx, "krb5_change_password(): %s", error_message(retval));
		krb_pass_utter(ctx->pamh, pam_args.quiet, error_message(retval));
		retval = PAM_AUTHTOK_ERR;
		goto done;
	}
	if (result_code) {
		char *message;

		dlog(ctx, "krb5_change_password() result_code_string=%s",
				result_code_string.data);
		retval = PAM_AUTHTOK_ERR;
		message = malloc(result_string.length + result_code_string.length + 3);
		if (!message)
			dlog(ctx, "malloc() failure");
		else {
			sprintf(message, "%.*s%s%.*s",
					result_code_string.length, result_code_string.data,
					result_string.length == 0 ? "" : ": ",
					result_string.length, result_string.data);
			krb_pass_utter(ctx->pamh, pam_args.quiet, message);
			free(message);
		}
	}

	if (result_string.data)
		free(result_string.data);
	if (result_code_string.data)
		free(result_code_string.data);
done:
	return retval;
}

/* Change a user's password */
int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct context *ctx = NULL;
    struct credlist *clist = NULL;

    int		pamret;
    char	*pass = NULL;

    parse_args(flags, argc, argv);
    dlog(ctx, "%s: entry", __FUNCTION__);

    if (flags & PAM_PRELIM_CHECK) /* not sure if this a right way to do it */
        return PAM_SUCCESS;
    if (!(flags & PAM_UPDATE_AUTHTOK))
	return PAM_AUTHTOK_ERR;

    pamret = fetch_context(pamh, &ctx);
    if (pamret != PAM_SUCCESS) {
        pamret = new_context(pamh, &ctx);
        if (pamret != PAM_SUCCESS) {
            if (pam_args.ignore_root && strcmp("root", ctx->name) == 0) {
                dlog(ctx, "ignoring root password change");
                pamret = PAM_SUCCESS;
            }
	} else {
	    dlog(ctx, "creating context failed");
            goto done;
	}
        pamret = pam_set_data(pamh, "ctx", ctx, destroy_context);
        if (pamret != PAM_SUCCESS) {
            dlog(ctx, "cannot set context data");
            goto done;
        }
    }

    /* Auth using old password */
    if ((pamret = password_auth(ctx, "kadmin/changepw", &clist)) != PAM_SUCCESS)
	goto done;

    /* Now get the new password */
    if ((pamret = get_new_password(ctx, &pass)) != PAM_SUCCESS)
	goto cleanup;

    /* Change it */
    pamret = password_change(ctx, clist, pass);

cleanup:
    free_credlist(ctx, clist);
done:
    dlog(ctx, "%s: exit (%s)", __FUNCTION__, pamret ? "failure" : "success");
    /* TODO: re-store ctx back into pam */
    return pamret;
}
