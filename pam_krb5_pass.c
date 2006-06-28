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
get_new_password(struct context *ctx, struct pam_args *args, char **pass)
{
	int pamret = PAM_SUCCESS;
	char *pass2;

	*pass = NULL;
	if (args->try_first_pass || args->use_first_pass)
		pam_get_item(ctx->pamh, PAM_AUTHTOK, (const void **) pass);

	if (!*pass) {
		if ((pamret = get_user_info(ctx->pamh, "Enter new password: ", PAM_PROMPT_ECHO_OFF, pass) != PAM_SUCCESS)) { 
                    dlog(ctx, args, "get_user_info(): %s", pam_strerror(ctx->pamh, pamret));
                    pamret = PAM_SERVICE_ERR;
                    goto done;
		}
		if ((pamret = get_user_info(ctx->pamh, "Enter it again: ", PAM_PROMPT_ECHO_OFF, &pass2)) != PAM_SUCCESS) {
                    dlog(ctx, args, "get_user_info(): %s", pam_strerror(ctx->pamh, pamret));
                    pamret = PAM_SERVICE_ERR;
                    goto done;
		}

		if (strcmp(*pass, pass2) != 0) {
                    dlog(ctx, args, "strcmp(): passwords not equal!");
                    krb_pass_utter(ctx->pamh, args->quiet, "Passwords don't match");
                    *pass = NULL;
                    pamret = PAM_AUTHTOK_ERR;
                    goto done;
		}
	}
done:
	return pamret;
}

static int
password_change(struct context *ctx, struct pam_args *args,
                struct credlist *clist, const char *pass)
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
            dlog(ctx, args, "krb5_change_password(): %s", error_message(retval));
            krb_pass_utter(ctx->pamh, args->quiet, error_message(retval));
            retval = PAM_AUTHTOK_ERR;
            goto done;
	}
	if (result_code) {
		char *message;

		dlog(ctx, args, "krb5_change_password() result_code_string=%s",
				result_code_string.data);
		retval = PAM_AUTHTOK_ERR;
		message = malloc(result_string.length + result_code_string.length + 3);
		if (!message)
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
    struct context *ctx;
    struct pam_args *args;
    struct credlist *clist = NULL;

    int		pamret = PAM_SUCCESS;
    const char	*tmpname;
    char	*pass = NULL;

    pamret = fetch_context(pamh, &ctx);
    args = parse_args(ctx, flags, argc, argv);
    dlog(ctx, args, "%s: entry (flags %d)", __FUNCTION__, flags);

    /* We don't do anything useful for the preliminary check. */
    if (flags & PAM_PRELIM_CHECK)
	goto done;

    if (!(flags & PAM_UPDATE_AUTHTOK)) {
	pamret = PAM_AUTHTOK_ERR;
	goto done;
    }

    if (args->ignore_root) {
	pamret = pam_get_user(pamh, &tmpname, NULL);
	if (pamret == PAM_SUCCESS && strcmp("root", tmpname) == 0) {
	    dlog(ctx, args, "ignoring root password change");
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
	    dlog(ctx, args, "creating context failed (%d)", pamret);
	    pamret = PAM_AUTHTOK_ERR;
	    goto done;
	}
	pamret = pam_set_data(pamh, "ctx", ctx, destroy_context);
	if (pamret != PAM_SUCCESS) {
	    dlog(ctx, args, "cannot set context data");
	    pamret = PAM_AUTHTOK_ERR;
	    goto done;
	}
    }

    /* Auth using old password */
    pamret = password_auth(ctx, args, "kadmin/changepw", &clist);
    if (pamret != PAM_SUCCESS) {
	pamret = PAM_AUTHTOK_ERR;
	goto done;
    }

    /* Now get the new password */
    if ((pamret = get_new_password(ctx, args, &pass)) != PAM_SUCCESS)
	goto cleanup;

    /* Change it */
    pamret = password_change(ctx, args, clist, pass);

cleanup:
    free_credlist(ctx, clist);

done:
    dlog(ctx, args, "%s: exit (%s)", __FUNCTION__, pamret ? "failure" : "success");
    /* TODO: re-store ctx back into pam */
    free_args(args);
    return pamret;
}
