/*
 * pam_krb5_pass.c
 *
 * PAM password management functions for pam_krb5
 *
 */

static const char rcsid[] = "$Id: pam_krb5_pass.c,v 1.2 2000/11/30 20:40:37 hartmans Exp $";

#include <errno.h>
#include <stdio.h>	/* sprintf */
#include <stdlib.h>	/* malloc */
#include <syslog.h>	/* syslog */
#include <string.h>	/* strcmp, strlen, memset */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <krb5.h>
#include <com_err.h>
#include "pam_krb5.h"

/* A useful logging macro */
#define DLOG(error_func, error_msg) \
if (debug) \
    syslog(LOG_DEBUG, "pam_krb5: pam_sm_chauthtok(%s %s): %s: %s", \
	   service, name, error_func, error_msg)

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
    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
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

/* Change a user's password */
int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    krb5_error_code	krbret;
    krb5_context	pam_context;
    krb5_creds		creds;
    krb5_principal	princ;
    krb5_get_init_creds_opt opts;

    int		result_code;
    krb5_data	result_code_string, result_string;

    int		pamret, i;
    char	*name, *service = NULL, *pass = NULL, *pass2, *message;
    char	*princ_name = NULL;
    char	*prompt = NULL;

    int debug = 0, quiet = 0;
    int try_first_pass = 0, use_first_pass = 0;

    
    if (flags & PAM_PRELIM_CHECK) /* not sure if this a right way to do it */
        return PAM_SUCCESS;
    if (!(flags & PAM_UPDATE_AUTHTOK))
	return PAM_AUTHTOK_ERR;
    if (flags & PAM_SILENT)
        quiet++;

    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "debug") == 0)
	    debug = 1;
	else if (strcmp(argv[i], "try_first_pass") == 0)
	    try_first_pass = 1;
	else if (strcmp(argv[i], "use_first_pass") == 0)
	    use_first_pass = 1;
    }

    /* Get username */
    if ((pam_get_item(pamh, PAM_USER, (const void **) &name)) != 0) {
	return PAM_SERVICE_ERR;
    }

    /* Get service name */
    (void) pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
    if (!service)
	service = "unknown";

    DLOG("entry", "");

    if ((krbret = krb5_init_context(&pam_context)) != 0) {
	DLOG("krb5_init_context()", error_message(krbret));
	return PAM_SERVICE_ERR;
    }

    if ((krbret = krb5_init_context(&pam_context)) != 0) {
	DLOG("krb5_init_context()", error_message(krbret));
	return PAM_SERVICE_ERR;
    }
    krb5_get_init_creds_opt_init(&opts);
    memset(&creds, 0, sizeof(krb5_creds));

    /* Get principal name */
    if ((krbret = krb5_parse_name(pam_context, name, &princ)) != 0) {
	DLOG("krb5_parse_name()", error_message(krbret));
	pamret = PAM_USER_UNKNOWN;
	goto cleanup3;
    }

    /* Now convert the principal name into something human readable */
    if ((krbret = krb5_unparse_name(pam_context, princ, &princ_name)) != 0) {
	DLOG("krb5_unparse_name()", error_message(krbret));
	pamret = PAM_SERVICE_ERR;
	goto cleanup2;
    }

    /* Get password */
    prompt = malloc(16 + strlen(princ_name));
    if (!prompt) {
	DLOG("malloc()", "failure");
	pamret = PAM_BUF_ERR;
	goto cleanup2;
    }
    (void) sprintf(prompt, "Password for %s: ", princ_name);

    if (try_first_pass || use_first_pass)
	(void) pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **) &pass);

get_pass:
    if (!pass) {
	try_first_pass = 0;
	if ((pamret = get_user_info(pamh, prompt, PAM_PROMPT_ECHO_OFF, 
	  &pass)) != 0) {
	    DLOG("get_user_info()", pam_strerror(pamh, pamret));
	    pamret = PAM_SERVICE_ERR;
	    goto cleanup2;
	}
	/* We have to free pass. */
	if ((pamret = pam_set_item(pamh, PAM_AUTHTOK, pass)) != 0) {
	    DLOG("pam_set_item()", pam_strerror(pamh, pamret));
	    free(pass);
	    pamret = PAM_SERVICE_ERR;
	    goto cleanup2;
	}
	free(pass);
	/* Now we get it back from the library. */
	(void) pam_get_item(pamh, PAM_AUTHTOK, (const void **) &pass);
    }

    if ((krbret = krb5_get_init_creds_password(pam_context, &creds, princ, 
      pass, pam_prompter, pamh, 0, "kadmin/changepw", &opts)) != 0) {
	DLOG("krb5_get_init_creds_password()", error_message(krbret));
	if (try_first_pass && krbret == KRB5KRB_AP_ERR_BAD_INTEGRITY) {
	    pass = NULL;
	    goto get_pass;
	}
	pamret = PAM_AUTH_ERR;
	goto cleanup2;
    }

    /* Now get the new password */
    pass = NULL;
    if (try_first_pass || use_first_pass)
        (void) pam_get_item(pamh, PAM_AUTHTOK, (const void **) &pass);
    if (!pass) {
        free(prompt);
        prompt = "Enter new password: ";
        if ((pamret = get_user_info(pamh, prompt, PAM_PROMPT_ECHO_OFF, &pass)) 
          != 0) {
            DLOG("get_user_info()", pam_strerror(pamh, pamret));
            prompt = NULL;
            pamret = PAM_SERVICE_ERR;
            goto cleanup;
        }
        prompt = "Enter it again: ";
        if ((pamret = get_user_info(pamh, prompt, PAM_PROMPT_ECHO_OFF,
          &pass2)) != 0) {
            DLOG("get_user_info()", pam_strerror(pamh, pamret));
            prompt = NULL;
            pamret = PAM_SERVICE_ERR;
            goto cleanup;
        }
        prompt = NULL;

        if (strcmp(pass, pass2) != 0) {
            DLOG("strcmp()", "passwords not equal");
            krb_pass_utter(pamh, quiet, "Passwords don't match");
            pamret = PAM_AUTHTOK_ERR;
            goto cleanup;
        }
    }

    /* Change it */
    pamret = PAM_SUCCESS;
    if ((krbret = krb5_change_password(pam_context, &creds, pass,
      &result_code, &result_code_string, &result_string)) != 0) {
	DLOG("krb5_change_password()", error_message(krbret));
        krb_pass_utter(pamh, quiet, error_message(krbret));
	pamret = PAM_AUTHTOK_ERR;
	goto cleanup;
    }
    if (result_code) {
	DLOG("krb5_change_password() result_code_string=%s",
             result_code_string.data);
	pamret = PAM_AUTHTOK_ERR;
        message = malloc(result_string.length + result_code_string.length + 3);
        if (!message) {
            DLOG("malloc()", "failure");
        } else {
            sprintf(message, "%.*s%s%.*s",
                    result_code_string.length, result_code_string.data,
                    result_string.length == 0 ? "" : ": ",
                    result_string.length, result_string.data);
            krb_pass_utter(pamh, quiet, message);
            free(message);
        }
	goto cleanup;
    }

    if (result_string.data)
	free(result_string.data);
    if (result_code_string.data)
	free(result_code_string.data);

cleanup:
    krb5_free_cred_contents(pam_context, &creds);
cleanup2:
    krb5_free_principal(pam_context, princ);
cleanup3:
    if (prompt)
	free(prompt);
    if (princ_name)
	free(princ_name);

    krb5_free_context(pam_context);
    DLOG("exit", pamret ? "failure" : "success");
    return pamret;
}
