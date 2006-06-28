#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <krb5.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "pam_krb5.h"

const char *
compat_princ_component(krb5_context context, krb5_principal princ, int n)
{
	return krb5_princ_component(context, princ, n)->data;
}

void
compat_free_data_contents(krb5_context context, krb5_data *data)
{
	krb5_free_data_contents(context, data);
}

krb5_error_code
compat_cc_next_cred(krb5_context context, const krb5_ccache id, 
    krb5_cc_cursor *cursor, krb5_creds *creds)
{
	return krb5_cc_next_cred(context, id, cursor, creds);
}

/*
 * There are a lot of structures and different layers of code at work here,
 * making this code quite confusing.  This function is a prompter function to
 * pass into the Kerberos library, in particular krb5_get_init_creds_password.
 * It is used by the Kerberos library to prompt for a password if need be, and
 * also to prompt for password changes if the password was expired.
 *
 * The purpose of this function is to serve as glue between the Kerberos
 * library and the application (by way of the PAM glue).  PAM expects us to
 * pass back to the conversation function an array of prompts and receive from
 * the application an array of responses to those prompts.  We pass the
 * application an array of struct pam_message pointers, and the application
 * passes us an array of struct pam_response pointers.
 *
 * Kerberos, meanwhile, passes us in an array of krb5_prompt structs.  This
 * struct contains the prompt, a flag saying whether to suppress echoing of
 * what the user types for that prompt, and a buffer into which to store the
 * response.
 *
 * Therefore, what we're doing here is copying the prompts from the
 * krb5_prompt structs into pam_message structs, calling the conversation
 * function, and then copying the responses back out of pam_response structs
 * into the krb5_prompt structs to return to the Kerberos library.
 */
static krb5_error_code
mit_pam_prompter(krb5_context context, void *data, const char *name,
	     const char *banner, int num_prompts, krb5_prompt prompts[])
{
    int		pam_prompts = num_prompts;
    int		pamret, i;

    struct pam_message	*msg;
    struct pam_response	*resp = NULL;
    struct pam_conv	*conv;
    pam_handle_t	*pamh = (pam_handle_t *) data;

    if ((pamret = pam_get_item(pamh, PAM_CONV, (void *) &conv)) != 0)
	return KRB5KRB_ERR_GENERIC;

    if (name)
	pam_prompts++;

    if (banner)
	pam_prompts++;

    msg = calloc(sizeof(struct pam_message) * pam_prompts, 1);
    if (!msg)
	return ENOMEM;

    /* Now use pam_prompts as an index */
    pam_prompts = 0;

    /* Sigh. malloc all the prompts. */
    if (name) {
	msg[pam_prompts].msg = malloc(strlen(name) + 1);
	if (!msg[pam_prompts].msg)
	    goto cleanup;
	strcpy((char *) msg[pam_prompts].msg, name);
	msg[pam_prompts].msg_style = PAM_TEXT_INFO;
	pam_prompts++;
    }

    if (banner) {
	msg[pam_prompts].msg = malloc(strlen(banner) + 1);
	if (!msg[pam_prompts].msg)
	    goto cleanup;
	strcpy((char *) msg[pam_prompts].msg, banner);
	msg[pam_prompts].msg_style = PAM_TEXT_INFO;
	pam_prompts++;
    }

    for (i = 0; i < num_prompts; i++) {
	msg[pam_prompts].msg = malloc(strlen(prompts[i].prompt) + 3);
	if (!msg[pam_prompts].msg)
	    goto cleanup;
	sprintf((char *) msg[pam_prompts].msg, "%s: ", prompts[i].prompt);
	msg[pam_prompts].msg_style = prompts[i].hidden ? PAM_PROMPT_ECHO_OFF
						       : PAM_PROMPT_ECHO_ON;
	pam_prompts++;
    }

    if ((pamret = conv->conv(pam_prompts, (const struct pam_message **) &msg, 
      &resp, conv->appdata_ptr)) != 0)
	goto cleanup;

    if (!resp)
	goto cleanup;

    /* Reuse pam_prompts as a starting index */
    pam_prompts = 0;
    if (name)
	pam_prompts++;
    if (banner)
	pam_prompts++;

    for (i = 0; i < num_prompts; i++, pam_prompts++) {
	register int len;
	if (!resp[pam_prompts].resp) {
	    pamret = PAM_AUTH_ERR;
	    goto cleanup;
	}
	len = strlen(resp[pam_prompts].resp); /* Help out the compiler */
	if (len > prompts[i].reply->length) {
	    pamret = PAM_AUTH_ERR;
	    goto cleanup;
	}

        /*
         * The trailing nul is not included in length, but other applications
         * expect it to be there.  Therefore, we copy one more byte than the
         * actual length of the password, but set length to just the length of
         * the password.
         */
	memcpy(prompts[i].reply->data, resp[pam_prompts].resp, len + 1);
	prompts[i].reply->length = len;
    }

cleanup:
    /* pam_prompts is correct at this point */

    for (i = 0; i < pam_prompts; i++) {
	if (msg[i].msg)
	    free((char *) msg[i].msg);
    }
    free(msg);

    /*
     * Note that PAM is underspecified with respect to freeing resp[i].resp.
     * It's not clear if I should free it, or if the application has to.
     * Therefore most (all?) apps won't free it, and I can't either, as I am
     * not sure it was malloced.  All PAM implementations I've seen leak
     * memory here.  Not so bad, IFF you fork/exec for each PAM authentication
     * (as is typical).
     */
    if (resp)
	free(resp);

    return (pamret ? KRB5KRB_ERR_GENERIC : 0);
}

krb5_prompter_fct pam_prompter = mit_pam_prompter;
