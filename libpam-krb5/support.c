/*
 * support.c
 *
 * Support functions for pam_krb5
 */

static const char rcsid[] = "$Id: support.c,v 1.1 2000/11/30 20:09:45 hartmans Exp $";

#include <stdio.h>	/* BUFSIZ */
#include <syslog.h>	/* syslog */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <krb5.h>
#include "pam_krb5.h"

/*
 * Get info from the user. Disallow null responses (regardless of flags).
 * response gets allocated and filled in on successful return. Caller
 * is responsible for freeing it.
 */
int
get_user_info(pam_handle_t *pamh, char *prompt, int type, char **response)
{
    int pamret;
    struct pam_message	msg, *pmsg;
    struct pam_response	*resp = NULL;
    struct pam_conv	*conv;

    if (pamret = pam_get_item(pamh, PAM_CONV, (void **) &conv))
	return pamret;

    /* set up conversation call */
    pmsg = &msg;
    msg.msg_style = type;
    msg.msg = prompt;

    if (pamret = conv->conv(1, &pmsg, &resp, conv->appdata_ptr))
	return pamret;

    /* Caller should ignore errors for non-response conversations */
    if (!resp)
	return PAM_CONV_ERR;

    if (!(resp->resp && resp->resp[0])) {
	free(resp);
	return PAM_AUTH_ERR;
    }

    *response = resp->resp;
    free(resp);
    return pamret;
}


krb5_error_code
pam_prompter(krb5_context context, void *data, const char *name,
	     const char *banner, int num_prompts, krb5_prompt prompts[])
{
    int		pam_prompts = num_prompts;
    int		pamret, i;

    struct pam_message	*msg;
    struct pam_response	*resp = NULL;
    struct pam_conv	*conv;
    pam_handle_t	*pamh = (pam_handle_t *) data;

    if (pamret = pam_get_item(pamh, PAM_CONV, (void **) &conv))
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
	strcpy(msg[pam_prompts].msg, name);
	msg[pam_prompts].msg_style = PAM_TEXT_INFO;
	pam_prompts++;
    }

    if (banner) {
	msg[pam_prompts].msg = malloc(strlen(banner) + 1);
	if (!msg[pam_prompts].msg)
	    goto cleanup;
	strcpy(msg[pam_prompts].msg, banner);
	msg[pam_prompts].msg_style = PAM_TEXT_INFO;
	pam_prompts++;
    }

    for (i = 0; i < num_prompts; i++) {
	msg[pam_prompts].msg = malloc(strlen(prompts[i].prompt) + 3);
	if (!msg[pam_prompts].msg)
	    goto cleanup;
	sprintf(msg[pam_prompts].msg, "%s: ", prompts[i].prompt);
	msg[pam_prompts].msg_style = prompts[i].hidden ? PAM_PROMPT_ECHO_OFF
						       : PAM_PROMPT_ECHO_ON;
	pam_prompts++;
    }

    if (pamret = conv->conv(pam_prompts, &msg, &resp, conv->appdata_ptr))
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
	memcpy(prompts[i].reply->data, resp[pam_prompts].resp, len);
	prompts[i].reply->length = len;
    }

cleanup:
    /* pam_prompts is correct at this point */

    for (i = 0; i < pam_prompts; i++) {
	if (msg[i].msg)
	    free(msg[i].msg);
    }
    free(msg);

    if (resp) {
	for (i = 0; i < pam_prompts; i++) {
	    /*
	     * Note that PAM is underspecified wrt free()'ing resp[i].resp.
	     * It's not clear if I should free it, or if the application
	     * has to. Therefore most (all?) apps won't free() it, and I
	     * can't either, as I am not sure it was malloc()'d. All PAM
	     * implementations I've seen leak memory here. Not so bad, IFF
	     * you fork/exec for each PAM authentication (as is typical).
	     */
#if 0
	    if (resp[i].resp)
		free(resp[i].resp);
#endif /* 0 */
	}
	/* This does not lose resp[i].resp if the application saved a copy. */
	free(resp);
    }

    return (pamret ? KRB5KRB_ERR_GENERIC : 0);
}


/*
 * This routine with some modification is from the MIT V5B6 appl/bsd/login.c
 *
 * Verify the Kerberos ticket-granting ticket just retrieved for the
 * user.  If the Kerberos server doesn't respond, assume the user is
 * trying to fake us out (since we DID just get a TGT from what is
 * supposedly our KDC).  If the host/<host> service is unknown (i.e.,
 * the local keytab doesn't have it), let her in.
 *
 * Returns 1 for confirmation, -1 for failure, 0 for uncertainty.
 */
int
verify_krb_v5_tgt(krb5_context context, krb5_ccache ccache, int debug)
{
    char		phost[BUFSIZ];
    krb5_error_code	retval;
    krb5_principal	princ;
    krb5_keyblock *	keyblock = 0;
    krb5_data		packet;
    krb5_auth_context	auth_context = NULL;
    krb5_keytab		keytab = NULL;
    char *		kt_name = NULL;

    packet.data = 0;

    /*
     * Get the server principal for the local host.
     * (Use defaults of "host" and canonicalized local name.)
     */
    if (retval = krb5_sname_to_principal(context, NULL, NULL,
					 KRB5_NT_SRV_HST, &princ)) {
	if (debug)
	    syslog(LOG_DEBUG, "pam_krb5: verify_krb_v5_tgt(): %s: %s",
		   "krb5_sname_to_principal()", error_message(retval));
	return -1;
    }

    /* Extract the name directly. */
    strncpy(phost, krb5_princ_component(c, princ, 1)->data, BUFSIZ);
    phost[BUFSIZ - 1] = '\0';

    /*
     * Do we have host/<host> keys?
     * (use default/configured keytab, kvno IGNORE_VNO to get the
     * first match, and enctype is currently ignored anyhow.)
     */
    if (retval = krb5_kt_read_service_key(context, NULL, princ, 0,
					  ENCTYPE_DES_CBC_MD5, &keyblock)) {
	/* Keytab or service key does not exist */
	if (debug)
	    syslog(LOG_DEBUG, "pam_krb5: verify_krb_v5_tgt(): %s: %s",
		   "krb5_kt_read_service_key()", error_message(retval));
	retval = 0;
	goto cleanup;
    }
    if (keyblock)
	krb5_free_keyblock(context, keyblock);

    /* Talk to the kdc and construct the ticket. */
    retval = krb5_mk_req(context, &auth_context, 0, "host", phost,
			 NULL, ccache, &packet);
    if (auth_context) {
	krb5_auth_con_free(context, auth_context);
	auth_context = NULL; /* setup for rd_req */
    }
    if (retval) {
	if (debug)
	    syslog(LOG_DEBUG, "pam_krb5: verify_krb_v5_tgt(): %s: %s",
		   "krb5_mk_req()", error_message(retval));
	retval = -1;
	goto cleanup;
    }

    /* Try to use the ticket. */
    retval = krb5_rd_req(context, &auth_context, &packet, princ,
			 NULL, NULL, NULL);
    if (retval) {
	if (debug)
	    syslog(LOG_DEBUG, "pam_krb5: verify_krb_v5_tgt(): %s: %s",
		   "krb5_rd_req()", error_message(retval));
	retval = -1;
    } else {
	retval = 1;
    }

cleanup:
    if (packet.data)
	krb5_free_data_contents(context, &packet);
    krb5_free_principal(context, princ);
    return retval;

}


/* Free the memory for cache_name. Called by pam_end() */
void
cleanup_cache(pam_handle_t *pamh, void *data, int pam_end_status)
{
    krb5_context	pam_context;
    krb5_ccache		ccache;

    if (krb5_init_context(&pam_context))
	return;

    ccache = (krb5_ccache) data;
    (void) krb5_cc_destroy(pam_context, ccache);
    krb5_free_context(pam_context);
}
