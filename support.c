/*
 * support.c
 *
 * Support functions for pam_krb5
 */

static const char rcsid[] = "$Id: support.c,v 1.2 2000/11/30 20:40:37 hartmans Exp $";

#include <errno.h>
#include <stdio.h>	/* BUFSIZ */
#include <stdlib.h>	/* malloc */
#include <string.h>	/* strncpy */
#include <syslog.h>	/* syslog */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <krb5.h>
#include <com_err.h>
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
    struct pam_message	msg;
    const struct pam_message *pmsg;
    struct pam_response	*resp = NULL;
    struct pam_conv	*conv;

    if ((pamret = pam_get_item(pamh, PAM_CONV, (const void **) &conv)) != 0)
	return pamret;

    /* set up conversation call */
    pmsg = &msg;
    msg.msg_style = type;
    msg.msg = prompt;

    if ((pamret = conv->conv(1, &pmsg, &resp, conv->appdata_ptr)) != 0)
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

    packet.data = 0;

    /*
     * Get the server principal for the local host.
     * (Use defaults of "host" and canonicalized local name.)
     */
    if ((retval = krb5_sname_to_principal(context, NULL, NULL, KRB5_NT_SRV_HST,
      &princ)) != 0) {
	if (debug)
	    syslog(LOG_DEBUG, "pam_krb5: verify_krb_v5_tgt(): %s: %s",
		   "krb5_sname_to_principal()", error_message(retval));
	return -1;
    }

    /* Extract the name directly. */
    strncpy(phost, compat_princ_component(context, princ, 1), BUFSIZ);
    phost[BUFSIZ - 1] = '\0';

    /*
     * Do we have host/<host> keys?
     * (use default/configured keytab, kvno IGNORE_VNO to get the
     * first match, and enctype is currently ignored anyhow.)
     */
    if ((retval = krb5_kt_read_service_key(context, NULL, princ, 0,
      ENCTYPE_DES_CBC_MD5, &keyblock)) != 0) {
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
	compat_free_data_contents(context, &packet);
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
