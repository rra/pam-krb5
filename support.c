/*
 * support.c
 *
 * Support functions for pam_krb5
 */

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <krb5.h>
#include <com_err.h>
#include "pam_krb5.h"
#include "credlist.h"

struct pam_args pam_args;

void
parse_args(int flags, int argc, const char **argv)
{
	int i;

	memset(&pam_args, 0, sizeof(pam_args));
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			pam_args.debug = 1;
		else if (strcmp(argv[i], "try_first_pass") == 0)
			pam_args.try_first_pass = 1;
		else if (strcmp(argv[i], "use_first_pass") == 0)
			pam_args.use_first_pass = 1;
		else if (strcmp(argv[i], "forwardable") == 0)
			pam_args.forwardable = 1;
		else if (strcmp(argv[i], "reuse_ccache") == 0)
			pam_args.reuse_ccache = 1;
		else if (strcmp(argv[i], "no_ccache") == 0)
			pam_args.no_ccache = 1;
		else if (strcmp(argv[i], "ignore_root") == 0)
			pam_args.ignore_root = 1;
		else if (strncmp(argv[i], "ccache=", 7) == 0)
			pam_args.ccache = (char *) &argv[i][7];
		else if (strncmp(argv[i], "ccache_dir=", 11) == 0)
			pam_args.ccache_dir = (char *) &argv[i][11];
		else if (strcmp(argv[i], "search_k5login") == 0)
			pam_args.search_k5login = 1;
	}
	
	if (flags & PAM_SILENT)
		pam_args.quiet++;
	if (!pam_args.ccache_dir)
		pam_args.ccache_dir = "/tmp";
}

/*
 * Used to support trying each principal in the .k5login file.  Read through
 * each line that parses correctly as a principal and use the provided
 * password to try to authenticate as that user.  If at any point we succeed,
 * fill out creds, set princ to the successful principal in the context, and
 * return PAM_SUCCESS.  Otherwise, return PAM_AUTH_ERR for a general
 * authentication error or PAM_SERVICE_ERR for a system error.  If
 * PAM_AUTH_ERR is returned, retval will be filled in with the Kerberos
 * error if available, 0 otherwise.
 */
static int
k5login_password_auth(struct context *ctx, krb5_creds *creds,
                      krb5_get_init_creds_opt *opts, char *in_tkt_service,
                      char *pass, int *retval)
{
    char *filename;
    char line[BUFSIZ];
    size_t len;
    FILE *k5login;
    struct passwd *pwd;
    struct stat st;
    int k5_errno;
    krb5_principal princ;

    /* Assume no Kerberos error. */
    *retval = 0;

    /* C sucks at string manipulation.  Generate the filename for the user's
       .k5login file. */
    pwd = getpwnam(ctx->name);
    if (pwd == NULL)
        return PAM_AUTH_ERR;
    len = strlen(pwd->pw_dir) + strlen("/.k5login");
    filename = malloc(len + 1);
    if (filename == NULL)
        return PAM_SERVICE_ERR;
    strncpy(filename, pwd->pw_dir, len);
    filename[len] = '\0';
    strncat(filename, "/.k5login", len - strlen(pwd->pw_dir));

    /* If there is no file, do this the easy way. */
    if (access(filename, R_OK) != 0) {
        k5_errno = krb5_parse_name(ctx->context, ctx->name, &ctx->princ);
        if (k5_errno != 0) {
            dlog(ctx, "krb5_parse_name(): %s", error_message(k5_errno));
            return PAM_SERVICE_ERR;
        }
        *retval = krb5_get_init_creds_password(ctx->context, creds,
                     ctx->princ, pass, pam_prompter, ctx->pamh, 0,
                     in_tkt_service, opts);
        return (*retval == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
    }

    /* Make sure the ownership on .k5login is okay.  The user must own their
       own .k5login or it must be owned by root. */
    k5login = fopen(filename, "r");
    free(filename);
    if (k5login == NULL)
        return PAM_AUTH_ERR;
    if (fstat(fileno(k5login), &st) != 0)
        goto fail;
    if (st.st_uid != 0 && (st.st_uid != pwd->pw_uid))
        goto fail;

    /* Parse the .k5login file.  Ignore any lines that are too long or that
       don't parse into a Kerberos principal. */
    while (fgets(line, BUFSIZ, k5login) != NULL) {
        len = strlen(line);
        if (line[len - 1] != '\n') {
            while (fgets(line, BUFSIZ, k5login) != NULL) {
                len = strlen(line);
                if (line[len - 1] == '\n')
                    break;
            }
            continue;
        }
        line[len - 1] = '\0';
        k5_errno = krb5_parse_name(ctx->context, line, &princ);
        if (k5_errno != 0)
            continue;

        /* Now, attempt to authenticate as that user. */
        *retval = krb5_get_init_creds_password(ctx->context, creds,
                     princ, pass, pam_prompter, ctx->pamh, 0,
                     in_tkt_service, opts);

        /* If that worked, update ctx->princ and return success.  Otherwise,
           continue on to the next line. */
        if (*retval == 0) {
            if (ctx->princ)
                krb5_free_principal(ctx->context, ctx->princ);
            ctx->princ = princ;
            fclose(k5login);
            return PAM_SUCCESS;
        }
        krb5_free_principal(ctx->context, princ);
    }

fail:
    fclose(k5login);
    return PAM_AUTH_ERR;
}

/*
 * Prompt the user for a password; authenticate the password with the KDC.
 * If correct, fill in creds with TGT magic. */
int
password_auth(struct context *ctx, char *in_tkt_service,
		struct credlist **credlist)
{
	krb5_get_init_creds_opt opts;
	krb5_creds creds;
	int retval;
	char *pass = NULL;
	int retry;
	int success;

	new_credlist(ctx, credlist);
	memset(&creds, 0, sizeof(krb5_creds));
	krb5_get_init_creds_opt_init(&opts);
	if (pam_args.forwardable)
		krb5_get_init_creds_opt_set_forwardable(&opts, 1);

	if (pam_args.ignore_root && strcmp("root", ctx->name) == 0) {
		dlog(ctx, "ignoring root user login");
		retval = PAM_SERVICE_ERR;
		goto done;
	}

	retry = pam_args.try_first_pass ? 1 : 0;
	if (pam_args.try_first_pass || pam_args.use_first_pass)
		pam_get_item(ctx->pamh, PAM_AUTHTOK, (void *) &pass);

	/* If try_first_pass or use_first_pass is set, grab the old password
	 * (if set) instead of prompting.  If try_first_pass is set, and
	 * the old password doesn't work, prompt for the password (loop). */
	do {
		if (!pass) {
			retry = 0;
			if ((retval = get_user_info(ctx->pamh, "Password: ", PAM_PROMPT_ECHO_OFF, &pass)) != PAM_SUCCESS) {
				dlog(ctx, "get_user_info(): %s", pam_strerror(ctx->pamh, retval));
				retval = PAM_SERVICE_ERR;
				goto done;
			}

			/* set this for the next pam module's try_first_pass */
			retval = pam_set_item(ctx->pamh, PAM_AUTHTOK, pass);
			free(pass);
			if (retval != PAM_SUCCESS) {
				dlog(ctx, "pam_set_item(): %s", pam_strerror(ctx->pamh, retval));
				retval = PAM_SERVICE_ERR;
				goto done;
			}
			pam_get_item(ctx->pamh, PAM_AUTHTOK, (void *) &pass);
		}

		/* Get a TGT */
		if (pam_args.search_k5login) {
			success = k5login_password_auth(ctx, &creds, &opts,
				      in_tkt_service, pass, &retval);
		} else {
			retval = krb5_get_init_creds_password(ctx->context,
				     &creds, ctx->princ, pass, pam_prompter,
				     ctx->pamh, 0, in_tkt_service, &opts);
			success = (retval == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
		}
		if (success == PAM_SUCCESS) {
			retval = append_to_credlist(ctx, credlist, creds);
			if (retval != PAM_SUCCESS)
				goto done;
			break;
		}
		pass = NULL;
	} while (retry && retval == KRB5KRB_AP_ERR_BAD_INTEGRITY);

	if (retval == 0 && pass) {
		/* success; set this in case we're changing the passwd */
		if ((retval = pam_set_item(ctx->pamh, PAM_OLDAUTHTOK, pass)) != PAM_SUCCESS) {
			dlog(ctx, "pam_set_item(): %s", pam_strerror(ctx->pamh, retval));
			retval = PAM_SERVICE_ERR;
			goto done;
		}
	}
	else {
		dlog(ctx, "krb5_get_init_creds_password(): %s", error_message(retval));
		if (retval == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN)
			retval = PAM_USER_UNKNOWN;
		else if (retval == KRB5_KDC_UNREACH)
			retval = PAM_AUTHINFO_UNAVAIL;
		else
			retval = PAM_AUTH_ERR;
		goto done;
	}

#if 0
	/* Verify the local user exists (AFTER getting the password) */
	if (strchr(ctx->name, '@')) {
		if ((pamret = to_local_user(ctx)) != PAM_SUCCESS)
			goto cleanup;
	}

	/* Someone convince me the above is actually needed for something.
	 * -dil */
#endif


	retval = PAM_SUCCESS;
done:
	return retval;
}

int
init_ccache(struct context *ctx, const char *ccname,
		struct credlist *clist, krb5_ccache *cache)
{
	struct credlist *c = clist;
	int retval;
#if 0
	/* For CNS */
	if ((retval = krb5_cc_register(ctx->context, &krb5_mcc_ops,
				       	FALSE)) != 0) {
		/* Solaris dtlogin doesn't call pam_end() on failure */
		if (retval != KRB5_CC_TYPE_EXISTS) {
			dlog(ctx, "krb5_cc_register(): %s", error_message(krbret));
			goto done;
		}
	}
#endif

	if ((retval = krb5_cc_resolve(ctx->context, ccname, cache)) != 0) {
		dlog(ctx, "krb5_cc_resolve(): %s", error_message(retval));
		retval = PAM_SERVICE_ERR;
		goto done;
	}
	if ((retval = krb5_cc_initialize(ctx->context, *cache,
					ctx->princ)) != 0) {
		dlog(ctx, "krb5_cc_initialize(): %s", error_message(retval));
		retval = PAM_SERVICE_ERR;
		goto done;
	}
	while (c) {
		if ((retval = krb5_cc_store_cred(ctx->context, *cache, &c->creds)) != 0) {
			dlog(ctx, "krb5_cc_store_cred(): %s", error_message(retval));
			retval = PAM_SERVICE_ERR;
			goto done;
		}
		c = c->next;
	}

	if (verify_krb_v5_tgt(ctx->context, *cache, ctx->service) == -1) {
		retval = PAM_AUTH_ERR;
		goto done;
	}

done:
	if (retval != PAM_SUCCESS && *cache)
		krb5_cc_destroy(ctx->context, *cache);
	return retval;
}

/*
 * Get info from the user. Disallow null responses (regardless of flags).
 * response gets allocated and filled in on successful return. Caller
 * is responsible for freeing it.
 */
int
get_user_info(pam_handle_t *pamh, const char *prompt, int type, char **response)
{
    int pamret;
    struct pam_message	msg;
    const struct pam_message *pmsg;
    struct pam_response	*resp = NULL;
    struct pam_conv	*conv;

    if ((pamret = pam_get_item(pamh, PAM_CONV, (void *) &conv)) != 0)
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
 * Modified by Sam Hartman <hartmans@mit.edu> to support PAM services
 * for Debian.
 *
 * Verify the Kerberos ticket-granting ticket just retrieved for the
 * user.  If the Kerberos server doesn't respond, assume the user is
 * trying to fake us out (since we DID just get a TGT from what is
 * supposedly our KDC).  If the host/<host> service is unknown (i.e.,
 * the local keytab doesn't have it), and we cannot find another
 * service we do have, let her in.
 *
 * Returns 1 for confirmation, -1 for failure, 0 for uncertainty.
 */
int
verify_krb_v5_tgt(krb5_context context, krb5_ccache ccache,
		  const char *pam_service)
{
    char		phost[BUFSIZ];
    char *services [3];
    char **service;
    krb5_error_code	retval = -1;
    krb5_principal	princ;
    krb5_keyblock *	keyblock = 0;
    krb5_data		packet;
    krb5_auth_context	auth_context = NULL;

    packet.data = 0;

    /*
    * If possible we want to try and verify the ticket we have
    * received against a keytab.  We will try multiple service
    * principals, including at least the host principal and the PAM
    * service principal.  The host principal is preferred because access
    * to that key is generally sufficient to compromise root, while the
    *     service key for this PAM service may be less carefully guarded.
    * It is important to check the keytab first before the KDC so we do
    * not get spoofed by a fake  KDC.*/
    services [0] = "host";
    services [1] = (char *) pam_service;
    services [2] = NULL;
    for ( service = &services[0]; *service != NULL; service++ ) {
      if ((retval = krb5_sname_to_principal(context, NULL, *service, KRB5_NT_SRV_HST,
					    &princ)) != 0) {
	if (pam_args.debug)
	  syslog(LOG_DEBUG, "pam_krb5: verify_krb_v5_tgt(): %s: %s",
		 "krb5_sname_to_principal()", error_message(retval));
	return -1;
      }

      /* Extract the name directly. */
      strncpy(phost, compat_princ_component(context, princ, 1), BUFSIZ);
      phost[BUFSIZ - 1] = '\0';

      /*
       * Do we have service/<host> keys?
       * (use default/configured keytab, kvno IGNORE_VNO to get the
       * first match, and ignore enctype.)
       */
      if ((retval = krb5_kt_read_service_key(context, NULL, princ, 0,
					     0, &keyblock)) != 0)
	continue;
      break;
    }
    if (retval != 0 ) {		/* failed to find key */
	/* Keytab or service key does not exist */
	if (pam_args.debug)
	    syslog(LOG_DEBUG, "pam_krb5: verify_krb_v5_tgt(): %s: %s",
		   "krb5_kt_read_service_key()", error_message(retval));
	retval = 0;
	goto cleanup;
    }
    if (keyblock)
	krb5_free_keyblock(context, keyblock);

    /* Talk to the kdc and construct the ticket. */
    retval = krb5_mk_req(context, &auth_context, 0, *service, phost,
			 NULL, ccache, &packet);
    if (auth_context) {
	krb5_auth_con_free(context, auth_context);
	auth_context = NULL; /* setup for rd_req */
    }
    if (retval) {
	if (pam_args.debug)
	    syslog(LOG_DEBUG, "pam_krb5: verify_krb_v5_tgt(): %s: %s",
		   "krb5_mk_req()", error_message(retval));
	retval = -1;
	goto cleanup;
    }

    /* Try to use the ticket. */
    retval = krb5_rd_req(context, &auth_context, &packet, princ,
			 NULL, NULL, NULL);
    if (auth_context) {
	krb5_auth_con_free(context, auth_context);
	auth_context = NULL; /* setup for rd_req */
    }
    if (retval) {
	if (pam_args.debug)
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
