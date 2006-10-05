/*
 * support.c
 *
 * Support functions for pam_krb5
 */

#include "config.h"

#ifdef HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#else
# include <com_err.h>
#endif
#include <errno.h>
#include <krb5.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pam_krb5.h"

/*
 * Given the context (if any), the PAM arguments and the user we're
 * authenticating, see if we should ignore that user because they're root or
 * have a low-numbered UID and we were configured to ignore such users.
 * Returns true if we should ignore them, false otherwise.
 */
int
pamk5_should_ignore(struct context *ctx, struct pam_args *args,
                    const char *username)
{
    struct passwd *pwd;

    if (args->ignore_root && strcmp("root", username) == 0) {
        pamk5_debug(ctx, args, "ignoring root user");
        return 1;
    }
    if (args->minimum_uid > 0) {
        pwd = getpwnam(username);
        if (pwd != NULL && pwd->pw_uid < args->minimum_uid) {
            pamk5_debug(ctx, args, "ignoring low-UID user (%d < %d)",
                        pwd->pw_uid, args->minimum_uid);
            return 1;
        }
    }
    return 0;
}


/*
 * Used to support trying each principal in the .k5login file.  Read through
 * each line that parses correctly as a principal and use the provided
 * password to try to authenticate as that user.  If at any point we succeed,
 * fill out creds, set princ to the successful principal in the context, and
 * return PAM_SUCCESS.  Otherwise, return PAM_AUTH_ERR for a general
 * authentication error or PAM_SERVICE_ERR for a system error.  If
 * PAM_AUTH_ERR is returned, retval will be filled in with the Kerberos error
 * if available, 0 otherwise.
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

    /*
     * C sucks at string manipulation.  Generate the filename for the user's
     * .k5login file.  This function always fails if the user isn't a local
     * user.
     */
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
        if (k5_errno != 0)
            return PAM_SERVICE_ERR;
        *retval = krb5_get_init_creds_password(ctx->context, creds,
                     ctx->princ, pass, pamk5_prompter_krb5, ctx->pamh, 0,
                     in_tkt_service, opts);
        return (*retval == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
    }

    /*
     * Make sure the ownership on .k5login is okay.  The user must own their
     * own .k5login or it must be owned by root.
     */
    k5login = fopen(filename, "r");
    free(filename);
    if (k5login == NULL)
        return PAM_AUTH_ERR;
    if (fstat(fileno(k5login), &st) != 0)
        goto fail;
    if (st.st_uid != 0 && (st.st_uid != pwd->pw_uid))
        goto fail;

    /*
     * Parse the .k5login file and attempt authentication for each principal.
     * Ignore any lines that are too long or that don't parse into a Kerberos
     * principal.
     */
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
                     princ, pass, pamk5_prompter_krb5, ctx->pamh, 0,
                     in_tkt_service, opts);

        /*
         * If that worked, update ctx->princ and return success.  Otherwise,
         * continue on to the next line.
         */
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
 * Prompt the user for a password and authenticate the password with the KDC.
 * If correct, fill in credlist with the obtained TGT or ticket.
 * in_tkt_service, if non-NULL, specifies the service to get tickets for; the
 * only interesting non-null case is kadmin/changepw for changing passwords.
 * Therefore, if it is non-null, we look for the password in PAM_OLDAUTHOK and
 * save it there instead of using PAM_AUTHTOK.
 */
int
pamk5_password_auth(struct context *ctx, struct pam_args *args,
                    char *in_tkt_service, struct credlist **credlist)
{
    krb5_get_init_creds_opt opts;
    krb5_creds creds;
    krb5_verify_init_creds_opt verify_opts;
    int retval, retry, success;
    char *pass = NULL;
    int authtok = in_tkt_service == NULL ? PAM_AUTHTOK : PAM_OLDAUTHTOK;

    /* Bail if we should be ignoring this user. */
    if (pamk5_should_ignore(ctx, args, ctx->name)) {
        retval = PAM_SERVICE_ERR;
        goto done;
    }

    pamk5_credlist_new(ctx, credlist);
    memset(&creds, 0, sizeof(krb5_creds));

    /* Set ticket options. */
    krb5_get_init_creds_opt_init(&opts);
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_DEFAULT_FLAGS
    krb5_get_init_creds_opt_set_default_flags(ctx->context, "pam",
                                              args->realm_data, &opts);
#endif
    if (args->forwardable)
        krb5_get_init_creds_opt_set_forwardable(&opts, 1);
    if (args->renew_lifetime != 0)
        krb5_get_init_creds_opt_set_renew_life(&opts, args->renew_lifetime);

    /* Fill in the principal to authenticate as. */
    retval = krb5_parse_name(ctx->context, ctx->name, &ctx->princ);
    if (retval != 0) {
        pamk5_debug_krb5(ctx, args, "krb5_parse_name", retval);
        retval = PAM_SERVICE_ERR;
        goto done;
    }

    /*
     * If try_first_pass or use_first_pass is set, grab the old password (if
     * set) instead of prompting.  If try_first_pass is set, and the old
     * password doesn't work, prompt for the password (loop).
     */
    retry = args->try_first_pass ? 1 : 0;
    if (args->try_first_pass || args->use_first_pass || args->use_authtok)
        retval = pam_get_item(ctx->pamh, authtok, (void *) &pass);
    if (args->use_authtok && retval != PAM_SUCCESS) {
        pamk5_debug_pam(ctx, args, "no stored password", retval);
        retval = PAM_SERVICE_ERR;
        goto done;
    }
    do {
        if (pass == NULL) {
            retry = 0;
            retval = pamk5_prompt(ctx->pamh, "Password: ",
                                  PAM_PROMPT_ECHO_OFF, &pass);
            if (retval != PAM_SUCCESS) {
                pamk5_debug_pam(ctx, args, "error getting password", retval);
                retval = PAM_SERVICE_ERR;
                goto done;
            }

            /* Set this for the next PAM module's try_first_pass. */
            retval = pam_set_item(ctx->pamh, authtok, pass);
            free(pass);
            if (retval != PAM_SUCCESS) {
                pamk5_debug_pam(ctx, args, "error storing password", retval);
                retval = PAM_SERVICE_ERR;
                goto done;
            }
            pam_get_item(ctx->pamh, authtok, (void *) &pass);
        }

        /* Get a TGT */
        if (args->search_k5login) {
            success = k5login_password_auth(ctx, &creds, &opts,
                          in_tkt_service, pass, &retval);
        } else {
            retval = krb5_get_init_creds_password(ctx->context,
                          &creds, ctx->princ, pass, pamk5_prompter_krb5,
                          ctx->pamh, 0, in_tkt_service, &opts);
            success = (retval == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
        }
        if (success == PAM_SUCCESS) {
            retval = pamk5_credlist_append(ctx, credlist, creds);
            if (retval != PAM_SUCCESS)
                goto done;
            break;
        }
        pass = NULL;
    } while (retry && retval == KRB5KRB_AP_ERR_BAD_INTEGRITY);

    /*
     * Last step.  Verify the obtained TGT by obtaining and checking a service
     * ticket.  This is required to verify that no one is spoofing the KDC,
     * but requires read access to a keytab with an appropriate key.  By
     * default, the Kerberos library will silently succeed if no verification
     * keys are available, but the user can change this by setting
     * verify_ap_req_nofail in [libdefaults] in /etc/krb5.conf.
     *
     * Don't do this if we're authenticating for password changes.  We can't
     * get a service ticket from a kadmin/changepw ticket and the user
     * probably isn't going to have access to a keytab to check KDC spoofing
     * anyway.
     */
    if (retval == 0 && in_tkt_service == NULL) {
        krb5_verify_init_creds_opt_init(&verify_opts);
        retval = krb5_verify_init_creds(ctx->context, &creds, NULL, NULL,
                                        &ctx->cache, &verify_opts);
        if (retval != 0) {
            pamk5_error(ctx, "credential verification failed: %s",
                        pamk5_compat_get_err_text(ctx->context, retval));
            retval = PAM_AUTH_ERR;
            goto done;
        }
    }

    /* If we failed, return the appropriate PAM error code. */
    if (retval != 0) {
        pamk5_debug_krb5(ctx, args, "krb5_get_init_creds_password", retval);
        if (retval == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN)
            retval = PAM_USER_UNKNOWN;
        else if (retval == KRB5_KDC_UNREACH)
            retval = PAM_AUTHINFO_UNAVAIL;
        else
            retval = PAM_AUTH_ERR;
        goto done;
    }
    retval = PAM_SUCCESS;

done:
    return retval;
}


/*
 * Given a cache name and a credential list, initialize the cache, store the
 * credentials in that cache, and return a pointer to the new cache in the
 * cache argument.  Returns a PAM success or error code.
 */
int
pamk5_ccache_init(struct context *ctx, struct pam_args *args,
                  const char *ccname, struct credlist *clist,
                  krb5_ccache *cache)
{
    struct credlist *cred;
    int retval;

    retval = krb5_cc_resolve(ctx->context, ccname, cache);
    if (retval != 0) {
        pamk5_debug_krb5(ctx, args, "krb5_cc_resolve", retval);
        retval = PAM_SERVICE_ERR;
        goto done;
    }
    retval = krb5_cc_initialize(ctx->context, *cache, ctx->princ);
    if (retval != 0) {
        pamk5_debug_krb5(ctx, args, "krb5_cc_initialize", retval);
        retval = PAM_SERVICE_ERR;
        goto done;
    }
    for (cred = clist; cred != NULL; cred = cred->next) {
        retval = krb5_cc_store_cred(ctx->context, *cache, &cred->creds);
        if (retval != 0) {
            pamk5_debug_krb5(ctx, args, "krb5_cc_store_cred", retval);
            retval = PAM_SERVICE_ERR;
            goto done;
        }
    }

done:
    if (retval != PAM_SUCCESS && *cache != NULL)
        krb5_cc_destroy(ctx->context, *cache);
    return retval;
}


/*
 * Get info from the user.  Disallow null responses (regardless of flags).
 * response is allocated and filled in on successful return.  Caller is
 * responsible for freeing it.
 */
int
pamk5_prompt(pam_handle_t *pamh, const char *prompt, int type,
             char **response)
{
    int pamret;
    struct pam_message msg;
    const struct pam_message *pmsg;
    struct pam_response	*resp = NULL;
    struct pam_conv *conv;

    pamret = pam_get_item(pamh, PAM_CONV, (void *) &conv);
    if (pamret != PAM_SUCCESS)
	return pamret;
    pmsg = &msg;
    msg.msg_style = type;
    msg.msg = prompt;
    pamret = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);
    if (pamret != PAM_SUCCESS)
	return pamret;

    /* Caller should ignore errors for non-response conversations. */
    if (resp == NULL)
	return PAM_CONV_ERR;
    if (resp->resp == NULL || resp->resp[0] == '\0') {
	free(resp);
	return PAM_AUTH_ERR;
    }
    *response = resp->resp;
    free(resp);
    return PAM_SUCCESS;
}

/*
 * Verify the user authentication.  Call krb5_kuserok if this is a local
 * account, or do the krb5_aname_to_localname verification if ignore_k5login
 * was requested.  It's the responsibility of the calling application to deal
 * with authorization issues for non-local accounts (ones containing a realm
 * component).
 */
int
pamk5_validate_auth(struct context *ctx, struct pam_args *args)
{
    struct passwd *pwd;
    char kuser[65];             /* MAX_USERNAME == 65 (MIT Kerberos 1.4.1). */

    if (ctx == NULL)
        return PAM_SERVICE_ERR;
    if (ctx->name == NULL)
        return PAM_SERVICE_ERR;

    if (strchr(ctx->name, '@') != NULL)
        return PAM_SUCCESS;
    pwd = getpwnam(ctx->name);
    if (args->ignore_k5login || pwd == NULL) {
        krb5_context c = ctx->context;

        if (krb5_aname_to_localname(c, ctx->princ, sizeof(kuser), kuser) != 0)
            return PAM_AUTH_ERR;
        if (strcmp(kuser, ctx->name) != 0)
            return PAM_AUTH_ERR;
    } else {
        if (!krb5_kuserok(ctx->context, ctx->princ, ctx->name))
            return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}
