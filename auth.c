/*
 * Core authentication routines for pam_krb5.
 *
 * The actual authentication work is done here, either via password or via
 * PKINIT.  The only external interface is pamk5_password_auth, which calls
 * the appropriate internal functions.  This interface is used by both the
 * authentication and the password groups.
 *
 * Copyright 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 * Copyright 2005, 2006, 2007, 2008, 2009, 2010
 *     Russ Allbery <rra@stanford.edu>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <errno.h>
#ifdef HAVE_HX509_ERR_H
# include <hx509_err.h>
#endif
#include <pwd.h>
#include <sys/stat.h>

#include <internal.h>
#include <pam-util/args.h>
#include <pam-util/logging.h>
#include <pam-util/vector.h>

/*
 * If the PKINIT smart card error statuses aren't defined, define them to 0.
 * This will cause the right thing to happen with the logic around PKINIT.
 */
#ifndef HX509_PKCS11_NO_TOKEN
# define HX509_PKCS11_NO_TOKEN 0
#endif
#ifndef HX509_PKCS11_NO_SLOT
# define HX509_PKCS11_NO_SLOT 0
#endif


/*
 * Fill in ctx->princ from the value of ctx->name or (if configured) from
 * prompting.  If we don't prompt and ctx->name contains an @-sign,
 * canonicalize it to a local account name.  If the canonicalization fails,
 * don't worry about it.  It may be that the application doesn't care.
 */
static krb5_error_code
parse_name(struct pam_args *args)
{
    struct context *ctx = args->config->ctx;
    krb5_context c = ctx->context;
    char *user = ctx->name;
    char *newuser = NULL;
    char kuser[65] = "";        /* MAX_USERNAME == 65 (MIT Kerberos 1.4.1). */
    krb5_error_code k5_errno;
    int retval;

    /*
     * If configured to prompt for the principal, do that first.  Fall back on
     * using the local username as normal if prompting fails or if the user
     * just presses Enter.
     */
    if (args->config->prompt_principal) {
        retval = pamk5_conv(args, "Principal: ", PAM_PROMPT_ECHO_ON, &user);
        if (retval != PAM_SUCCESS)
            putil_err_pam(args, retval, "error getting principal");
        if (*user == '\0') {
            free(user);
            user = ctx->name;
        }
    }

    /*
     * We don't just call krb5_parse_name so that we can work around a bug in
     * MIT Kerberos versions prior to 1.4, which store the realm in a static
     * variable inside the library and don't notice changes.  If no realm is
     * specified and a realm is set in our arguments, append the realm to
     * force krb5_parse_name to do the right thing.
     */
    if (args->realm != NULL && strchr(user, '@') == NULL) {
        if (asprintf(&newuser, "%s@%s", user, args->realm) < 0)
            return KRB5_CC_NOMEM;
        if (user != ctx->name)
            free(user);
        user = newuser;
    }
    k5_errno = krb5_parse_name(c, user, &ctx->princ);
    if (user != ctx->name)
        free(user);

    /*
     * Now that we have a principal to call krb5_aname_to_localname, we can
     * canonicalize ctx->name to a local name.  We do this even if we were
     * explicitly prompting for a principal, but we use ctx->name to generate
     * the local username, not the principal name.  It's unlikely, and would
     * be rather weird, if the user were to specify a principal name for the
     * username and then enter a different username at the principal prompt,
     * but this behavior seems to make the most sense.
     */
    if (k5_errno == 0 && strchr(ctx->name, '@') != NULL) {
        if (krb5_aname_to_localname(c, ctx->princ, sizeof(kuser), kuser) != 0)
            return 0;
        user = strdup(kuser);
        if (user == NULL) {
            putil_crit(args, "cannot allocate memory: %s", strerror(errno));
            return 0;
        }
        free(ctx->name);
        ctx->name = user;
        args->user = user;
    }
    return k5_errno;
}


/*
 * Set initial credential options for FAST if support is available.  We open
 * the ticket cache and read the principal from it first to ensure that the
 * cache exists and contains credentials, and skip setting the FAST cache if
 * we cannot do that.
 */
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_CCACHE_NAME
static void
set_fast_options(struct pam_args *args, krb5_get_init_creds_opt *opts)
{
    krb5_context c = args->config->ctx->context;
    krb5_error_code k5_errno;
    krb5_principal princ = NULL;
    krb5_principal princ2 = NULL;
    krb5_ccache fast_ccache = NULL;
    krb5_creds *fast_creds = NULL;
    char armor_name[] = "/tmp/krb5cc_pam_armor_XXXXXX";
    char *cache = args->config->fast_ccache;
    int pamret;
    krb5_get_init_creds_opt *fast_opts = NULL;

    /*
     * If fast_ccache was given, we don't need anonymous.
     */
    if (cache == NULL) {
        if (!args->config->anon_fast)
            return;

        cache = armor_name;
        fast_creds = calloc(1, sizeof(krb5_creds));
        if (fast_creds == NULL) {
            pamk5_err(args, "cannot allocate memory: %s, not using fast",
                      strerror(errno));
            goto done;
        }

        k5_errno = krb5_build_principal_ext(c, &princ,
                                            strlen(args->realm), args->realm,
                                            strlen(KRB5_WELLKNOWN_NAMESTR),
                                            KRB5_WELLKNOWN_NAMESTR,
                                            strlen(KRB5_ANONYMOUS_PRINCSTR),
                                            KRB5_ANONYMOUS_PRINCSTR,
                                            NULL);
        if (k5_errno != 0) {
            pamk5_debug_krb5(args, k5_errno,
                             "cannot create anonymous principal");
            goto done;
        }

        k5_errno = krb5_get_init_creds_opt_alloc(c, &fast_opts);
        if (k5_errno != 0) {
            pamk5_err_krb5(args, k5_errno,
                           "cannot allocate memory, not using fast");
            goto done;
        }

        krb5_get_init_creds_opt_set_anonymous(fast_opts, 1);

        k5_errno = krb5_get_init_creds_password(c, fast_creds, princ, NULL,
                                                NULL, NULL, 0, NULL,
                                                fast_opts);
        if (k5_errno != 0) {
            pamk5_debug_krb5(args, k5_errno, "failed getting initial "
                             "credentials for anonymous user");
            goto done;
        }

        /*
         * same as pamk5_cache_init_random, but differnt name and different
         * environment, and need to swap principals
         */
        pamret = pamk5_cache_mkstemp(args, cache);
        if (pamret != PAM_SUCCESS)
            goto done;

        /*
         * write cache file. pamk5_cache_init uses args->config->ctx->princ to
         * initialize the cache, so it is temporarily swapped.
         */
        princ2 = args->config->ctx->princ;
        args->config->ctx->princ = fast_creds->client;
        pamret = pamk5_cache_init(args, cache, fast_creds,
                                  &fast_ccache);
        args->config->ctx->princ = princ2;
        if (pamret != PAM_SUCCESS)
            goto done;

        pamret = pamk5_set_krb5ccname(args, cache,
                                      "PAM_FAST_KRB5CCNAME");
        if (pamret != PAM_SUCCESS) {
            pamk5_debug_pam(args, pamret,
                            "cannot save temporary fast cache name");
        }

        krb5_free_principal(c, princ);
        princ = NULL;
    } else {
        k5_errno = krb5_cc_resolve(c, cache, &fast_ccache);
        if (k5_errno != 0) {
            pamk5_debug_krb5(args, k5_errno, "failed resolving fast ccache %s",
                             cache);
            goto done;
        }
    }

    k5_errno = krb5_cc_get_principal(c, fast_ccache, &princ);
    if (k5_errno != 0) {
        putil_debug_krb5(args, k5_errno,
                         "failed to get principal from fast ccache %s", cache);
        goto done;
    }
    k5_errno = krb5_get_init_creds_opt_set_fast_ccache_name(c, opts, cache);
    if (k5_errno != 0)
        putil_err_krb5(args, k5_errno, "failed setting fast ccache to %s",
                       cache);

done:
    if (fast_creds != NULL) {
        krb5_free_cred_contents(c, fast_creds);
        free(fast_creds);
    }
    if (fast_ccache != NULL) {
        if (args->config->anon_fast && k5_errno != 0)
            krb5_cc_destroy(c, fast_ccache);
        else
            krb5_cc_close(c, fast_ccache);
    }
    if (princ != NULL)
        krb5_free_principal(c, princ);
    if (fast_opts != NULL)
        krb5_get_init_creds_opt_free(c, fast_opts);
}
#else /* !HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_CCACHE_NAME */
# define set_fast_options(a, o) /* empty */
#endif


/*
 * Set initial credential options based on our configuration information, and
 * using the Heimdal call to set initial credential options if it's available.
 * This function is used both for regular password authentication and for
 * PKINIT.  It also configures FAST if requested and the Kerberos libraries
 * support it.
 *
 * Takes a flag indicating whether we're getting tickets for a specific
 * service.  If so, we don't try to get forwardable, renewable, or proxiable
 * tickets.
 */
static void
set_credential_options(struct pam_args *args, krb5_get_init_creds_opt *opts,
                       int service)
{
    struct pam_config *config = args->config;
    krb5_context c = config->ctx->context;

    krb5_get_init_creds_opt_set_default_flags(c, "pam", args->realm, opts);
    if (!service) {
        if (config->forwardable)
            krb5_get_init_creds_opt_set_forwardable(opts, 1);
        if (config->ticket_lifetime != 0)
            krb5_get_init_creds_opt_set_tkt_life(opts, config->ticket_lifetime);
        if (config->renew_lifetime != 0)
            krb5_get_init_creds_opt_set_renew_life(opts,
                                                   config->renew_lifetime);
        krb5_get_init_creds_opt_set_change_password_prompt(opts,
            (config->defer_pwchange || config->fail_pwchange) ? 0 : 1);
    } else {
        krb5_get_init_creds_opt_set_forwardable(opts, 0);
        krb5_get_init_creds_opt_set_proxiable(opts, 0);
        krb5_get_init_creds_opt_set_renew_life(opts, 0);
    }
    set_fast_options(args, opts);

    /*
     * Set options for PKINIT.  Only used with MIT Kerberos; Heimdal's
     * implementatin of PKINIT uses a separate API instead of setting
     * get_init_creds options.
     */
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PA
    if (config->try_pkinit) {
        if (config->pkinit_user != NULL)
            krb5_get_init_creds_opt_set_pa(c, opts, "X509_user_identity",
                                           config->pkinit_user);
        if (config->pkinit_anchors != NULL)
            krb5_get_init_creds_opt_set_pa(c, opts, "X509_anchors",
                                           config->pkinit_anchors);
        if (config->preauth_opt != NULL && config->preauth_opt->count > 0) {
            size_t i;
            char *name, *value;
            char save;

            for (i = 0; i < config->preauth_opt->count; i++) {
                name = config->preauth_opt->strings[i];
                if (name == NULL)
                    continue;
                value = strchr(name, '=');
                if (value != NULL) {
                    save = *value;
                    *value = '\0';
                    value++;
                }
                krb5_get_init_creds_opt_set_pa(c, opts,
                    name, (value != NULL) ? value : "yes");
                if (value != NULL)
                    value[-1] = save;
            }
        }
    }
#endif /* HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PA */
}


/*
 * Authenticate by trying each principal in the .k5login file.
 *
 * Read through each line that parses correctly as a principal and use the
 * provided password to try to authenticate as that user.  If at any point we
 * succeed, fill out creds, set princ to the successful principal in the
 * context, and return PAM_SUCCESS.  Otherwise, return PAM_AUTH_ERR for a
 * general authentication error or PAM_SERVICE_ERR for a system error.
 *
 * If PAM_AUTH_ERR is returned, retval will be filled in with the Kerberos
 * error if available, 0 otherwise.
 */
static int
k5login_password_auth(struct pam_args *args, krb5_creds *creds,
                      krb5_get_init_creds_opt *opts, const char *service,
                      char *pass, int *retval)
{
    struct context *ctx = args->config->ctx;
    char *filename = NULL;
    char line[BUFSIZ];
    size_t len;
    FILE *k5login;
    struct passwd *pwd;
    struct stat st;
    int k5_errno;
    krb5_principal princ;

    /*
     * C sucks at string manipulation.  Generate the filename for the user's
     * .k5login file.  If the user doesn't exist, the .k5login file doesn't
     * exist, or the .k5login file cannot be read, fall back on the easy way
     * and assume ctx->princ is already set properly.
     */
    pwd = pam_modutil_getpwnam(args->pamh, ctx->name);
    if (pwd != NULL) {
        len = strlen(pwd->pw_dir) + strlen("/.k5login");
        filename = malloc(len + 1);
    }
    if (filename != NULL) {
        strncpy(filename, pwd->pw_dir, len);
        filename[len] = '\0';
        strncat(filename, "/.k5login", len - strlen(pwd->pw_dir));
    }
    if (pwd == NULL || filename == NULL || access(filename, R_OK) != 0) {
        *retval = krb5_get_init_creds_password(ctx->context, creds,
                     ctx->princ, pass, pamk5_prompter_krb5, args, 0,
                     (char *) service, opts);
        return (*retval == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
    }

    /*
     * Make sure the ownership on .k5login is okay.  The user must own their
     * own .k5login or it must be owned by root.  If that fails, set the
     * Kerberos error code to errno.
     */
    k5login = fopen(filename, "r");
    if (k5login == NULL) {
        *retval = errno;
        free(filename);
        return PAM_AUTH_ERR;
    }
    free(filename);
    if (fstat(fileno(k5login), &st) != 0) {
        *retval = errno;
        goto fail;
    }
    if (st.st_uid != 0 && (st.st_uid != pwd->pw_uid)) {
        *retval = EACCES;
        putil_err(args, "unsafe .k5login ownership (saw %lu, expected %lu)",
                  (unsigned long) st.st_uid, (unsigned long) pwd->pw_uid);
        goto fail;
    }

    /*
     * Parse the .k5login file and attempt authentication for each principal.
     * Ignore any lines that are too long or that don't parse into a Kerberos
     * principal.  Assume an invalid password error if there are no valid
     * lines in .k5login.
     */
    *retval = KRB5KRB_AP_ERR_BAD_INTEGRITY;
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
                     princ, pass, pamk5_prompter_krb5, args, 0,
                     (char *) service, opts);

        /*
         * If that worked, update ctx->princ and return success.  Otherwise,
         * continue on to the next line.
         */
        if (*retval == 0) {
            if (ctx->princ != NULL)
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
 * Authenticate using an alternative principal mapping.
 *
 * Create a principal based on the principal mapping and the user, and use the
 * provided password to try to authenticate as that user.  If we succeed, fill
 * out creds, set princ to the successful principal in the context, and return
 * PAM_SUCCESS.  Otherwise, return PAM_AUTH_ERR for a general authentication
 * error or PAM_SERVICE_ERR for a system error.
 *
 * If PAM_AUTH_ERR is returned, retval will be filled in with the Kerberos
 * error if available, 0 otherwise.
 */
static int
alt_password_auth(struct pam_args *args, krb5_creds *creds,
                  krb5_get_init_creds_opt *opts, const char *service,
                  char *pass, int *retval)
{
    struct context *ctx = args->config->ctx;
    char *kuser;
    krb5_principal princ;
    int ret, k5_errno;

    ret = pamk5_map_principal(args, ctx->name, &kuser);
    if (ret != PAM_SUCCESS)
        return ret;
    k5_errno = krb5_parse_name(ctx->context, kuser, &princ);
    if (k5_errno != 0) {
        *retval = k5_errno;
        free(kuser);
        return PAM_AUTH_ERR;
    }
    free(kuser);

    /* Log the principal we're attempting to authenticate as. */
    if (args->debug) {
        char *principal;

        k5_errno = krb5_unparse_name(ctx->context, princ, &principal);
        if (k5_errno != 0)
            putil_debug_krb5(args, k5_errno, "krb5_unparse_name failed");
        else {
            putil_debug(args, "mapping %s to %s", ctx->name, principal);
            free(principal);
        }
    }

    /* Now, attempt to authenticate as that user. */
    *retval = krb5_get_init_creds_password(ctx->context, creds, princ, pass,
                 pamk5_prompter_krb5, args, 0, (char *) service, opts);
    if (*retval != 0) {
        putil_debug_krb5(args, *retval, "alternate authentication failed");
        return PAM_AUTH_ERR;
    } else {
        putil_debug(args, "alternate authentication successful");
        if (ctx->princ != NULL)
            krb5_free_principal(ctx->context, ctx->princ);
        ctx->princ = princ;
        return PAM_SUCCESS;
    }
}


#if HAVE_KRB5_HEIMDAL && HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT
/*
 * Attempt authentication via PKINIT.  Currently, this uses an API specific to
 * Heimdal.  Once MIT Kerberos supports PKINIT, some of the details may need
 * to move into the compat layer.
 *
 * Some smart card readers require the user to enter the PIN at the keyboard
 * after inserting the smart card.  Others have a pad on the card and no
 * prompting by PAM is required.  The Kerberos library prompting functions
 * should be able to work out which is required.
 *
 * PKINIT is just one of many pre-authentication mechanisms that could be
 * used.  It's handled separately because of possible smart card interactions
 * and the possibility that some users may be authenticated via PKINIT and
 * others may not.
 *
 * Takes the same arguments as pamk5_password_auth and returns a
 * krb5_error_code.  If successful, the credentials will be stored in creds.
 */
static krb5_error_code
pkinit_auth(struct pam_args *args, const char *service, krb5_creds **creds)
{
    struct context *ctx = args->config->ctx;
    krb5_get_init_creds_opt *opts = NULL;
    krb5_error_code retval;
    char *dummy = NULL;

    /*
     * We may not be able to dive directly into the PKINIT functions because
     * the user may not have a chance to enter the smart card.  For example,
     * gnome-screensaver jumps into PAM as soon as the mouse is moved and
     * expects to be prompted for a password, which may not happen if the
     * smart card is the type that has a pad for the PIN on the card.
     *
     * Allow the user to set pkinit_prompt as an option.  If set, we tell the
     * user they need to insert the card.
     *
     * We always ignore the input.  If the user wants to use a password
     * instead, they'll be prompted later when the PKINIT code discovers that
     * no smart card is available.
     */
    if (args->config->pkinit_prompt) {
        pamk5_conv(args,
                   args->config->use_pkinit
                       ? "Insert smart card and press Enter:"
                       : "Insert smart card if desired, then press Enter:",
                   PAM_PROMPT_ECHO_OFF, &dummy);
    }

    /*
     * Set credential options.  We have to use the allocated version of the
     * credential option struct to store the PKINIT options.
     */
    *creds = calloc(1, sizeof(krb5_creds));
    if (*creds == NULL)
        return ENOMEM;
    retval = krb5_get_init_creds_opt_alloc(ctx->context, &opts);
    if (retval != 0)
        return retval;
    set_credential_options(args, opts, service != NULL);
    retval = krb5_get_init_creds_opt_set_pkinit(ctx->context, opts,
                  ctx->princ, args->config->pkinit_user,
                  args->config->pkinit_anchors, NULL, NULL, 0,
                  pamk5_prompter_krb5, args, NULL);
    if (retval != 0)
        goto done;

    /* Finally, do the actual work and return the results. */
    retval = krb5_get_init_creds_password(ctx->context, *creds, ctx->princ,
                 NULL, pamk5_prompter_krb5, args, 0, (char *) service, opts);

done:
    krb5_get_init_creds_opt_free(ctx->context, opts);
    if (retval != 0) {
        krb5_free_cred_contents(ctx->context, *creds);
        free(*creds);
        *creds = NULL;
    }
    return retval;
}
#endif /* HAVE_KRB5_HEIMDAL && HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT */


/*
 * Try to verify credentials by obtaining and checking a service ticket.  This
 * is required to verify that no one is spoofing the KDC, but requires read
 * access to a keytab with a valid key.  By default, the Kerberos library will
 * silently succeed if no verification keys are available, but the user can
 * change this by setting verify_ap_req_nofail in [libdefaults] in
 * /etc/krb5.conf.
 *
 * The MIT Kerberos implementation of krb5_verify_init_creds hardwires the
 * host key for the local system as the desired principal if no principal is
 * given.  If we have an explicitly configured keytab, instead read that
 * keytab, find the first principal in that keytab, and use that.
 *
 * Returns a Kerberos status code (0 for success).
 */
static krb5_error_code
verify_creds(struct pam_args *args, krb5_creds *creds)
{
    krb5_verify_init_creds_opt opts;
    krb5_keytab keytab = NULL;
    krb5_kt_cursor cursor;
    int cursor_valid = 0;
    krb5_keytab_entry entry;
    krb5_principal princ = NULL;
    krb5_error_code retval;
    krb5_context c = args->config->ctx->context;

    memset(&entry, 0, sizeof(entry));
    krb5_verify_init_creds_opt_init(&opts);
    if (args->config->keytab) {
        retval = krb5_kt_resolve(c, args->config->keytab, &keytab);
        if (retval != 0) {
            putil_err_krb5(args, retval, "cannot open keytab %s",
                           args->config->keytab);
            keytab = NULL;
        }
        if (retval == 0)
            retval = krb5_kt_start_seq_get(c, keytab, &cursor);
        if (retval == 0) {
            cursor_valid = 1;
            retval = krb5_kt_next_entry(c, keytab, &entry, &cursor);
        }
        if (retval == 0)
            retval = krb5_copy_principal(c, entry.principal, &princ);
        if (retval != 0)
            putil_err_krb5(args, retval, "error reading keytab %s",
                           args->config->keytab);
        if (entry.principal != NULL)
            krb5_kt_free_entry(c, &entry);
        if (cursor_valid)
            krb5_kt_end_seq_get(c, keytab, &cursor);
    }
    retval = krb5_verify_init_creds(c, creds, princ, keytab, NULL, &opts);
    if (retval != 0)
        putil_err_krb5(args, retval, "credential verification failed");
    if (princ != NULL)
        krb5_free_principal(c, princ);
    if (keytab != NULL)
        krb5_kt_close(c, keytab);
    return retval;
}


/*
 * Prompt the user for a password and authenticate the password with the KDC.
 * If correct, fill in creds with the obtained TGT or ticket.  service, if
 * non-NULL, specifies the service to get tickets for; the only interesting
 * non-null case is kadmin/changepw for changing passwords.  Therefore, if it
 * is non-null, we look for the password in PAM_OLDAUTHOK and save it there
 * instead of using PAM_AUTHTOK.
 */
int
pamk5_password_auth(struct pam_args *args, const char *service,
                    krb5_creds **creds)
{
    struct context *ctx;
    krb5_get_init_creds_opt *opts = NULL;
    int retval, retry;
    int success = PAM_AUTH_ERR;
    bool creds_valid = false;
    int do_alt = 1;
    int do_only_alt = 0;
    char *pass = NULL;
    int authtok = (service == NULL) ? PAM_AUTHTOK : PAM_OLDAUTHTOK;
    const char* fast_cache_name;
    krb5_ccache fast_cache;

    /* Sanity check and initialization. */
    if (args->config->ctx == NULL)
        return PAM_SERVICE_ERR;
    ctx = args->config->ctx;

    /* Fill in the principal to authenticate as. */
    if (ctx->princ == NULL) {
        retval = parse_name(args);
        if (retval != 0) {
            putil_err_krb5(args, retval, "krb5_parse_name failed");
            return PAM_SERVICE_ERR;
        }
    }

    /* Log the principal we're attempting to authenticate as. */
    if (args->debug && !args->config->search_k5login) {
        char *principal;

        retval = krb5_unparse_name(ctx->context, ctx->princ, &principal);
        if (retval != 0)
            putil_debug_krb5(args, retval, "krb5_unparse_name failed");
        else {
            putil_debug(args, "attempting authentication as %s", principal);
            free(principal);
        }
    }

    /*
     * If PKINIT is available and we were configured to attempt it, try
     * authenticating with PKINIT first.  Otherwise, fail all authentication
     * if PKINIT is not available and use_pkinit was set.  Fake an error code
     * that gives an approximately correct error message.
     */
#if HAVE_KRB5_HEIMDAL && HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT
    if (args->config->use_pkinit || args->config->try_pkinit) {
        retval = pkinit_auth(args, service, creds);
        if (retval == 0)
            goto done;
        putil_debug_krb5(args, retval, "pkinit failed");
        if (retval != HX509_PKCS11_NO_TOKEN && retval != HX509_PKCS11_NO_SLOT)
            goto done;
        if (retval != 0 && args->config->use_pkinit)
            goto done;
    }
#else
    if (args->config->use_pkinit) {
        retval = KRB5_KDC_UNREACH;
        goto done;
    }
#endif

    /* Allocate cred structure and set credential options. */
    *creds = calloc(1, sizeof(krb5_creds));
    if (*creds == NULL) {
        putil_crit(args, "cannot allocate memory: %s", strerror(errno));
        return PAM_SERVICE_ERR;
    }
    retval = krb5_get_init_creds_opt_alloc(ctx->context, &opts);
    if (retval != 0) {
        putil_crit_krb5(args, retval, "cannot allocate credential options");
        goto done;
    }
    set_credential_options(args, opts, service != NULL);

    /*
     * If try_first_pass, use_first_pass, or force_first_pass is set, grab the
     * old password (if set) instead of prompting.  If try_first_pass is set,
     * and the old password doesn't work, prompt for the password (loop).  If
     * use_first_pass is set, only prompt if there's no existing password.  If
     * force_first_pass is set, fail if the password is not already set.
     *
     * The empty password has to be handled separately, since the Kerberos
     * libraries may treat it as equivalent to no password and prompt when
     * we don't want them to.  We make the assumption here that the empty
     * password is always invalid and is an authentication failure.
     */
    retry = args->config->try_first_pass ? 1 : 0;
    if (args->config->try_first_pass || args->config->use_first_pass
        || args->config->force_first_pass)
        retval = pam_get_item(args->pamh, authtok, (PAM_CONST void **) &pass);
    if (args->config->use_first_pass || args->config->force_first_pass) {
        if (pass != NULL && *pass == '\0') {
            putil_debug(args, "rejecting empty password");
            retval = PAM_AUTH_ERR;
            goto done;
        }
    }
    if (args->config->force_first_pass
        && (retval != PAM_SUCCESS || pass == NULL)) {
        putil_debug_pam(args, retval, "no stored password");
        retval = PAM_SERVICE_ERR;
        goto done;
    }
    do {
        if ((pass == NULL || *pass == '\0') && !args->config->try_pkinit) {
            const char *prompt = (service == NULL) ? NULL : "Current";

            retry = 0;
            retval = pamk5_get_password(args, prompt, &pass);
            if (retval != PAM_SUCCESS) {
                putil_debug_pam(args, retval, "error getting password");
                retval = PAM_SERVICE_ERR;
                goto done;
            }
            if (*pass == '\0') {
                putil_debug(args, "rejecting empty password");
                retval = PAM_AUTH_ERR;
                goto done;
            }

            /* Set this for the next PAM module's try_first_pass. */
            retval = pam_set_item(args->pamh, authtok, pass);
            memset(pass, 0, strlen(pass));
            free(pass);
            if (retval != PAM_SUCCESS) {
                putil_err_pam(args, retval, "error storing password");
                retval = PAM_SERVICE_ERR;
                goto done;
            }
            pam_get_item(args->pamh, authtok, (PAM_CONST void **) &pass);
        }

        /*
         * Get a TGT.  First, try authenticating as the alternate principal if
         * one were configured.  If that fails or wasn't configured, continue
         * on to trying search_k5login or a regular authentication unless
         * configuration indicates that regular authentication should not be
         * attempted.
         */
        if (args->config->alt_auth_map != NULL && do_alt) {
            success = alt_password_auth(args, *creds, opts, service, pass,
                          &retval);
            if (success == PAM_SUCCESS)
                break;

            /*
             * If principal doesn't exist and alternate authentication is
             * required (only_alt_auth), bail, since we'll never succeed.  If
             * force_alt_auth is set, skip attempting normal authentication
             * iff the alternate principal exists.
             */
            if (args->config->only_alt_auth) {
                if (retval == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN)
                    goto done;
                else
                    do_only_alt = 1;
            } else if (args->config->force_alt_auth) {
                if (retval == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN)
                    do_alt = 0;
                else
                    do_only_alt = 1;
            }
        }
        if (!do_only_alt) {
            if (args->config->search_k5login) {
                success = k5login_password_auth(args, *creds, opts, service,
                              pass, &retval);
            } else {
                retval = krb5_get_init_creds_password(ctx->context, *creds,
                              ctx->princ, pass, pamk5_prompter_krb5, args, 0,
                              (char *) service, opts);
                success = (retval == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
            }
        }

        /*
         * Heimdal may return an expired key error even if the password is
         * incorrect.  To avoid accepting any incorrect password for the user
         * in the fully correct password change case, confirm that we can get
         * a password change ticket for the user using this password, and
         * otherwise change the error to invalid password.
         */
        if (retval == KRB5KDC_ERR_KEY_EXP) {
            retval = krb5_get_init_creds_password(ctx->context, *creds,
                         ctx->princ, pass, pamk5_prompter_krb5, args, 0,
                         (char *) "kadmin/changepw", opts);
            if (retval == 0) {
                retval = KRB5KDC_ERR_KEY_EXP;
                creds_valid = true;
            }
        }

        /*
         * If we succeeded, we're done.  Otherwise, clear the password and
         * then see if we should try again after prompting for a password.  If
         * we failed, make sure retval is not 0 out of paranoia, since later
         * on all we care about is retval.
         */
        if (success == PAM_SUCCESS)
            break;
        else if (retval == 0)
            retval = PAM_SERVICE_ERR;
        pass = NULL;
    } while (retry && retval == KRB5KRB_AP_ERR_BAD_INTEGRITY);
    if (retval != 0)
        putil_debug_krb5(args, retval, "krb5_get_init_creds_password");
    else
        creds_valid = true;

done:
    /*
     * If we think we succeeded, whether through the regular path or via
     * PKINIT, try to verify the credentials.  Don't do this if we're
     * authenticating for password changes (or any other case where we're not
     * getting a TGT).  We can't get a service ticket from a kadmin/changepw
     * ticket.
     */
    if (retval == 0 && service == NULL)
        retval = verify_creds(args, *creds);

    /*
     * If we failed, free any credentials we have sitting around and return
     * the appropriate PAM error code.  If we succeeded and debug is enabled,
     * log the successful authentication.
     */ 
    if (retval == 0)
        retval = PAM_SUCCESS;
    else {
        if (*creds != NULL) {
            if (creds_valid)
                krb5_free_cred_contents(ctx->context, *creds);
            free(*creds);
            *creds = NULL;
        }
        switch (retval) {
        case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
            retval = PAM_USER_UNKNOWN;
            break;
        case KRB5KDC_ERR_KEY_EXP:
            retval = PAM_NEW_AUTHTOK_REQD;
            break;
        case KRB5KDC_ERR_NAME_EXP:
            retval = PAM_ACCT_EXPIRED;
            break;
        case KRB5_KDC_UNREACH:
        case KRB5_REALM_CANT_RESOLVE:
            retval = PAM_AUTHINFO_UNAVAIL;
            break;
        default:
            retval = PAM_AUTH_ERR;
            break;
        }
    }
    if (opts != NULL)
        krb5_get_init_creds_opt_free(ctx->context, opts);

    /*
     * Whatever the results, destroy the anonymous fast armor cache
     */
    if (args->config->anon_fast) {
        fast_cache_name = pamk5_get_krb5ccname(args, "PAM_FAST_KRB5CCNAME");
        if (fast_cache_name != NULL) {

            success = krb5_cc_resolve(ctx->context, fast_cache_name,
                                      &fast_cache);
            if (success != 0) {
                pamk5_debug_krb5(args, success,
                                 "cannot resolve temporary fast cache %s",
                                 fast_cache_name);
            } else {

                krb5_cc_destroy(ctx->context, fast_cache);

                if (pam_putenv(args->pamh, "PAM_FAST_KRB5CCNAME") !=
                    PAM_SUCCESS)
                    pam_putenv(args->pamh, "PAM_FAST_KRB5CCNAME=");
            }
        }
    }

    return retval;
}


/*
 * Authenticate a user via Kerberos 5.
 *
 * It would be nice to be able to save the ticket cache temporarily as a
 * memory cache and then only write it out to disk during the session
 * initialization.  Unfortunately, OpenSSH 4.2 and later do PAM authentication
 * in a subprocess and therefore has no saved module-specific data available
 * once it opens a session, so we have to save the ticket cache to disk and
 * store in the environment where it is.  The alternative is to use something
 * like System V shared memory, which seems like more trouble than it's worth.
 */
int
pamk5_authenticate(struct pam_args *args)
{
    struct context *ctx = NULL;
    krb5_creds *creds = NULL;
    char *pass = NULL;
    char *principal;
    int pamret;
    bool set_context = false;
    krb5_error_code retval;

    /* Temporary backward compatibility. */
    if (args->config->use_authtok && !args->config->force_first_pass) {
        putil_err(args, "use_authtok option in authentication group should"
                  " be changed to force_first_pass");
        args->config->force_first_pass = true;
    }

    /* Create a context and obtain the user. */
    pamret = pamk5_context_new(args);
    if (pamret != PAM_SUCCESS)
        goto done;
    ctx = args->config->ctx;

    /* Check whether we should ignore this user. */
    if (pamk5_should_ignore(args, ctx->name)) {
        pamret = PAM_USER_UNKNOWN;
        goto done;
    }

    /*
     * Do the actual authentication.
     *
     * The complexity arises if the password was expired (which means the
     * Kerberos library was also unable to prompt for the password change
     * internally).  In that case, there are three possibilities:
     * fail_pwchange says we treat that as an authentication failure and stop,
     * defer_pwchange says to set a flag that will result in an error at the
     * acct_mgmt step, and force_pwchange says that we should change the
     * password here and now.
     *
     * defer_pwchange is the formally correct behavior.  Set a flag in the
     * context and return success.  That flag will later be checked by
     * pam_sm_acct_mgmt.  We need to set the context as PAM data in the
     * defer_pwchange case, but we don't want to set the PAM data until we've
     * checked .k5login.  If we've stacked multiple pam-krb5 invocations in
     * different realms as optional, we don't want to override a previous
     * successful authentication.
     *
     * Note this means that, if the user can authenticate with multiple realms
     * and authentication succeeds in one realm and is then expired in a later
     * realm, the expiration in the latter realm wins.  This isn't ideal, but
     * avoiding that case is more complicated than it's worth.
     *
     * We would like to set the current password as PAM_OLDAUTHTOK so that
     * when the application subsequently calls pam_chauthtok, the user won't
     * be reprompted.  However, the PAM library clears all the auth tokens
     * when pam_authenticate exits, so this isn't possible.
     *
     * In the force_pwchange case, try to use the password the user just
     * entered to authenticate to the password changing service, but don't
     * throw an error if that doesn't work.  We have to move it from
     * PAM_AUTHTOK to PAM_OLDAUTHTOK to be in the place where password
     * changing expects, and have to unset PAM_AUTHTOK or we'll just change
     * the password to the same thing it was.
     */
    pamret = pamk5_password_auth(args, NULL, &creds);
    if (pamret == PAM_NEW_AUTHTOK_REQD) {
        if (args->config->fail_pwchange)
            pamret = PAM_AUTH_ERR;
        else if (args->config->defer_pwchange) {
            putil_debug(args, "expired account, deferring failure");
            ctx->expired = 1;
            pamret = PAM_SUCCESS;
        } else if (args->config->force_pwchange) {
            pam_syslog(args->pamh, LOG_INFO, "user %s password expired,"
                       " forcing password change", ctx->name);
            pamk5_conv(args, "Password expired.  You must change it now.",
                       PAM_TEXT_INFO, NULL);
            pamret = pam_get_item(args->pamh, PAM_AUTHTOK,
                                  (PAM_CONST void **) &pass);
            if (pamret == PAM_SUCCESS && pass != NULL)
                pam_set_item(args->pamh, PAM_OLDAUTHTOK, pass);
            pam_set_item(args->pamh, PAM_AUTHTOK, NULL);
            args->config->use_first_pass = true;
            pamret = pamk5_password_change(args, false);
            if (pamret == PAM_SUCCESS)
                putil_debug(args, "successfully changed expired password");
        }
    }
    if (pamret != PAM_SUCCESS) {
        putil_log_failure(args, "authentication failure");
        goto done;
    }

    /* Check .k5login and alt_auth_map. */
    pamret = pamk5_authorized(args);
    if (pamret != PAM_SUCCESS) {
        putil_log_failure(args, "failed authorization check");
        goto done;
    }

    /* Reset PAM_USER in case we canonicalized, but ignore errors. */
    if (!ctx->expired) {
        pamret = pam_set_item(args->pamh, PAM_USER, ctx->name);
        if (pamret != PAM_SUCCESS)
            putil_err_pam(args, pamret, "cannot set PAM_USER");
    }

    /* Log the successful authentication. */
    retval = krb5_unparse_name(ctx->context, ctx->princ, &principal);
    if (retval != 0) {
        putil_err_krb5(args, retval, "krb5_unparse_name failed");
        pam_syslog(args->pamh, LOG_INFO, "user %s authenticated as UNKNOWN",
                   ctx->name);
    } else {
        pam_syslog(args->pamh, LOG_INFO, "user %s authenticated as %s%s",
                   ctx->name, principal, ctx->expired ? " (expired)" : "");
        krb5_free_unparsed_name(ctx->context, principal);
    }

    /* Now that we know we're successful, we can store the context. */
    pamret = pam_set_data(args->pamh, "pam_krb5", ctx, pamk5_context_destroy);
    if (pamret != PAM_SUCCESS) {
        putil_err_pam(args, pamret, "cannot set context data");
        pamk5_context_free(args);
        pamret = PAM_SERVICE_ERR;
        goto done;
    }
    set_context = true;

    /*
     * If we have an expired account or if we're not creating a ticket cache,
     * we're done.  Otherwise, store the obtained credentials in a temporary
     * cache.
     */
    if (!args->config->no_ccache && !ctx->expired)
        pamret = pamk5_cache_init_random(args, creds);

done:
    if (creds != NULL) {
        krb5_free_cred_contents(ctx->context, creds);
        free(creds);
    }

    /*
     * Don't free our Kerberos context if we set a context, since the context
     * will take care of that.
     */
    if (set_context)
        args->ctx = NULL;

    /*
     * Clear the context on failure so that the account management module
     * knows that we didn't authenticate with Kerberos.  Only clear the
     * context if we set it.  Otherwise, we may be blowing away the context of
     * a previous successful authentication.
     */
    if (pamret != PAM_SUCCESS) {
        if (set_context)
            pam_set_data(args->pamh, "pam_krb5", NULL, NULL);
        else
            pamk5_context_free(args);
    }
    return pamret;
}
