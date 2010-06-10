/*
 * Option handling for pam_krb5.
 *
 * Responsible for initializing the args struct that's passed to nearly all
 * internal functions.  Retrieves configuration information from krb5.conf and
 * parses the PAM configuration.
 *
 * Copyright 2005, 2006, 2007, 2008, 2009, 2010
 *     Russ Allbery <rra@stanford.edu>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#include <krb5.h>
#include <stdlib.h>
#include <string.h>

#include <internal.h>

/*
 * Not all platforms have this, so just implement it ourselves.  Copy a
 * certain number of characters of a string into a newly allocated
 * nul-terminated string.
 */
static char *
xstrndup(const char *s, size_t n)
{
    char *p;

    p = malloc(n + 1);
    if (p == NULL)
        return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

/*
 * Allocate a new struct pam_args and initialize its data members.  Explicitly
 * setting the pointers to NULL only matters on hosts where NULL isn't the
 * zero bit pattern, which probably don't exist, but I'm anal.
 */
static struct pam_args *
pamk5_args_new(void)
{
    struct pam_args *args;

    args = calloc(1, sizeof(struct pam_args));
    if (args == NULL)
        return NULL;
    args->banner = NULL;
    args->ccache = NULL;
    args->ccache_dir = NULL;
    args->fast_ccache = NULL;
    args->keytab = NULL;
    args->pkinit_anchors = NULL;
    args->pkinit_user = NULL;
    args->preauth_opt = NULL;
    args->realm = NULL;
    args->realm_data = NULL;
    args->ctx = NULL;
    args->pamh = NULL;
    return args;
}

/*
 * Free the allocated args struct and any memory it points to.
 */
void
pamk5_args_free(struct pam_args *args)
{
    int i;

    if (args != NULL) {
        if (args->banner != NULL)
            free(args->banner);
        if (args->ccache != NULL)
            free(args->ccache);
        if (args->ccache_dir != NULL)
            free(args->ccache_dir);
        if (args->fast_ccache != NULL)
            free(args->fast_ccache);
        if (args->keytab != NULL)
            free(args->keytab);
        if (args->pkinit_anchors != NULL)
            free(args->pkinit_anchors);
        if (args->pkinit_user != NULL)
            free(args->pkinit_user);
        if (args->realm != NULL)
            free(args->realm);
        if (args->preauth_opt != NULL) {
            for (i = 0; i < args->preauth_opt_count; i++)
                if (args->preauth_opt[i] != NULL)
                    free(args->preauth_opt[i]);
            free(args->preauth_opt);
        }
        pamk5_compat_free_realm(args);
        free(args);
    }
}

/*
 * Load a string option from Kerberos appdefaults.  This requires an annoying
 * workaround because one cannot specify a default value of NULL.
 */
static void
default_string(struct pam_args *args, krb5_context c, const char *opt,
               const char *defval, char **result)
{
    if (defval == NULL)
        defval = "";
    krb5_appdefault_string(c, "pam", args->realm_data, opt, defval, result);
    if (*result != NULL && (*result)[0] == '\0') {
        free(*result);
        *result = NULL;
    }
}

/*
 * Load a number option from Kerberos appdefaults.  The native interface
 * doesn't support numbers, so we actually read a string and then convert.
 */
static void
default_number(struct pam_args *args, krb5_context c, const char *opt,
               int defval, int *result)
{
    char *tmp;

    krb5_appdefault_string(c, "pam", args->realm_data, opt, "", &tmp);
    if (tmp != NULL && tmp[0] != '\0')
        *result = atoi(tmp);
    else
        *result = defval;
    if (tmp != NULL)
        free(tmp);
}

/*
 * Load a boolean option from Kerberos appdefaults.  This is a simple wrapper
 * around the Kerberos library function.
 */
static void
default_boolean(struct pam_args *args, krb5_context c, const char *opt,
                int defval, int *result)
{
    krb5_appdefault_boolean(c, "pam", args->realm_data, opt, defval, result);
}

/*
 * Load a time option from Kerberos appdefaults.  The native interface doesn't
 * support times, so we actually read a string and then convert.
 */
static void
default_time(struct pam_args *args, krb5_context c, const char *opt,
             krb5_deltat defval, krb5_deltat *result)
{
    char *tmp;
    int ret;
    const char *message;

    krb5_appdefault_string(c, "pam", args->realm_data, opt, "", &tmp);
    if (tmp != NULL && tmp[0] != '\0') {
        ret = krb5_string_to_deltat(tmp, result);
        if (ret != 0) {
            message = pamk5_compat_get_error(c, ret);
            pamk5_err(args, "bad time value for %s: %s", opt, message);
            pamk5_compat_free_error(c, message);
            *result = defval;
        }
    } else
        *result = defval;
    if (tmp != NULL)
        free(tmp);
}

/*
 * Splits preauth options apart on spaces and stores the result in the
 * provided pam_args struct.  We don't return success.  On memory allocation
 * failure, we just don't set the attribute, which will generally cause
 * preauth to fail.
 */
static int
split_preauth(struct pam_args *args, const char *preauth)
{
    const char *p, *start;
    size_t count, i;

    /* Count the number of options. */
    if (*preauth == '\0')
        return 1;
    for (count = 1, p = preauth + 1; *p != '\0'; p++)
        if ((*p == ' ' || *p == '\t') && !(p[-1] == ' ' || p[-1] == '\t'))
            count++;

    /*
     * If the string ends in whitespace, we've overestimated the number of
     * strings by one.
     */
    if (p[-1] == ' ' || p[-1] == '\t')
        count--;
    if (count == 0)
        return 1;

    /* Allocate the array and fill it in. */
    args->preauth_opt = malloc(count * sizeof(char *));
    if (args->preauth_opt == NULL)
        return 0;
    for (start = preauth, p = preauth, i = 0; *p != '\0'; p++)
        if (*p == ' ' || *p == '\t') {
            if (start != p) {
                args->preauth_opt[i] = xstrndup(start, p - start);
                if (args->preauth_opt[i] == NULL)
                    goto fail;
            }
            start = p + 1;
        }
    if (start != p) {
        args->preauth_opt[i] = xstrndup(start, p - start);
        if (args->preauth_opt[i] == NULL)
            goto fail;
    }
    args->preauth_opt_count = i;
    return 1;

fail:
    for (; i > 0; i--)
        free(args->preauth_opt[i - 1]);
    free(args->preauth_opt);
    args->preauth_opt = NULL;
    return 0;
}

/*
 * This is where we parse options.  Many of our options can be set in either
 * krb5.conf or in the PAM configuration, with the latter taking precedence
 * over the former.  In order to retrieve options from krb5.conf, we need a
 * Kerberos context, but we do this before we've retrieved any context from
 * the PAM environment.  So instead, we create a temporary context just for
 * this.
 *
 * Yes, we redo this for every PAM invocation, and yes, I'm worried about the
 * overhead too, but premature optimization is the root of all evil.  Mostly
 * the krb5.conf searching and setting of defaults is the only issue; the long
 * if statement only happens if there are PAM arguments.
 */
struct pam_args *
pamk5_args_parse(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct pam_args *args;
    int i, num, retval;
    krb5_context c;
    char *preauth_opt = NULL;
    char **new_preauth;

    args = pamk5_args_new();
    if (args == NULL)
        return NULL;
    args->pamh = pamh;

    /*
     * Do an initial scan to see if the realm is already set in our options.
     * If so, that overrides.
     */
    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "realm=", 6) == 0) {
            if (args->realm != NULL)
                free(args->realm);
            args->realm = strdup(&argv[i][strlen("realm=")]);
        }
    }

    /*
     * Obtain a context and set the realm if we need to and then set defaults
     * from krb5.conf.  Use the pam section of appdefaults for compatibility
     * with the Red Hat module.  If we can't get a context, just quietly
     * proceed; we'll die soon enough later and this way we'll die after we
     * know whether to debug things.
     */
    if (pamk5_compat_issetugid())
        retval = pamk5_compat_secure_context(&c);
    else
        retval = krb5_init_context(&c);
    if (retval != 0)
        c = NULL;
    if (c != NULL) {
        if (args->realm == NULL)
            krb5_get_default_realm(c, &args->realm);
        if (args->realm != NULL)
            pamk5_compat_set_realm(args, args->realm);
        default_string(args, c, "alt_auth_map", NULL, &args->alt_auth_map);
        default_string(args, c, "banner", "Kerberos", &args->banner);
        default_string(args, c, "ccache", NULL, &args->ccache);
        default_string(args, c, "ccache_dir", "FILE:/tmp", &args->ccache_dir);
        default_boolean(args, c, "clear_on_fail", 0, &args->clear_on_fail);
        default_boolean(args, c, "debug", 0, &args->debug);
        default_boolean(args, c, "defer_pwchange", 0, &args->defer_pwchange);
        default_boolean(args, c, "expose_account", 0, &args->expose_account);
        default_boolean(args, c, "fail_pwchange", 0, &args->fail_pwchange);
        default_string(args, c, "fast_ccache", NULL, &args->fast_ccache);
        default_boolean(args, c, "force_alt_auth", 0, &args->force_alt_auth);
        default_boolean(args, c, "force_pwchange", 0, &args->force_pwchange);
        default_boolean(args, c, "forwardable", 0, &args->forwardable);
        default_boolean(args, c, "ignore_k5login", 0, &args->ignore_k5login);
        default_boolean(args, c, "ignore_root", 0, &args->ignore_root);
        default_string(args, c, "keytab", NULL, &args->keytab);
        default_number(args, c, "minimum_uid", 0, &args->minimum_uid);
        default_boolean(args, c, "only_alt_auth", 0, &args->only_alt_auth);
        default_string(args, c, "pkinit_anchors", NULL, &args->pkinit_anchors);
        default_boolean(args, c, "pkinit_prompt", 0, &args->pkinit_prompt);
        default_string(args, c, "pkinit_user", NULL, &args->pkinit_user);
        default_string(args, c, "preauth_opt", NULL, &preauth_opt);
        default_boolean(args, c, "prompt_principal", 0, &args->prompt_princ);
        default_time(args, c, "renew_lifetime", 0, &args->renew_lifetime);
        default_boolean(args, c, "retain_after_close", 0, &args->retain);
        default_boolean(args, c, "search_k5login", 0, &args->search_k5login);
        default_time(args, c, "ticket_lifetime", 0, &args->lifetime);
        default_boolean(args, c, "try_pkinit", 0, &args->try_pkinit);
        default_boolean(args, c, "use_pkinit", 0, &args->use_pkinit);
        krb5_free_context(c);

        /* If preauth_opt was set, split it on spaces. */
        if (preauth_opt != NULL) {
            split_preauth(args, preauth_opt);
            free(preauth_opt);
        }
    }

    /*
     * Now, parse the arguments taken from the PAM configuration, which should
     * override anything in krb5.conf since they may be specific to particular
     * applications.  There are also additional arguments here that don't make
     * sense in krb5.conf.
     */
    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "alt_auth_map=", 12) == 0) {
            if (args->alt_auth_map != NULL)
                free(args->alt_auth_map);
            args->alt_auth_map = strdup(&argv[i][strlen("alt_auth_map=")]);
        }
        else if(strncmp(argv[i], "banner=", 7) == 0) {
            if (args->banner != NULL)
                free(args->banner);
            args->banner = strdup(&argv[i][strlen("banner=")]);
        }
        else if (strncmp(argv[i], "ccache=", 7) == 0) {
            if (args->ccache != NULL)
                free(args->ccache);
            args->ccache = strdup(&argv[i][strlen("ccache=")]);
        }
        else if (strncmp(argv[i], "ccache_dir=", 11) == 0) {
            if (args->ccache_dir != NULL)
                free(args->ccache_dir);
            args->ccache_dir = strdup(&argv[i][strlen("ccache_dir=")]);
        }
        else if (strcmp(argv[i], "clear_on_fail") == 0)
            args->clear_on_fail = 1;
        else if (strcmp(argv[i], "debug") == 0)
            args->debug = 1;
        else if (strcmp(argv[i], "defer_pwchange") == 0)
            args->defer_pwchange = 1;
        else if (strcmp(argv[i], "expose_account") == 0)
            args->expose_account = 1;
        else if (strcmp(argv[i], "fail_pwchange") == 0)
            args->fail_pwchange = 1;
        else if (strncmp(argv[i], "fast_ccache=", 12) == 0) {
            if (args->fast_ccache != NULL)
                free(args->fast_ccache);
            args->fast_ccache = strdup(&argv[i][strlen("fast_ccache=")]);
        }
        else if (strcmp(argv[i], "force_first_pass") == 0)
            args->force_first_pass = 1;
        else if (strcmp(argv[i], "force_pwchange") == 0)
            args->force_pwchange = 1;
        else if (strcmp(argv[i], "force_alt_auth") == 0)
            args->force_alt_auth = 1;
        else if (strcmp(argv[i], "forwardable") == 0)
            args->forwardable = 1;
        else if (strcmp(argv[i], "ignore_k5login") == 0)
            args->ignore_k5login = 1;
        else if (strcmp(argv[i], "ignore_root") == 0)
            args->ignore_root = 1;
        else if (strncmp(argv[i], "keytab=", 7) == 0) {
            if (args->keytab != NULL)
                free(args->keytab);
            args->keytab = strdup(&argv[i][strlen("keytab=")]);
        }
        else if (strncmp(argv[i], "minimum_uid=", 12) == 0)
            args->minimum_uid = atoi(&argv[i][strlen("minimum_uid=")]);
        else if (strcmp(argv[i], "no_ccache") == 0)
            args->no_ccache = 1;
        else if (strcmp(argv[i], "only_alt_auth") == 0)
            args->only_alt_auth = 1;
        else if (strncmp(argv[i], "pkinit_anchors=", 15) == 0) {
            if (args->pkinit_anchors != NULL)
                free(args->pkinit_anchors);
            args->pkinit_anchors = strdup(&argv[i][strlen("pkinit_anchors=")]);
        }
        else if (strcmp(argv[i], "pkinit_prompt") == 0)
            args->pkinit_prompt = 1;
        else if (strncmp(argv[i], "pkinit_user=", 12) == 0) {
            if (args->pkinit_user != NULL)
                free(args->pkinit_user);
            args->pkinit_user = strdup(&argv[i][strlen("pkinit_user=")]);
        }
        else if (strncmp(argv[i], "preauth_opt=", 12) == 0) {
            num = args->preauth_opt_count;
            new_preauth = realloc(args->preauth_opt,
                                  sizeof(char *) * args->preauth_opt_count);
            if (new_preauth != NULL) {
                args->preauth_opt[num]
                    = strdup(&argv[i][strlen("preauth_opt")]);
                args->preauth_opt_count++;
            }
        }
        else if (strcmp(argv[i], "prompt_principal") == 0)
            args->prompt_princ = 1;
        else if (strncmp(argv[i], "realm=", 6) == 0)
            ; /* Handled above. */
        else if (strncmp(argv[i], "renew_lifetime=", 15) == 0) {
            const char *value;

            value = argv[i] + strlen("renew_lifetime=");
            krb5_string_to_deltat((char *) value, &args->renew_lifetime);
        }
        else if (strcmp(argv[i], "retain_after_close") == 0)
            args->retain = 1;
        else if (strcmp(argv[i], "search_k5login") == 0)
            args->search_k5login = 1;
        else if (strncmp(argv[i], "ticket_lifetime=", 16) == 0) {
            const char *value;

            value = argv[i] + strlen("ticket_lifetime=");
            krb5_string_to_deltat((char *) value, &args->lifetime);
        }
        else if (strcmp(argv[i], "try_first_pass") == 0)
            args->try_first_pass = 1;
        else if (strcmp(argv[i], "try_pkinit") == 0)
            args->try_pkinit = 1;
        else if (strcmp(argv[i], "use_authtok") == 0)
            args->use_authtok = 1;
        else if (strcmp(argv[i], "use_first_pass") == 0)
            args->use_first_pass = 1;
        else if (strcmp(argv[i], "use_pkinit") == 0)
            args->use_pkinit = 1;
        else
            pamk5_err(NULL, "unknown option %s", argv[i]);
    }
    if (flags & PAM_SILENT)
        args->silent = 1;

    /* An empty banner should be treated the same as not having one. */
    if (args->banner != NULL && args->banner[0] == '\0') {
        free(args->banner);
        args->banner = NULL;
    }

    /* Sanity-check try_first_pass, use_first_pass, and force_first_pass. */
    if (args->force_first_pass && args->try_first_pass) {
        pamk5_err(NULL, "force_first_pass set, ignoring try_first_pass");
        args->try_first_pass = 0;
        args->use_first_pass = 0;
    }
    if (args->force_first_pass && args->use_first_pass) {
        pamk5_err(NULL, "force_first_pass set, ignoring use_first_pass");
        args->use_first_pass = 0;
    }
    if (args->use_first_pass && args->try_first_pass) {
        pamk5_err(NULL, "use_first_pass set, ignoring try_first_pass");
        args->try_first_pass = 0;
    }

    /*
     * Don't set expose_account if we're using search_k5login.  The user will
     * get a principal formed from the account into which they're logging in,
     * which isn't the password they'll use (that's the whole point of
     * search_k5login).
     */
    if (args->search_k5login)
        args->expose_account = 0;

    /* UIDs are unsigned on some systems. */
    if (args->minimum_uid < 0)
        args->minimum_uid = 0;

    /*
     * Warn if PKINIT options were set and PKINIT isn't supported.  The MIT
     * method (krb5_get_init_creds_opt_set_pa) can't support use_pkinit.
     */
#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT
# ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PA
    if (args->try_pkinit)
	pamk5_err(NULL, "try_pkinit requested but PKINIT not available");
# endif
    if (args->use_pkinit)
	pamk5_err(NULL, "use_pkinit requested but PKINIT not available or"
                  " cannot be enforced");
#endif

    /* Warn if the FAST option was set and FAST isn't supported. */
#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_CCACHE_NAME
    if (args->fast_ccache)
        pamk5_err(args, "fast_ccache requested but FAST not supported by"
                  " Kerberos libraries");
#endif

    return args;
}
