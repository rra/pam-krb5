/*
 * options.c
 *
 * Option handling for pam-krb5.
 */

#include "config.h"

#include <krb5.h>
#include <stdlib.h>
#include <string.h>

#include "pam_krb5.h"

/*
 * Allocate a new struct pam_args and initialize its data members.
 */
static struct pam_args *
pamk5_args_new(void)
{
    struct pam_args *args;

    args = calloc(1, sizeof(struct pam_args));
    if (args == NULL)
        return NULL;
    args->ccache = NULL;
    args->ccache_dir = NULL;
    args->realm = NULL;
    args->realm_data = NULL;
    return args;
}

/*
 * Free the allocated args struct and any memory it points to.
 */
void
pamk5_args_free(struct pam_args *args)
{
    if (args != NULL) {
        if (args->ccache != NULL)
            free(args->ccache);
        if (args->ccache_dir != NULL)
            free(args->ccache_dir);
        if (args->realm != NULL)
            free(args->realm);
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

    krb5_appdefault_string(c, "pam", args->realm_data, opt, "", &tmp);
    if (tmp != NULL && tmp[0] != '\0') {
        ret = krb5_string_to_deltat(tmp, result);
        if (ret != 0) {
            pamk5_error(NULL, "bad time value for %s: %s", opt,
                        pamk5_compat_get_err_text(c, ret));
            *result = defval;
        }
    } else
        *result = defval;
    if (tmp != NULL)
        free(tmp);
}

/*
 * This is where we parse options.  Many of our options can be set in either
 * krb5.conf or in the PAM configuration, with the latter taking precedence
 * over the former.  In order to retrieve options from krb5.conf, we need a
 * Kerberos context; we take a struct context as our first argument, and if
 * it's NULL, we create a temporary context just for this.
 */
struct pam_args *
pamk5_args_parse(struct context *ctx, int flags, int argc, const char **argv)
{
    struct pam_args *args;
    int i, retval;
    krb5_context c;
    int local_context = 0;

    args = pamk5_args_new();
    if (args == NULL)
        return NULL;

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
    if (ctx != NULL)
        c = ctx->context;
    else {
        retval = krb5_init_context(&c);
        if (retval != 0)
            c = NULL;
        else
            local_context = 1;
    }
    if (c != NULL) {
        if (args->realm == NULL)
            krb5_get_default_realm(c, &args->realm);
        if (args->realm != NULL)
            pamk5_compat_set_realm(args, args->realm);
        default_string(args, c, "ccache", NULL, &args->ccache);
        default_string(args, c, "ccache_dir", "/tmp", &args->ccache_dir);
        default_boolean(args, c, "debug", 0, &args->debug);
        default_boolean(args, c, "forwardable", 0, &args->forwardable);
        default_boolean(args, c, "ignore_k5login", 0, &args->ignore_k5login);
        default_boolean(args, c, "ignore_root", 0, &args->ignore_root);
        default_number(args, c, "minimum_uid", 0, &args->minimum_uid);
        default_time(args, c, "renew_lifetime", 0, &args->renew_lifetime);
        default_boolean(args, c, "retain_after_close", 0, &args->retain);
        default_boolean(args, c, "search_k5login", 0, &args->search_k5login);
        if (local_context)
            krb5_free_context(c);
    }

    /*
     * Now, parse the arguments taken from the PAM configuration, which should
     * override anything in krb5.conf since they may be specific to particular
     * applications.  There are also additional arguments here that don't make
     * sense in krb5.conf.
     */
    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "ccache=", 7) == 0) {
            if (args->ccache != NULL)
                free(args->ccache);
            args->ccache = strdup(&argv[i][strlen("ccache=")]);
        }
        else if (strncmp(argv[i], "ccache_dir=", 11) == 0) {
            if (args->ccache_dir != NULL)
                free(args->ccache_dir);
            args->ccache_dir = strdup(&argv[i][strlen("ccache_dir=")]);
        }
        else if (strcmp(argv[i], "debug") == 0)
            args->debug = 1;
        else if (strcmp(argv[i], "forwardable") == 0)
            args->forwardable = 1;
        else if (strcmp(argv[i], "ignore_k5login") == 0)
            args->ignore_k5login = 1;
        else if (strcmp(argv[i], "ignore_root") == 0)
            args->ignore_root = 1;
        else if (strncmp(argv[i], "minimum_uid=", 12) == 0)
            args->minimum_uid = atoi(&argv[i][strlen("minimum_uid=")]);
        else if (strcmp(argv[i], "no_ccache") == 0)
            args->no_ccache = 1;
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
        else if (strcmp(argv[i], "try_first_pass") == 0)
            args->try_first_pass = 1;
        else if (strcmp(argv[i], "use_authtok") == 0)
            args->use_authtok = 1;
        else if (strcmp(argv[i], "use_first_pass") == 0)
            args->use_first_pass = 1;
        else
            pamk5_error(NULL, "unknown option %s", argv[i]);
    }
	
    if (flags & PAM_SILENT)
        args->quiet++;

    return args;
}
