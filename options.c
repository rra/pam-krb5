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
    char *tmp;

    /*
     * Set char * members to NULL explicitly, as all-0-bits may or may not be
     * a NULL pointer.  In practice it is everywhere, but may as well be
     * pedantically correct.
     */
    args = calloc(1, sizeof(struct pam_args));
    args->ccache = NULL;
    args->ccache_dir = NULL;
    args->renew_lifetime = NULL;
    args->realm = NULL;
    args->realm_data = NULL;

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
        krb5_appdefault_string(c, "pam", args->realm_data, "ccache", "",
                               &args->ccache);
        if (args->ccache[0] == '\0') {
            free(args->ccache);
            args->ccache = NULL;
        }
        krb5_appdefault_string(c, "pam", args->realm_data, "ccache_dir",
                               "/tmp", &args->ccache_dir);
        krb5_appdefault_boolean(c, "pam", args->realm_data, "debug", 0,
                                &args->debug);
        krb5_appdefault_boolean(c, "pam", args->realm_data, "forwardable", 0,
                                &args->forwardable);
        krb5_appdefault_boolean(c, "pam", args->realm_data, "ignore_k5login",
                                0, &args->ignore_k5login);
        krb5_appdefault_boolean(c, "pam", args->realm_data, "ignore_root", 0,
                                &args->ignore_root);
        krb5_appdefault_string(c, "pam", args->realm_data, "minimum_uid", "",
                               &tmp);
        if (tmp[0] != '\0')
            args->minimum_uid = atoi(tmp);
        free(tmp);
        krb5_appdefault_string(c, "pam", args->realm_data, "renew_lifetime",
                               "", &args->renew_lifetime);
        if (args->renew_lifetime[0] == '\0') {
            free(args->renew_lifetime);
            args->renew_lifetime = NULL;
        }
        krb5_appdefault_boolean(c, "pam", args->realm_data,
                                "retain_after_close", 0, &args->retain);
        krb5_appdefault_boolean(c, "pam", args->realm_data, "search_k5login",
                                0, &args->search_k5login);
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
            if (args->renew_lifetime != NULL)
                free(args->renew_lifetime);
            args->renew_lifetime = strdup(&argv[i][strlen("renew_lifetime=")]);
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
    }
	
    if (flags & PAM_SILENT)
        args->quiet++;

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
        if (args->renew_lifetime != NULL)
            free(args->renew_lifetime);
        pamk5_compat_free_realm(args);
        free(args);
    }
}
