/*
 * options.c
 *
 * Option handling for pam-krb5.
 */

#include <string.h>

#include <krb5.h>
#include "pam_krb5.h"
#include "context.h"

struct pam_args pam_args;

/*
 * This is where we set all of our global state.  Many of our options can be
 * set in either krb5.conf or in the PAM configuration, with the latter taking
 * precedence over the former.  In order to retrieve options from krb5.conf,
 * we need a Kerberos context; we take a struct context as our first argument,
 * and if it's NULL, we create a temporary context just for this.
 */
void
parse_args(struct context *ctx, int flags, int argc, const char **argv)
{
    int i, retval;
    krb5_context c;
    int local_context = 0;

    /*
     * Set char * members to NULL explicitly, as all-0-bits may or may not be
     * a NULL pointer.  In practice it is everywhere, but may as well be
     * pedantically correct.
     */
    memset(&pam_args, 0, sizeof(pam_args));
    pam_args.ccache = NULL;
    pam_args.ccache_dir = NULL;
    pam_args.renew_lifetime = NULL;

    /*
     * Obtain a context if we need to and then set defaults from krb5.conf.
     * Use the pam section of appdefaults for compatibility with the Red Hat
     * module.  If we can't get a context, just quietly proceed; we'll die
     * soon enough later and this way we'll die after we know whether to debug
     * things.
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
        krb5_appdefault_boolean(c, "pam", NULL, "debug", 0, &pam_args.debug);
        krb5_appdefault_boolean(c, "pam", NULL, "forwardable", 0,
                                &pam_args.forwardable);
        krb5_appdefault_boolean(c, "pam", NULL, "ignore_root", 0,
                                &pam_args.ignore_root);
        krb5_appdefault_boolean(c, "pam", NULL, "search_k5login", 0,
                                &pam_args.search_k5login);
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
        if (strncmp(argv[i], "ccache=", 7) == 0)
            pam_args.ccache = (char *) &argv[i][7];
        else if (strncmp(argv[i], "ccache_dir=", 11) == 0)
            pam_args.ccache_dir = (char *) &argv[i][11];
        else if (strcmp(argv[i], "debug") == 0)
            pam_args.debug = 1;
        else if (strcmp(argv[i], "forwardable") == 0)
            pam_args.forwardable = 1;
        else if (strcmp(argv[i], "ignore_k5login") == 0)
            pam_args.ignore_k5login = 1;
        else if (strcmp(argv[i], "ignore_root") == 0)
            pam_args.ignore_root = 1;
        else if (strcmp(argv[i], "no_ccache") == 0)
            pam_args.no_ccache = 1;
        else if (strcmp(argv[i], "renew_lifetime") == 0)
            pam_args.renew_lifetime = (char *) argv[i];
        else if (strcmp(argv[i], "reuse_ccache") == 0)
            pam_args.reuse_ccache = 1;
        else if (strcmp(argv[i], "search_k5login") == 0)
            pam_args.search_k5login = 1;
        else if (strcmp(argv[i], "try_first_pass") == 0)
            pam_args.try_first_pass = 1;
        else if (strcmp(argv[i], "use_first_pass") == 0)
            pam_args.use_first_pass = 1;
    }
	
    if (flags & PAM_SILENT)
        pam_args.quiet++;
    if (!pam_args.ccache_dir)
        pam_args.ccache_dir = "/tmp";
}
