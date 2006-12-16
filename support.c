/*
 * support.c
 *
 * Support functions for pam_krb5.
 *
 * Some general utility functions used by multiple PAM groups that aren't
 * associated with any particular chunk of functionality.
 */

#include "config.h"

#include <krb5.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string.h>

#include "internal.h"

/*
 * Given the PAM arguments and the user we're authenticating, see if we should
 * ignore that user because they're root or have a low-numbered UID and we
 * were configured to ignore such users.  Returns true if we should ignore
 * them, false otherwise.
 */
int
pamk5_should_ignore(struct pam_args *args, const char *username)
{
    struct passwd *pwd;

    if (args->ignore_root && strcmp("root", username) == 0) {
        pamk5_debug(args, "ignoring root user");
        return 1;
    }
    if (args->minimum_uid > 0) {
        pwd = getpwnam(username);
        if (pwd != NULL && pwd->pw_uid < args->minimum_uid) {
            pamk5_debug(args, "ignoring low-UID user (%lu < %d)",
                        (unsigned long) pwd->pw_uid, args->minimum_uid);
            return 1;
        }
    }
    return 0;
}


/*
 * Verify the user authorization.  Call krb5_kuserok if this is a local
 * account, or do the krb5_aname_to_localname verification if ignore_k5login
 * was requested.  For non-local accounts, the principal must match the
 * authentication identity.
 */
int
pamk5_authorized(struct pam_args *args)
{
    struct context *ctx;
    krb5_context c;
    struct passwd *pwd;
    char kuser[65];             /* MAX_USERNAME == 65 (MIT Kerberos 1.4.1). */

    if (args == NULL || args->ctx == NULL || args->ctx->context == NULL)
        return PAM_SERVICE_ERR;
    ctx = args->ctx;
    if (ctx->name == NULL)
        return PAM_SERVICE_ERR;
    c = ctx->context;

    /*
     * If the name to which we're authenticating contains @ (is fully
     * qualified), it must match the principal exactly.
     */
    if (strchr(ctx->name, '@') != NULL) {
        char *principal;
        int retval;

        retval = krb5_unparse_name(c, ctx->princ, &principal);
        if (retval != 0)
            return PAM_SERVICE_ERR;
        if (strcmp(principal, ctx->name) != 0) {
            free(principal);
            return PAM_AUTH_ERR;
        }
        return PAM_SUCCESS;
    }

    /*
     * Otherwise, apply either krb5_aname_to_localname or krb5_kuserok
     * depending on the situation.
     */
    pwd = getpwnam(ctx->name);
    if (args->ignore_k5login || pwd == NULL) {
        if (krb5_aname_to_localname(c, ctx->princ, sizeof(kuser), kuser) != 0)
            return PAM_AUTH_ERR;
        if (strcmp(kuser, ctx->name) != 0)
            return PAM_AUTH_ERR;
    } else {
        if (!krb5_kuserok(c, ctx->princ, ctx->name))
            return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}
