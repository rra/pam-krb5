/*
 * Support functions for pam-krb5.
 *
 * Some general utility functions used by multiple PAM groups that aren't
 * associated with any particular chunk of functionality.
 *
 * Copyright 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 * Copyright 2005, 2006, 2007, 2009 Russ Allbery <rra@stanford.edu>
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
#include <pwd.h>

#include <internal.h>
#include <pam-util/args.h>
#include <pam-util/logging.h>


/*
 * Given the PAM arguments and the user we're authenticating, see if we should
 * ignore that user because they're root or have a low-numbered UID and we
 * were configured to ignore such users.  Returns true if we should ignore
 * them, false otherwise.  Ignores any fully-qualified principal names.
 */
int
pamk5_should_ignore(struct pam_args *args, PAM_CONST char *username)
{
    struct passwd *pwd;

    if (args->config->ignore_root && strcmp("root", username) == 0) {
        putil_debug(args, "ignoring root user");
        return 1;
    }
    if (args->config->minimum_uid > 0 && strchr(username, '@') == NULL) {
        pwd = pam_modutil_getpwnam(args->pamh, username);
        if (pwd != NULL && pwd->pw_uid < (uid_t) args->config->minimum_uid) {
            putil_debug(args, "ignoring low-UID user (%lu < %ld)",
                        (unsigned long) pwd->pw_uid,
                        args->config->minimum_uid);
            return 1;
        }
    }
    return 0;
}

/*
 * Map the user to a Kerberos principal according to alt_auth_map.  Returns 0
 * on success, storing the mapped principal name in newly allocated memory in
 * principal.  The caller is responsible for freeing.  Returns an errno value
 * on any error.
 */
int
pamk5_map_principal(struct pam_args *args, const char *username,
                    char **principal)
{
    char *user = NULL;
    char *realm;
    const char *i;
    size_t needed, offset;
    int oerrno;

    /* Makes no sense if alt_auth_map isn't set. */
    if (args->config->alt_auth_map == NULL)
        return EINVAL;

    /* Need to split off the realm if it is present. */
    realm = strchr(username, '@');
    if (realm == NULL)
        user = (char *) username;
    else {
        user = strdup(username);
        if (user == NULL)
            return errno;
        realm = strchr(user, '@');
        if (realm == NULL)
            goto fail;
        *realm = '\0';
        realm++;
    }

    /* Now, allocate a string and build the principal. */
    needed = 0;
    for (i = args->config->alt_auth_map; *i != '\0'; i++) {
        if (i[0] == '%' && i[1] == 's') {
            needed += strlen(user);
            i++;
        } else {
            needed++;
        }
    }
    if (realm != NULL && strchr(args->config->alt_auth_map, '@') == NULL)
        needed += 1 + strlen(realm);
    needed++;
    *principal = malloc(needed);
    if (*principal == NULL)
        goto fail;
    offset = 0;
    for (i = args->config->alt_auth_map; *i != '\0'; i++) {
        if (i[0] == '%' && i[1] == 's') {
            memcpy(*principal + offset, user, strlen(user));
            offset += strlen(user);
            i++;
        } else {
            (*principal)[offset] = *i;
            offset++;
        }
    }
    if (realm != NULL && strchr(args->config->alt_auth_map, '@') == NULL) {
        (*principal)[offset] = '@';
        offset++;
        memcpy(*principal + offset, realm, strlen(realm));
        offset += strlen(realm);
    }
    (*principal)[offset] = '\0';
    if (user != username)
        free(user);
    return 0;

fail:
    if (user != NULL && user != username) {
        oerrno = errno;
        free(user);
        errno = oerrno;
    }
    return errno;
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
    krb5_error_code retval;
    struct passwd *pwd;
    char kuser[65];             /* MAX_USERNAME == 65 (MIT Kerberos 1.4.1). */

    if (args == NULL || args->config == NULL || args->config->ctx == NULL
        || args->config->ctx->context == NULL)
        return PAM_SERVICE_ERR;
    ctx = args->config->ctx;
    if (ctx->name == NULL)
        return PAM_SERVICE_ERR;
    c = ctx->context;

    /*
     * If alt_auth_map was set, authorize the user if the authenticated
     * principal matches the mapped principal.  alt_auth_map essentially
     * serves as a supplemental .k5login.
     */
    if (args->config->alt_auth_map != NULL) {
        char *mapped;
        char *authed;
        krb5_principal princ;

        if (pamk5_map_principal(args, ctx->name, &mapped) != 0) {
            putil_err(args, "cannot map principal name");
            return PAM_SERVICE_ERR;
        }
        retval = krb5_parse_name(c, mapped, &princ);
        if (retval != 0) {
            putil_err_krb5(args, retval,
                           "cannot parse mapped principal name %s", mapped);
            free(mapped);
            return PAM_SERVICE_ERR;
        }
        free(mapped);
        retval = krb5_unparse_name(c, princ, &mapped);
        if (retval != 0) {
            putil_err_krb5(args, retval,
                           "krb5_unparse_name on mapped principal failed");
            krb5_free_principal(c, princ);
            return PAM_SERVICE_ERR;
        }
        krb5_free_principal(c, princ);
        retval = krb5_unparse_name(c, ctx->princ, &authed);
        if (retval != 0) {
            putil_err_krb5(args, retval, "krb5_unparse_name failed");
            free(mapped);
            return PAM_SERVICE_ERR;
        }
        if (strcmp(authed, mapped) == 0) {
            krb5_free_unparsed_name(c, authed);
            krb5_free_unparsed_name(c, mapped);
            return PAM_SUCCESS;
        } else {
            putil_debug(args, "mapped user %s does not match principal %s",
                        mapped, authed);
        }
        krb5_free_unparsed_name(c, authed);
        krb5_free_unparsed_name(c, mapped);
    }

    /*
     * If the name to which we're authenticating contains @ (is fully
     * qualified), it must match the principal exactly.
     */
    if (strchr(ctx->name, '@') != NULL) {
        char *principal;

        retval = krb5_unparse_name(c, ctx->princ, &principal);
        if (retval != 0) {
            putil_err_krb5(args, retval, "krb5_unparse_name failed");
            return PAM_SERVICE_ERR;
        }
        if (strcmp(principal, ctx->name) != 0) {
            putil_err(args, "user %s does not match principal %s", ctx->name,
                      principal);
            krb5_free_unparsed_name(c, principal);
            return PAM_AUTH_ERR;
        }
        krb5_free_unparsed_name(c, principal);
        return PAM_SUCCESS;
    }

    /*
     * Otherwise, apply either krb5_aname_to_localname or krb5_kuserok
     * depending on the situation.
     */
    pwd = pam_modutil_getpwnam(args->pamh, ctx->name);
    if (args->config->ignore_k5login || pwd == NULL) {
        retval = krb5_aname_to_localname(c, ctx->princ, sizeof(kuser), kuser);
        if (retval != 0) {
            putil_err_krb5(args, retval, "cannot convert principal to user");
            return PAM_AUTH_ERR;
        }
        if (strcmp(kuser, ctx->name) != 0) {
            putil_err(args, "user %s does not match local name %s", ctx->name,
                      kuser);
            return PAM_AUTH_ERR;
        }
    } else {
        if (!krb5_kuserok(c, ctx->princ, ctx->name)) {
            putil_err(args, "krb5_kuserok for user %s failed", ctx->name);
            return PAM_AUTH_ERR;
        }
    }

    return PAM_SUCCESS;
}
