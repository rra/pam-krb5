/*
 * Ticket cache initialization.
 *
 * Provides functions for creating ticket caches, used by pam_authenticate,
 * pam_setcred, and pam_chauthtok after changing an expired password.
 *
 * Copyright 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 * Copyright 2005, 2006, 2007, 2008, 2009 Russ Allbery <rra@stanford.edu>
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

#include <internal.h>
#include <pam-util/args.h>
#include <pam-util/logging.h>


/*
 * Get the name of a cache.  Takes the name of the environment variable that
 * should be set to indicate which cache to use, either the permanent cache
 * (KRB5CCNAME) or the temporary cache (PAM_KRB5CCNAME).
 *
 * Treat an empty environment variable setting the same as if the variable
 * was not set, since on FreeBSD we can't delete the environment variable,
 * only set it to an empty value.
 */
const char *
pamk5_get_krb5ccname(struct pam_args *args, const char *key)
{
    const char *name;

    /* When refreshing a cache, we need to try the regular environment. */
    name = pam_getenv(args->pamh, key);
    if (name == NULL || *name == '\0')
        name = getenv(key);
    if (name == NULL || *name == '\0')
        return NULL;
    else
        return name;
}


/*
 * Put the ticket cache information into the environment.  Takes the path and
 * the environment variable to set, since this is used both for the permanent
 * cache (KRB5CCNAME) and the temporary cache (PAM_KRB5CCNAME).  Returns a PAM
 * status code.
 */
int
pamk5_set_krb5ccname(struct pam_args *args, const char *name, const char *key)
{
    char *env_name = NULL;
    int pamret;

    if (asprintf(&env_name, "%s=%s", key, name) < 0) {
        putil_crit(args, "asprintf failed: %s", strerror(errno));
        pamret = PAM_BUF_ERR;
        goto done;
    }
    pamret = pam_putenv(args->pamh, env_name);
    if (pamret != PAM_SUCCESS) {
        putil_err_pam(args, pamret, "pam_putenv failed");
        pamret = PAM_SERVICE_ERR;
        goto done;
    }
    pamret = PAM_SUCCESS;

done:
    if (env_name != NULL)
        free(env_name);
    return pamret;
}


/*
 * Given the template for a ticket cache name, initialize that file securely
 * mkstemp.  Returns a PAM success or error code.
 */
int
pamk5_cache_mkstemp(struct pam_args *args, char *template)
{
    int ccfd;

    ccfd = mkstemp(template);
    if (ccfd < 0) {
        putil_crit(args, "mkstemp(\"%s\") failed: %s", template,
                   strerror(errno));
        return PAM_SERVICE_ERR;
    }
    close(ccfd);
    return PAM_SUCCESS;
}


/*
 * Given a cache name and the initial credentials, initialize the cache, store
 * the credentials in that cache, and return a pointer to the new cache in the
 * cache argument.  Returns a PAM success or error code.
 */
int
pamk5_cache_init(struct pam_args *args, const char *ccname, krb5_creds *creds,
                 krb5_ccache *cache)
{
    struct context *ctx;
    int retval;

    if (args == NULL || args->config == NULL || args->config->ctx == NULL
        || args->config->ctx->context == NULL)
        return PAM_SERVICE_ERR;
    ctx = args->config->ctx;
    retval = krb5_cc_resolve(ctx->context, ccname, cache);
    if (retval != 0) {
        putil_err_krb5(args, retval, "cannot resolve ticket cache %s", ccname);
        retval = PAM_SERVICE_ERR;
        goto done;
    }
    retval = krb5_cc_initialize(ctx->context, *cache, ctx->princ);
    if (retval != 0) {
        putil_err_krb5(args, retval, "cannot initialize ticket cache %s",
                       ccname);
        retval = PAM_SERVICE_ERR;
        goto done;
    }
    retval = krb5_cc_store_cred(ctx->context, *cache, creds);
    if (retval != 0) {
        putil_err_krb5(args, retval, "cannot store credentials in %s", ccname);
        retval = PAM_SERVICE_ERR;
        goto done;
    }

done:
    if (retval != PAM_SUCCESS && *cache != NULL) {
        krb5_cc_destroy(ctx->context, *cache);
        *cache = NULL;
    }
    return retval;
}


/*
 * Initialize an internal ticket cache with a random name, store the given
 * credentials in the cache, and store the cache in the context.  Put the path
 * in PAM_KRB5CCNAME where it can be picked up later by pam_setcred.  Returns
 * a PAM success or error code.
 */
int
pamk5_cache_init_random(struct pam_args *args, krb5_creds *creds)
{
    char *cache_name = NULL;
    const char *dir;
    int pamret;

    /* Store the obtained credentials in a temporary cache. */
    dir = args->config->ccache_dir;
    if (strncmp("FILE:", args->config->ccache_dir, strlen("FILE:")) == 0)
        dir += strlen("FILE:");
    if (asprintf(&cache_name, "%s/krb5cc_pam_XXXXXX", dir) < 0) {
        putil_crit(args, "malloc failure: %s", strerror(errno));
        return PAM_SERVICE_ERR;
    }
    pamret = pamk5_cache_mkstemp(args, cache_name);
    if (pamret != PAM_SUCCESS)
        goto done;
    pamret = pamk5_cache_init(args, cache_name, creds,
                              &args->config->ctx->cache);
    if (pamret != PAM_SUCCESS)
        goto done;
    putil_debug(args, "temporarily storing credentials in %s", cache_name);
    pamret = pamk5_set_krb5ccname(args, cache_name, "PAM_KRB5CCNAME");

done:
    free(cache_name);
    return pamret;
}

krb5_error_code pamk5_cache_init_anon_fast(struct pam_args *args, krb5_ccache *out_ccache) {
    krb5_context c = args->config->ctx->context;
    krb5_creds *fast_creds = NULL;
    char* realm = NULL;
    krb5_error_code k5_errno;
    krb5_principal princ = NULL;
    krb5_get_init_creds_opt *fast_opts = NULL;
    krb5_ccache fast_ccache = NULL;
    char *armor_name = NULL;
    int pamret;

    if (args->realm != NULL) {
        realm = args->realm;
    } else {
        k5_errno = krb5_get_default_realm(c, &realm);
        if (k5_errno != 0) {
            putil_debug_krb5(args, k5_errno,
                             "Can't find a realm for anonymous user");
            goto done;
        }
    }
    k5_errno = krb5_build_principal_ext(c, &princ,
                                        strlen(realm), realm,
                                        strlen(KRB5_WELLKNOWN_NAMESTR),
                                        KRB5_WELLKNOWN_NAMESTR,
                                        strlen(KRB5_ANONYMOUS_PRINCSTR),
                                        KRB5_ANONYMOUS_PRINCSTR,
                                        NULL);
    if (args->realm == NULL)
        krb5_free_default_realm(c, realm);
    if (k5_errno != 0) {
        putil_debug_krb5(args, k5_errno,
                         "cannot create anonymous principal");
        goto done;
    }

    armor_name = strdup("/tmp/krb5cc_pam_armor_XXXXXX");
    pamret = pamk5_cache_mkstemp(args, armor_name);
    if (pamret != PAM_SUCCESS)
        goto done;

    k5_errno = krb5_cc_resolve(c, armor_name, &fast_ccache);
    if (k5_errno != 0) {
        putil_err_krb5(args, k5_errno,
                       "Can't create temp fast cache: %s", armor_name);
        goto done;
    }

    fast_creds = calloc(1, sizeof(krb5_creds));
    if (fast_creds == NULL) {
        putil_err(args, "cannot allocate memory: %s, not using fast",
                  strerror(errno));
        k5_errno = ENOMEM;
        goto done;
    }

    k5_errno = krb5_get_init_creds_opt_alloc(c, &fast_opts);
    if (k5_errno != 0) {
        putil_err_krb5(args, k5_errno,
                       "cannot allocate memory, not using fast");
        goto done;
    }

    krb5_get_init_creds_opt_set_anonymous(fast_opts, 1);
    krb5_get_init_creds_opt_set_tkt_life(fast_opts, 60);
    krb5_get_init_creds_opt_set_out_ccache(c, fast_opts, fast_ccache);

    k5_errno = krb5_get_init_creds_password(c, fast_creds, princ, NULL,
                                            NULL, NULL, 0, NULL,
                                            fast_opts);
    if (k5_errno != 0) {
        putil_debug_krb5(args, k5_errno, "failed getting initial "
                         "credentials for anonymous user");
        goto done;
    }
    *out_ccache = fast_ccache;

 done:
    if (armor_name != NULL)
        free(armor_name);
    if (k5_errno != 0 && fast_ccache != NULL)
        krb5_cc_destroy(c, fast_ccache);
    if (fast_opts != NULL)
        krb5_get_init_creds_opt_free(c, fast_opts);
    if (princ != NULL)
        krb5_free_principal(c, princ);
    if (fast_creds != NULL) {
        krb5_free_cred_contents(c, fast_creds);
        free(fast_creds);
    }

    return k5_errno;
}
