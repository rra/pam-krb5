/*
 * pam_krb5_auth.c
 *
 * PAM authentication management functions for pam_krb5
 *
 */

#define PAM_SM_AUTH

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <krb5.h>
#include <com_err.h>
#include "pam_krb5.h"
#include "credlist.h"

static const char *
get_krb5ccname(struct context *ctx, const char *key)
{
	const char *name;

	/* TODO: figure out why pam_getenv() returns NULL */
	name = pam_getenv(ctx->pamh, key);
	if (!name)
		name = getenv(key);
	if (!name && ctx && ctx->context && ctx->cache)
		name = krb5_cc_get_name(ctx->context, ctx->cache);

	return name;
}

static int
set_krb5ccname(struct context *ctx, const char *name, const char *key)
{
	char *env_name = NULL;
	int pamret;
       
	env_name = malloc(strlen(key) + 1 + strlen(name) + 1);
	if (!env_name) {
                error(ctx, "malloc failure: %s", strerror(errno));
		pamret = PAM_BUF_ERR;
		goto done;
	}

	sprintf(env_name, "%s=%s", key, name);
	if ((pamret = pam_putenv(ctx->pamh, env_name)) != PAM_SUCCESS) {
		error(ctx, "pam_putenv: %s", pam_strerror(ctx->pamh, pamret));
		pamret = PAM_SERVICE_ERR;
		goto done;
	}

	pamret = PAM_SUCCESS;
done:
	if (env_name)
		free(env_name);
	return pamret;
}

/*
 * Authenticate a user via krb5.
 *
 * It would be nice to be able to save the ticket cache temporarily as a
 * memory cache and then only write it out to disk during the session
 * initialization.  Unfortunately, OpenSSH 4.2 does PAM authentication in a
 * subprocess and therefore has no saved module-specific data available once
 * it opens a session, so we have to save the ticket cache to disk and store
 * in the environment where it is.
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
		    const char **argv)
{
    struct context *ctx;
    struct pam_args *args;
    struct credlist *clist = NULL;
    int pamret = PAM_SERVICE_ERR;
    char cache_name[] = "/tmp/krb5cc_pam_XXXXXX";
    int ccfd;

    args = parse_args(NULL, flags, argc, argv);
    ENTRY(ctx, args, flags);

    if ((pamret = new_context(pamh, &ctx)) != PAM_SUCCESS)
	    goto done;

    /* do this first, so destroy_context magically cleans up for us */
    if ((pamret = pam_set_data(pamh, "ctx", ctx,
				    destroy_context)) != PAM_SUCCESS) {
	free_context(ctx);
	pamret = PAM_SERVICE_ERR;
	goto done;
    }

    if ((pamret = password_auth(ctx, args, NULL, &clist)) != PAM_SUCCESS)
	goto done;
    ccfd = mkstemp(cache_name);
    if (ccfd < 0) {
	error(ctx, "mkstemp(\"%s\") failed: %s", cache_name, strerror(errno));
	pamret = PAM_SERVICE_ERR;
	goto done;
    }
    close(ccfd);
    if ((pamret = init_ccache(ctx, args, cache_name, clist, &ctx->cache)) != PAM_SUCCESS)
	goto done;
    if ((pamret = validate_auth(ctx, args)) != PAM_SUCCESS)
        goto done;
    if ((pamret = set_krb5ccname(ctx, cache_name, "PAM_KRB5CCNAME")) != PAM_SUCCESS)
	goto done;

done:
    free_credlist(ctx, clist);
    EXIT(ctx, args, pamret);

    /* Clear the context on failure so that the account management module
       knows that we didn't authenticate with Kerberos. */
    if (pamret != PAM_SUCCESS)
	pam_set_data(pamh, "ctx", NULL, NULL);
    free_args(args);
    return pamret;
}

/* Determine the name of the ticket cache.  Handles ccache and ccache_dir PAM
   options and returns newly allocated memory. */
static char *
build_ccache_name(struct context *ctx, struct pam_args *args, uid_t uid)
{
    char *cache_name;

    if (args->ccache == NULL) {
	size_t ccache_size = 1 + strlen(args->ccache_dir) +
	    strlen("/krb5cc_4294967295_XXXXXX");

	cache_name = malloc(ccache_size);
	if (!cache_name) {
	    error(ctx, "malloc failure: %s", strerror(errno));
	    return NULL;
	}
	snprintf(cache_name, ccache_size, "%s/krb5cc_%d_XXXXXX",
                 args->ccache_dir, uid);
    } else {
	size_t len = 0, delta;
	char *p, *q;

	for (p = args->ccache; *p != '\0'; p++) {
	    if (p[0] == '%' && p[1] == 'u') {
		len += snprintf(NULL, 0, "%d", uid);
		p++;
	    } else if (p[0] == '%' && p[1] == 'p') {
		len += snprintf(NULL, 0, "%d", getpid());
		p++;
	    } else {
		len++;
	    }
	}
	len++;
	cache_name = malloc(len);
	if (cache_name == NULL) {
	    error(ctx, "malloc failure: %s", strerror(errno));
	    return NULL;
	}
	for (p = args->ccache, q = cache_name; *p != '\0'; p++) {
	    if (p[0] == '%' && p[1] == 'u') {
		delta = snprintf(q, len, "%d", uid);
		q += delta;
		len -= delta;
		p++;
	    } else if (p[0] == '%' && p[1] == 'p') {
		delta = snprintf(q, len, "%d", getpid());
		q += delta;
		len -= delta;
		p++;
	    } else {
		*q = *p;
		q++;
		len--;
	    }
	}
	*q = '\0';
    }
    return cache_name;
}

/* Create a new context for a session if we've lost the context created during
   authentication (such as when running under OpenSSH. */
static int
create_session_context(struct pam_args *args, pam_handle_t *pamh,
                       struct context **newctx)
{
    struct context *ctx = NULL;
    const char *tmpname;
    int status, pamret;

    if (args->ignore_root || args->minimum_uid > 0) {
        pamret = pam_get_user(pamh, &tmpname, NULL);
        if (pamret == PAM_SUCCESS && should_ignore_user(ctx, args, tmpname)) {
            pamret = PAM_SUCCESS;
            goto fail;
        }
    }
    pamret = new_context(pamh, &ctx);
    if (pamret != PAM_SUCCESS) {
	debug(ctx, args, "creating session context failed");
	goto fail;
    }
    tmpname = get_krb5ccname(ctx, "PAM_KRB5CCNAME");
    if (tmpname == NULL) {
	debug(ctx, args, "unable to get PAM_KRB5CCNAME, assuming"
              " non-Kerberos login");
	pamret = PAM_SUCCESS;
	goto fail;
    }
    debug(ctx, args, "found initial ticket cache at %s", tmpname);
    if (krb5_cc_resolve(ctx->context, tmpname, &ctx->cache) != 0) {
	debug(ctx, args, "cannot resolve cache %s", tmpname);
	pamret = PAM_SERVICE_ERR;
	goto fail;
    }
    status = krb5_cc_get_principal(ctx->context, ctx->cache, &ctx->princ);
    if (status != 0) {
	debug_krb5(ctx, args, "cannot retrieve principal", status);
	pamret = PAM_SERVICE_ERR;
	goto fail;
    }
    pamret = pam_set_data(pamh, "ctx", ctx, destroy_context);
    if (pamret != PAM_SUCCESS) {
	debug_pam(ctx, args, "cannot set context data", pamret);
	goto fail;
    }
    *newctx = ctx;
    return PAM_SUCCESS;

fail:
    if (ctx != NULL)
	free_context(ctx);
    return pamret;
}

/* Called after a successful authentication. Set user credentials. */
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
	       const char **argv)
{
    struct context *ctx;
    struct pam_args *args;
    struct credlist *clist = NULL;
    krb5_ccache cache = NULL;
    char *cache_name = NULL;
    int reinit = 0;
    int pamret;
    struct passwd *pw = NULL;
    uid_t uid;
    gid_t gid;

    pamret = fetch_context(pamh, &ctx);
    args = parse_args(ctx, flags, argc, argv);
    ENTRY(ctx, args, flags);

    if (flags & PAM_DELETE_CRED) {
	pamret = pam_set_data(pamh, "ctx", NULL, destroy_context);
        goto done;
    }

    if (flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED))
	reinit = 1;

    /* XXX: it may be worth checking for REINIT/REFRESH and ESTABLISH set
     * at the same time; currently, REINIT/REFRESH will simply override.. */
    if (!(flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED | PAM_ESTABLISH_CRED))) {
        pamret = PAM_SERVICE_ERR;
        goto done;
    }

    /*
     * pamret holds the status of fetch_context from above, so indicates
     * whether we were able to successfully find the context from the previous
     * authentication.  If we weren't, we were probably run by OpenSSH with
     * its broken PAM handling, so we're going to cobble up a new context for
     * ourselves.
     */
    if (pamret != PAM_SUCCESS) {
	debug(ctx, args, "no context found, creating one");
	pamret = create_session_context(args, pamh, &ctx);
	if (ctx == NULL)
	    goto done;
    }

    /* Revalidate the user. */
    pamret = validate_auth(ctx, args);
    if (pamret != PAM_SUCCESS)
        goto done;

    /* Some programs (xdm, for instance) appear to call setcred over and
     * over again, so avoid doing useless work. */
    if (ctx->initialized)
	return PAM_SUCCESS;

    if (args->no_ccache)
	goto done;

    /* Get the uid. This should exist. */
    pw = getpwnam(ctx->name);
    if (!pw) {
	debug(ctx, args, "getpwnam failed for %s", ctx->name);
	pamret = PAM_USER_UNKNOWN;
	goto done;
    }
    uid = pw->pw_uid;
    gid = pw->pw_gid;

    /* Get the cache name */
    if (reinit) {
	const char *name, *k5name;

	name = get_krb5ccname(ctx, "KRB5CCNAME");
	if (name == NULL) {
	    debug(ctx, args, "unable to get KRB5CCNAME");
	    pamret = PAM_SERVICE_ERR;
	    goto done;
	}

	/*
         * If the cache we have in the context and the cache we're
         * reinitializing are the same cache, don't do anything; otherwise,
         * we'll end up destroying the cache.
         */
	if (ctx->cache != NULL) {
	    k5name = krb5_cc_get_name(ctx->context, ctx->cache);
	    if (k5name != NULL && strcmp(name, k5name) == 0) {
		pamret = PAM_SUCCESS;
		goto done;
	    }
	}

	cache_name = strdup(name);
	if (!cache_name) {
	    error(ctx, "malloc failure: %s", strerror(errno));
	    pamret = PAM_BUF_ERR;
	    goto done;
	}
	debug(ctx, args, "refreshing ticket cache %s", cache_name);

	/*
         * If we're refreshing the cache, we didn't really create it and the
         * user's open session created by login is probably still managing
         * it.  Thus, don't remove it when PAM is shut down.
         */
	ctx->dont_destroy_cache = 1;
    }
    else {
	int ccache_fd;
	size_t len;

	cache_name = build_ccache_name(ctx, args, uid);
	if (cache_name == NULL) {
	    pamret = PAM_BUF_ERR;
	    goto done;
	}
	len = strlen(cache_name);
	if (len > 6 && strncmp("XXXXXX", cache_name + len - 6, 6) == 0) {
	    ccache_fd = mkstemp(cache_name);
	    if (ccache_fd == -1) {
		error(ctx, "mkstemp failure: %s", strerror(errno));
		pamret = PAM_SERVICE_ERR;
		goto done;
	    }
	    close(ccache_fd);
	}
    }

    /* Initialize the new ccache */
    debug(ctx, args, "initializing ticket cache %s", cache_name);
    pamret = copy_credlist(ctx, &clist, ctx->cache);
    if (pamret != PAM_SUCCESS)
	goto done;
    pamret = init_ccache(ctx, args, cache_name, clist, &cache);
    if (pamret != PAM_SUCCESS)
	goto done;
    if (chown(cache_name, uid, gid) == -1) {
	debug(ctx, args, "chown of ticket cache failed: %s", strerror(errno));
	pamret = PAM_SERVICE_ERR;	
	goto done;
    }
    pamret = set_krb5ccname(ctx, cache_name, "KRB5CCNAME");
    if (pamret != PAM_SUCCESS)
	goto done;
    if (pam_getenv(pamh, "PAM_KRB5CCNAME") != NULL) {
        pamret = pam_putenv(pamh, "PAM_KRB5CCNAME");
	if (pamret != PAM_SUCCESS)
	    goto done;
    }
    ctx->initialized = 1;

    krb5_cc_destroy(ctx->context, ctx->cache);
    ctx->cache = cache;
    cache = NULL;

done:
    if (cache)
	krb5_cc_destroy(ctx->context, cache);
    if (cache_name)
	free(cache_name);
    free_credlist(ctx, clist);
    EXIT(ctx, args, pamret);
    free_args(args);
    return pamret;
}
