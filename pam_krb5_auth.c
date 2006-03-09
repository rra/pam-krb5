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

void Jokostat(char *);
extern krb5_cc_ops krb5_mcc_ops;

#if 0
static int
to_local_user(struct context *ctx)
{
	char lname[64];
	int retval;

	memset(lname, 0, sizeof(lname));

	/* get a local account name for this principal */
	if ((retval = krb5_aname_to_localname(ctx->context, ctx->princ,
					sizeof(lname), lname)) != 0) {
		dlog(ctx, "krb5_aname_to_localname(): %s", error_message(retval));
		retval = PAM_USER_UNKNOWN;
		goto done;
	}
	
	dlog(ctx, "changing PAM_USER to %s", lname);
	if ((retval = pam_set_item(ctx->pamh, PAM_USER, lname)) != 0) {
		dlog(ctx, "pam_set_item(): %s", pam_strerror(ctx->pamh, retval));
		retval = PAM_SERVICE_ERR;
		goto done;
	}
	if ((retval = pam_get_item(ctx->pamh, PAM_USER, (const void **) &ctx->name) != 0)) {
		dlog(ctx, "pam_get_item(): %s", pam_strerror(ctx->pamh, retval));
		retval = PAM_SERVICE_ERR;
	}
done:
	return retval;
}
#endif

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
		dlog(ctx, "malloc() failure");
		pamret = PAM_BUF_ERR;
		goto done;
	}

	sprintf(env_name, "%s=%s", key, name);
	if ((pamret = pam_putenv(ctx->pamh, env_name)) != PAM_SUCCESS) {
		dlog(ctx, "pam_putenv(): %s", pam_strerror(ctx->pamh, pamret));
		pamret = PAM_SERVICE_ERR;
		goto done;
	}

	pamret = PAM_SUCCESS;
done:
	if (env_name)
		free(env_name);
	return pamret;
}

/* Authenticate a user via krb5.

   It would be nice to be able to save the ticket cache temporarily as a
   memory cache and then only write it out to disk during the session
   initialization.  Unfortunately, OpenSSH 4.2 does PAM authentication in a
   subprocess and therefore has no saved module-specific data available once
   it opens a session, so we have to save the ticket cache to disk and store
   in the environment where it is. */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
		    const char **argv)
{
    struct context *ctx = NULL;
    struct credlist *clist = NULL;
    int pamret = PAM_SERVICE_ERR;
    char cache_name[] = "/tmp/krb5cc_pam_XXXXXX";
    int ccfd;

    parse_args(flags, argc, argv);
    dlog(ctx, "%s: entry", __FUNCTION__);

    if ((pamret = new_context(pamh, &ctx)) != PAM_SUCCESS)
	    goto done;

    /* do this first, so destroy_context magically cleans up for us */
    if ((pamret = pam_set_data(pamh, "ctx", ctx,
				    destroy_context)) != PAM_SUCCESS) {
	free_context(ctx);
	pamret = PAM_SERVICE_ERR;
	goto done;
    }

    if ((pamret = password_auth(ctx, NULL, &clist)) != PAM_SUCCESS)
	goto done;
    ccfd = mkstemp(cache_name);
    if (ccfd < 0) {
	dlog(ctx, "mkstemp(\"%s\") failed: %s", cache_name, strerror(errno));
	pamret = PAM_SERVICE_ERR;
	goto done;
    }
    close(ccfd);
    if ((pamret = init_ccache(ctx, cache_name, clist, &ctx->cache)) != PAM_SUCCESS)
	goto done;
    if ((pamret = validate_auth(ctx)) != PAM_SUCCESS)
        goto done;
    if ((pamret = set_krb5ccname(ctx, cache_name, "PAM_KRB5CCNAME")) != PAM_SUCCESS)
	goto done;

done:
    free_credlist(ctx, clist);
    dlog(ctx, "%s: exit (%s)", __FUNCTION__, pamret ? "failure" : "success");

    /* Clear the context on failure so that the account management module
       knows that we didn't authenticate with Kerberos. */
    if (pamret != PAM_SUCCESS)
	pam_set_data(pamh, "ctx", NULL, NULL);
    return pamret;
}

/* Determine the name of the ticket cache.  Handles ccache and ccache_dir PAM
   options and returns newly allocated memory. */
static char *
build_ccache_name(struct context *ctx, uid_t uid)
{
    char *cache_name;

    if (pam_args.ccache == NULL) {
	size_t ccache_size = 1 + strlen(pam_args.ccache_dir) +
	    strlen("/krb5cc_4294967295_XXXXXX");

	cache_name = malloc(ccache_size);
	if (!cache_name) {
	    dlog(ctx, "malloc() failure");
	    return NULL;
	}
	snprintf(cache_name, ccache_size, "%s/krb5cc_%d_XXXXXX",
			pam_args.ccache_dir, uid);
    } else {
	size_t len = 0, delta;
	char *p, *q;

	for (p = pam_args.ccache; *p != '\0'; p++) {
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
	    dlog(ctx, "malloc() failure");
	    return NULL;
	}
	for (p = pam_args.ccache, q = cache_name; *p != '\0'; p++) {
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
create_session_context(pam_handle_t *pamh, struct context **newctx)
{
    struct context *ctx = NULL;
    const char *tmpname;
    int pamret;

    if (pam_args.ignore_root) {
        pamret = pam_get_user(pamh, &tmpname, NULL);
        if (pamret == PAM_SUCCESS && strcmp("root", tmpname) == 0) {
            dlog(ctx, "ignoring root login");
            pamret = PAM_SUCCESS;
            goto fail;
        }
    }
    pamret = new_context(pamh, &ctx);
    if (pamret != PAM_SUCCESS) {
	dlog(ctx, "creating session context failed");
	goto fail;
    }
    tmpname = get_krb5ccname(ctx, "PAM_KRB5CCNAME");
    if (tmpname == NULL) {
	dlog(ctx, "unable to get PAM_KRB5CCNAME, assuming non-Kerberos login");
	pamret = PAM_SUCCESS;
	goto fail;
    }
    dlog(ctx, "found initial ticket cache at %s", tmpname);
    if (krb5_cc_resolve(ctx->context, tmpname, &ctx->cache) != 0) {
	dlog(ctx, "cannot resolve cache %s", tmpname);
	pamret = PAM_SERVICE_ERR;
	goto fail;
    }
    if (krb5_cc_get_principal(ctx->context, ctx->cache, &ctx->princ) != 0) {
	dlog(ctx, "cannot retrieve principal");
	pamret = PAM_SERVICE_ERR;
	goto fail;
    }
    if ((pamret = pam_set_data(pamh, "ctx", ctx,
			       destroy_context)) != PAM_SUCCESS) {
	dlog(ctx, "cannot set context data");
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
    struct context *ctx = NULL;
    struct credlist *clist = NULL;
    krb5_ccache cache = NULL;
    char *cache_name = NULL;
    int reinit = 0;
    int pamret;
    struct passwd *pw = NULL;
    uid_t uid;
    gid_t gid;

    parse_args(flags, argc, argv);
    dlog(ctx, "%s: entry (0x%x)", __FUNCTION__, flags); 

    if (flags & PAM_DELETE_CRED)
	return pam_set_data(pamh, "ctx", NULL, destroy_context);

    if (flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED))
	reinit = 1;

    /* XXX: it may be worth checking for REINIT/REFRESH and ESTABLISH set
     * at the same time; currently, REINIT/REFRESH will simply override.. */
    if (!(flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED | PAM_ESTABLISH_CRED)))
	return PAM_SERVICE_ERR;

    pamret = fetch_context(pamh, &ctx);
    if (pamret != PAM_SUCCESS) {
	dlog(ctx, "%s: no context found, creating one", __FUNCTION__);
	pamret = create_session_context(pamh, &ctx);
	if (ctx == NULL)
	    goto done;
    }

    /* Revalidate the user. */
    pamret = validate_auth(ctx);
    if (pamret != PAM_SUCCESS)
        goto done;

    /* Some programs (xdm, for instance) appear to call setcred over and
     * over again, so avoid doing useless work. */
    if (ctx->initialized)
	return PAM_SUCCESS;

    if (pam_args.no_ccache)
	goto done;

    /* Get the uid. This should exist. */
    pw = getpwnam(ctx->name);
    if (!pw) {
	dlog(ctx, "getpwnam(): %s", ctx->name);
	pamret = PAM_USER_UNKNOWN;
	goto done;
    }
    uid = pw->pw_uid;
    gid = pw->pw_gid;

    /* Get the cache name */
    if (reinit) {
	const char *name, *k5name;

	name = get_krb5ccname(ctx, "KRB5CCNAME");
	if (!name) {
	    dlog(ctx, "Unable to get KRB5CCNAME!");
	    pamret = PAM_SERVICE_ERR;
	    goto done;
	}

	/* If the cache we have in the context and the cache we're
	 * reinitializing are the same cache, don't do anything; otherwise,
	 * we'll end up destroying the cache. */
	if (ctx->cache != NULL) {
	    k5name = krb5_cc_get_name(ctx->context, ctx->cache);
	    if (k5name != NULL && strcmp(name, k5name) == 0) {
		pamret = PAM_SUCCESS;
		goto done;
	    }
	}

	cache_name = strdup(name);
	if (!cache_name) {
	    dlog(ctx, "malloc() failure");
	    pamret = PAM_BUF_ERR;
	    goto done;
	}
	dlog(ctx, "%s: attempting to refresh cred cache %s", __FUNCTION__, cache_name);

	/* If we're refreshing the cache, we didn't really create it;
	 * some other application (probably login?) is still using it.
	 * Thus, don't remove it! */
	ctx->dont_destroy_cache = 1;
    }
    else {
	int ccache_fd;
	size_t len;

	cache_name = build_ccache_name(ctx, uid);
	if (cache_name == NULL) {
	    pamret = PAM_BUF_ERR;
	    goto done;
	}
	len = strlen(cache_name);
	if (len > 6 && strncmp("XXXXXX", cache_name + len - 6, 6) == 0) {
	    ccache_fd = mkstemp(cache_name);
	    if (ccache_fd == -1) {
		dlog(ctx, "mkstemp() failure");
		pamret = PAM_SERVICE_ERR;
		goto done;
	    }
	    close(ccache_fd);
	}
    }

    /* Initialize the new ccache */
    dlog(ctx, "%s: initializing cred cache %s", __FUNCTION__, cache_name);
    if ((pamret = copy_credlist(ctx, &clist, ctx->cache)) != PAM_SUCCESS)
	goto done;
    if ((pamret = init_ccache(ctx, cache_name, clist, &cache)) != PAM_SUCCESS)
	goto done;

    if (chown(cache_name, uid, gid) == -1) {
	dlog(ctx, "chown(): %s", strerror(errno));
	pamret = PAM_SERVICE_ERR;	
	goto done;
    }
    if ((pamret = set_krb5ccname(ctx, cache_name, "KRB5CCNAME")) != PAM_SUCCESS)
	goto done;
    if (pam_getenv(pamh, "PAM_KRB5CCNAME") != NULL)
	if ((pamret = pam_putenv(pamh, "PAM_KRB5CCNAME")) != PAM_SUCCESS)
	    goto done;
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
    dlog(ctx, "%s: exit (%s)", __FUNCTION__, pamret ? "failure" : "success");
    return pamret;
}

#include <sys/stat.h>
void Jokostat(char *n)
{
	struct stat	b;
	int		ret;

	if (strstr(n, "FILE:") != n) {
		syslog(LOG_DEBUG, "Jokostat: no fcache: %s", n);
		return;
	}

	ret=stat(&n[5],&b);
	if(ret!=0)
	{
		syslog(LOG_DEBUG, "Jokostat prout");
		return;
	}

	syslog(LOG_DEBUG, "Jokostat: %d %d:%d %o", geteuid(), b.st_uid, b.st_gid, b.st_mode);

	return;
}

