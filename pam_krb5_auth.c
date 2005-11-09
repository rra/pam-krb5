/*
 * pam_krb5_auth.c
 *
 * PAM authentication management functions for pam_krb5
 *
 */

#define PAM_SM_AUTH

#include <errno.h>
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

static void
destroy_context(pam_handle_t *pamh, void *data, int pam_end_status)
{
	struct context *ctx = (struct context *) data;
	if (ctx)
		free_context(ctx);
}

/* Authenticate a user via krb5 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
		    const char **argv)
{
    struct context *ctx = NULL;
    struct credlist *clist = NULL;
    int pamret = PAM_SERVICE_ERR;
    char cache_name[L_tmpnam + 8];

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

    /* Generate a unique cache_name */
    strcpy(cache_name, "MEMORY:");
    tmpnam(&cache_name[7]);

    if ((pamret = password_auth(ctx, NULL, &clist)) != PAM_SUCCESS)
	goto done;
    if ((pamret = init_ccache(ctx, cache_name, clist, &ctx->cache)) != PAM_SUCCESS)
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

static const char *
get_krb5ccname(struct context *ctx)
{
	const char *name;

	/* TODO: figure out why pam_getenv() returns NULL */
	name = getenv("KRB5CCNAME");
	if (!name && ctx && ctx->context && ctx->cache)
		name = krb5_cc_get_name(ctx->context, ctx->cache);

	return name;
}

static int
set_krb5ccname(struct context *ctx, const char *name)
{
	char *env_name = NULL;
	int pamret;
       
	env_name = malloc(sizeof("KRB5CCNAME=") + strlen(name));
	if (!env_name) {
		dlog(ctx, "malloc() failure");
		pamret = PAM_BUF_ERR;
		goto done;
	}

	sprintf(env_name, "KRB5CCNAME=%s", name);
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
    uid_t euid = geteuid(); /* Usually 0 */
    gid_t egid = getegid();

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
    if (pamret != PAM_SUCCESS)
	goto done;

    if (pam_args.no_ccache)
	goto done;

    /* Get the uid. This should exist. */
    pw = getpwnam(ctx->name);
    if (!pw) {
	dlog(ctx, "getpwnam(): %s", ctx->name);
	pamret = PAM_USER_UNKNOWN;
	goto done;
    }

    /* Avoid following a symlink as root */
    if (setegid(pw->pw_gid)) {
	dlog(ctx, "setegid(): %s", ctx->name);
	pamret = PAM_SERVICE_ERR;
	goto done;
    }
    if (seteuid(pw->pw_uid)) {
	dlog(ctx, "seteuid(): %s", ctx->name);
	pamret = PAM_SERVICE_ERR;
	goto done;
    }

    /* Get the cache name */
    if (reinit) {
	const char *name = get_krb5ccname(ctx);
	if (!name) {
	    dlog(ctx, "Unable to get KRBCCNAME!");
	    pamret = PAM_SERVICE_ERR;
	    goto done;
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
        size_t ccache_size = 1 + strlen(pam_args.ccache_dir) +
		strlen("/krb5cc_4294967295_XXXXXX");

        cache_name = malloc(ccache_size);
	if (!cache_name) {
	    dlog(ctx, "malloc() failure");
	    pamret = PAM_BUF_ERR;
	    goto done;
	}
        snprintf(cache_name, ccache_size, "%s/krb5cc_%d_XXXXXX",
			pam_args.ccache_dir, pw->pw_uid);
	ccache_fd = mkstemp(cache_name);
	if (ccache_fd == -1) {
            dlog(ctx, "mkstemp() failure");
	    pamret = PAM_BUF_ERR;
	    goto done;
	}
	close(ccache_fd);

    }

    /* Initialize the new ccache */
    dlog(ctx, "%s: initializing cred cache %s", __FUNCTION__, cache_name);
    if ((pamret = copy_credlist(ctx, &clist, ctx->cache)) != PAM_SUCCESS)
	goto done;
    if ((pamret = init_ccache(ctx, cache_name, clist, &cache)) != PAM_SUCCESS)
	goto done;

    if (chown(cache_name, pw->pw_uid, pw->pw_gid) == -1) {
	dlog(ctx, "chown(): %s", strerror(errno));
	pamret = PAM_SERVICE_ERR;	
	goto done;
    }
    if ((pamret = set_krb5ccname(ctx, cache_name)) != PAM_SUCCESS)
	goto done;

    if (!reinit)
    	krb5_cc_destroy(ctx->context, ctx->cache);
    ctx->cache = cache;
    cache = NULL;

done:
    if (cache)
	krb5_cc_destroy(ctx->context, cache);
    if (cache_name)
	free(cache_name);
    free_credlist(ctx, clist);
    seteuid(euid);
    setegid(egid);
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

