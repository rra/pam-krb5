/*
 * context.c
 *
 * Manage context structure
 */

#include "context.h"
#include "pam_krb5.h"
#include <string.h>

int
new_context(pam_handle_t *pamh, struct context **ctx)
{
	struct context *c;
	int retval;

	c = calloc(1, sizeof(*c));
	if (!c) {
		retval = PAM_BUF_ERR;
		goto done;
	}
	*ctx = c;
	c->pamh = pamh;

	/* this will prompt for the username if it's not already set;
	 * otherwise, just grab the saved username. */
	retval = pam_get_user(c->pamh, &c->name, NULL);
	if (retval != PAM_SUCCESS || c->name == NULL) {
		if (retval == PAM_CONV_AGAIN)
			retval = PAM_INCOMPLETE;
		else
			retval = PAM_SERVICE_ERR;
		goto done;
	}
	pam_get_item(c->pamh, PAM_SERVICE, (const void **) &c->service);
	if (c->service == NULL)
		c->service = "unknown";

	if ((retval = krb5_init_context(&c->context)) != 0) {
		dlog(c, "krb5_init_context(): %s", error_message(retval));
		retval = PAM_SERVICE_ERR;
		goto done;
	}

	retval = valid_context(c);
done:
	if (c && retval != PAM_SUCCESS) {
		free_context(c);
		*ctx = NULL;
	}
	return retval;
}

int
fetch_context(pam_handle_t *pamh, struct context **ctx)
{
	int pamret;

	if ((pamret = pam_get_data(pamh, "ctx", (void *) ctx)) != PAM_SUCCESS)
		goto done;
	pamret = valid_context(*ctx);
done:
	if (pamret != PAM_SUCCESS)
		*ctx = NULL;
	return pamret;
}

int
valid_context(struct context *c)
{
	int retval = PAM_SERVICE_ERR;

	if (!c)
		goto done;
	if (!c->name)
		goto done;
	if (pam_args.ignore_root && strcmp("root", c->name) == 0)
		goto done;

        /* Fetch the principal unless we're going to be searching through the
           .k5login file.  If we are going to be searching, don't set a
           principal here, since otherwise we'll fail krb5_kuserok before we
           get a chance to try. */
	if (!c->princ && !pam_args.search_k5login) {
		if ((retval = krb5_parse_name(c->context, c->name,
					       &c->princ)) != 0) {
			dlog(c, "krb5_parse_name(): %s", error_message(retval));
			retval = PAM_SERVICE_ERR;
			goto done;
		}
	}

	if (c->princ && !krb5_kuserok(c->context, c->princ, c->name)) {
		retval = PAM_SERVICE_ERR;
		goto done;
	}
	retval = PAM_SUCCESS;
done:
	return retval;
}

void
free_context(struct context *ctx)
{
	if (ctx->context) {
		if (ctx->princ)
			krb5_free_principal(ctx->context, ctx->princ);
		if (ctx->cache && !ctx->dont_destroy_cache) {
			dlog(ctx, "krb5_cc_destroy: ctx->cache: %s",
					krb5_cc_get_name(ctx->context, ctx->cache));
			krb5_cc_destroy(ctx->context, ctx->cache);
		}
		krb5_free_context(ctx->context);
	}
	free(ctx);
}
