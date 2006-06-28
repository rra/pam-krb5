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
		error(c, "krb5_init_context: %s", error_message(retval));
		retval = PAM_SERVICE_ERR;
		goto done;
	}

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

done:
	if (pamret != PAM_SUCCESS)
		*ctx = NULL;
	return pamret;
}

void
free_context(struct context *ctx)
{
	if (ctx == NULL)
		return;
	if (ctx->context) {
		if (ctx->princ)
			krb5_free_principal(ctx->context, ctx->princ);
		if (ctx->cache && !ctx->dont_destroy_cache) {
			krb5_cc_destroy(ctx->context, ctx->cache);
		}
		krb5_free_context(ctx->context);
	}
	free(ctx);
}

void
destroy_context(pam_handle_t *pamh, void *data, int pam_end_status)
{
	struct context *ctx = (struct context *) data;
	if (ctx)
		free_context(ctx);
}
