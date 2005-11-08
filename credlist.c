/*
 * credlist.c
 *
 * Simple list of krb5_creds
 */

#include "credlist.h"
#include "pam_krb5.h"
#include <stdlib.h>

int
new_credlist(struct context *ctx, struct credlist **clist)
{
	*clist = NULL;
	return PAM_SUCCESS;
}

void
free_credlist(struct context *ctx, struct credlist *clist)
{
	struct credlist *c;

	while (clist) {
		krb5_free_cred_contents(ctx->context, &clist->creds);
		c = clist;
		clist = clist->next;
		free(c);
	}
}

int
append_to_credlist(struct context *ctx, struct credlist **clist,
		krb5_creds creds)
{
	struct credlist *c = calloc(1, sizeof(*c));

	if (!c) {
		dlog(ctx, "calloc() failure");
		return PAM_BUF_ERR;
	}
	c->creds = creds;
	c->next = *clist;
	*clist = c;

	return PAM_SUCCESS;
}

int
copy_credlist(struct context *ctx, struct credlist **clist,
		krb5_ccache cache)
{
	krb5_cc_cursor c;
	krb5_creds creds;
	int retval;

	if ((retval = krb5_cc_start_seq_get(ctx->context, cache, &c)) != 0) {
		dlog(ctx, "krb5_cc_start_seq_get(): %s", error_message(retval));
		return PAM_SERVICE_ERR;
	}

	while (krb5_cc_next_cred(ctx->context, cache, &c, &creds) == 0) {
		if ((retval = append_to_credlist(ctx, clist, creds)) != PAM_SUCCESS)
			goto done;
	}
	retval = PAM_SUCCESS;

done:
	krb5_cc_end_seq_get(ctx->context, cache, &c);
	return retval;
}
