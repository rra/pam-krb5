/*
 * context.h
 *
 */

#ifndef CONTEXT_H_
#define CONTEXT_H_

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <krb5.h>

struct context
{
	pam_handle_t *pamh;
	const char *name, *service;
	krb5_context context;

	/* principal and cache information */
	krb5_ccache cache;
	krb5_principal princ;
	int dont_destroy_cache;
	int initialized;
};

int new_context(pam_handle_t *pamh, struct context **ctx);
int fetch_context(pam_handle_t *pamh, struct context **ctx);
int valid_context(struct context *ctx);
void free_context(struct context *ctx);
void destroy_context(pam_handle_t *pamh, void *data, int pam_end_status);

#endif /* CONTEXT_H_ */
