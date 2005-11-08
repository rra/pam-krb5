/*
 * credlist.h
 *
 */

#ifndef CREDLIST_H_
#define CREDLIST_H_

#include <krb5.h>

struct credlist
{
	krb5_creds creds;
	struct credlist *next;
};

struct context;

int new_credlist(struct context *ctx, struct credlist **clist);
int append_to_credlist(struct context *ctx, struct credlist **clist,
		krb5_creds creds);
int copy_credlist(struct context *ctx, struct credlist **clist,
		krb5_ccache cache);
void free_credlist(struct context *ctx, struct credlist *clist);

#endif /* CREDLIST_H_ */
