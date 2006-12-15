/*
 * credlist.c
 *
 * Simple list of krb5_creds.
 *
 * Used to stash credentials temporarily until they can be stored in a ticket
 * cache, or when copying credentials between ticket caches.
 */

#include "config.h"

#include <krb5.h>
#include <stdlib.h>

#include "internal.h"


/*
 * Initialize a credlist structure.
 */
int
pamk5_credlist_new(struct context *ctx, struct credlist **clist)
{
    *clist = NULL;
    return PAM_SUCCESS;
}


/*
 * Free a credlist, including all of the credentials stored in it.
 */
void
pamk5_credlist_free(struct context *ctx, struct credlist *clist)
{
    struct credlist *c;

    while (clist != NULL) {
        krb5_free_cred_contents(ctx->context, &clist->creds);
        c = clist;
        clist = clist->next;
        free(c);
    }
}


/*
 * Append a credential to a credlist.  Returns PAM_BUF_ERR on failure and
 * PAM_SUCCESS on success.
 */
int
pamk5_credlist_append(struct context *ctx, struct credlist **clist,
                      krb5_creds creds)
{
    struct credlist *c;

    c = calloc(1, sizeof(*c));
    if (c == NULL)
        return PAM_BUF_ERR;
    c->creds = creds;
    c->next = *clist;
    *clist = c;
    return PAM_SUCCESS;
}


/*
 * Copy the credentials from a ticket cache into a credlist.  Returns
 * PAM_SUCCESS on success and PAM_SERVICE_ERR on failure.
 */
int
pamk5_credlist_copy(struct context *ctx, struct credlist **clist,
                    krb5_ccache cache)
{
    krb5_cc_cursor c;
    krb5_creds creds;
    int retval;

    retval = krb5_cc_start_seq_get(ctx->context, cache, &c);
    if (retval != 0)
        return PAM_SERVICE_ERR;
    while (krb5_cc_next_cred(ctx->context, cache, &c, &creds) == 0) {
        retval = pamk5_credlist_append(ctx, clist, creds);
        if (retval != PAM_SUCCESS)
            goto done;
    }
    retval = PAM_SUCCESS;

done:
    krb5_cc_end_seq_get(ctx->context, cache, &c);
    return retval;
}
