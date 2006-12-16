/*
 * credlist.c
 *
 * Simple list of krb5_creds.
 *
 * Used to stash credentials temporarily until they can be stored in a ticket
 * cache, or when copying credentials between ticket caches.
 */

#include "config.h"

#include <errno.h>
#include <krb5.h>
#include <stdlib.h>

#include "internal.h"


/*
 * Initialize a credlist structure.
 */
void
pamk5_credlist_new(struct credlist **clist)
{
    *clist = NULL;
}


/*
 * Free a credlist, including all of the credentials stored in it.
 */
void
pamk5_credlist_free(struct credlist **clist, krb5_context context)
{
    struct credlist *c;

    while (*clist != NULL) {
        krb5_free_cred_contents(context, &(*clist)->creds);
        c = *clist;
        *clist = (*clist)->next;
        free(c);
    }
}


/*
 * Append a credential to a credlist.  Returns 0 on success and ENOMEM on
 * failure.
 */
krb5_error_code
pamk5_credlist_append(struct credlist **clist, krb5_creds creds)
{
    struct credlist *c;

    c = calloc(1, sizeof(*c));
    if (c == NULL)
        return ENOMEM;
    c->creds = creds;
    c->next = *clist;
    *clist = c;
    return 0;
}


/*
 * Copy the credentials from a ticket cache into a credlist.  Returns a
 * Kerberos v5 error code.
 */
krb5_error_code
pamk5_credlist_copy(struct credlist **clist, krb5_context context,
                    krb5_ccache cache)
{
    krb5_cc_cursor c;
    krb5_creds creds;
    int retval;

    retval = krb5_cc_start_seq_get(context, cache, &c);
    if (retval != 0)
        return retval;
    while (krb5_cc_next_cred(context, cache, &c, &creds) == 0) {
        retval = pamk5_credlist_append(clist, creds);
        if (retval != 0)
            goto done;
    }
    retval = 0;

done:
    krb5_cc_end_seq_get(context, cache, &c);
    return retval;
}


/*
 * Store the credentials from a credlist into a ticket cache.  Returns a
 * Kerberos v5 error code.
 */
krb5_error_code
pamk5_credlist_store(struct credlist **clist, krb5_context context,
                     krb5_ccache cache)
{
    struct credlist *cred;
    int retval;

    for (cred = *clist; cred != NULL; cred = cred->next) {
        retval = krb5_cc_store_cred(context, cache, &cred->creds);
        if (retval != 0)
            return retval;
    }
    return 0;
}
