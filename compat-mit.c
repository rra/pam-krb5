/*
 * compat-mit.c
 *
 * Kerberos compatibility functions for MIT Kerberos.
 */

#include "config.h"

#ifdef HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#else
# include <com_err.h>
#endif
#include <errno.h>
#include <krb5.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

void
pamk5_compat_free_data_contents(krb5_context c, krb5_data *data)
{
    krb5_free_data_contents(c, data);
}


void
pamk5_compat_free_keytab_contents(krb5_context c, krb5_keytab_entry *entry)
{
    krb5_free_keytab_entry_contents(c, entry);
}


#ifdef HAVE_KRB5_GET_ERROR_MESSAGE
const char *
pamk5_compat_get_error(krb5_context c, krb5_error_code code)
{
    const char *msg;

    msg = krb5_get_error_message(c, code);
    if (msg == NULL)
        return "unknown error";
    else
        return msg;
}
#else /* !HAVE_KRB5_GET_ERROR_MESSAGE */
const char *
pamk5_compat_get_error(krb5_context c, krb5_error_code code)
{
    return error_message(code);
}
#endif


#ifdef HAVE_KRB5_FREE_ERROR_MESSAGE
void
pamk5_compat_free_error(krb5_context c, const char *msg)
{
    krb5_free_error_message(c, msg);
}
#else /* !HAVE_KRB5_FREE_ERROR_MESSAGE */
void
pamk5_compat_free_error(krb5_context c, const char *msg)
{
    return;
}
#endif /* !HAVE_KRB5_FREE_ERROR_MESSAGE */


krb5_error_code
pamk5_compat_set_realm(struct pam_args *args, const char *realm)
{
    pamk5_compat_free_realm(args);
    args->realm_data = malloc(sizeof(*args->realm_data));
    if (args->realm_data == NULL)
        return errno;
    args->realm_data->data = strdup(realm);
    if (args->realm_data->data == NULL) {
        free(args->realm_data);
        args->realm_data = NULL;
        return errno;
    }
    args->realm_data->magic = KV5M_DATA;
    args->realm_data->length = strlen(realm);
    return 0;
}


void
pamk5_compat_free_realm(struct pam_args *args)
{
    if (args->realm_data != NULL) {
        if (args->realm_data->data != NULL)
            free(args->realm_data->data);
        free(args->realm_data);
    }
}
