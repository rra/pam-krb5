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


const char *
pamk5_compat_get_err_text(krb5_context c, krb5_error_code code)
{
    return error_message(code);
}


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
