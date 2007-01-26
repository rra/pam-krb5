/*
 * compat-heimdal.c
 *
 * Kerberos compatibility functions for Heimdal.
 */

#include "config.h"

#include <errno.h>
#include <krb5.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

void
pamk5_compat_free_data_contents(krb5_context c, krb5_data *data)
{
    krb5_data_free(data);
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
    return krb5_get_err_text(c, code);
}
#endif /* !HAVE_KRB5_GET_ERROR_MESSAGE */


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


void
pamk5_compat_free_error(krb5_context c, const char *msg)
{
    return;
}


krb5_error_code
pamk5_compat_set_realm(struct pam_args *args, const char *realm)
{
    pamk5_compat_free_realm(args);
    args->realm_data = strdup(realm);
    if (args->realm_data == NULL)
        return errno;
    return 0;
}


void
pamk5_compat_free_realm(struct pam_args *args)
{
    if (args->realm_data != NULL) {
        free(args->realm_data);
        args->realm_data = NULL;
    }
}
