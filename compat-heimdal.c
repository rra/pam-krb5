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


void
pamk5_compat_free_keytab_contents(krb5_context c, krb5_keytab_entry *entry)
{
    krb5_kt_free_entry(c, entry);
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
