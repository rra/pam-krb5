/*
 * compat_heimdal.c
 *
 * Kerberos compatibility functions for Heimdal.
 */

#include <krb5.h>

#include "pam_krb5.h"

void
pamk5_compat_free_data_contents(krb5_context c, krb5_data *data)
{
    krb5_data_free(data);
}


const char *
pamk5_compat_get_err_text(krb5_context c, krb5_error_code code)
{
    return krb5_get_err_text(c, code);
}


static krb5_error_code
heimdal_pam_prompter(krb5_context c, void *data, const char *banner,
                     int num_prompts, krb5_prompt prompts[])
{
    return pamk5_prompter_krb5(c, data, NULL, banner, num_prompts, prompts);
}

krb5_prompter_fct pamk5_pam_prompter = heimdal_pam_prompter;
