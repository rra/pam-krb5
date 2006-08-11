/*
 * compat_heimdal.c
 *
 * Kerberos compatibility functions for Heimdal.
 */

#include <krb5.h>

#include "pam_krb5.h"

const char *
pamk5_compat_princ_component(krb5_context c, krb5_principal princ, int n)
{
    return princ->name.name_string.val[n];
}


void
pamk5_compat_free_data_contents(krb5_context c, krb5_data *data)
{
    krb5_data_free(data);
}


krb5_error_code
pamk5_compat_cc_next_cred(krb5_context c, const krb5_ccache id, 
                          krb5_cc_cursor *cursor, krb5_creds *creds)
{
    return krb5_cc_next_cred(c, id, creds, cursor);
}


static krb5_error_code
heimdal_pam_prompter(krb5_context c, void *data, const char *banner,
                     int num_prompts, krb5_prompt prompts[])
{
    return pamk5_prompter_krb5(c, data, NULL, banner, num_prompts, prompts);
}

krb5_prompter_fct pamk5_pam_prompter = heimdal_pam_prompter;
