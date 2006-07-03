/*
 * compat_mit.c
 *
 * Kerberos compatibility functions for MIT Kerberos.
 */

#include <krb5.h>

#include "pam_krb5.h"

const char *
compat_princ_component(krb5_context context, krb5_principal princ, int n)
{
    return krb5_princ_component(context, princ, n)->data;
}


void
compat_free_data_contents(krb5_context context, krb5_data *data)
{
    krb5_free_data_contents(context, data);
}


krb5_error_code
compat_cc_next_cred(krb5_context context, const krb5_ccache id, 
                    krb5_cc_cursor *cursor, krb5_creds *creds)
{
    return krb5_cc_next_cred(context, id, cursor, creds);
}


static krb5_error_code
mit_pam_prompter(krb5_context context, void *data, const char *name,
                 const char *banner, int num_prompts, krb5_prompt prompts[])
{
    return prompter_krb5(context, data, name, banner, num_prompts, prompts);
}

krb5_prompter_fct pam_prompter = mit_pam_prompter;
