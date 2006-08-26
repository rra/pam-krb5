/*
 * compat_mit.c
 *
 * Kerberos compatibility functions for MIT Kerberos.
 */

#ifdef HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#else
# include <com_err.h>
#endif
#include <krb5.h>

#include "pam_krb5.h"

const char *
pamk5_compat_princ_component(krb5_context c, krb5_principal princ, int n)
{
    return krb5_princ_component(c, princ, n)->data;
}


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


static krb5_error_code
mit_pam_prompter(krb5_context c, void *data, const char *name,
                 const char *banner, int num_prompts, krb5_prompt prompts[])
{
    return pamk5_prompter_krb5(c, data, name, banner, num_prompts, prompts);
}

krb5_prompter_fct pamk5_pam_prompter = mit_pam_prompter;
