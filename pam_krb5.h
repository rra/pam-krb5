/*
 * pam_krb5.h
 *
 * $Id: pam_krb5.h,v 1.1 2000/11/30 20:09:37 hartmans Exp $
 */

int get_user_info(pam_handle_t *, char *, int, char **);
krb5_error_code pam_prompter(krb5_context, void *, const char *,
			     const char *, int, krb5_prompt[]);
int verify_krb_v5_tgt(krb5_context, krb5_ccache, int);
void cleanup_cache(pam_handle_t *, void *, int);
