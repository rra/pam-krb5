/*
 * pam_krb5_sess.c
 *
 * PAM session management functions for pam_krb5
 * (null functions)
 *
 */

#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <krb5.h>
#include "pam_krb5.h"

int pam_sm_setcred (pam_handle_t *, int, int, const char **);

/* Initiate session management */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return pam_sm_setcred (pamh, PAM_ESTABLISH_CRED, argc, argv);
}


/* Terminate session management */
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return pam_set_data(pamh, "ctx", NULL, NULL);
}

