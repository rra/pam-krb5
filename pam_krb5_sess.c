/*
 * pam_krb5_sess.c
 *
 * PAM session management functions for pam_krb5
 * (null functions)
 *
 */

static const char rcsid[] = "$Id: pam_krb5_sess.c,v 1.2 2001/05/12 22:42:14 hartmans Exp $";

#include <security/pam_appl.h>
#include <security/pam_modules.h>
int pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv);

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
    return PAM_SUCCESS;
}

