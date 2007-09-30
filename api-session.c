/*
 * api-session.c
 *
 * Implements the PAM session group API (pam_sm_open_session and
 * pam_sm_close_session).
 *
 * Opening a session is equivalent to calling pam_setcred with the flag to
 * establish credentials.  Closing a session destroys the PAM context, which
 * will destroy the ticket cache.
 *
 * These calls aren't logged since we don't bother doing option parsing here;
 * instead, we defer that for pam_sm_setcred or don't bother doing it at all
 * for pam_sm_close_session.
 */

/* Get prototypes for both the authentication and session functions. */
#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include "config.h"

#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#elif HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
# include <pam/pam_modules.h>
#endif

#include "internal.h"

/* Store the user's credentials.  The flags are ignored. */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                    const char **argv)
{
    return pam_sm_setcred(pamh, PAM_ESTABLISH_CRED, argc, argv);
}


/*
 * Terminate session management, which in this case means freeing our
 * context, along with destroying its associated ticket cache if appropriate.
 * The flags are ignored.
 */
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
    return pam_set_data(pamh, "pam_krb5", NULL, NULL);
}
