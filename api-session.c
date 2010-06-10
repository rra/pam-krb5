/*
 * Implements the PAM session group API (pam_sm_open_session and
 * pam_sm_close_session).
 *
 * Opening a session is mostly equivalent to calling pam_setcred with the flag
 * to establish credentials but may return PAM_IGNORE.  Closing a session
 * destroys the PAM context, which will destroy the ticket cache.
 *
 * Copyright 2005, 2006, 2007, 2009 Russ Allbery <rra@stanford.edu>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

/* Get prototypes for the session functions. */
#define PAM_SM_SESSION

#include <config.h>
#include <portable/pam.h>

#include <errno.h>
#include <string.h>

#include <internal.h>

/*
 * Store the user's credentials.  Nearly all of the work is done by
 * pamk5_setcred.
 */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                    const char **argv)
{
    struct pam_args *args;
    int pamret;

    args = pamk5_args_parse(pamh, flags, argc, argv);
    if (args == NULL) {
        pamk5_crit(NULL, "cannot allocate memory: %s", strerror(errno));
        pamret = PAM_SERVICE_ERR;
        goto done;
    }
    ENTRY(args, flags);
    pamret = pamk5_setcred(args, 0);

done:
    EXIT(args, pamret);
    pamk5_args_free(args);
    return pamret;
}


/*
 * Terminate session management, which in this case means freeing our
 * context, along with destroying its associated ticket cache if appropriate.
 */
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
    struct pam_args *args;
    int pamret;

    args = pamk5_args_parse(pamh, flags, argc, argv);
    if (args == NULL) {
        pamk5_crit(NULL, "cannot allocate memory: %s", strerror(errno));
        pamret = PAM_SERVICE_ERR;
        goto done;
    }
    ENTRY(args, flags);
    pamret = pam_set_data(pamh, "pam_krb5", NULL, NULL);
    if (pamret != PAM_SUCCESS)
        pamk5_err_pam(args, pamret, "cannot clear context data");
    args->ctx = NULL;

done:
    EXIT(args, pamret);
    pamk5_args_free(args);
    return pamret;
}
