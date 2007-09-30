/*
 * compat.c
 *
 * Wrapper to include the appropriate Kerberos compatibility functions, to
 * provide compatibility functions that are the same for both Heimdal and
 * MIT, and to provide compatibility versions of functions not found in some
 * PAM libraries.
 */

#include "config.h"

#include <errno.h>
#include <krb5.h>
#ifdef HAVE_SECURITY_PAM_MODUTIL_H
# include <security/pam_modutil.h>
#endif
#include <stdlib.h>

#ifdef HAVE_KRB5_MIT
# include "compat-mit.c"
#elif HAVE_KRB5_HEIMDAL
# include "compat-heimdal.c"
#else
# error "Unknown Kerberos implementation"
#endif

/*
 * Older versions of both Heimdal and MIT may not have these function, which
 * was added to support PKINIT and other more complex options.
 */
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
krb5_error_code
pamk5_compat_opt_alloc(krb5_context c, krb5_get_init_creds_opt **opts)
{
    return krb5_get_init_creds_opt_alloc(c, opts);
}

void
pamk5_compat_opt_free(krb5_context c, krb5_get_init_creds_opt *opts)
{
# ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_FREE_2_ARGS
    krb5_get_init_creds_opt_free(c, opts);
# else
    krb5_get_init_creds_opt_free(opts);
# endif
}

#else /* !HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC */

krb5_error_code
pamk5_compat_opt_alloc(krb5_context c, krb5_get_init_creds_opt **opts)
{
    *opts = calloc(1, sizeof(krb5_get_init_creds_opt));
    if (opts == NULL)
        return ENOMEM;
    return 0;
}

void
pamk5_compat_opt_free(krb5_context c, krb5_get_init_creds_opt *opts)
{
    free(opts);
}
#endif /* !HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC */


/*
 * Linux PAM provides a thread-safe version of getpwnam that we want to use if
 * available.  If it's not, fall back on getpwnam.  (Ideally, we should check
 * for getpwnam_r and use it, but I haven't written that routine.)
 */
#ifdef HAVE_PAM_MODUTIL_GETPWNAM

struct passwd *
pamk5_compat_getpwnam(struct pam_args *args, const char *user)
{
    return pam_modutil_getpwnam(args->pamh, user);
}

#else /* !HAVE_PAM_MODUTIL_GETPWNAM */

struct passwd *
pamk5_compat_getpwnam(struct pam_args *args UNUSED, const char *user)
{
    return getpwnam(user);
}

#endif /* !HAVE_PAM_MODUTIL_GETPWNAM */
