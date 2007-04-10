/*
 * compat.c
 *
 * Wrapper to include the appropriate Kerberos compatibility functions and
 * provide compatibility functions that are the same for both Heimdal and
 * MIT.
 */

#include "config.h"

#include <errno.h>
#include <krb5.h>
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
    krb5_get_init_creds_opt_init(*opts);
    return 0;
}

void
pamk5_compat_opt_free(krb5_context c, krb5_get_init_creds_opt *opts)
{
    free(opts);
}
#endif /* !HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC */
