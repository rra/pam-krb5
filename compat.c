/*
 * Kerberos and PAM compatibility functions.
 *
 * Wrapper to include the appropriate Kerberos compatibility functions, to
 * provide compatibility functions that are the same for both Heimdal and
 * MIT, and to provide compatibility versions of functions not found in some
 * PAM libraries.
 *
 * Copyright 2005, 2006, 2007 Russ Allbery <rra@debian.org>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 * See LICENSE for licensing terms.
 */

#include "config.h"

#include <errno.h>
#include <krb5.h>
#ifndef HAVE_PAM_MODUTIL_GETPWNAM
# include <pwd.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODUTIL_H
# include <security/pam_modutil.h>
#endif
#include <stdlib.h>

#if !defined(HAVE_KRB5_GET_ERROR_MESSAGE) && !defined(HAVE_KRB5_GET_ERR_TEXT)
# if defined(HAVE_IBM_SVC_KRB5_SVC_H)
#  include <ibm_svc/krb5_svc.h>
# elif defined(HAVE_ET_COM_ERR_H)
#  include <et/com_err.h>
# else
#  include <com_err.h>
# endif
#endif

#ifdef HAVE_KRB5_MIT
# include "compat-mit.c"
#elif HAVE_KRB5_HEIMDAL
# include "compat-heimdal.c"
#else
# error "Unknown Kerberos implementation"
#endif

/* AIX doesn't have the appdefault functions. */
#ifndef HAVE_KRB5_APPDEFAULT_STRING
# include "compat-aix.c"
#endif

/*
 * This string is returned for unknown error messages.  We use a static
 * variable so that we can be sure not to free it.
 */
static const char error_unknown[] = "unknown error";


/*
 * Older versions of both Heimdal and MIT may not have these function, which
 * was added to support PKINIT and other more complex options.
 */
krb5_error_code
pamk5_compat_opt_alloc(krb5_context c, krb5_get_init_creds_opt **opts)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
    return krb5_get_init_creds_opt_alloc(c, opts);
#else
    *opts = calloc(1, sizeof(krb5_get_init_creds_opt));
    if (opts == NULL)
        return ENOMEM;
    return 0;
#endif
}

void
pamk5_compat_opt_free(krb5_context c, krb5_get_init_creds_opt *opts)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
# ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_FREE_2_ARGS
    krb5_get_init_creds_opt_free(c, opts);
# else
    krb5_get_init_creds_opt_free(opts);
# endif
#else
    free(opts);
#endif
}


/*
 * Given a Kerberos error code, return the corresponding error.  Prefer the
 * Kerberos interface if available since it will provide context-specific
 * error information, whereas the error_message() call will only provide a
 * fixed message.
 */
const char *
pamk5_compat_get_error(krb5_context ctx, krb5_error_code code)
{
    const char *msg = NULL;

# if defined(HAVE_KRB5_GET_ERROR_MESSAGE)
    msg = krb5_get_error_message(ctx, code);
# elif defined(HAVE_KRB5_GET_ERR_TEXT)
    msg = krb5_get_err_text(ctx, code);
# elif defined(HAVE_KRB5_SVC_GET_MSG)
    krb5_svc_get_msg(code, &msg);
# else
    msg = error_message(code);
# endif
    if (msg == NULL)
        return error_unknown;
    else
        return msg;
}


/*
 * Free an error string if necessary.  If we returned a static string, make
 * sure we don't free it.
 */
void
pamk5_compat_free_error(krb5_context ctx, const char *msg)
{
    if (msg == error_unknown)
        return;
# if defined(HAVE_KRB5_FREE_ERROR_MESSAGE)
    krb5_free_error_message(ctx, msg);
# elif defined(HAVE_KRB5_SVC_GET_MSG)
    krb5_free_string((char *) msg);
# endif
}


/*
 * Linux PAM provides a thread-safe version of getpwnam that we want to use if
 * available.  If it's not, fall back on getpwnam.  (Ideally, we should check
 * for getpwnam_r and use it, but I haven't written that routine.)
 */
struct passwd *
pamk5_compat_getpwnam(struct pam_args *args, const char *user)
{
#ifdef HAVE_PAM_MODUTIL_GETPWNAM
    return pam_modutil_getpwnam(args->pamh, user);
#else
    return getpwnam(user);
#endif
}


/*
 * AIX's NAS Kerberos implementation mysteriously provides the struct and the
 * krb5_verify_init_creds function but not this function.
 */
#ifndef HAVE_KRB5_VERIFY_INIT_CREDS_OPT_INIT
void
krb5_verify_init_creds_opt_init(krb5_verify_init_creds_opt *opt)
{
    opt->flags = 0;
    opt->ap_req_nofail = 0;
}
#endif
