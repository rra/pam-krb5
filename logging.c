/*
 * Logging functions for pam_krb5.
 *
 * Logs errors and debugging messages from pam_krb5 functions.  The debug
 * versions only log anything if debugging was enabled; the error versions
 * always log.
 *
 * Copyright 2005, 2006, 2007 Russ Allbery <rra@debian.org>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

#include "config.h"

#include <krb5.h>
#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#elif HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
# include <pam/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
# include <security/pam_ext.h>
#elif HAVE_PAM_PAM_EXT_H
# include <pam/pam_ext.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include "internal.h"

#ifndef LOG_AUTHPRIV
# define LOG_AUTHPRIV LOG_AUTH
#endif

/*
 * Linux PAM provides pam_vsyslog.  Just call it if it's available; otherwise,
 * implement our own.  We won't be able to get access to which PAM group we're
 * in if we implement our own, but we try to get the service name at least.
 */
void
pamk5_compat_vsyslog(pam_handle_t *pamh, int priority, const char *fmt,
                     va_list args)
{
#ifdef HAVE_PAM_VSYSLOG
    pam_vsyslog(pamh, priority, fmt, args);
#else
    char msg[BUFSIZ];
    const char *service = NULL;
    int retval;

    retval = pam_get_item(pamh, PAM_SERVICE, (void **) &service);
    if (retval != PAM_SUCCESS)
        service = NULL;
    vsnprintf(msg, sizeof(msg), fmt, args);
    syslog(priority | LOG_AUTHPRIV, "pam_krb5%s%s%s: %s",
           (service == NULL) ? "" : "(",
           (service == NULL) ? "" : service,
           (service == NULL) ? "" : ")", msg);
#endif
}


/*
 * Linux PAM provides pam_syslog, but don't bother using it; just always
 * implement in terms of pamk5_compat_vsyslog.  Then we don't need variadic
 * macros.
 */
void
pamk5_compat_syslog(pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    pamk5_compat_vsyslog(pamh, priority, fmt, args);
    va_end(args);
}


/*
 * Basic error logging.  Log a message with LOG_ERR priority.
 */
void
pamk5_error(struct pam_args *pargs, const char *fmt, ...)
{
    const char *name = "none";
    char msg[256];
    va_list args;

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    if (pargs != NULL && pargs->ctx != NULL && pargs->ctx->name != NULL)
        name = pargs->ctx->name;
    syslog(LOG_ERR | LOG_AUTHPRIV, "(pam_krb5): %s: %s", name, msg);
}


/*
 * Log a Kerberos v5 failure with LOG_ERR priority.  We don't free the message
 * if we have no context under the assumption that no memory would be
 * allocated in that case.  This is true for the current MIT Kerberos
 * implementation.
 */
void
pamk5_error_krb5(struct pam_args *args, const char *msg, int status)
{
    const char *k5_msg = NULL;

    if (args != NULL && args->ctx != NULL && args->ctx->context != NULL)
        k5_msg = pamk5_compat_get_error(args->ctx->context, status);
    else
        k5_msg = pamk5_compat_get_error(NULL, status);
    pamk5_error(args, "%s: %s", msg, k5_msg);
    if (args != NULL && args->ctx != NULL && args->ctx->context != NULL)
        pamk5_compat_free_error(args->ctx->context, k5_msg);
}


/*
 * Log a generic debugging message only if debug is enabled.
 */
void
pamk5_debug(struct pam_args *pargs, const char *fmt, ...)
{
    const char *name = "none";
    char msg[256];
    va_list args;

    if (!pargs->debug)
        return;

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    if (pargs != NULL && pargs->ctx != NULL && pargs->ctx->name != NULL)
        name = pargs->ctx->name;
    syslog(LOG_DEBUG | LOG_AUTHPRIV, "(pam_krb5): %s: %s", name, msg);
}


/*
 * Log a PAM failure if debugging is enabled.
 */
void
pamk5_debug_pam(struct pam_args *args, const char *msg, int status)
{
    pamk5_debug(args, "%s: %s", msg, pam_strerror(args->pamh, status));
}


/*
 * Log a Kerberos v5 failure if debugging is enabled.  We don't free the
 * message if we have no context under the assumption that no memory would be
 * allocated in that case.  This is true for the current MIT Kerberos
 * implementation.
 */
void
pamk5_debug_krb5(struct pam_args *args, const char *msg, int status)
{
    const char *k5_msg = NULL;

    if (args != NULL && args->ctx != NULL && args->ctx->context != NULL)
        k5_msg = pamk5_compat_get_error(args->ctx->context, status);
    else
        k5_msg = pamk5_compat_get_error(NULL, status);
    pamk5_debug(args, "%s: %s", msg, k5_msg);
    if (args != NULL && args->ctx != NULL && args->ctx->context != NULL)
        pamk5_compat_free_error(args->ctx->context, k5_msg);
}
