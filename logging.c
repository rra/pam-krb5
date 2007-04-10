/*
 * logging.c
 *
 * Logging functions for pam_krb5.
 *
 * Logs errors and debugging messages from pam_krb5 functions.  The debug
 * versions only log anything if debugging was enabled; the error versions
 * always log.
 */

#include "config.h"

#include <krb5.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include "internal.h"

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
    syslog(LOG_ERR, "(pam_krb5): %s: %s", name, msg);
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
    syslog(LOG_DEBUG, "(pam_krb5): %s: %s", name, msg);
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
