/*
 * Logging functions for pam_krb5.
 *
 * Logs errors and debugging messages from pam_krb5 functions.  The debug
 * versions only log anything if debugging was enabled; the error versions
 * always log.
 *
 * Copyright 2005, 2006, 2007, 2009 Russ Allbery <rra@debian.org>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/pam.h>

#include <krb5.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include <internal.h>

#ifndef LOG_AUTHPRIV
# define LOG_AUTHPRIV LOG_AUTH
#endif

/*
 * Log wrapper function that adds the user.  Log a message with the given
 * priority, prefixed by (user <user>) with the account name being
 * authenticated if known.
 */
void
pamk5_log(struct pam_args *pargs, int priority, const char *fmt, ...)
{
    const char *name;
    char *msg;
    va_list args;
    int retval;

    if (pargs != NULL && pargs->ctx != NULL && pargs->ctx->name != NULL) {
        name = pargs->ctx->name;
        va_start(args, fmt);
        retval = vasprintf(&msg, fmt, args);
        va_end(args);
        if (retval < 0) {
            syslog(LOG_CRIT | LOG_AUTHPRIV,
                   "cannot allocate memory in vasprintf: %m");
            return;
        }
        pam_syslog(pargs->pamh, priority, "(user %s) %s", name, msg);
        free(msg);
    } else {
        va_start(args, fmt);
        pam_vsyslog(pargs->pamh, priority, fmt, args);
        va_end(args);
    }
}


/*
 * Log a generic error with LOG_ERR priority.
 */
void
pamk5_error(struct pam_args *pargs, const char *fmt, ...)
{
    char *msg;
    va_list args;
    int retval;

    va_start(args, fmt);
    retval = vasprintf(&msg, fmt, args);
    va_end(args);
    if (retval < 0) {
        syslog(LOG_CRIT | LOG_AUTHPRIV,
               "cannot allocate memory in vasprintf: %m");
        return;
    }
    pamk5_log(pargs, LOG_ERR, "%s", msg);
    free(msg);
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
    pamk5_log(args, LOG_ERR, "%s: %s", msg, k5_msg);
    if (args != NULL && args->ctx != NULL && args->ctx->context != NULL)
        pamk5_compat_free_error(args->ctx->context, k5_msg);
}


/*
 * Log a generic debugging message only if debug is enabled.
 */
void
pamk5_debug(struct pam_args *pargs, const char *fmt, ...)
{
    char *msg;
    va_list args;
    int retval;

    if (!pargs->debug)
        return;

    va_start(args, fmt);
    retval = vasprintf(&msg, fmt, args);
    va_end(args);
    if (retval < 0) {
        syslog(LOG_CRIT | LOG_AUTHPRIV,
               "cannot allocate memory in vasprintf: %m");
        return;
    }
    pamk5_log(pargs, LOG_DEBUG, "%s", msg);
    free(msg);
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
