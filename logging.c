/*
 * Logging functions for pam_krb5.
 *
 * Logs errors and debugging messages from pam_krb5 functions.  The debug
 * versions only log anything if debugging was enabled; the error versions
 * always log.
 *
 * Copyright 2005, 2006, 2007, 2009 Russ Allbery <rra@stanford.edu>
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
#include <unistd.h>

#include <internal.h>

#ifndef LOG_AUTHPRIV
# define LOG_AUTHPRIV LOG_AUTH
#endif

/*
 * Utility function to format a message into newly allocated memory, reporting
 * an error via syslog if vasprintf fails.
 */
static char *
format(const char *fmt, va_list args)
{
    char *msg;

    if (vasprintf(&msg, fmt, args) < 0) {
        syslog(LOG_CRIT | LOG_AUTHPRIV, "vasprintf failed: %m");
        return NULL;
    }
    return msg;
}


/*
 * Log wrapper function that adds the user.  Log a message with the given
 * priority, prefixed by (user <user>) with the account name being
 * authenticated if known.
 */
static void
log_vplain(struct pam_args *pargs, int priority, const char *fmt, va_list args)
{
    const char *name;
    char *msg;

    if (priority == LOG_DEBUG && (pargs == NULL || !pargs->debug))
        return;
    if (pargs != NULL && pargs->ctx != NULL && pargs->ctx->name != NULL) {
        name = pargs->ctx->name;
        msg = format(fmt, args);
        if (msg == NULL)
            return;
        pam_syslog(pargs->pamh, priority, "(user %s) %s", name, msg);
        free(msg);
    } else if (pargs != NULL) {
        pam_vsyslog(pargs->pamh, priority, fmt, args);
    } else {
        msg = format(fmt, args);
        if (msg == NULL)
            return;
        syslog(priority | LOG_AUTHPRIV, "%s", msg);
        free(msg);
    }
}


/*
 * Wrapper around log_vplain with variadic arguments.
 */
static void
log_plain(struct pam_args *pargs, int priority, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_vplain(pargs, priority, fmt, args);
    va_end(args);
}


/*
 * Log wrapper function for reporting a PAM error.  Log a message with the
 * given priority, prefixed by (user <user>) with the account name being
 * authenticated if known, followed by a colon and the formatted PAM error.
 */
static void
log_pam(struct pam_args *pargs, int priority, int status, const char *fmt,
        va_list args)
{
    char *msg;

    if (priority == LOG_DEBUG && (pargs == NULL || !pargs->debug))
        return;
    msg = format(fmt, args);
    if (msg == NULL)
        return;
    if (pargs == NULL)
        log_plain(NULL, priority, "%s", msg);
    else
        log_plain(pargs, priority, "%s: %s", msg,
                  pam_strerror(pargs->pamh, status));
    free(msg);
}


/*
 * Log wrapper function for reporting a Kerberos error.  Log a message with
 * the given priority, prefixed by (user <user>) with the account name being
 * authenticated if known, followed by a colon and the formatted Kerberos
 * error.
 */
static void
log_krb5(struct pam_args *pargs, int priority, int status, const char *fmt,
         va_list args)
{
    char *msg;
    const char *k5_msg = NULL;

    if (priority == LOG_DEBUG && (pargs == NULL || !pargs->debug))
        return;
    msg = format(fmt, args);
    if (msg == NULL)
        return;
    if (pargs != NULL && pargs->ctx != NULL && pargs->ctx->context != NULL)
        k5_msg = pamk5_compat_get_error(pargs->ctx->context, status);
    else
        k5_msg = pamk5_compat_get_error(NULL, status);
    log_plain(pargs, priority, "%s: %s", msg, k5_msg);
    free(msg);
    if (pargs != NULL && pargs->ctx != NULL && pargs->ctx->context != NULL)
        pamk5_compat_free_error(pargs->ctx->context, k5_msg);
}


/*
 * The public interfaces.  For each common log level (crit, err, and debug),
 * generate a pamk5_<level> function and one for _pam and _krb5.  Do this with
 * the preprocessor to save duplicate code.
 */
#define LOG_FUNCTION(level, priority)                                   \
    void                                                                \
    pamk5_ ## level(struct pam_args *pargs, const char *fmt, ...)       \
    {                                                                   \
        va_list args;                                                   \
                                                                        \
        va_start(args, fmt);                                            \
        log_vplain(pargs, priority, fmt, args);                         \
        va_end(args);                                                   \
    }                                                                   \
    void                                                                \
    pamk5_ ## level ## _pam(struct pam_args *pargs, int status,         \
                            const char *fmt, ...)                       \
    {                                                                   \
        va_list args;                                                   \
                                                                        \
        va_start(args, fmt);                                            \
        log_pam(pargs, priority, status, fmt, args);                    \
        va_end(args);                                                   \
    }                                                                   \
    void                                                                \
    pamk5_ ## level ## _krb5(struct pam_args *pargs, int status,        \
                             const char *fmt, ...)                      \
    {                                                                   \
        va_list args;                                                   \
                                                                        \
        va_start(args, fmt);                                            \
        log_krb5(pargs, priority, status, fmt, args);                   \
        va_end(args);                                                   \
    }
LOG_FUNCTION(crit,  LOG_CRIT)
LOG_FUNCTION(err,   LOG_ERR)
LOG_FUNCTION(debug, LOG_DEBUG)


/*
 * Report an authentication failure.  This is a separate function since we
 * want to include various PAM metadata in the log message and put it in a
 * standard format.  The format here is modeled after the pam_unix
 * authentication failure message from Linux PAM.
 */
void
pamk5_log_failure(struct pam_args *pargs, const char *fmt, ...)
{
    char *msg;
    va_list args;
    const char *ruser = NULL;
    const char *rhost = NULL;
    const char *tty = NULL;
    const char *name = NULL;

    if (pargs->ctx != NULL && pargs->ctx->name != NULL)
        name = pargs->ctx->name;
    va_start(args, fmt);
    msg = format(fmt, args);
    if (msg == NULL)
        return;
    va_end(args);
    pam_get_item(pargs->pamh, PAM_RUSER, (PAM_CONST void **) &ruser);
    pam_get_item(pargs->pamh, PAM_RHOST, (PAM_CONST void **) &rhost);
    pam_get_item(pargs->pamh, PAM_TTY, (PAM_CONST void **) &tty);
    pam_syslog(pargs->pamh, LOG_NOTICE, "%s; logname=%s uid=%ld euid=%ld"
               " tty=%s ruser=%s rhost=%s", msg,
               (name  != NULL) ? name  : "",
               (long) getuid(), (long) geteuid(),
               (tty   != NULL) ? tty   : "",
               (ruser != NULL) ? ruser : "",
               (rhost != NULL) ? rhost : "");
}
