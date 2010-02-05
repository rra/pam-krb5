/*
 * Replacement for a missing pam_vsyslog.
 *
 * Provides close to the same functionality as the Linux PAM function
 * pam_vsyslog for other PAM implementations.  The logging prefix will not be
 * quite as good, since we don't have access to the PAM group name.
 *
 * To use this replacement, the Autoconf script for the package must define
 * MODULE_NAME to the name of the PAM module.  (PACKAGE isn't used since it
 * may use dashes where the module uses underscores.)
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * This work is hereby placed in the public domain by its author.
 */

#include <config.h>
#include <portable/pam.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#ifndef LOG_AUTHPRIV
# define LOG_AUTHPRIV LOG_AUTH
#endif

void
pam_vsyslog(const pam_handle_t *pamh, int priority, const char *fmt,
            va_list args)
{
    char *msg = NULL;
    const char *service = NULL;
    int retval;

    retval = pam_get_item(pamh, PAM_SERVICE, (PAM_CONST void **) &service);
    if (retval != PAM_SUCCESS)
        service = NULL;
    if (vasprintf(&msg, fmt, args) < 0) {
        syslog(LOG_CRIT | LOG_AUTHPRIV,
               "cannot allocate memory in vasprintf: %m");
        return;
    }
    syslog(priority | LOG_AUTHPRIV, MODULE_NAME "%s%s%s: %s",
           (service == NULL) ? "" : "(",
           (service == NULL) ? "" : service,
           (service == NULL) ? "" : ")", msg);
    free(msg);
}
