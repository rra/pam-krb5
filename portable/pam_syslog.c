/*
 * Replacement for a missing pam_syslog.
 *
 * Implements pam_syslog in terms of pam_vsyslog (which itself may be a
 * replacement) if the PAM implementation does not provide it.  This is a
 * Linux PAM extension.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * This work is hereby placed in the public domain by its author.
 */

#include <config.h>
#include <portable/pam.h>

#include <stdarg.h>

void
pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    pam_vsyslog(pamh, priority, fmt, args);
    va_end(args);
}
