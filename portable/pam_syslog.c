/*
 * Replacement for a missing pam_syslog.
 *
 * Implements pam_syslog in terms of pam_vsyslog (which itself may be a
 * replacement) if the PAM implementation does not provide it.  This is a
 * Linux PAM extension.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 *
 * The authors hereby relinquish any claim to any copyright that they may have
 * in this work, whether granted under contract or by operation of law or
 * international treaty, and hereby commit to the public, at large, that they
 * shall not, at any time in the future, seek to enforce any copyright in this
 * work against any person or entity, or prevent any person or entity from
 * copying, publishing, distributing or creating derivative works of this
 * work.
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
