/*
 * Portability wrapper around PAM header files.
 *
 * This header file includes the various PAM headers, wherever they may be
 * found on the system, and defines replacements for PAM functions that may
 * not be available on the local system.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * This work is hereby placed in the public domain by its author.
 */

#ifndef PORTABLE_PAM_H
#define PORTABLE_PAM_H 1

#include <config.h>
#include <portable/macros.h>

/* Linux PAM 1.1.0 requires sys/types.h before security/pam_modutil.h. */
#include <sys/types.h>

#ifndef HAVE_PAM_MODUTIL_GETPWNAM
# include <pwd.h>
#endif
#if defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
# include <pam/pam_modules.h>
#endif
#if defined(HAVE_SECURITY_PAM_EXT_H)
# include <security/pam_ext.h>
#elif defined(HAVE_PAM_PAM_EXT_H)
# include <pam/pam_ext.h>
#endif
#if defined(HAVE_SECURITY_PAM_MODUTIL_H)
# include <security/pam_modutil.h>
#elif defined(HAVE_PAM_PAM_MODUTIL_H)
# include <pam/pam_modutil.h>
#endif
#include <stdarg.h>

BEGIN_DECLS

/* Default to a hidden visibility for all portability functions. */
#pragma GCC visibility push(hidden)

/*
 * If pam_modutil_getpwnam is missing, ideally we should roll our own using
 * getpwnam_r.  However, this is a fair bit of work, since we have to stash
 * the allocated memory in the PAM data so that it will be freed properly.
 * Bail for right now.
 */
#if !HAVE_PAM_MODUTIL_GETPWNAM
# define pam_modutil_getpwnam(h, u) getpwnam(u)
#endif

/* Prototype missing optional PAM functions. */
#if !HAVE_PAM_SYSLOG
void pam_syslog(const pam_handle_t *, int, const char *, ...);
#endif
#if !HAVE_PAM_VSYSLOG
void pam_vsyslog(const pam_handle_t *, int, const char *, va_list);
#endif

/* Undo default visibility change. */
#pragma GCC visibility pop

#endif /* !PORTABLE_PAM_H */
