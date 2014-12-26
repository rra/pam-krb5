/*
 * Portability wrapper around kadm5/admin.h.
 *
 * This header adjusts for differences between the MIT and Heimdal kadmin
 * client libraries so that the code can be written to a consistent API
 * (favoring the Heimdal API as the exposed one).
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

#ifndef PORTABLE_KADMIN_H
#define PORTABLE_KADMIN_H 1

#include <config.h>

#include <kadm5/admin.h>
#ifdef HAVE_KADM5_KADM5_ERR_H
# include <kadm5/kadm5_err.h>
#else
# include <kadm5/kadm_err.h>
#endif

/*
 * MIT as of 1.10 supports version 3.  Heimdal as of 1.5 has a maximum version
 * of 2.  Define a KADM5_API_VERSION symbol that holds the maximum version.
 * (Heimdal does this for us, so we only have to do that with MIT, but be
 * general just in case.)
 */
#ifndef KADM5_API_VERSION
# ifdef KADM5_API_VERSION_3
#  define KADM5_API_VERSION KADM5_API_VERSION_3
# else
#  define KADM5_API_VERSION KADM5_API_VERSION_2
# endif
#endif

/* Heimdal doesn't define KADM5_PASS_Q_GENERIC. */
#ifndef KADM5_PASS_Q_GENERIC
# define KADM5_PASS_Q_GENERIC KADM5_PASS_Q_DICT
#endif

/* Heimdal doesn't define KADM5_MISSING_KRB5_CONF_PARAMS. */
#ifndef KADM5_MISSING_KRB5_CONF_PARAMS
# define KADM5_MISSING_KRB5_CONF_PARAMS KADM5_MISSING_CONF_PARAMS
#endif

/*
 * Heimdal provides _ctx functions that take an existing context.  MIT always
 * requires the context be passed in.  Code should use the _ctx variant, and
 * the below will fix it up if built against MIT.
 *
 * MIT also doesn't have a const prototype for the server argument, so cast it
 * so that we can use the KADM5_ADMIN_SERVICE define.
 */
#ifndef HAVE_KADM5_INIT_WITH_SKEY_CTX
# define kadm5_init_with_skey_ctx(c, u, k, s, p, sv, av, h) \
    kadm5_init_with_skey((c), (u), (k), (char *) (s), (p), (sv), (av), NULL, \
                         (h))
#endif

#endif /* !PORTABLE_KADMIN_H */
