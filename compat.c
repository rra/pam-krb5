/*
 * compat.c
 *
 * Wrapper to include the appropriate Kerberos compatibility functions.
 */

#include "config.h"

#ifdef HAVE_KRB5_MIT
# include "compat-mit.c"
#elif HAVE_KRB5_HEIMDAL
# include "compat-heimdal.c"
#else
# error "Unknown Kerberos implementation"
#endif
