/*
 * Kerberos and PAM compatibility functions.
 *
 * Wrapper to include the appropriate Kerberos compatibility functions, to
 * provide compatibility functions that are the same for both Heimdal and
 * MIT, and to provide compatibility versions of functions not found in some
 * PAM libraries.
 *
 * Copyright 2005, 2006, 2007, 2009 Russ Allbery <rra@stanford.edu>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#ifdef HAVE_KRB5_MIT
# include "compat-mit.c"
#elif HAVE_KRB5_HEIMDAL
# include "compat-heimdal.c"
#else
# error "Unknown Kerberos implementation"
#endif
