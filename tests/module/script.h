/*
 * PAM interaction script API.
 *
 * Provides an interface that loads a PAM interaction script from a file and
 * runs through that script, calling the internal PAM module functions and
 * checking their results.  This allows automation of PAM testing through
 * external data files instead of coding everything in C.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef TESTS_MODULE_SCRIPT_H
#define TESTS_MODULE_SCRIPT_H 1

#include <tests/tap/basic.h>

BEGIN_DECLS

/*
 * Given the file name of an interaction script (which may be a full path or
 * relative to SOURCE or BUILD), an optional user that may be NULL, and an
 * optional password that may be NULL, run that script, reporting the results
 * via the TAP format.
 */
void run_script(const char *file, const char *user, const char *password);

END_DECLS

#endif /* !TESTS_MODULE_SCRIPT_H */
