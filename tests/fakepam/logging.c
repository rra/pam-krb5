/*
 * Logging functions for the fake PAM library, used for testing.
 *
 * This file contains the implementation of pam_syslog and pam_vsyslog, which
 * log to an internal buffer rather than to syslog, and the testing function
 * used to recover that buffer.  It also includes the pam_strerror
 * implementation.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <config.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <tests/fakepam/testing.h>

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED __attribute__((__unused__))

/* The buffer used to accumulate log messages. */
static char *messages = NULL;


/*
 * Return the error string associated with the PAM error code.  We do this as
 * a giant case statement so that we don't assume anything about the error
 * codes used by the system PAM library.
 */
const char *
pam_strerror(pam_handle_t *pamh UNUSED, int code)
{
    switch (code) {
    case PAM_SUCCESS:     return "No error";
    case PAM_OPEN_ERR:    return "Failure loading service module";
    case PAM_SYMBOL_ERR:  return "Symbol not found";
    case PAM_SERVICE_ERR: return "Error in service module";
    case PAM_SYSTEM_ERR:  return "System error";
    case PAM_BUF_ERR:     return "Memory buffer error";
    default:              return "Unknown error";
    }
}


/*
 * Log a message using variadic arguments.  Just a wrapper around
 * pam_vsyslog.
 */
void
pam_syslog(const pam_handle_t *pamh, int priority, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    pam_vsyslog(pamh, priority, format, args);
    va_end(args);
}


/*
 * Log a PAM error message with a given priority.  Just appends the priority,
 * a space, and the error message, followed by a newline, to the internal
 * buffer, allocating new space if needed.  Ignore memory allocation failures;
 * we have no way of reporting them, but the tests will fail due to missing
 * output.
 */
void
pam_vsyslog(const pam_handle_t *pamh UNUSED, int priority, const char *format,
            va_list args)
{
    char *prefix = NULL;
    char *message = NULL;
    size_t size;

    asprintf(&prefix, "%d ", priority);
    if (prefix == NULL)
        return;
    vasprintf(&message, format, args);
    if (message == NULL)
        return;
    if (messages == NULL) {
        size = strlen(prefix) + strlen(message) + 1;
        messages = malloc(size);
        if (messages == NULL)
            return;
        strlcpy(messages, prefix, size);
        strlcat(messages, message, size);
    } else {
        size = strlen(prefix) + strlen(messages) + strlen(message) + 1;
        messages = realloc(messages, size);
        if (messages == NULL)
            return;
        strlcat(messages, prefix, size);
        strlcat(messages, message, size);
    }
    free(prefix);
    free(message);
}


/*
 * Used by test code.  Returns the accumulated messages and starts a new
 * message buffer.  Caller is responsible for freeing.
 */
char *
pam_output(void)
{
    char *output;

    output = messages;
    messages = NULL;
    return output;
}
