/*
 * PAM logging test suite.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010, 2011, 2012
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

#include <syslog.h>

#include <pam-util/args.h>
#include <pam-util/logging.h>
#include <tests/fakepam/pam.h>
#include <tests/tap/basic.h>
#include <tests/tap/string.h>

/* Test a normal PAM logging function. */                       \
#define TEST(func, p, n)                                        \
    do {                                                        \
        (func)(args, "%s", "foo");                              \
        basprintf(&expected, "%d %s", (p), "foo");              \
        seen = pam_output();                                    \
        is_string(expected, seen->strings[0], "%s", (n));       \
        pam_output_free(seen);                                  \
        free(expected);                                         \
    } while (0);

/* Test a PAM error logging function. */
#define TEST_PAM(func, c, p, n)                                 \
    do {                                                        \
        (func)(args, (c), "%s", "bar");                         \
        if ((c) == PAM_SUCCESS)                                 \
            basprintf(&expected, "%d %s", (p), "bar");          \
        else                                                    \
            basprintf(&expected, "%d %s: %s", (p), "bar",       \
                      pam_strerror(args->pamh, c));             \
        seen = pam_output();                                    \
        is_string(expected, seen->strings[0], "%s", (n));       \
        pam_output_free(seen);                                  \
        free(expected);                                         \
    } while (0);

/* Test a PAM Kerberos error logging function .*/
#define TEST_KRB5(func, p, n)                                             \
    do {                                                                  \
        const char *msg;                                                  \
                                                                          \
        code = krb5_parse_name(args->ctx, "foo@bar@EXAMPLE.COM", &princ); \
        (func)(args, code, "%s", "krb");                                  \
        code = krb5_parse_name(args->ctx, "foo@bar@EXAMPLE.COM", &princ); \
        msg = krb5_get_error_message(args->ctx, code);                    \
        basprintf(&expected, "%d %s: %s", (p), "krb", msg);               \
        seen = pam_output();                                              \
        is_string(expected, seen->strings[0], "%s", (n));                 \
        pam_output_free(seen);                                            \
        free(expected);                                                   \
        krb5_free_error_message(args->ctx, msg);                          \
    } while (0);


int
main(void)
{
    pam_handle_t *pamh;
    struct pam_args *args;
    struct pam_conv conv = { NULL, NULL };
    char *expected;
    struct output *seen;
#ifdef HAVE_KERBEROS
    krb5_error_code code;
    krb5_principal princ;
#endif

    plan(15);

    if (pam_start("test", NULL, &conv, &pamh) != PAM_SUCCESS)
        sysbail("Fake PAM initialization failed");
    args = putil_args_new(pamh, 0);
    TEST(putil_crit,  LOG_CRIT,  "putil_crit");
    TEST(putil_err,   LOG_ERR,   "putil_err");
    putil_debug(args, "%s", "foo");
    ok(pam_output() == NULL, "putil_debug without debug on");
    args->debug = true;
    TEST(putil_debug, LOG_DEBUG, "putil_debug");
    args->debug = false;

    TEST_PAM(putil_crit_pam,  PAM_SYSTEM_ERR, LOG_CRIT,  "putil_crit_pam S");
    TEST_PAM(putil_crit_pam,  PAM_BUF_ERR,    LOG_CRIT,  "putil_crit_pam B");
    TEST_PAM(putil_crit_pam,  PAM_SUCCESS,    LOG_CRIT,  "putil_crit_pam ok");
    TEST_PAM(putil_err_pam,   PAM_SYSTEM_ERR, LOG_ERR,   "putil_err_pam");
    putil_debug_pam(args, PAM_SYSTEM_ERR, "%s", "bar");
    ok(pam_output() == NULL, "putil_debug_pam without debug on");
    args->debug = true;
    TEST_PAM(putil_debug_pam, PAM_SYSTEM_ERR, LOG_DEBUG, "putil_debug_pam");
    TEST_PAM(putil_debug_pam, PAM_SUCCESS,    LOG_DEBUG, "putil_debug_pam ok");
    args->debug = false;

#ifdef HAVE_KERBEROS
    TEST_KRB5(putil_crit_krb5,  LOG_CRIT,  "putil_crit_krb5");
    TEST_KRB5(putil_err_krb5,   LOG_ERR,   "putil_err_krb5");
    code = krb5_parse_name(args->ctx, "foo@bar@EXAMPLE.COM", &princ);
    putil_debug_krb5(args, code, "%s", "krb");
    ok(pam_output() == NULL, "putil_debug_krb5 without debug on");
    args->debug = true;
    TEST_KRB5(putil_debug_krb5, LOG_DEBUG, "putil_debug_krb5");
    args->debug = false;
#else
    skip_block(4, "not built with Kerberos support");
#endif

    putil_args_free(args);
    pam_end(pamh, 0);

    return 0;
}
