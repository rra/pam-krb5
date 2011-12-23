/*
 * Utility functions for tests that use Kerberos.
 *
 * Currently only provides kerberos_setup(), which assumes a particular set of
 * data files in either the SOURCE or BUILD directories and, using those,
 * obtains Kerberos credentials, sets up a ticket cache, and sets the
 * environment variable pointing to the Kerberos keytab to use for testing.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2009, 2010, 2011
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
#include <portable/krb5.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/string.h>


/*
 * These variables hold the allocated strings for the principal and the
 * environment to point to a different Kerberos ticket cache and keytab.  We
 * store them so that we can free them on exit for cleaner valgrind output,
 * making it easier to find real memory leaks in the tested programs.
 */
static char *principal = NULL;
static char *krb5ccname = NULL;
static char *krb5_ktname = NULL;


/*
 * Report a Kerberos error and bail out.
 */
void
bail_krb5(krb5_context ctx, krb5_error_code code, const char *format, ...)
{
    const char *k5_msg = NULL;
    char *message;
    va_list args;

    if (ctx != NULL)
        k5_msg = krb5_get_error_message(ctx, code);
    va_start(args, format);
    bvasprintf(&message, format, args);
    va_end(args);
    if (k5_msg == NULL)
        bail("%s", message);
    else
        bail("%s: %s", message, k5_msg);
}


/*
 * Report a Kerberos error as a diagnostic to stderr.
 */
void
diag_krb5(krb5_context ctx, krb5_error_code code, const char *format, ...)
{
    const char *k5_msg = NULL;
    char *message;
    va_list args;

    if (ctx != NULL)
        k5_msg = krb5_get_error_message(ctx, code);
    va_start(args, format);
    bvasprintf(&message, format, args);
    va_end(args);
    if (k5_msg == NULL)
        diag("%s", message);
    else
        diag("%s: %s", message, k5_msg);
    free(message);
    if (k5_msg != NULL)
        krb5_free_error_message(ctx, k5_msg);
}


/*
 * Clean up at the end of a test.  This removes the ticket cache and resets
 * and frees the memory allocated for the environment variables so that
 * valgrind output on test suites is cleaner.
 */
void
kerberos_cleanup(void)
{
    const char *build;
    char *path;

    build = getenv("BUILD");
    if (build == NULL)
        build = ".";
    basprintf(&path, "%s/tmp/krb5cc_test", build);
    unlink(path);
    free(path);
    basprintf(&path, "%s/tmp", build);
    rmdir(path);
    free(path);
    if (principal != NULL) {
        free(principal);
        principal = NULL;
    }
    putenv((char *) "KRB5CCNAME=");
    putenv((char *) "KRB5_KTNAME=");
    if (krb5ccname != NULL) {
        free(krb5ccname);
        krb5ccname = NULL;
    }
    if (krb5_ktname != NULL) {
        free(krb5_ktname);
        krb5_ktname = NULL;
    }
}


/*
 * Obtain Kerberos tickets for the principal specified in config/principal
 * using the keytab specified in config/keytab, both of which are presumed to
 * be in tests in either the build or the source tree.  Also sets KRB5_KTNAME
 * and KRB5CCNAME.
 *
 * Returns the contents of config/principal in newly allocated memory or NULL
 * if Kerberos tests are apparently not configured.  If Kerberos tests are
 * configured but something else fails, calls bail.
 */
const char *
kerberos_setup(void)
{
    char *path, *krbtgt;
    const char *build, *realm;
    FILE *file;
    char buffer[BUFSIZ];
    krb5_error_code code;
    krb5_context ctx;
    krb5_ccache ccache;
    krb5_principal kprinc;
    krb5_keytab keytab;
    krb5_get_init_creds_opt *opts;
    krb5_creds creds;

    /* If we were called before, clean up after the previous run. */
    if (principal != NULL)
        kerberos_cleanup();

    /* Read the principal name and find the keytab file. */
    path = test_file_path("config/principal");
    if (path == NULL)
        return NULL;
    file = fopen(path, "r");
    if (file == NULL) {
        free(path);
        return NULL;
    }
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        fclose(file);
        bail("cannot read %s", path);
    }
    fclose(file);
    if (buffer[strlen(buffer) - 1] != '\n')
        bail("no newline in %s", path);
    free(path);
    buffer[strlen(buffer) - 1] = '\0';
    path = test_file_path("config/keytab");
    if (path == NULL)
        return NULL;

    /* Set the KRB5CCNAME and KRB5_KTNAME environment variables. */
    build = getenv("BUILD");
    if (build == NULL)
        build = ".";
    basprintf(&krb5ccname, "KRB5CCNAME=%s/tmp/krb5cc_test", build);
    basprintf(&krb5_ktname, "KRB5_KTNAME=%s", path);
    putenv(krb5ccname);
    putenv(krb5_ktname);

    /* Now do the Kerberos initialization. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "error initializing Kerberos");
    code = krb5_cc_default(ctx, &ccache);
    if (code != 0)
        bail_krb5(ctx, code, "error setting ticket cache");
    code = krb5_parse_name(ctx, buffer, &kprinc);
    if (code != 0)
        bail_krb5(ctx, code, "error parsing principal %s", buffer);
    realm = krb5_principal_get_realm(ctx, kprinc);
    basprintf(&krbtgt, "krbtgt/%s@%s", realm, realm);
    code = krb5_kt_resolve(ctx, path, &keytab);
    if (code != 0)
        bail_krb5(ctx, code, "cannot open keytab %s", path);
    code = krb5_get_init_creds_opt_alloc(ctx, &opts);
    if (code != 0)
        bail_krb5(ctx, code, "cannot allocate credential options");
    krb5_get_init_creds_opt_set_default_flags(ctx, NULL, realm, opts);
    krb5_get_init_creds_opt_set_forwardable(opts, 0);
    krb5_get_init_creds_opt_set_proxiable(opts, 0);
    code = krb5_get_init_creds_keytab(ctx, &creds, kprinc, keytab, 0, krbtgt,
                                      opts);
    if (code != 0)
        bail_krb5(ctx, code, "cannot get Kerberos tickets");
    code = krb5_cc_initialize(ctx, ccache, kprinc);
    if (code != 0)
        bail_krb5(ctx, code, "error initializing ticket cache");
    code = krb5_cc_store_cred(ctx, ccache, &creds);
    if (code != 0)
        bail_krb5(ctx, code, "error storing credentials");
    krb5_cc_close(ctx, ccache);
    krb5_free_cred_contents(ctx, &creds);
    krb5_kt_close(ctx, keytab);
    krb5_free_principal(ctx, kprinc);
    krb5_free_context(ctx);
    krb5_get_init_creds_opt_free(ctx, opts);
    free(krbtgt);
    test_file_path_free(path);

    /*
     * Register the cleanup function as an atexit handler so that the caller
     * doesn't have to worry about cleanup.
     */
    if (atexit(kerberos_cleanup) != 0)
        sysdiag("cannot register cleanup function");

    /* Store the principal and return it. */
    principal = bstrdup(buffer);
    return principal;
}


/*
 * Find the principal of the first entry of a keytab and return it.  The
 * caller is responsible for freeing the result with krb5_free_principal.
 * Exit on error.
 */
krb5_principal
kerberos_keytab_principal(krb5_context ctx, const char *path)
{
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_principal princ;
    krb5_error_code status;

    status = krb5_kt_resolve(ctx, path, &keytab);
    if (status != 0)
        bail_krb5(ctx, status, "error opening %s", path);
    status = krb5_kt_start_seq_get(ctx, keytab, &cursor);
    if (status != 0)
        bail_krb5(ctx, status, "error reading %s", path);
    status = krb5_kt_next_entry(ctx, keytab, &entry, &cursor);
    if (status == 0) {
        status = krb5_copy_principal(ctx, entry.principal, &princ);
        if (status != 0)
            bail_krb5(ctx, status, "error copying principal from %s", path);
        krb5_kt_free_entry(ctx, &entry);
    }
    if (status != 0)
        bail("no principal found in keytab file %s", path);
    krb5_kt_end_seq_get(ctx, keytab, &cursor);
    krb5_kt_close(ctx, keytab);
    return princ;
}
