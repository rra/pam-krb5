/*
 * Authentication tests for the pam-krb5 module without a ticket cache.
 *
 * This test case includes all tests that require Kerberos to be configured
 * and a username and password available, but which don't write a ticket
 * cache (which requires additional work to test the cache ownership).
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/module/script.h>
#include <tests/tap/process.h>


int
main(void)
{
    char *path;
    char principal[BUFSIZ], password[BUFSIZ];
    FILE *file;
    const char *argv[2];
    char *env;

    /* Load the Kerberos principal and password from a file. */
    path = test_file_path("config/password");
    if (path == NULL)
        skip_all("Kerberos tests not configured");
    file = fopen(path, "r");
    if (file == NULL)
        sysbail("cannot open %s", path);
    if (fgets(principal, sizeof(principal), file) == NULL)
        bail("cannot read %s", path);
    if (fgets(password, sizeof(password), file) == NULL)
        bail("cannot read password from %s", path);
    fclose(file);
    if (principal[strlen(principal) - 1] != '\n')
        bail("no newline in %s", path);
    principal[strlen(principal) - 1] = '\0';
    if (password[strlen(password) - 1] != '\n')
        bail("principal or password too long in %s", path);
    password[strlen(password) - 1] = '\0';
    test_file_path_free(path);

    /*
     * Generate a test krb5.conf file in the current directory and use it.  We
     * need to do this to ensure that we don't pick up unwanted configuration
     * from the system krb5.conf file.
     */
    path = test_file_path("data/generate-krb5-conf");
    if (path == NULL)
        bail("cannot find generate-krb5-conf");
    argv[0] = path;
    argv[1] = NULL;
    run_setup(argv);
    test_file_path_free(path);
    if (asprintf(&env, "KRB5_CONFIG=%s/krb5.conf", getenv("BUILD")) < 0)
        sysbail("cannot build KRB5_CONFIG");
    putenv(env);

    plan(15);

    run_script("data/scripts/no-cache/basic", principal, password);
    run_script("data/scripts/no-cache/prompt", principal, password);
    run_script("data/scripts/no-cache/auth-only", principal, password);

    if (chdir(getenv("BUILD")) == 0)
        unlink("krb5.conf");
    putenv((char *) "KRB5_CONFIG=");
    free(env);
    return 0;
}
