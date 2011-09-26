/*
 * Authentication tests for the pam-krb5 module with ticket cache.
 *
 * This test case includes all tests that require Kerberos to be configured, a
 * username and password available, and a ticket cache created, but with the
 * PAM module running as the same user for which the ticket cache will be
 * created (so without setuid and with chown doing nothing).
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <pwd.h>

#include <tests/fakepam/testing.h>
#include <tests/module/script.h>
#include <tests/tap/basic.h>
#include <tests/tap/process.h>


int
main(void)
{
    char *path, *realm;
    char principal[BUFSIZ], password[BUFSIZ];
    struct script_config config;
    FILE *file;
    const char *argv[3];
    char *env;
    struct passwd pwd;

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
    config.password = password;
    config.str1 = bstrdup(principal);

    /*
     * Strip the realm from the principal.  We'll make the realm of the
     * principal our default realm.
     */
    realm = strchr(principal, '@');
    if (realm == NULL)
        bail("test principal has no realm");
    *realm = '\0';
    realm++;
    config.user = principal;

    /*
     * Generate a test krb5.conf file in the current directory and use it.  We
     * need to do this to ensure that we don't pick up unwanted configuration
     * from the system krb5.conf file.
     */
    path = test_file_path("data/generate-krb5-conf");
    if (path == NULL)
        bail("cannot find generate-krb5-conf");
    argv[0] = path;
    argv[1] = realm;
    argv[2] = NULL;
    run_setup(argv);
    test_file_path_free(path);
    if (asprintf(&env, "KRB5_CONFIG=%s/krb5.conf", getenv("BUILD")) < 0)
        sysbail("cannot build KRB5_CONFIG");
    putenv(env);

    /* Create a fake passwd struct for our user. */
    memset(&pwd, 0, sizeof(pwd));
    pwd.pw_name = principal;
    pwd.pw_uid = getuid();
    pwd.pw_gid = getgid();
    if (asprintf(&pwd.pw_dir, "%s/data", getenv("BUILD")) < 0)
        sysbail("cannot build user home directory");
    pam_set_pwd(&pwd);

    plan(5);

    run_script("data/scripts/cache/basic", &config);

    if (chdir(getenv("BUILD")) == 0)
        unlink("krb5.conf");
    putenv((char *) "KRB5_CONFIG=");
    free(env);
    free(pwd.pw_dir);
    free((char *) config.str1);
    return 0;
}
