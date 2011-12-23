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
#include <portable/krb5.h>
#include <portable/system.h>

#include <pwd.h>
#include <sys/stat.h>
#include <time.h>

#include <tests/fakepam/pam.h>
#include <tests/fakepam/script.h>
#include <tests/tap/basic.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>


int
main(void)
{
    char *path, *realm, *newpass, *env;
    char principal[BUFSIZ], password[BUFSIZ];
    struct script_config config;
    FILE *file;
    const char *argv[3];

    /* Load the Kerberos principal and password from a file. */
    memset(&config, 0, sizeof(config));
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
    config.extra[0] = bstrdup(principal);

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
    basprintf(&env, "KRB5_CONFIG=%s/krb5.conf", getenv("BUILD"));
    putenv(env);

    plan_lazy();

    /*
     * Change the password to something new.  This needs to be sufficiently
     * random that it's unlikely to fall afoul of password strength checking.
     */
    basprintf(&newpass, "ngh1,a%lu nn9af6", (unsigned long) getpid());
    config.newpass = newpass;
    run_script("data/scripts/password/basic", &config);

    /* Change the password back. */
    config.password = newpass;
    config.newpass = password;
    run_script("data/scripts/password/basic", &config);

    free(newpass);
    if (chdir(getenv("BUILD")) == 0)
        unlink("krb5.conf");
    putenv((char *) "KRB5_CONFIG=");
    free(env);
    free((char *) config.extra[0]);
    return 0;
}
