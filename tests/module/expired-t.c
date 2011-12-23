/*
 * Tests for the pam-krb5 module with an expired password.
 *
 * This test case checks correct handling of an account whose password has
 * expired and the multiple different paths the module can take for handling
 * that case.
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
#include <time.h>

#include <tests/fakepam/pam.h>
#include <tests/fakepam/script.h>
#include <tests/tap/basic.h>
#include <tests/tap/kadmin.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>


int
main(void)
{
    struct script_config config;
    struct kerberos_password *password;
    char *path, *env, *newpass, *date;
    const char *argv[3];
    struct passwd pwd;
    time_t now;

    /* Load the Kerberos principal and password from a file. */
    password = kerberos_config_password();
    if (password == NULL)
        skip_all("Kerberos tests not configured");
    memset(&config, 0, sizeof(config));
    config.user = password->username;
    config.password = password->password;
    config.extra[0] = password->principal;

    /*
     * Ensure we can expire the password.  Heimdal has a prompt for the
     * expiration time, so save that to use as a substitution in the script.
     */
    now = time(NULL) - 1;
    if (!kerberos_expire_password(password->principal, now))
        skip_all("kadmin not configured or kadmin mismatch");
    date = bstrdup(ctime(&now));
    date[strlen(date) - 1] = '\0';
    config.extra[1] = date;

    /*
     * Generate a test krb5.conf file in the current directory and use it.  We
     * need to do this to ensure that we don't pick up unwanted configuration
     * from the system krb5.conf file.
     */
    path = test_file_path("data/generate-krb5-conf");
    if (path == NULL)
        bail("cannot find generate-krb5-conf");
    argv[0] = path;
    argv[1] = password->realm;
    argv[2] = NULL;
    run_setup(argv);
    test_file_path_free(path);
    basprintf(&env, "KRB5_CONFIG=%s/krb5.conf", getenv("BUILD"));
    putenv(env);

    /* Create a fake passwd struct for our user. */
    memset(&pwd, 0, sizeof(pwd));
    pwd.pw_name = password->username;
    pwd.pw_uid = getuid();
    pwd.pw_gid = getgid();
    basprintf(&pwd.pw_dir, "%s/data", getenv("BUILD"));
    pam_set_pwd(&pwd);

    /*
     * We'll be changing the password to something new.  This needs to be
     * sufficiently random that it's unlikely to fall afoul of password
     * strength checking.
     */
    basprintf(&newpass, "ngh1,a%lu nn9af6", (unsigned long) getpid());
    config.newpass = newpass;

    plan_lazy();

    /* Default behavior. */
#ifdef HAVE_KRB5_HEIMDAL
    run_script("data/scripts/expired/basic-heimdal", &config);
    config.newpass = password->password;
    config.password = newpass;
    kerberos_expire_password(password->principal, now);
    run_script("data/scripts/expired/basic-heimdal-debug", &config);
#else
    run_script("data/scripts/expired/basic-mit", &config);
    config.newpass = password->password;
    config.password = newpass;
    kerberos_expire_password(password->principal, now);
    run_script("data/scripts/expired/basic-mit-debug", &config);
#endif

    /*
     * We can only run the remaining checks if we can suppress the Kerberos
     * library behavior of prompting for a new password when the password has
     * expired.
     */
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CHANGE_PASSWORD_PROMPT

    /* Check the forced failure behavior. */
    run_script("data/scripts/expired/fail", &config);
    run_script("data/scripts/expired/fail-debug", &config);

    /* Defer the error to the account management check. */
    config.newpass = newpass;
    config.password = password->password;
    kerberos_expire_password(password->principal, now);
    run_script("data/scripts/expired/defer", &config);
    config.newpass = password->password;
    config.password = newpass;
    kerberos_expire_password(password->principal, now);
    run_script("data/scripts/expired/defer-debug", &config);

#endif /* HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CHANGE_PASSWORD_PROMPT */

    free(date);
    free(newpass);
    free(pwd.pw_dir);
    if (chdir(getenv("BUILD")) == 0)
        unlink("krb5.conf");
    putenv((char *) "KRB5_CONFIG=");
    free(env);
    kerberos_config_password_free(password);
    return 0;
}
