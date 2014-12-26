/*
 * Tests for the pam-krb5 module with an expired password.
 *
 * This test case checks correct handling of an account whose password has
 * expired and the multiple different paths the module can take for handling
 * that case.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012
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
    struct kerberos_config *krbconf;
    char *newpass, *date;
    struct passwd pwd;
    time_t now;

    /* Load the Kerberos principal and password from a file. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_PASSWORD);
    memset(&config, 0, sizeof(config));
    config.user = krbconf->username;
    config.password = krbconf->password;
    config.extra[0] = krbconf->userprinc;

    /*
     * Ensure we can expire the password.  Heimdal has a prompt for the
     * expiration time, so save that to use as a substitution in the script.
     */
    now = time(NULL) - 1;
    if (!kerberos_expire_password(krbconf->userprinc, now))
        skip_all("kadmin not configured or kadmin mismatch");
    date = bstrdup(ctime(&now));
    date[strlen(date) - 1] = '\0';
    config.extra[1] = date;

    /* Generate a testing krb5.conf file. */
    kerberos_generate_conf(krbconf->realm);

    /* Create a fake passwd struct for our user. */
    memset(&pwd, 0, sizeof(pwd));
    pwd.pw_name = krbconf->username;
    pwd.pw_uid = getuid();
    pwd.pw_gid = getgid();
    basprintf(&pwd.pw_dir, "%s/tmp", getenv("BUILD"));
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
    config.newpass = krbconf->password;
    config.password = newpass;
    kerberos_expire_password(krbconf->userprinc, now);
    run_script("data/scripts/expired/basic-heimdal-debug", &config);
#else
    run_script("data/scripts/expired/basic-mit", &config);
    config.newpass = krbconf->password;
    config.password = newpass;
    kerberos_expire_password(krbconf->userprinc, now);
    run_script("data/scripts/expired/basic-mit-debug", &config);
#endif

    /* Test again with PAM_SILENT, specified two ways. */
#ifdef HAVE_KRB5_HEIMDAL
    config.newpass = newpass;
    config.password = krbconf->password;
    kerberos_expire_password(krbconf->userprinc, now);
    run_script("data/scripts/expired/basic-heimdal-silent", &config);
    config.newpass = krbconf->password;
    config.password = newpass;
    kerberos_expire_password(krbconf->userprinc, now);
    run_script("data/scripts/expired/basic-heimdal-flag-silent", &config);
#else
    config.newpass = newpass;
    config.password = krbconf->password;
    kerberos_expire_password(krbconf->userprinc, now);
    run_script("data/scripts/expired/basic-mit-silent", &config);
    config.newpass = krbconf->password;
    config.password = newpass;
    kerberos_expire_password(krbconf->userprinc, now);
    run_script("data/scripts/expired/basic-mit-flag-silent", &config);
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
    config.password = krbconf->password;
    config.authtok = krbconf->password;
    kerberos_expire_password(krbconf->userprinc, now);
    run_script("data/scripts/expired/defer", &config);
    config.newpass = krbconf->password;
    config.password = newpass;
    config.authtok = newpass;
    kerberos_expire_password(krbconf->userprinc, now);
    run_script("data/scripts/expired/defer-debug", &config);

#else /* !HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CHANGE_PASSWORD_PROMPT */

    /* Mention that we skipped something for the record. */
    skip_block(4, "cannot disable library password prompting");

#endif /* HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CHANGE_PASSWORD_PROMPT */

    /* In case we ran into some error, try to unexpire the password. */
    kerberos_expire_password(krbconf->userprinc, 0);

    free(date);
    free(newpass);
    free(pwd.pw_dir);
    return 0;
}
