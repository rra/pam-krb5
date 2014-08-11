/*
 * Authentication tests for the pam-krb5 module with ticket cache.
 *
 * This test case includes all tests that require Kerberos to be configured, a
 * username and password available, and a ticket cache created, but with the
 * PAM module running as the same user for which the ticket cache will be
 * created (so without setuid and with chown doing nothing).
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012, 2014
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
#include <tests/tap/kerberos.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>


int
main(void)
{
    struct script_config config;
    struct kerberos_config *krbconf;
    char *newpass;

    /* Load the Kerberos principal and password from a file. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_PASSWORD);
    memset(&config, 0, sizeof(config));
    config.user = krbconf->username;
    config.password = krbconf->password;
    config.extra[0] = krbconf->userprinc;

    /* Generate a testing krb5.conf file. */
    kerberos_generate_conf(krbconf->realm);

    plan_lazy();

    /*
     * Change the password to something new.  This needs to be sufficiently
     * random that it's unlikely to fall afoul of password strength checking.
     */
    basprintf(&newpass, "ngh1,a%lu nn9af6%lu", (unsigned long) getpid(),
              (unsigned long) time(NULL));
    config.newpass = newpass;
    run_script("data/scripts/password/basic", &config);
    config.password = newpass;
    config.newpass = krbconf->password;
    run_script("data/scripts/password/basic-debug", &config);

    /* Test prompt_principal with password change. */
    config.password = krbconf->password;
    config.newpass = newpass;
    run_script("data/scripts/password/prompt-principal", &config);

    /* Change the password back and test expose-account. */
    config.password = newpass;
    config.newpass = krbconf->password;
    run_script("data/scripts/password/expose", &config);

    /*
     * Test two banner settings by changing the password and then changing it
     * back again.
     */
    config.password = krbconf->password;
    config.newpass = newpass;
    run_script("data/scripts/password/banner", &config);
    config.password = newpass;
    config.newpass = krbconf->password;
    run_script("data/scripts/password/no-banner", &config);

    /* Do the same, but with expose_account set as well. */
    config.password = krbconf->password;
    config.newpass = newpass;
    run_script("data/scripts/password/banner-expose", &config);
    config.password = newpass;
    config.newpass = krbconf->password;
    run_script("data/scripts/password/no-banner-expose", &config);

    /* Test use_authtok. */
    config.password = krbconf->password;
    config.newpass = NULL;
    config.authtok = newpass;
    run_script("data/scripts/password/authtok", &config);

    /* Test use_authtok with force_first_pass. */
    config.password = NULL;
    config.authtok = krbconf->password;
    config.oldauthtok = newpass;
    run_script("data/scripts/password/authtok-force", &config);

    free(newpass);
    return 0;
}
