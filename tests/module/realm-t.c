/*
 * Authentication tests for realm support in pam-krb5.
 *
 * Test the realm option in the PAM configuration, which is special in several
 * ways since it influences krb5.conf parsing and is read out of order in the
 * initial configuration.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <tests/fakepam/script.h>
#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>


int
main(void)
{
    struct script_config config;
    struct kerberos_config *krbconf;

    /* Load the Kerberos principal and password from a file. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_PASSWORD);
    memset(&config, 0, sizeof(config));
    config.user = krbconf->username;
    config.authtok = krbconf->password;

    /* Don't keep track of the tests in each script. */
    plan_lazy();

    /* Start with a nonexistent default realm for authentication failure. */
    kerberos_generate_conf("bogus.example.com");
    config.extra[0] = "bogus.example.com";
    run_script("data/scripts/realm/fail-no-realm", &config);
    run_script("data/scripts/realm/fail-no-realm-debug", &config);

    /* Running a script that sets realm properly should pass. */
    config.extra[0] = krbconf->realm;
    run_script("data/scripts/realm/pass-realm", &config);

    /* Switch to the correct realm, but set the wrong realm in PAM. */
    kerberos_cleanup_conf();
    kerberos_generate_conf(krbconf->realm);
    config.extra[0] = "bogus.example.com";
    run_script("data/scripts/realm/fail-realm", &config);

    return 0;
}
