/*
 * Tests for the alt_auth_map functionality in libpam-krb5.
 *
 * This test case tests the variations of the alt_auth_map functionality for
 * both authentication and account management.  It requires a Kerberos
 * configuration, but does not attempt to save a session ticket cache (to
 * avoid requiring user configuration).
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/fakepam/script.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>


int
main(void)
{
    struct script_config config;
    struct kerberos_config *krbconf;

    /*
     * Load the Kerberos principal and password from a file, but set the
     * principal as extra[0] and use something else bogus as the user.  We
     * want to test that alt_auth_map works when there's no relationship
     * between the mapped principal and the user.
     */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_PASSWORD);
    memset(&config, 0, sizeof(config));
    config.user = "bogus-nonexistent-account";
    config.extra[0] = krbconf->userprinc;
    config.authtok = krbconf->password;

    /*
     * Generate a testing krb5.conf file with a nonexistent default realm so
     * that we can be sure that our principals will stay fully-qualified in
     * the logs.
     */
    kerberos_generate_conf("bogus.example.com");
    config.extra[1] = "bogus.example.com";

    plan_lazy();
    run_script("data/scripts/alt-auth/basic", &config);
    run_script("data/scripts/alt-auth/basic-debug", &config);

    return 0;
}
