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

#include <tests/fakepam/script.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>


int
main(void)
{
    struct script_config config;
    struct kerberos_password *password;

    /* Load the Kerberos principal and password from a file. */
    password = kerberos_config_password();
    if (password == NULL)
        skip_all("Kerberos tests not configured");
    memset(&config, 0, sizeof(config));
    config.user = password->principal;
    config.password = password->password;

    /*
     * Generate a testing krb5.conf file with a nonexistent default realm so
     * that we can be sure that our principals will stay fully-qualified in
     * the logs.
     */
    kerberos_generate_conf("bogus.example.com");

    plan_lazy();
    run_script_dir("data/scripts/no-cache", &config);

    kerberos_config_password_free(password);
    return 0;
}
