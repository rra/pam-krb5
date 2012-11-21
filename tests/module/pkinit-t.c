/*
 * PKINIT authentication tests for the pam-krb5 module.
 *
 * This test case includes tests that require a PKINIT certificate, but which
 * don't write a Kerberos ticket cache.
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


int
main(void)
{
    struct script_config config;
    struct kerberos_config *krbconf;

    /* Load the Kerberos principal and certificate path. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_PKINIT);
    memset(&config, 0, sizeof(config));
    config.user = krbconf->pkinit_principal;
    config.extra[0] = krbconf->pkinit_cert;

    /*
     * Generate a testing krb5.conf file with a nonexistent default realm so
     * that we can be sure that our principals will stay fully-qualified in
     * the logs.
     */
    kerberos_generate_conf("bogus.example.com");

    /*
     * Currently, what we can test and how to test varies a lot by Kerberos
     * implementation.  This will improve later.
     */
    plan_lazy();
#ifdef HAVE_KRB5_HEIMDAL
    run_script("data/scripts/pkinit/basic", &config);
    run_script("data/scripts/pkinit/basic-debug", &config);
    run_script("data/scripts/pkinit/prompt-use", &config);
#else
    run_script("data/scripts/pkinit/no-use-pkinit", &config);
#endif
    run_script("data/scripts/pkinit/try-pkinit", &config);
#ifdef HAVE_KRB5_HEIMDAL
    run_script("data/scripts/pkinit/try-pkinit-debug", &config);
    run_script("data/scripts/pkinit/prompt-try", &config);
#else
    run_script("data/scripts/pkinit/try-pkinit-debug-mit", &config);
    run_script("data/scripts/pkinit/preauth-opt-mit", &config);
#endif

    return 0;
}
