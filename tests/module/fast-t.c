/*
 * Tests for FAST support in pam-krb5.
 *
 * Tests for Flexible Authentication Secure Tunneling, a mechanism for
 * improving the preauthentication part of the Kerberos protocol and
 * protecting it against various attacks.
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

    /* Skip the test if FAST is not available. */
#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_CCACHE_NAME
    skip_all("FAST support not available");
#endif

    /*
     * To test FAST with an existing ticket cache, we also need a keytab, but
     * we can test anonymous FAST without that.  So only say that we require a
     * password.
     */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_PASSWORD);
    memset(&config, 0, sizeof(config));
    config.user = krbconf->userprinc;
    config.authtok = krbconf->password;

    /*
     * Generate a testing krb5.conf file with a nonexistent default realm so
     * that we can be sure that our principals will stay fully-qualified in
     * the logs.
     */
    kerberos_generate_conf("bogus.example.com");

    plan_lazy();

    /* If we have a keytab and ticket cache available, test fast_ccache. */
    if (krbconf->keytab == NULL)
        skip_block(4, "Kerberos keytab required to test fast_ccache");
    else {
        config.extra[0] = krbconf->cache;
        run_script("data/scripts/fast/ccache", &config);
        run_script("data/scripts/fast/ccache-debug", &config);
        run_script("data/scripts/fast/no-ccache", &config);
        run_script("data/scripts/fast/no-ccache-debug", &config);
    }

    /*
     * Test anonymous FAST.  This will require some pre-testing later.  For
     * this, we need to use our real local realm.
     */
    kerberos_generate_conf(krbconf->realm);
    config.user = krbconf->username;
    config.extra[0] = krbconf->userprinc;
    run_script("data/scripts/fast/anonymous", &config);
    run_script("data/scripts/fast/anonymous-debug", &config);

    return 0;
}
