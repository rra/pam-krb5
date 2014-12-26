/*
 * Tests for FAST support in pam-krb5.
 *
 * Tests for Flexible Authentication Secure Tunneling, a mechanism for
 * improving the preauthentication part of the Kerberos protocol and
 * protecting it against various attacks.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
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


/*
 * Test whether anonymous authentication works.  If this doesn't, we need to
 * skip the tests of anonymous FAST.
 */
static bool
anon_fast_works(void)
{
    krb5_context ctx;
    krb5_error_code retval;
    krb5_principal princ = NULL;
    char *realm;
    krb5_creds creds;
    krb5_get_init_creds_opt *opts = NULL;

    /* Construct the anonymous principal name. */
    retval = krb5_init_context(&ctx);
    if (retval != 0)
        bail("cannot initialize Kerberos");
    retval = krb5_get_default_realm(ctx, &realm);
    if (retval != 0)
        bail("cannot get default realm");
    retval = krb5_build_principal_ext(ctx, &princ, strlen(realm), realm,
                 strlen(KRB5_WELLKNOWN_NAME), KRB5_WELLKNOWN_NAME,
                 strlen(KRB5_ANON_NAME), KRB5_ANON_NAME, NULL);
    if (retval != 0)
        bail("cannot construct anonymous principal");
    krb5_free_default_realm(ctx, realm);

    /* Obtain the credentials. */
    memset(&creds, 0, sizeof(creds));
    retval = krb5_get_init_creds_opt_alloc(ctx, &opts);
    if (retval != 0)
        bail("cannot create credential options");
    krb5_get_init_creds_opt_set_anonymous(opts, 1);
    krb5_get_init_creds_opt_set_tkt_life(opts, 60);
    retval = krb5_get_init_creds_password(ctx, &creds, princ, NULL, NULL,
                                          NULL, 0, NULL, opts);

    /* Clean up. */
    if (princ != NULL)
        krb5_free_principal(ctx, princ);
    if (opts != NULL)
        krb5_get_init_creds_opt_free(ctx, opts);
    krb5_free_cred_contents(ctx, &creds);
    return (retval == 0);
}


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
    if (anon_fast_works()) {
        run_script("data/scripts/fast/anonymous", &config);
        run_script("data/scripts/fast/anonymous-debug", &config);
    } else {
        skip_block(2, "Anonymous authentication required to test anon_fast");
    }

    return 0;
}
