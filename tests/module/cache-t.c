/*
 * Authentication tests for the pam-krb5 module with ticket cache.
 *
 * This test case includes all tests that require Kerberos to be configured, a
 * username and password available, and a ticket cache created, but with the
 * PAM module running as the same user for which the ticket cache will be
 * created (so without setuid and with chown doing nothing).
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012
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

/* Additional data used by the cache check callback. */
struct extra {
    char *realm;
};


/*
 * PAM test callback to check whether we created a ticket cache and the ticket
 * cache is for the correct user.
 */
static void
check_cache(pam_handle_t *pamh, const struct script_config *config, void *data)
{
    struct extra *extra = data;
    const char *cache, *file;
    struct stat st;
    char *prefix;
    krb5_error_code code;
    krb5_context ctx = NULL;
    krb5_ccache ccache = NULL;
    krb5_principal princ = NULL;
    krb5_principal tgtprinc = NULL;
    krb5_creds in, out;
    char *principal = NULL;

    /* Check cache naming, ownership, and permissions. */
    cache = pam_getenv(pamh, "KRB5CCNAME");
    ok(cache != NULL, "KRB5CCNAME is set in PAM environment");
    if (cache == NULL)
        return;
    basprintf(&prefix, "FILE:/tmp/krb5cc_%lu_", (unsigned long) getuid());
    diag("KRB5CCNAME = %s", cache);
    ok(strncmp(prefix, cache, strlen(prefix)) == 0,
       "cache file name prefix is correct");
    free(prefix);
    file = cache + strlen("FILE:");
    is_int(0, stat(file, &st), "cache exists");
    is_int(getuid(), st.st_uid, "...with correct UID");
    is_int(getgid(), st.st_gid, "...with correct GID");
    is_int(0600, (st.st_mode & 0777), "...with correct permissions");

    /* Check the existence of the ticket cache and its principal. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail("cannot create Kerberos context");
    code = krb5_cc_resolve(ctx, cache, &ccache);
    is_int(0, code, "able to resolve Kerberos ticket cache");
    code = krb5_cc_get_principal(ctx, ccache, &princ);
    is_int(0, code, "able to get principal");
    code = krb5_unparse_name(ctx, princ, &principal);
    is_int(0, code, "...and principal is valid");
    is_string(config->extra[0], principal, "...and matches our principal");

    /* Retrieve the krbtgt for the realm and check properties. */
    code = krb5_build_principal_ext(ctx, &tgtprinc,
                                    strlen(extra->realm), extra->realm,
                                    KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                    strlen(extra->realm), extra->realm,
                                    NULL);
    if (code != 0)
        bail("cannot create krbtgt principal name");
    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.server = tgtprinc;
    in.client = princ;
    code = krb5_cc_retrieve_cred(ctx, ccache, KRB5_TC_MATCH_SRV_NAMEONLY,
                                 &in, &out);
    is_int(0, code, "able to get krbtgt credentials");
    ok(out.times.endtime > time(NULL) + 30 * 60, "...good for 30 minutes");
    krb5_free_cred_contents(ctx, &out);

    /* Close things and release memory. */
    krb5_free_principal(ctx, tgtprinc);
    krb5_free_unparsed_name(ctx, principal);
    krb5_free_principal(ctx, princ);
    krb5_cc_close(ctx, ccache);
    krb5_free_context(ctx);
}


int
main(void)
{
    struct script_config config;
    struct kerberos_config *krbconf;
    char *k5login;
    struct extra extra;
    struct passwd pwd;
    FILE *file;

    /* Load the Kerberos principal and password from a file. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_PASSWORD);
    memset(&config, 0, sizeof(config));
    config.user = krbconf->username;
    extra.realm = krbconf->realm;
    config.authtok = krbconf->password;
    config.extra[0] = krbconf->userprinc;

    /* Generate a testing krb5.conf file. */
    kerberos_generate_conf(krbconf->realm);

    /* Create a fake passwd struct for our user. */
    memset(&pwd, 0, sizeof(pwd));
    pwd.pw_name = krbconf->username;
    pwd.pw_uid = getuid();
    pwd.pw_gid = getgid();
    basprintf(&pwd.pw_dir, "%s/tmp", getenv("BUILD"));
    pam_set_pwd(&pwd);

    plan_lazy();

    /* Basic test. */
    run_script("data/scripts/cache/basic", &config);

    /* Check the cache status before the session is closed. */
    config.callback = check_cache;
    config.data = &extra;
    run_script("data/scripts/cache/open-session", &config);

    /* Change the authenticating user and test search_k5login. */
    pwd.pw_name = (char *) "testuser";
    config.user = "testuser";
    basprintf(&k5login, "%s/.k5login", pwd.pw_dir);
    file = fopen(k5login, "w");
    if (file == NULL)
        sysbail("cannot create %s", k5login);
    if (fprintf(file, "%s\n", krbconf->userprinc) < 0)
        sysbail("cannot write to %s", k5login);
    if (fclose(file) < 0)
        sysbail("cannot flush %s", k5login);
    run_script("data/scripts/cache/search-k5login", &config);
    config.callback = NULL;
    run_script("data/scripts/cache/search-k5login-debug", &config);
    unlink(k5login);
    free(k5login);

    /* Test search_k5login when no .k5login file exists. */
    pwd.pw_name = krbconf->username;
    config.user = krbconf->username;
    diag("testing search_k5login with no .k5login file");
    run_script("data/scripts/cache/search-k5login", &config);

    free(pwd.pw_dir);
    return 0;
}
