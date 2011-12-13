/*
 * Authentication tests for the pam-krb5 module with ticket cache.
 *
 * This test case includes all tests that require Kerberos to be configured, a
 * username and password available, and a ticket cache created, but with the
 * PAM module running as the same user for which the ticket cache will be
 * created (so without setuid and with chown doing nothing).
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
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
#include <tests/tap/process.h>

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
    if (asprintf(&prefix, "FILE:/tmp/krb5cc_%lu_",
                 (unsigned long) getuid()) < 0)
        sysbail("cannot build cache prefix");
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
    char *path, *realm, *k5login;
    char principal[BUFSIZ], password[BUFSIZ];
    struct script_config config;
    struct extra extra;
    FILE *file;
    const char *argv[3];
    char *env;
    struct passwd pwd;

    /* Load the Kerberos principal and password from a file. */
    memset(&config, 0, sizeof(config));
    path = test_file_path("config/password");
    if (path == NULL)
        skip_all("Kerberos tests not configured");
    file = fopen(path, "r");
    if (file == NULL)
        sysbail("cannot open %s", path);
    if (fgets(principal, sizeof(principal), file) == NULL)
        bail("cannot read %s", path);
    if (fgets(password, sizeof(password), file) == NULL)
        bail("cannot read password from %s", path);
    fclose(file);
    if (principal[strlen(principal) - 1] != '\n')
        bail("no newline in %s", path);
    principal[strlen(principal) - 1] = '\0';
    if (password[strlen(password) - 1] != '\n')
        bail("principal or password too long in %s", path);
    password[strlen(password) - 1] = '\0';
    test_file_path_free(path);
    config.password = password;
    config.extra[0] = bstrdup(principal);

    /*
     * Strip the realm from the principal.  We'll make the realm of the
     * principal our default realm.
     */
    realm = strchr(principal, '@');
    if (realm == NULL)
        bail("test principal has no realm");
    *realm = '\0';
    realm++;
    extra.realm = realm;
    config.user = principal;

    /*
     * Generate a test krb5.conf file in the current directory and use it.  We
     * need to do this to ensure that we don't pick up unwanted configuration
     * from the system krb5.conf file.
     */
    path = test_file_path("data/generate-krb5-conf");
    if (path == NULL)
        bail("cannot find generate-krb5-conf");
    argv[0] = path;
    argv[1] = realm;
    argv[2] = NULL;
    run_setup(argv);
    test_file_path_free(path);
    if (asprintf(&env, "KRB5_CONFIG=%s/krb5.conf", getenv("BUILD")) < 0)
        sysbail("cannot build KRB5_CONFIG");
    putenv(env);

    /* Create a fake passwd struct for our user. */
    memset(&pwd, 0, sizeof(pwd));
    pwd.pw_name = principal;
    pwd.pw_uid = getuid();
    pwd.pw_gid = getgid();
    if (asprintf(&pwd.pw_dir, "%s/data", getenv("BUILD")) < 0)
        sysbail("cannot build user home directory");
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
    if (asprintf(&k5login, "%s/.k5login", pwd.pw_dir) < 0)
        sysbail("cannot build .k5login path");
    file = fopen(k5login, "w");
    if (file == NULL)
        sysbail("cannot create %s", k5login);
    if (fprintf(file, "%s@%s\n", principal, realm) < 0)
        sysbail("cannot write to %s", k5login);
    if (fclose(file) < 0)
        sysbail("cannot flush %s", k5login);
    run_script("data/scripts/cache/search-k5login", &config);

    unlink(k5login);
    free(k5login);
    if (chdir(getenv("BUILD")) == 0)
        unlink("krb5.conf");
    putenv((char *) "KRB5_CONFIG=");
    free(env);
    free(pwd.pw_dir);
    free((char *) config.extra[0]);
    return 0;
}
