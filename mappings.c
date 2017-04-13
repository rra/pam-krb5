#if 0
#define putil_debug(a1, ...) printf(__VA_ARGS__)
#endif
/*
 * Support for regex username mappings.
 *
 * It can be useful to map one style of username on to a principal name. e.g.
 * the user can supply an NT style WORKGROUP\user name which is mapped to
 * a principal.  Rules can be written such as:
 * mappings = ^DOMAIN\\(.*) $1@CORP.DOMAIN.COM
 *
 * multiple pairs of match/replace rules can be defined on the same line.
 * the used mappings string will be selected from krb5.conf according to
 * the usual rules of precendence given in krb5.conf(5).
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <sys/types.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal.h>
#include <pam-util/args.h>
//#include <pam-util/logging.h>
#include <pam-util/vector.h>

#define SEPARATOR '$'


/*
 * Map the user to a Kerberos principal according to regex.  Returns 0
 * on success, storing the mapped principal name in newly allocated memory in
 * principal.  The caller is responsible for freeing.  Returns an errno value
 * on any error.
 *
 * The structure of this function is copied from the src/map.c RHEL pam_krb5
 * implementation: https://pagure.io/pam_krb5.  The style has been adjusted
 * for consistency with the rest of this package.
 */
static int
map_principal(struct pam_args *args, const char *pattern, const char *replace,
              const char *username, char **principal)
{
    size_t max_principal_len = 256;
    regex_t re;
    regmatch_t *matches;
    const char *specifiers = "0123456789", *p;
    size_t n_matches;
    unsigned int i, j;
    int k, match;
    int retval;

    /* Limit the length of the match array. */
    n_matches = strlen(username) * 2;
    if (n_matches > 100) {
        return -1;
    }
    if (n_matches < strlen(specifiers)) {
        n_matches = strlen(specifiers) * 2;
    }
    matches = malloc(n_matches * sizeof(regmatch_t));
    if (matches == NULL) {
        return -1;
    }

    for (i = 0; i < n_matches; i++) {
        matches[i].rm_so = -1;
        matches[i].rm_eo = -1;
    }

    /* Build the pattern and check for a match. */
    retval = regcomp(&re, pattern, REG_EXTENDED);
    if (retval != 0) {
        free(matches);
        putil_debug(args, "invalid match specification %s", pattern);
        return -1;
    }
    retval = regexec(&re, username, n_matches, matches, 0);
    if (retval != 0) {
        free(matches);
        regfree(&re);
        return -1;
    }
    if (matches[0].rm_so == -1 && matches[0].rm_eo != -1) {
        free(matches);
        regfree(&re);
        return -1;
    }
    regfree(&re);

    *principal = calloc(sizeof(char), max_principal_len + 1);

    /* Build the output string. */
    for (i = 0, j = 0; replace[i] != '\0' && j <= max_principal_len; i++) {
        switch (replace[i]) {
        case SEPARATOR:
            i++;
            if (replace[i] == SEPARATOR) {
                (*principal)[j++] = replace[i];
            } else {
                /* Decide which match to insert here. */
                p = strchr(specifiers, replace[i]);
                if (p != NULL) {
                    match = p - specifiers;
                } else {
                    match = -1;
                }
                /* Only bother if we have a match. */
                if (match != -1 &&
                    matches[match].rm_so != -1 &&
                    matches[match].rm_eo != -1) {
                    k = matches[match].rm_so;
                    while (k < matches[match].rm_eo &&
                           j <= max_principal_len) {
                        (*principal)[j++] = username[k++];
                    }
                }
            }
            break;
        default:
            (*principal)[j++] = replace[i];
            break;
        }
    }
    free(matches);
    /* Check for unexpected truncation. */
    if (replace[i] != '\0') {
        free(*principal);
        *principal = NULL;
        return -1;
    }

    putil_debug(args, "%s mapped to %s", username, *principal);

    return 0;
}


/*
 * Test authentication with the mapped username and the supplied password.
 */
static krb5_error_code
try_auth_principal(struct pam_args *args, const char *service,
                   krb5_get_init_creds_opt *opts, const char *pass,
                   krb5_creds *creds, const char* kuser)
{
    struct context *ctx = args->config->ctx;
    krb5_principal princ;
    krb5_error_code retval;

    retval = krb5_parse_name(ctx->context, kuser, &princ);
    if (retval != 0) {
        return retval;
    }

    /* Log the principal we're attempting to authenticate as. */
    if (args->debug) {
        char *principal;

        retval = krb5_unparse_name(ctx->context, princ, &principal);
        if (retval != 0) {
            putil_debug_krb5(args, retval, "krb5_unparse_name failed");
        } else {
            putil_debug(args, "mapping %s to %s", ctx->name, principal);
            krb5_free_unparsed_name(ctx->context, principal);
        }
    }

    /*
     * Now, attempt to authenticate as that user.  On success, save the
     * principal.  Return the Kerberos status code.
     */
    retval = krb5_get_init_creds_password(ctx->context, creds, princ,
                (char *) pass, pamk5_prompter_krb5, args, 0,
                (char *) service, opts);
    if (retval != 0) {
        putil_debug_krb5(args, retval, "alternate authentication failed");
        krb5_free_principal(ctx->context, princ);
        return retval;
    } else {
        putil_debug(args, "alternate authentication successful");
        if (ctx->princ != NULL)
            krb5_free_principal(ctx->context, ctx->princ);
        ctx->princ = princ;
        return 0;
    }
}


/*
 * Authenticate using a principal mappings configuration.
 *
 * Build pairs of match/replacement strings from the mappings configuration.
 * Iterate over those pairs trying the supplied password if there is a
 * username match.  If it succeeds, fill out creds, set principal in the
 * context and return 0.  Otherwise return a Kerberos error code or an errno
 * value.
 */
krb5_error_code
pamk5_mappings_auth(struct pam_args *args, const char *service,
                    krb5_get_init_creds_opt *opts, const char *pass,
                    krb5_creds *creds)
{
    struct context *ctx = args->config->ctx;
    struct vector *mappings = args->config->mappings;
    char *kuser = NULL;
    krb5_error_code retval;
    size_t i;

    if (mappings->count == 0 || (mappings->count % 2) != 0) {
        return -1;
    }

    for (i = 0; i < mappings->count; i+=2) {
        putil_debug(args, "testing mapping %s to %s for %s",
                    mappings->strings[i], mappings->strings[i+1], ctx->name);
        retval = map_principal(args, mappings->strings[i],
                               mappings->strings[i+1], ctx->name, &kuser);
        if (retval == 0) {
            retval = try_auth_principal(args, service, opts, pass,
                                        creds, kuser);
            if (retval == 0) {
                free(kuser);
                return retval;
            }
            free(kuser);
            kuser = NULL;
        }
    }

    return -1;
}


/*
 * Verify an alternate authentication.
 *
 * Meant to be called from pamk5_authorized, this checks that the principal in
 * the context matches the mappings derived identity of the user we're
 * authenticating.  Returns PAM_SUCCESS if they match, PAM_AUTH_ERR if they
 * don't match, and PAM_SERVICE_ERR on an internal error.
 */
static int
try_verify_principal(struct pam_args *args, const char *kuser)
{
    struct context *ctx;
    char *mapped = NULL;
    char *authed = NULL;
    krb5_principal princ = NULL;
    krb5_error_code retval;
    int status = PAM_SERVICE_ERR;

    ctx = args->config->ctx;
    retval = krb5_parse_name(ctx->context, kuser, &princ);
    if (retval != 0) {
        putil_err_krb5(args, retval,
                       "cannot parse mapped principal name %s", mapped);
        goto done;
    }
    retval = krb5_unparse_name(ctx->context, princ, &mapped);
    if (retval != 0) {
        putil_err_krb5(args, retval,
                       "krb5_unparse_name on mapped principal failed");
        goto done;
    }
    retval = krb5_unparse_name(ctx->context, ctx->princ, &authed);
    if (retval != 0) {
        putil_err_krb5(args, retval, "krb5_unparse_name failed");
        goto done;
    }
    if (strcmp(authed, mapped) == 0)
        status = PAM_SUCCESS;
    else {
        putil_debug(args, "mapped user %s does not match principal %s",
                    mapped, authed);
        status = PAM_AUTH_ERR;
    }

done:
    if (authed != NULL)
        krb5_free_unparsed_name(ctx->context, authed);
    if (mapped != NULL)
        krb5_free_unparsed_name(ctx->context, mapped);
    if (princ != NULL)
        krb5_free_principal(ctx->context, princ);

    return status;
}


int
pamk5_mappings_auth_verify(struct pam_args *args)
{
    struct context *ctx;
    struct vector *mappings;
    char *kuser = NULL;
    krb5_error_code retval;
    size_t i;

    if (args == NULL || args->config == NULL || args->config->ctx == NULL) {
        return PAM_SERVICE_ERR;
    }
    ctx = args->config->ctx;
    if (ctx->context == NULL || ctx->name == NULL) {
        return PAM_SERVICE_ERR;
    }

    if (args->config->mappings == NULL) {
        return PAM_SERVICE_ERR;
    }
    mappings = args->config->mappings;
    if (mappings->count == 0 || (mappings->count % 2) != 0) {
        return PAM_SERVICE_ERR;
    }

    for (i = 0; i < mappings->count; i+=2) {
        retval = map_principal(args, mappings->strings[i],
                               mappings->strings[i+1], ctx->name, &kuser);

        if(retval == 0) {
            retval = try_verify_principal(args, kuser);
            if(retval == PAM_SUCCESS) {
                free(kuser);
                return retval;
            }
            free(kuser);
        }
    }

    putil_err(args, "cannot map principal name");

    return PAM_AUTH_ERR;
}


#if 0
int
main(int argc, char **argv)
{
    char *kuser;
    int retval;

    if (argc < 4) {
        printf("Usage: %s pattern replacment data\n", argv[0]);
        return 1;
    }
    retval = map_principal(NULL, argv[1], argv[2], argv[3], &kuser);
    if (retval == 0) {
        printf("Match: \"%s\" -> \"%s\"\n", argv[3], kuser);
        free(kuser);
        kuser = NULL;
    } else {
        printf("No match: \"%s\"\n", argv[3]);
    }
    return 0;
}
#endif
