/*
 * Prompt users for information.
 *
 * Handles all interaction with the PAM conversation, either directly or
 * indirectly through the Kerberos libraries.
 *
 * Copyright 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 * Copyright 2005, 2006, 2007, 2009, 2014 Russ Allbery <eagle@eyrie.org>
 * Copyright 2005 Andres Salomon <dilinger@debian.org>
 * Copyright 1999, 2000 Frank Cusack <fcusack@fcusack.com>
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <errno.h>

#include <internal.h>
#include <pam-util/args.h>
#include <pam-util/logging.h>


/*
 * Prompt for a password.
 *
 * This function handles prompting both for a password for regular
 * authentication and for passwords when changing one's password.  The default
 * prompt is simply "Password:" for the former.  For the latter, a string
 * describing the type of password is passed in as prefix.  In this case, the
 * prompts is:
 *
 *     <prefix> <banner> password:
 *
 * where <prefix> is the argument passed and <banner> is the value of
 * args->banner (defaulting to "Kerberos").
 *
 * If args->config->expose_account is set, we append the principal name (taken
 * from args->config->ctx->princ) before the colon, so the prompts are:
 *
 *     Password for <principal>:
 *     <prefix> <banner> password for <principal>:
 *
 * Normally this is not done because it exposes the realm and possibly any
 * username to principal mappings, plus may confuse some ssh clients if sshd
 * passes the prompt back to the client.
 *
 * The entered password is stored in password.  The memory is allocated by the
 * application and returned as part of the PAM conversation.  It must be freed
 * by the caller.
 *
 * Returns a PAM success or error code.
 */
int
pamk5_get_password(struct pam_args *args, const char *prefix, char **password)
{
    struct context *ctx = args->config->ctx;
    char *prompt = NULL;
    char *principal = NULL;
    krb5_error_code k5_errno;
    int retval;

    if (args->config->expose_account || prefix != NULL)
        if (ctx != NULL && ctx->context != NULL && ctx->princ != NULL) {
            k5_errno = krb5_unparse_name(ctx->context, ctx->princ, &principal);
            if (k5_errno != 0)
                putil_debug_krb5(args, k5_errno, "krb5_unparse_name failed");
        }
    if (prefix == NULL) {
        if (args->config->expose_account && principal != NULL) {
            if (asprintf(&prompt, "Password for %s: ", principal) < 0)
                goto fail;
        } else {
            prompt = strdup("Password: ");
            if (prompt == NULL)
                goto fail;
        }
    } else {
        const char *banner;
        const char *bspace;

        banner = (args->config->banner == NULL) ? "" : args->config->banner;
        bspace = (args->config->banner == NULL) ? "" : " ";
        if (args->config->expose_account && principal != NULL) {
            retval = asprintf(&prompt, "%s%s%s password for %s: ", prefix,
                              bspace, banner, principal);
            if (retval < 0)
                goto fail;
        } else {
            retval = asprintf(&prompt, "%s%s%s password: ", prefix, bspace,
                              banner);
            if (retval < 0)
                goto fail;
        }
    }
    if (principal != NULL)
        krb5_free_unparsed_name(ctx->context, principal);
    retval = pamk5_conv(args, prompt, PAM_PROMPT_ECHO_OFF, password);
    free(prompt);
    return retval;

fail:
    if (principal != NULL)
        krb5_free_unparsed_name(ctx->context, principal);
    return PAM_BUF_ERR;
}


/*
 * Get information from the user or display a message to the user, as
 * determined by type.  If PAM_SILENT was given, don't pass any text or error
 * messages to the application.
 *
 * The response variable is set to the response returned by the conversation
 * function on a successful return if a response was desired.  Caller is
 * responsible for freeing it.
 */
int
pamk5_conv(struct pam_args *args, const char *message, int type,
           char **response)
{
    int pamret;
    struct pam_message msg;
    PAM_CONST struct pam_message *pmsg;
    struct pam_response *resp = NULL;
    struct pam_conv *conv;
    int want_reply;

    if (args->silent && (type == PAM_ERROR_MSG || type == PAM_TEXT_INFO))
        return PAM_SUCCESS;
    pamret = pam_get_item(args->pamh, PAM_CONV, (PAM_CONST void **) &conv);
    if (pamret != PAM_SUCCESS)
	return pamret;
    if (conv->conv == NULL)
        return PAM_CONV_ERR;
    pmsg = &msg;
    msg.msg_style = type;
    msg.msg = (PAM_CONST char *) message;
    pamret = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);
    if (pamret != PAM_SUCCESS)
	return pamret;

    /*
     * Only expect a response for PAM_PROMPT_ECHO_OFF or PAM_PROMPT_ECHO_ON
     * message types.  This mildly annoying logic makes sure that everything
     * is freed properly (except the response itself, if wanted, which is
     * returned for the caller to free) and that the success status is set
     * based on whether the reply matched our expectations.
     *
     * If we got a reply even though we didn't want one, still overwrite the
     * reply before freeing in case it was a password.
     */
    want_reply = (type == PAM_PROMPT_ECHO_OFF || type == PAM_PROMPT_ECHO_ON);
    if (resp == NULL || resp->resp == NULL)
	pamret = want_reply ? PAM_CONV_ERR : PAM_SUCCESS;
    else if (want_reply && response != NULL) {
        *response = resp->resp;
        pamret = PAM_SUCCESS;
    } else {
        memset(resp->resp, 0, strlen(resp->resp));
        free(resp->resp);
        pamret = want_reply ? PAM_SUCCESS : PAM_CONV_ERR;
    }
    free(resp);
    return pamret;
}


/*
 * This is the generic prompting function called by both the MIT Kerberos and
 * Heimdal prompting implementations.  The MIT function takes a name and the
 * Heimdal function doesn't, which is the only difference between the two.
 * Both are simple wrappers that call this function.
 *
 * There are a lot of structures and different layers of code at work here,
 * making this code quite confusing.  This function is a prompter function to
 * pass into the Kerberos library, in particular krb5_get_init_creds_password.
 * It is used by the Kerberos library to prompt for a password if need be, and
 * also to prompt for password changes if the password was expired.
 *
 * The purpose of this function is to serve as glue between the Kerberos
 * library and the application (by way of the PAM glue).  PAM expects us to
 * pass back to the conversation function an array of prompts and receive from
 * the application an array of responses to those prompts.  We pass the
 * application an array of struct pam_message pointers, and the application
 * passes us an array of struct pam_response pointers.
 *
 * Kerberos, meanwhile, passes us in an array of krb5_prompt structs.  This
 * struct contains the prompt, a flag saying whether to suppress echoing of
 * what the user types for that prompt, and a buffer into which to store the
 * response.
 *
 * Therefore, what we're doing here is copying the prompts from the
 * krb5_prompt structs into pam_message structs, calling the conversation
 * function, and then copying the responses back out of pam_response structs
 * into the krb5_prompt structs to return to the Kerberos library.
 */
krb5_error_code
pamk5_prompter_krb5(krb5_context context UNUSED, void *data, const char *name,
                    const char *banner, int num_prompts, krb5_prompt *prompts)
{
    struct pam_args *args = data;
    int total_prompts = num_prompts;
    int pam_prompts, pamret, i;
    int retval = KRB5KRB_ERR_GENERIC;
    struct pam_message **msg;
    struct pam_response *resp = NULL;
    struct pam_conv *conv;

    /* Treat the name and banner as prompts that doesn't need input. */
    if (name != NULL && !args->silent)
        total_prompts++;
    if (banner != NULL && !args->silent)
        total_prompts++;

    /* If we have zero prompts, do nothing, silently. */
    if (total_prompts == 0)
        return 0;

    /* Obtain the conversation function from the application. */
    pamret = pam_get_item(args->pamh, PAM_CONV, (PAM_CONST void **) &conv);
    if (pamret != 0)
        return KRB5KRB_ERR_GENERIC;
    if (conv->conv == NULL)
        return KRB5KRB_ERR_GENERIC;

    /*
     * Allocate memory to copy all of the prompts into a pam_message.
     *
     * Linux PAM and Solaris PAM expect different things here.  Solaris PAM
     * expects to receive a pointer to a pointer to an array of pam_message
     * structs.  Linux PAM expects to receive a pointer to an array of
     * pointers to pam_message structs.  In order for the module to work with
     * either PAM implementation, we need to set up a structure that is valid
     * either way you look at it.
     *
     * We do this by making msg point to the array of struct pam_message
     * pointers (what Linux PAM expects), and then make the first one of those
     * pointers point to the array of pam_message structs.  Solaris will then
     * be happy, looking at only the first element of the outer array and
     * finding it pointing to the inner array.  Then, for Linux, we point the
     * other elements of the outer array to the storage allocated in the inner
     * array.
     *
     * All this also means we have to be careful how we free the resulting
     * structure since it's double-linked in a subtle way.  Thankfully, we get
     * to free it ourselves.
     */
    msg = calloc(total_prompts, sizeof(struct pam_message *));
    if (msg == NULL)
        return ENOMEM;
    *msg = calloc(total_prompts, sizeof(struct pam_message));
    if (*msg == NULL) {
        free(msg);
        return ENOMEM;
    }
    for (i = 1; i < total_prompts; i++)
        msg[i] = msg[0] + i;

    /* pam_prompts is an index into msg and a count when we're done. */
    pam_prompts = 0;
    if (name != NULL && !args->silent) {
        msg[pam_prompts]->msg = strdup(name);
        if (msg[pam_prompts]->msg == NULL)
            goto cleanup;
        msg[pam_prompts]->msg_style = PAM_TEXT_INFO;
        pam_prompts++;
    }
    if (banner != NULL && !args->silent) {
        msg[pam_prompts]->msg = strdup(banner);
        if (msg[pam_prompts]->msg == NULL)
            goto cleanup;
        msg[pam_prompts]->msg_style = PAM_TEXT_INFO;
        pam_prompts++;
    }
    for (i = 0; i < num_prompts; i++) {
        int status;
        size_t len;
        bool has_colon;

        /*
         * Heimdal adds the trailing colon and space, while MIT does not.
         * Work around the difference by looking to see if there's a trailing
         * colon and space already and only adding it if there is not.
         */
        len = strlen(prompts[i].prompt);
        has_colon = (len > 2
                     && prompts[i].prompt[len - 1] == ' '
                     && prompts[i].prompt[len - 2] == ':');
        status = asprintf((char **) &msg[pam_prompts]->msg, "%s%s",
                          prompts[i].prompt, has_colon ? "" : ": ");
        if (status < 0)
            goto cleanup;
        msg[pam_prompts]->msg_style = prompts[i].hidden ? PAM_PROMPT_ECHO_OFF
                                                        : PAM_PROMPT_ECHO_ON;
        pam_prompts++;
    }

    /* Call into the application conversation function. */
    pamret = conv->conv(pam_prompts, (PAM_CONST struct pam_message **) msg,
                        &resp, conv->appdata_ptr);
    if (pamret != 0) 
        goto cleanup;
    if (resp == NULL)
        goto cleanup;

    /*
     * Reuse pam_prompts as a starting index and copy the data into the reply
     * area of the krb5_prompt structs.
     */
    pam_prompts = 0;
    if (name != NULL && !args->silent)
        pam_prompts++;
    if (banner != NULL && !args->silent)
        pam_prompts++;
    for (i = 0; i < num_prompts; i++, pam_prompts++) {
        size_t len;

        if (resp[pam_prompts].resp == NULL)
            goto cleanup;
        len = strlen(resp[pam_prompts].resp);
        if (len > prompts[i].reply->length)
            goto cleanup;

        /*
         * The trailing nul is not included in length, but other applications
         * expect it to be there.  Therefore, we copy one more byte than the
         * actual length of the password, but set length to just the length of
         * the password.
         */
        memcpy(prompts[i].reply->data, resp[pam_prompts].resp, len + 1);
        prompts[i].reply->length = len;
    }
    retval = 0;

cleanup:
    for (i = 0; i < total_prompts; i++)
        free((char *) msg[i]->msg);
    free(*msg);
    free(msg);

    /*
     * Clean up the responses.  These may contain passwords, so we overwrite
     * them before we free them.
     */
    if (resp != NULL) {
        for (i = 0; i < total_prompts; i++) {
            if (resp[i].resp != NULL) {
                memset(resp[i].resp, 0, strlen(resp[i].resp));
                free(resp[i].resp);
            }
        }
        free(resp);
    }
    return retval;
}
