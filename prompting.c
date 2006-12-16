/*
 * prompting.c
 *
 * Functions to prompt users for information.
 */

#include "config.h"

#include <errno.h>
#include <krb5.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

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
    const struct pam_message *pmsg;
    struct pam_response	*resp = NULL;
    struct pam_conv *conv;
    int want_reply;

    if (args->silent && (type == PAM_ERROR_MSG || type == PAM_TEXT_INFO))
        return PAM_SUCCESS;
    pamret = pam_get_item(args->pamh, PAM_CONV, (void *) &conv);
    if (pamret != PAM_SUCCESS)
	return pamret;
    pmsg = &msg;
    msg.msg_style = type;
    msg.msg = message;
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
    if (resp != NULL)
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
pamk5_prompter_krb5(krb5_context context, void *data, const char *name,
                    const char *banner, int num_prompts, krb5_prompt *prompts)
{
    struct pam_args *args = data;
    int total_prompts = num_prompts;;
    int pam_prompts, pamret, i;
    int retval = KRB5KRB_ERR_GENERIC;
    struct pam_message **msg;
    struct pam_response *resp = NULL;
    struct pam_conv *conv;

    /* Obtain the conversation function from the application. */
    pamret = pam_get_item(args->pamh, PAM_CONV, (void *) &conv);
    if (pamret != 0)
        return KRB5KRB_ERR_GENERIC;

    /* Treat the name and banner as prompts that doesn't need input. */
    if (name != NULL && !args->silent)
        total_prompts++;
    if (banner != NULL && !args->silent)
        total_prompts++;

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
       msg[pam_prompts]->msg = malloc(strlen(name) + 1);
       if (msg[pam_prompts]->msg == NULL)
           goto cleanup;
       strcpy((char *) msg[pam_prompts]->msg, name);
       msg[pam_prompts]->msg_style = PAM_TEXT_INFO;
       pam_prompts++;
    }
    if (banner != NULL && !args->silent) {
        msg[pam_prompts]->msg = malloc(strlen(banner) + 1);
        if (msg[pam_prompts]->msg == NULL)
            goto cleanup;
        strcpy((char *) msg[pam_prompts]->msg, banner);
        msg[pam_prompts]->msg_style = PAM_TEXT_INFO;
        pam_prompts++;
    }
    for (i = 0; i < num_prompts; i++) {
        msg[pam_prompts]->msg = malloc(strlen(prompts[i].prompt) + 3);
        if (msg[pam_prompts]->msg == NULL)
            goto cleanup;
        sprintf((char *) msg[pam_prompts]->msg, "%s: ", prompts[i].prompt);
        msg[pam_prompts]->msg_style = prompts[i].hidden ? PAM_PROMPT_ECHO_OFF
                                                        : PAM_PROMPT_ECHO_ON;
        pam_prompts++;
    }

    /* Call into the application conversation function. */
    pamret = conv->conv(pam_prompts, (const struct pam_message **) msg,
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
    for (i = 0; i < total_prompts; i++) {
        if (msg[i]->msg != NULL)
            free((char *) msg[i]->msg);
    }
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
