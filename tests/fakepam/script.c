/*
 * Run a PAM interaction script for testing.
 *
 * Provides an interface that loads a PAM interaction script from a file and
 * runs through that script, calling the internal PAM module functions and
 * checking their results.  This allows automation of PAM testing through
 * external data files instead of coding everything in C.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>

#include <tests/fakepam/internal.h>
#include <tests/fakepam/pam.h>
#include <tests/fakepam/script.h>
#include <tests/tap/basic.h>
#include <tests/tap/string.h>


/*
 * The PAM conversation function.  Takes the prompts struct from the
 * configuration and interacts appropriately.  If a prompt is of the expected
 * type but not the expected string, it still responds; if it's not of the
 * expected type, it returns PAM_CONV_ERR.
 *
 * Currently only handles a single prompt at a time.
 */
static int
converse(int num_msg, const struct pam_message **msg,
         struct pam_response **resp, void *appdata_ptr)
{
    struct prompts *prompts = appdata_ptr;
    struct prompt *prompt;
    char *message;
    size_t length;
    int i;

    *resp = bcalloc(num_msg, sizeof(struct pam_response));
    for (i = 0; i < num_msg; i++) {
        message = bstrdup(msg[i]->msg);

        /* Remove newlines for comparison purposes. */
        length = strlen(message);
        while (length > 0 && message[length - 1] == '\n')
            message[length-- - 1] = '\0';

        /* Check if we've gotten too many prompts but quietly ignore them. */
        if (prompts->current >= prompts->size) {
            diag("unexpected prompt: %s", message);
            free(message);
            ok(0, "more prompts than expected");
            continue;
        }

        /* Be sure everything matches and return the response, if any. */
        prompt = &prompts->prompts[prompts->current];
        is_int(prompt->style, msg[i]->msg_style, "style of prompt %lu",
               (unsigned long) prompts->current);
        is_string(prompt->prompt, message, "value of prompt %lu",
                  (unsigned long) prompts->current);
        free(message);
        prompts->current++;
        if (prompt->style == msg[i]->msg_style && prompt->response != NULL) {
            (*resp)[i].resp = bstrdup(prompt->response);
            (*resp)[i].resp_retcode = 0;
        }
    }

    /*
     * Always return success even if the prompts don't match.  Otherwise,
     * we're likely to abort the conversation in the middle and possibly
     * leave passwords set incorrectly.
     */
    return PAM_SUCCESS;
}


/*
 * Check the actual PAM output against the expected output.  We divide the
 * expected and seen output into separate lines and compare each one so that
 * we can handle wildcards.
 */
static void
check_output(const struct output *wanted, const struct output *seen)
{
    size_t i, length;

    if (wanted == NULL && seen == NULL)
        ok(1, "no output");
    else if (wanted == NULL) {
        for (i = 0; i < seen->count; i++)
            diag("unexpected: %s", seen->strings[0]);
        ok(0, "no output");
    } else if (seen == NULL) {
        for (i = 0; i < wanted->count; i++)
            is_string(wanted->strings[i], NULL, "output line %lu",
                      (unsigned long) i);
    } else {
        for (i = 0; i < wanted->count && i < seen->count; i++) {
            length = strlen(wanted->strings[i]);

            /*
             * Handle the %* wildcard.  If this occurs in the desired string,
             * it must be the end of the string, and it means that all output
             * after that point is ignored.  So truncate both strings at that
             * point so that we'll only compare the first parts.
             *
             * This is a hacky substitute for real regex matching, which would
             * be a much better option.
             */
            if (length > 1
                && strcmp(wanted->strings[i] + (length - 2), "%*") == 0
                && strlen(seen->strings[i]) > (length - 2)) {
                wanted->strings[i][length - 2] = '\0';
                seen->strings[i][length - 2] = '\0';
            }
            is_string(wanted->strings[i], seen->strings[i], "output line %lu",
                      (unsigned long) i);
        }
        if (wanted->count > seen->count)
            for (i = seen->count; i < wanted->count; i++)
                is_string(wanted->strings[i], NULL, "output line %lu",
                          (unsigned long) i);
        else if (seen->count > wanted->count) {
            for (i = wanted->count; i < seen->count; i++)
                diag("unexpected: %s", seen->strings[i]);
            ok(0, "unexpected output lines");
        } else {
            ok(1, "no excess output");
        }
    }
}
        

/*
 * The core of the work.  Given the path to a PAM interaction script, which
 * may be relative to SOURCE or BUILD, the user (may be NULL), and the stored
 * password (may be NULL), run that script, outputing the results in TAP
 * format.
 */
void
run_script(const char *file, const struct script_config *config)
{
    char *path;
    struct output *output;
    const char *user;
    FILE *script;
    struct work *work;
    struct options *opts;
    struct action *action, *oaction;
    struct pam_conv conv = { NULL, NULL };
    pam_handle_t *pamh;
    int status;
    size_t i, j;
    const char *argv_empty[] = { NULL };

    /* Open and parse the script. */
    if (access(file, R_OK) == 0)
        path = bstrdup(file);
    else {
        path = test_file_path(file);
        if (path == NULL)
            bail("cannot find PAM script %s", file);
    }
    script = fopen(path, "r");
    if (script == NULL)
        sysbail("cannot open %s", path);
    work = parse_script(script, config);
    fclose(script);
    diag("Starting %s", file);
    if (work->prompts != NULL) {
        conv.conv = converse;
        conv.appdata_ptr = work->prompts;
    }

    /* Initialize PAM. */
    user = config->user;
    if (user == NULL)
        user = "testuser";
    status = pam_start("test", user, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (config->password != NULL)
        pamh->authtok = bstrdup(config->password);

    /* Run the actions and check their return status. */
    for (action = work->actions; action != NULL; action = action->next) {
        if (work->options[action->group].argv == NULL)
            status = (*action->call)(pamh, action->flags, 0, argv_empty);
        else {
            opts = &work->options[action->group];
            status = (*action->call)(pamh, action->flags, opts->argc,
                                     (const char **) opts->argv);
        }
        is_int(action->status, status, "status for %s", action->name);
    }
    output = pam_output();
    check_output(work->output, output);
    pam_output_free(output);

    /* If we have a test callback, call it now. */
    if (config->callback != NULL)
        config->callback (pamh, config, config->data);

    /* Free memory and return. */
    pam_end(pamh, PAM_SUCCESS);
    action = work->actions;
    while (action != NULL) {
        free(action->name);
        oaction = action;
        action = action->next;
        free(oaction);
    }
    for (i = 0; i < ARRAY_SIZE(work->options); i++)
        if (work->options[i].argv != NULL) {
            for (j = 0; work->options[i].argv[j] != NULL; j++)
                free(work->options[i].argv[j]);
            free(work->options[i].argv);
        }
    if (work->output)
        pam_output_free(work->output);
    if (work->prompts != NULL) {
        for (i = 0; i < work->prompts->size; i++) {
            if (work->prompts->prompts[i].prompt != NULL)
                free(work->prompts->prompts[i].prompt);
            if (work->prompts->prompts[i].response != NULL)
                free(work->prompts->prompts[i].response);
        }
        free(work->prompts->prompts);
        free(work->prompts);
    }
    free(work);
    free(path);
}


/*
 * Check a filename for acceptable characters.  Returns true if the file
 * consists solely of [a-zA-Z0-9-] and false otherwise.
 */
static bool
valid_filename(const char *filename)
{
    const char *p;

    for (p = filename; *p != '\0'; p++) {
        if (*p >= 'A' && *p <= 'Z')
            continue;
        if (*p >= 'a' && *p <= 'z')
            continue;
        if (*p >= '0' && *p <= '9')
            continue;
        if (*p == '-')
            continue;
        return false;
    }
    return true;
}


/*
 * The same as run_script, but run every script found in the given directory,
 * skipping file names that contain characters other than alphanumerics and -.
 */
void
run_script_dir(const char *dir, const struct script_config *config)
{
    DIR *handle;
    struct dirent *entry;
    const char *path;
    char *file;

    if (access(dir, R_OK) == 0)
        path = dir;
    else
        path = test_file_path(dir);
    handle = opendir(path);
    if (handle == NULL)
        sysbail("cannot open directory %s", dir);
    errno = 0;
    while ((entry = readdir(handle)) != NULL) {
        if (!valid_filename(entry->d_name))
            continue;
        basprintf(&file, "%s/%s", path, entry->d_name);
        run_script(file, config);
        free(file);
        errno = 0;
    }
    if (errno != 0)
        sysbail("cannot read directory %s", dir);
    closedir(handle);
    if (path != dir)
        test_file_path_free((char *) path);
}
