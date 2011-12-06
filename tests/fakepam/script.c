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

    if (num_msg > 1)
        bail("only one prompt at a time currently supported");
    if (prompts->current >= prompts->size) {
        ok(0, "more prompts than expected");
        return PAM_CONV_ERR;
    }
    prompt = &prompts->prompts[prompts->current];
    is_int(prompt->style, msg[0]->msg_style, "style of prompt %lu",
           (unsigned long) prompts->current);
    is_string(prompt->prompt, msg[0]->msg, "value of prompt %lu",
              (unsigned long) prompts->current);
    prompts->current++;
    *resp = NULL;
    if (prompt->style == msg[0]->msg_style && prompt->response != NULL) {
        *resp = bmalloc(sizeof(struct pam_response));
        (*resp)->resp = bstrdup(prompt->response);
        (*resp)->resp_retcode = 0;
        return PAM_SUCCESS;
    } else {
        return PAM_CONV_ERR;
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
    char *path, *output;
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
    is_string(work->output, output, "Output is correct");
    free(output);

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
        free(work->output);
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
        if (asprintf(&file, "%s/%s", path, entry->d_name) < 0)
            sysbail("cannot create path to test script");
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
