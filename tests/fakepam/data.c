/*
 * Data manipulation functions for the fake PAM library, used for testing.
 *
 * This file contains the implementation of pam_get_* and pam_set_* for the
 * various data items supported by the PAM library, plus the PAM environment
 * manipulation functions.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <config.h>
#include <portable/pam.h>
#include <portable/system.h>

#include <tests/fakepam/pam.h>

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED __attribute__((__unused__))


/*
 * Return a stored PAM data element in the provided data variable.  As a
 * special case, if the data is NULL, pretend it doesn't exist.
 */
int
pam_get_data(const pam_handle_t *pamh, const char *name, const void **data)
{
    struct fakepam_data *item;

    for (item = pamh->data; item != NULL; item = item->next)
        if (strcmp(item->name, name) == 0) {
            if (item->data == NULL)
                return PAM_NO_MODULE_DATA;
            *data = item->data;
            return PAM_SUCCESS;
        }
    return PAM_NO_MODULE_DATA;
}


/*
 * Store a data item.  Replaces the existing data item (calling its cleanup)
 * if it is already set; otherwise, add a new data item.
 */
int
pam_set_data(pam_handle_t *pamh, const char *item, void *data,
             void (*cleanup)(pam_handle_t *, void *, int))
{
    struct fakepam_data *p;

    for (p = pamh->data; p != NULL; p = p->next)
        if (strcmp(p->name, item) == 0) {
            if (p->cleanup != NULL)
                p->cleanup (pamh, p->data, PAM_DATA_REPLACE);
            p->data = data;
            p->cleanup = cleanup;
            return PAM_SUCCESS;
        }
    p = malloc(sizeof(struct fakepam_data));
    if (p == NULL)
        return PAM_BUF_ERR;
    p->name = strdup(item);
    if (p->name == NULL) {
        free(p);
        return PAM_BUF_ERR;
    }
    p->data = data;
    p->cleanup = cleanup;
    p->next = pamh->data;
    pamh->data = p;
    return PAM_SUCCESS;
}


/*
 * Retrieve a PAM item.  Currently, this only supports a limited subset of the
 * possible items.
 */
int
pam_get_item(const pam_handle_t *pamh, int item, PAM_CONST void **data)
{
    switch (item) {
    case PAM_AUTHTOK:
        *data = pamh->authtok;
        return PAM_SUCCESS;
    case PAM_CONV:
        if (pamh->conversation) {
            *data = pamh->conversation;
            return PAM_SUCCESS;
        } else {
            return PAM_BAD_ITEM;
        }
    case PAM_USER:
        *data = (PAM_CONST char *) pamh->user;
        return PAM_SUCCESS;
    default:
        return PAM_BAD_ITEM;
    }
}


/*
 * Set a PAM item.  Currently only PAM_USER is supported.
 */
int
pam_set_item(pam_handle_t *pamh, int item, PAM_CONST void *data)
{
    switch (item) {
    case PAM_AUTHTOK:
        pamh->authtok = strdup(data);
        if (pamh->authtok == NULL)
            return PAM_BUF_ERR;
        return PAM_SUCCESS;
    case PAM_USER:
        pamh->user = (const char *) data;
        return PAM_SUCCESS;
    default:
        return PAM_BAD_ITEM;
    }
}


/*
 * Return the user for the PAM context.
 */
int
pam_get_user(pam_handle_t *pamh, PAM_CONST char **user,
             const char *prompt UNUSED)
{
    if (pamh->user == NULL)
        return PAM_CONV_ERR;
    else {
        *user = (PAM_CONST char *) pamh->user;
        return PAM_SUCCESS;
    }
}


/*
 * Return a setting in the PAM environment.
 */
PAM_CONST char *
pam_getenv(pam_handle_t *pamh, const char *name)
{
    size_t i;

    if (pamh->environ == NULL)
        return NULL;
    for (i = 0; pamh->environ[i] != NULL; i++)
        if (strncmp(name, pamh->environ[i], strlen(name)) == 0
            && pamh->environ[i][strlen(name)] == '=')
            return pamh->environ[i] + strlen(name) + 1;
    return NULL;
}


/*
 * Return a newly malloc'd copy of the complete PAM environment.  This must be
 * freed by the caller.
 */
char **
pam_getenvlist(pam_handle_t *pamh)
{
    char **env;
    size_t i;

    if (pamh->environ == NULL) {
        pamh->environ = malloc(sizeof(char **));
        if (pamh->environ == NULL)
            return NULL;
        pamh->environ[0] = NULL;
    }
    for (i = 0; pamh->environ[i] != NULL; i++)
        ;
    env = malloc((i + 1) * sizeof(char *));
    if (env == NULL)
        return NULL;
    for (i = 0; pamh->environ[i] != NULL; i++) {
        env[i] = strdup(pamh->environ[i]);
        if (env[i] == NULL)
            goto fail;
    }
    env[i] = NULL;
    return env;

fail:
    for (i = 0; env[i] != NULL; i++)
        free(env[i]);
    free(env);
    return NULL;
}


/*
 * Add a setting to the PAM environment.  If there is another existing
 * variable with the same value, the value is replaced, unless the setting
 * doesn't end in an equal sign.  If it doesn't end in an equal sign, any
 * existing environment variable of that name is removed.  This follows the
 * Linux PAM semantics.
 *
 * On HP-UX, there is no separate PAM environment, so the module just uses the
 * main environment.  For our tests to work on that platform, we therefore
 * have to do the same thing.
 */
#ifdef HAVE_PAM_GETENV
int
pam_putenv(pam_handle_t *pamh, const char *setting)
{
    const char *equals;
    size_t namelen;
    bool delete = false;
    bool found = false;
    size_t i, j;
    const char **env;

    if (setting == NULL)
        return PAM_PERM_DENIED;
    equals = strchr(setting, '=');
    if (equals != NULL)
        namelen = equals - setting;
    else {
        delete = true;
        namelen = strlen(setting);
    }

    /* Handle the first call to pam_putenv. */
    if (pamh->environ == NULL) {
        if (delete)
            return PAM_BAD_ITEM;
        pamh->environ = malloc(2 * sizeof(char *));
        if (pamh->environ == NULL)
            return PAM_BUF_ERR;
        pamh->environ[0] = setting;
        pamh->environ[1] = NULL;
        return PAM_SUCCESS;
    }

    /*
     * We have an existing array.  See if we're replacing a value, deleting a
     * value, or adding a new one.  When deleting, waste a bit of memory but
     * save some time by not bothering to reduce the size of the array.
     */
    for (i = 0; pamh->environ[i] != NULL; i++)
        if (strncmp(setting, pamh->environ[i], namelen) == 0
            && pamh->environ[i][namelen] == '=') {
            if (delete) {
                for (j = i + 1; pamh->environ[j] != NULL; i++, j++)
                    pamh->environ[i] = pamh->environ[j];
                pamh->environ[i] = NULL;
            } else {
                pamh->environ[i] = setting;
            }
            found = true;
            break;
        }
    if (!found) {
        if (delete)
            return PAM_BAD_ITEM;
        env = realloc(pamh->environ, (i + 2) * sizeof(char *));
        if (env == NULL)
            return PAM_BUF_ERR;
        pamh->environ = env;
        pamh->environ[i] = setting;
        pamh->environ[i + 1] = NULL;
    }
    return PAM_SUCCESS;
}

#else /* !HAVE_PAM_GETENV */

int
pam_putenv(pam_handle_t *pamh UNUSED, const char *setting)
{
    return putenv((char *) setting);
}

#endif /* !HAVE_PAM_GETENV */