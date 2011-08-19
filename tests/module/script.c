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
#include <pwd.h>

#include <tests/fakepam/testing.h>
#include <tests/module/script.h>
#include <tests/tap/basic.h>

/* Used for enumerating arrays. */
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

/* The type of a PAM module call. */
typedef int (*pam_call)(pam_handle_t *, int, int, const char **);

/*
 * Holds a linked list of actions: a PAM call that should return some
 * status.
 */
struct action {
    char *name;
    pam_call call;
    int status;
    struct action *next;
};

/*
 * Holds the complete set of things that we should do.  Currently, this
 * contains only a linked list of actions.
 */
struct work {
    struct action *actions;
};

/* Mapping of strings to PAM call constants. */
static const struct {
    const char *name;
    pam_call call;
} CALLS[] = {
    { "acct_mgmt",     pam_sm_acct_mgmt     },
    { "open_session",  pam_sm_open_session  },
    { "close_session", pam_sm_close_session },
};

/* Mapping of strings to PAM return values. */
static const struct {
    const char *name;
    int status;
} RETURNS[] = {
    { "PAM_IGNORE",  PAM_IGNORE  },
    { "PAM_SUCCESS", PAM_SUCCESS },
};


/*
 * Allocate memory, reporting a fatal error and exiting on failure.
 */
static void *
xmalloc(size_t size)
{
    void *p;

    p = malloc(size);
    if (p == NULL)
        sysbail("failed to malloc %lu", (unsigned long) size);
    return p;
}


/*
 * Copy a string, reporting a fatal error and exiting on failure.
 */
static char *
xstrdup(const char *s)
{
    char *p;
    size_t len;

    len = strlen(s) + 1;
    p = malloc(len);
    if (p == NULL)
        sysbail("failed to strdup %lu bytes", (unsigned long) len);
    memcpy(p, s, len);
    return p;
}


/*
 * Given a pointer to a string, skip any leading whitespace and return a
 * pointer to the first non-whitespace character.
 */
static char *
skip_whitespace(char *p)
{
    while (isspace((unsigned char)(*p)))
        p++;
    return p;
}


/*
 * Given a pointer to a string, find the next whitespace character (or the end
 * of the string) and return a pointer to it.
 */
static char *
find_whitespace(char *p)
{
    while (*p != '\0' && !isspace((unsigned char)(*p)))
        p++;
    return p;
}


/*
 * Read a line from a file into a BUFSIZ buffer, failing if the line was too
 * long to fit into the buffer, and returns a copy of that line in newly
 * allocated memory.  Ignores blank lines and comments.  Caller is responsible
 * for freeing.  Returns NULL on end of file and fails on read errors.
 */
static char *
readline(FILE *file)
{
    char buffer[BUFSIZ];
    char *line, *first;

    do {
        line = fgets(buffer, sizeof(buffer), file);
        if (line == NULL) {
            if (feof(file))
                return NULL;
            sysbail("cannot read line from script");
        }
        if (buffer[strlen(buffer) - 1] != '\n')
            bail("script line too long");
        buffer[strlen(buffer) - 1] = '\0';
        first = skip_whitespace(buffer);
    } while (first[0] == '#' || first[0] == '\0');
    line = xstrdup(buffer);
    return line;
}


/*
 * Given the name of a PAM call, map it to a call enum.  This is used later in
 * switch statements to determine which function to call.  Fails on any
 * unrecognized string.
 */
static pam_call
string_to_call(const char *name)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(CALLS); i++)
        if (strcmp(name, CALLS[i].name) == 0)
            return CALLS[i].call;
    bail("unrecognized PAM call %s", name);
}


/*
 * Given a PAM return status, map it to the actual expected value.  Fails on
 * any unrecognized string.
 */
static int
string_to_status(const char *name)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(RETURNS); i++)
        if (strcmp(name, RETURNS[i].name) == 0)
            return RETURNS[i].status;
    bail("unrecognized PAM status %s", name);
}


/*
 * Parse the run section of a PAM script.  This consists of one or more lines
 * in the format:
 *
 *     <call> = <status>
 *
 * where <call> is a PAM call and <status> is what it should return.  Returns
 * a linked list of actions.  Fails on any error in parsing.
 */
static struct action *
parse_run(FILE *script)
{
    struct action *head = NULL, *current, *next;
    char *line, *start, *end;

    for (line = readline(script); line != NULL; line = readline(script)) {
        next = xmalloc(sizeof(struct action));
        if (head == NULL)
            head = next;
        else
            current->next = next;
        start = skip_whitespace(line);
        end = find_whitespace(start);
        if (*end == '\0')
            bail("truncated action line: %s", line);
        *end = '\0';
        next->name = xstrdup(start);
        next->call = string_to_call(start);
        start = skip_whitespace(end + 1);
        if (*start != '=')
            bail("malformed action line: %s", start);
        start = skip_whitespace(start + 1);
        end = find_whitespace(start);
        if (*end != '\0')
            bail("malformed action line: %s", start);
        next->status = string_to_status(start);
        free(line);
        current = next;
    }
    if (head == NULL)
        bail("empty run section in script");
    return head;
}


/*
 * Parse a PAM interaction script.  This handles parsing of the top-level
 * section markers and dispatches the parsing to other functions.  Returns the
 * total work to do as a work struct.
 */
static struct work *
parse_script(FILE *script)
{
    struct work *work;
    char *line, *start, *end;

    work = xmalloc(sizeof(struct work));
    work->actions = NULL;
    for (line = readline(script); line != NULL; line = readline(script)) {
        start = skip_whitespace(line);
        if (*start != '[')
            bail("line outside of section: %s", line);
        end = find_whitespace(line);
        *end = '\0';
        if (strcmp(start, "[run]") == 0)
            work->actions = parse_run(script);
        else
            bail("unknown section: %s", start);
        free(line);
    }
    if (work->actions == NULL)
        bail("no run section defined");
    return work;
}
        

/*
 * The core of the work.  Given the path to a PAM interaction script, which
 * may be relative to SOURCE or BUILD, run that script, outputing the results
 * in TAP format.
 */
void
run_script(const char *file)
{
    char *path;
    FILE *script;
    struct work *work;
    struct action *action, *oaction;
    struct pam_conv conv = { NULL, NULL };
    pam_handle_t *pamh;
    int status;
    const char *argv_empty[] = { NULL };

    /* Open and parse the script. */
    if (access(file, R_OK) == 0)
        path = xstrdup(file);
    else {
        path = test_file_path(file);
        if (path == NULL)
            bail("cannot find PAM script %s", file);
    }
    script = fopen(path, "r");
    if (script == NULL)
        sysbail("cannot open %s", path);
    work = parse_script(script);
    diag("Starting %s", file);

    /* Initialize PAM. */
    status = pam_start("test", "testuser", &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");

    /* Run the actions and check their return status. */
    for (action = work->actions; action != NULL; action = action->next) {
        status = (*action->call)(pamh, 0, 0, argv_empty);
        is_int(action->status, status, "status for %s", action->name);
    }
    is_string(NULL, pam_output(), "No output");

    /* Free memory and return. */
    action = work->actions;
    while (action != NULL) {
        free(action->name);
        oaction = action;
        action = action->next;
        free(oaction);
    }
    free(work);
}
