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
#include <syslog.h>

#include <tests/fakepam/testing.h>
#include <tests/module/script.h>
#include <tests/tap/basic.h>

/* Used for enumerating arrays. */
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

/* The type of a PAM module call. */
typedef int (*pam_call)(pam_handle_t *, int, int, const char **);

/* The possible PAM groups as element numbers in an array of options. */
enum group_type {
    GROUP_ACCOUNT  = 0,
    GROUP_AUTH     = 1,
    GROUP_PASSWORD = 2,
    GROUP_SESSION  = 3,
};

/* Holds a PAM argc and argv. */
struct options {
    char **argv;
    int argc;
};

/*
 * Holds a linked list of actions: a PAM call that should return some
 * status.
 */
struct action {
    char *name;
    pam_call call;
    int flags;
    enum group_type group;
    int status;
    struct action *next;
};

/*
 * Holds the complete set of things that we should do.  Currently, this
 * contains only a linked list of actions.
 */
struct work {
    struct options options[4];
    struct action *actions;
    char *output;
};

/* Mapping of strings to PAM function pointers and group numbers. */
static const struct {
    const char *name;
    pam_call call;
    enum group_type group;
} CALLS[] = {
    { "acct_mgmt",     pam_sm_acct_mgmt,     GROUP_ACCOUNT  },
    { "authenticate",  pam_sm_authenticate,  GROUP_AUTH     },
    { "setcred",       pam_sm_setcred,       GROUP_AUTH     },
    { "chauthtok",     pam_sm_chauthtok,     GROUP_PASSWORD },
    { "open_session",  pam_sm_open_session,  GROUP_SESSION  },
    { "close_session", pam_sm_close_session, GROUP_SESSION  },
};

/* Mapping of PAM flag names without the leading PAM_ to values. */
static const struct {
    const char *name;
    int value;
} FLAGS[] = {
    { "CHANGE_EXPIRED_AUTHTOK", PAM_CHANGE_EXPIRED_AUTHTOK },
    { "DISALLOW_NULL_AUTHTOK",  PAM_DISALLOW_NULL_AUTHTOK  },
    { "DELETE_CRED",            PAM_DELETE_CRED            },
    { "ESTABLISH_CRED",         PAM_ESTABLISH_CRED         },
    { "REFRESH_CRED",           PAM_REFRESH_CRED           },
    { "REINITIALIZE_CRED",      PAM_REINITIALIZE_CRED      },
    { "SILENT",                 PAM_SILENT                 },
};

/* Mapping of strings to PAM groups. */
static const struct {
    const char *name;
    enum group_type group;
} GROUPS[] = {
    { "account",  GROUP_ACCOUNT  },
    { "auth",     GROUP_AUTH     },
    { "password", GROUP_PASSWORD },
    { "session",  GROUP_SESSION  },
};

/* Mapping of strings to PAM return values. */
static const struct {
    const char *name;
    int status;
} RETURNS[] = {
    { "PAM_IGNORE",  PAM_IGNORE  },
    { "PAM_SUCCESS", PAM_SUCCESS },
};

/* Mappings of strings to syslog priorities. */
static const struct {
    const char *name;
    int priority;
} PRIORITIES[] = {
    { "DEBUG",  LOG_DEBUG  },
    { "INFO",   LOG_INFO   },
    { "NOTICE", LOG_NOTICE },
    { "ERR",    LOG_ERR    },
    { "CRIT",   LOG_CRIT   },
};


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
    line = bstrdup(buffer);
    return line;
}


/*
 * Given the name of a PAM call, map it to a call enum.  This is used later in
 * switch statements to determine which function to call.  Fails on any
 * unrecognized string.  If the optional second argument is not NULL, also
 * store the group number in that argument.
 */
static pam_call
string_to_call(const char *name, enum group_type *group)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(CALLS); i++)
        if (strcmp(name, CALLS[i].name) == 0) {
            if (group != NULL)
                *group = CALLS[i].group;
            return CALLS[i].call;
        }
    bail("unrecognized PAM call %s", name);
}


/*
 * Given a PAM flag value without the leading PAM_, map it to the numeric
 * value of that flag.  Fails on any unrecognized string.
 */
static enum group_type
string_to_flag(const char *name)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(FLAGS); i++)
        if (strcmp(name, FLAGS[i].name) == 0)
            return FLAGS[i].value;
    bail("unrecognized PAM flag %s", name);
}


/*
 * Given a PAM group name, map it to the array index for the options array for
 * that group.  Fails on any unrecognized string.
 */
static enum group_type
string_to_group(const char *name)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(GROUPS); i++)
        if (strcmp(name, GROUPS[i].name) == 0)
            return GROUPS[i].group;
    bail("unrecognized PAM group %s", name);
}


/*
 * Given a syslog priority name, map it to the numeric value of that priority.
 * Fails on any unrecognized string.
 */
static int
string_to_priority(const char *name)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(PRIORITIES); i++)
        if (strcmp(name, PRIORITIES[i].name) == 0)
            return PRIORITIES[i].priority;
    bail("unrecognized syslog priority %s", name);
}


/*
 * Given a PAM return status, map it to the actual expected value.  Fails on
 * any unrecognized string.
 */
static int
string_to_status(const char *name)
{
    size_t i;

    if (name == NULL)
        bail("no PAM status on line");
    for (i = 0; i < ARRAY_SIZE(RETURNS); i++)
        if (strcmp(name, RETURNS[i].name) == 0)
            return RETURNS[i].status;
    bail("unrecognized PAM status %s", name);
}


/*
 * We found a section delimiter while parsing another section.  Rewind our
 * input file back before the section delimiter so that we'll read it again.
 * Takes the length of the line we read, which is used to determine how far to
 * rewind.
 */
static void
rewind_section(FILE *script, size_t length)
{
    if (fseek(script, -length - 1, SEEK_CUR) != 0)
        sysbail("cannot rewind file");
}


/*
 * Given a whitespace-delimited string of PAM options, split it into an argv
 * array and argc count and store it in the provided option struct.
 */
static void
split_options(char *string, struct options *options)
{
    char *opt;
    size_t size;

    for (opt = strtok(string, " "); opt != NULL; opt = strtok(NULL, " ")) {
        if (options->argv == NULL) {
            options->argv = bmalloc(sizeof(const char *) * 2);
            options->argv[0] = bstrdup(opt);
            options->argv[1] = NULL;
            options->argc = 1;
        } else {
            size = sizeof(const char *) * (options->argc + 2);
            options->argv = brealloc(options->argv, size);
            options->argv[options->argc] = bstrdup(opt);
            options->argv[options->argc + 1] = NULL;
            options->argc++;
        }
    }
}


/*
 * Parse the options section of a PAM script.  This consists of one or more
 * lines in the format:
 *
 *     <group> = <options>
 *
 * where options are either option names or option=value pairs, where the
 * value may not contain whitespace.  Returns an options struct, which stores
 * argc and argv values for each group.
 *
 * Takes the work struct as an argument and puts values into its array.
 */
static void
parse_options(FILE *script, struct work *work)
{
    char *line, *group, *token;
    size_t length;
    enum group_type type;

    for (line = readline(script); line != NULL; line = readline(script)) {
        length = strlen(line);
        group = strtok(line, " ");
        if (group == NULL)
            bail("malformed script line");
        if (group[0] == '[')
            break;
        type = string_to_group(group);
        token = strtok(NULL, " ");
        if (token == NULL || strcmp(token, "=") != 0)
            bail("malformed action line near %s", token);
        token = strtok(NULL, "");
        split_options(token, &work->options[type]);
        free(line);
    }
    if (line != NULL) {
        free(line);
        rewind_section(script, length);
    }
}


/*
 * Parse the call portion of a PAM call in the run section of a PAM script.
 * This handles parsing the PAM flags that optionally may be given as part of
 * the call.  Takes the token representing the call and a pointer to the
 * action struct to fill in with the call and the option flags.
 */
static void
parse_call(char *token, struct action *action)
{
    char *flags, *flag;

    action->flags = 0;
    flags = strchr(token, '(');
    if (flags != NULL) {
        *flags = '\0';
        flags++;
        for (flag = strtok(flags, "|,)"); flag != NULL;
             flag = strtok(NULL, "|,)")) {
            action->flags |= string_to_flag(flag);
        }
    }
    action->call = string_to_call(token, &action->group);
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
    char *line, *token, *call;
    size_t length;

    for (line = readline(script); line != NULL; line = readline(script)) {
        length = strlen(line);
        token = strtok(line, " ");
        if (token[0] == '[')
            break;
        next = bmalloc(sizeof(struct action));
        next->next = NULL;
        if (head == NULL)
            head = next;
        else
            current->next = next;
        next->name = bstrdup(token);
        call = token;
        token = strtok(NULL, " ");
        if (token == NULL || strcmp(token, "=") != 0)
            bail("malformed action line near %s", token);
        token = strtok(NULL, " ");
        next->status = string_to_status(token);
        parse_call(call, next);
        free(line);
        current = next;
    }
    if (head == NULL)
        bail("empty run section in script");
    if (line != NULL) {
        free(line);
        rewind_section(script, length);
    }
    return head;
}


/*
 * Parse the output section of a PAM script.  This consists of zero or more
 * lines in the format:
 *
 *     PRIORITY some output information
 *
 * where PRIORITY is replaced by the numeric syslog priority corresponding to
 * that priority and the rest of the output is used as-is except for the
 * following substitutions:
 *
 *     %u full user as passed to this function
 *
 * Returns the accumulated output as a single string.
 */
static char *
parse_output(FILE *script, const char *user)
{
    char *line, *token, *piece, *p, *out;
    char *output = NULL;
    size_t length;
    size_t total = 0;
    int priority;

    for (line = readline(script); line != NULL; line = readline(script)) {
        token = strtok(line, " ");
        priority = string_to_priority(token);
        if (asprintf(&piece, "%d ", priority) < 0)
            sysbail("asprintf failed");
        output = brealloc(output, total + strlen(piece));
        memcpy(output + total, piece, strlen(piece));
        total += strlen(piece);
        free(piece);
        token = strtok(NULL, "");
        if (token == NULL)
            bail("malformed line %s", line);
        length = 0;
        for (p = token; *p != '\0'; p++) {
            if (*p != '%')
                length++;
            else {
                p++;
                switch (*p) {
                case 'u':
                    length += strlen(user);
                    break;
                default:
                    length++;
                    break;
                }
            }
        }
        output = brealloc(output, total + length + 1);
        for (p = token, out = output + total; *p != '\0'; p++) {
            if (*p != '%')
                *out++ = *p;
            else {
                p++;
                switch (*p) {
                case 'u':
                    memcpy(out, user, strlen(user));
                    out += strlen(user);
                    break;
                default:
                    *out++ = *p;
                    break;
                }
            }
        }
        *out = '\0';
        total += out - output;
        free(line);
    }
    return output;
}


/*
 * Parse a PAM interaction script.  This handles parsing of the top-level
 * section markers and dispatches the parsing to other functions.  Returns the
 * total work to do as a work struct.
 */
static struct work *
parse_script(FILE *script, const char *user)
{
    struct work *work;
    char *line, *token;

    work = bmalloc(sizeof(struct work));
    memset(work, 0, sizeof(struct work));
    work->actions = NULL;
    for (line = readline(script); line != NULL; line = readline(script)) {
        token = strtok(line, " ");
        if (token[0] != '[')
            bail("line outside of section: %s", line);
        if (strcmp(token, "[options]") == 0)
            parse_options(script, work);
        else if (strcmp(token, "[run]") == 0)
            work->actions = parse_run(script);
        else if (strcmp(token, "[output]") == 0)
            work->output = parse_output(script, user);
        else
            bail("unknown section: %s", token);
        free(line);
    }
    if (work->actions == NULL)
        bail("no run section defined");
    return work;
}
        

/*
 * The core of the work.  Given the path to a PAM interaction script, which
 * may be relative to SOURCE or BUILD, the user (may be NULL), and the stored
 * password (may be NULL), run that script, outputing the results in TAP
 * format.
 */
void
run_script(const char *file, const char *user, const char *password)
{
    char *path, *output;
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
    work = parse_script(script, user);
    diag("Starting %s", file);

    /* Initialize PAM. */
    if (user == NULL)
        user = "testuser";
    status = pam_start("test", user, &conv, &pamh);
    if (status != PAM_SUCCESS)
        sysbail("cannot create PAM handle");
    if (password != NULL)
        pamh->authtok = password;

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
    free(work);
    free(path);
}
