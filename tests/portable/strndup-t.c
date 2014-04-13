/*
 * strndup test suite.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 *
 * The authors hereby relinquish any claim to any copyright that they may have
 * in this work, whether granted under contract or by operation of law or
 * international treaty, and hereby commit to the public, at large, that they
 * shall not, at any time in the future, seek to enforce any copyright in this
 * work against any person or entity, or prevent any person or entity from
 * copying, publishing, distributing or creating derivative works of this
 * work.
 */

#include <config.h>
#include <portable/system.h>

#include <errno.h>

#include <tests/tap/basic.h>

char *test_strndup(const char *, size_t);


int
main(void)
{
    char buffer[3];
    char *result = NULL;

    plan(7);

    result = test_strndup("foo", 8);
    is_string("foo", result, "strndup longer than string");
    free(result);
    result = test_strndup("foo", 2);
    is_string("fo", result, "strndup shorter than string");
    free(result);
    result = test_strndup("foo", 3);
    is_string("foo", result, "strndup same size as string");
    free(result);
    result = test_strndup("foo", 0);
    is_string("", result, "strndup of size 0");
    free(result);
    memcpy(buffer, "foo", 3);
    result = test_strndup(buffer, 3);
    is_string("foo", result, "strndup of non-nul-terminated string");
    free(result);
    errno = 0;
    result = test_strndup(NULL, 0);
    is_string(NULL, result, "strndup of NULL");
    is_int(errno, EINVAL, "...and returns EINVAL");

    return 0;
}
