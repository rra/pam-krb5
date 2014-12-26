/*
 * Replacement for a missing issetugid.
 *
 * Simulates the functionality as the Solaris function issetugid, which
 * returns true if the running program was setuid or setgid.  The replacement
 * test is not quite as comprehensive as what the Solaris function does, but
 * it should be good enough.
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

int
issetugid(void)
{
    if (getuid() != geteuid())
        return 1;
    if (getgid() != getegid())
        return 1;
    return 0;
}
