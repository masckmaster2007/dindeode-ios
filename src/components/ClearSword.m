#include "ClearSword.h"
#include "../LCUtils/utils.h"
#include <unistd.h>
#include <errno.h>

#import "clearsword/poc.h"

int enable_self_jit(void) {
    int r = clearsword_run();
    if (r != 0) return r;

    // Already CS_DEBUGGED? nothing to do
    int flags = 0;
    csops(getpid(), 0, &flags, sizeof(flags));
    if (flags & CS_DEBUGGED) return 0;

    uint64_t my_proc = find_proc(getpid()); // clearsword exposes this
    if (!my_proc) return ESRCH;

    uint32_t csflags = kread32(my_proc + CSFLAGS_OFFSET);
    csflags |= CS_DEBUGGED;
    kwrite32(my_proc + CSFLAGS_OFFSET, csflags);

    return 0;
}