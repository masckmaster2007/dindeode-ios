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

    uint64_t my_proc = find_self_proc();
    LOG("my_proc = 0x%llx", (unsigned long long)my_proc);

    if (!my_proc) return ESRCH;

    uint64_t proc_ro = early_kread64(my_proc + g_offsets.proc_p_ro);
    LOG("proc_ro = 0x%llx", (unsigned long long)proc_ro);

    if (!proc_ro) return EFAULT;

    uint64_t task = early_kread64(proc_ro + g_offsets.proc_ro_task);
    LOG("task = 0x%llx", (unsigned long long)task);

    return 0;
}