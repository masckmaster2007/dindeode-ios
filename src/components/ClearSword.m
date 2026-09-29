#include "../LCUtils/utils.h"   // CS_DEBUGGED, csops
#include "clearsword/darksword.c"  // g_offsets, g_ctx

#include <unistd.h>
#include <errno.h>
#include <os/log.h>

// iOS 17.x: proc_ro.csflags
#define PROC_RO_CSFLAGS_OFFSET 0x1C

int enable_self_jit(void) {
    LOG("================================");
    LOG("enable_self_jit() ENTER");
    LOG("================================");

    /*
     * ClearSword must initialize the kernel R/W primitives first.
     */
    LOG("calling clearsword_run()");

    int r = go();

    LOG("clearsword_run() returned %d", r);

    if (r != 0) {
        LOG("clearsword_run failed, aborting");
        return r;
    }

    LOG("ClearSword initialized successfully");

    /*
     * Check whether the process already has CS_DEBUGGED.
     */
    int flags = 0;

    LOG("checking current csflags with csops()");

    int csops_result = csops(getpid(), 0, &flags, sizeof(flags));

    LOG(
        "csops() returned %d, flags = 0x%x",
        csops_result,
        flags
    );

    if (csops_result == 0 && (flags & CS_DEBUGGED)) {
        LOG("CS_DEBUGGED is already set");
        return 0;
    }

    LOG("CS_DEBUGGED is not currently set");

    /*
     * Locate our proc.
     */
    LOG("calling find_self_proc()");

    uint64_t my_proc = find_self_proc();

    LOG(
        "find_self_proc() returned my_proc = 0x%llx",
        (unsigned long long)my_proc
    );

    if (!my_proc) {
        LOG("ERROR: my_proc is NULL");
        return ESRCH;
    }

    /*
     * proc->p_ro
     *
     * ClearSword uses proc_p_ro = 0x18 on this OS family.
     */
    LOG(
        "reading proc_ro at my_proc + 0x%llx",
        (unsigned long long)g_offsets.proc_p_ro
    );

    uint64_t proc_ro = 0;

    kread_length(
        my_proc + g_offsets.proc_p_ro,
        &proc_ro,
        sizeof(proc_ro)
    );

    LOG(
        "proc_ro = 0x%llx",
        (unsigned long long)proc_ro
    );

    if (!proc_ro) {
        LOG("ERROR: proc_ro is NULL");
        return EFAULT;
    }

    /*
     * Read the task as an additional sanity check before touching csflags.
     */
    uint64_t task = 0;

    LOG(
        "reading task at proc_ro + 0x%llx",
        (unsigned long long)g_offsets.proc_ro_task
    );

    kread_length(
        proc_ro + g_offsets.proc_ro_task,
        &task,
        sizeof(task)
    );

    LOG(
        "task = 0x%llx",
        (unsigned long long)task
    );

    /*
     * proc_ro.csflags is at +0x1C on iOS 17.3.1.
     */
    uint32_t csflags = 0;

    LOG(
        "reading csflags at proc_ro + 0x%X",
        PROC_RO_CSFLAGS_OFFSET
    );

    kread_length(
        proc_ro + PROC_RO_CSFLAGS_OFFSET,
        &csflags,
        sizeof(csflags)
    );

    LOG(
        "csflags before = 0x%08x",
        csflags
    );

    /*
     * Preserve all existing flags and add CS_DEBUGGED.
     */
    uint32_t new_csflags = csflags | CS_DEBUGGED;

    LOG(
        "csflags after  = 0x%08x",
        new_csflags
    );

    LOG("writing CS_DEBUGGED...");

    kwrite_length(
        proc_ro + PROC_RO_CSFLAGS_OFFSET,
        &new_csflags,
        sizeof(new_csflags)
    );

    LOG("csflags write completed");

    /*
     * Verify through csops().
     */
    flags = 0;

    LOG("verifying with csops()");

    csops_result = csops(getpid(), 0, &flags, sizeof(flags));

    LOG(
        "verification: csops() = %d, flags = 0x%x",
        csops_result,
        flags
    );

    if (csops_result == 0 && (flags & CS_DEBUGGED)) {
        LOG("SUCCESS: CS_DEBUGGED is set");
        return 0;
    }

    LOG("WARNING: CS_DEBUGGED is still not visible through csops()");
    return EACCES;
}