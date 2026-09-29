#include "ClearSword.h"
#include "../LCUtils/utils.h"
#include "clearsword/darksword.h"

#include <unistd.h>
#include <errno.h>
#include <os/log.h>
#include <stdint.h>
#include <string.h>

// iOS 17.x: proc_ro.csflags
#define PROC_RO_CSFLAGS_OFFSET 0x1C

int enable_self_jit(void) {
    LOG("================================");
    LOG("enable_self_jit() ENTER");
    LOG("================================");

    LOG("calling go()");

    int r = go();

    LOG("go() returned %d", r);

    if (r != 0) {
        LOG("go() failed, aborting");
        return r;
    }

    LOG("DarkSword initialized successfully");

    int flags = 0;

    LOG("checking current csflags with csops()");

    int csops_result =
        csops(getpid(), 0, &flags, sizeof(flags));

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

    LOG("calling find_self_proc()");

    uint64_t my_proc =
        find_self_proc();

    LOG(
        "find_self_proc() returned 0x%llx",
        (unsigned long long)my_proc
    );

    if (!my_proc) {
        LOG("ERROR: my_proc is NULL");
        return ESRCH;
    }

    uint64_t proc_ro = 0;

    LOG(
        "reading proc_ro at my_proc + 0x18"
    );

    proc_ro =
        early_kread64(
            my_proc + 0x18
        );

    LOG(
        "proc_ro = 0x%llx",
        (unsigned long long)proc_ro
    );

    if (!proc_ro) {
        LOG("ERROR: proc_ro is NULL");
        return EFAULT;
    }

    uint64_t task = 0;

    LOG("reading task at proc_ro + 0x8");

    task =
        early_kread64(
            proc_ro + 0x8
        );

    LOG(
        "task = 0x%llx",
        (unsigned long long)task
    );

    if (!task) {
        LOG("ERROR: task is NULL");
        return EFAULT;
    }

    uint32_t csflags = 0;

    LOG(
        "reading csflags at proc_ro + 0x%X",
        PROC_RO_CSFLAGS_OFFSET
    );

    early_kread(
        proc_ro + PROC_RO_CSFLAGS_OFFSET,
        &csflags,
        sizeof(csflags)
    );

    LOG(
        "csflags before = 0x%08x",
        csflags
    );

    uint32_t new_csflags =
        csflags | CS_DEBUGGED;

    LOG(
        "csflags after = 0x%08x",
        new_csflags
    );

    /*
     * DarkSword's early write primitive writes 0x20 bytes.
     * Read the existing 0x20-byte region, modify only the
     * 4-byte csflags field at +0x1C, then write the whole
     * buffer back.
     */
    uint8_t writeBuf[EARLY_KRW_LENGTH] = {0};

    LOG(
        "reading 0x20-byte proc_ro tail before write"
    );

    early_kread(
        proc_ro + PROC_RO_CSFLAGS_OFFSET,
        writeBuf,
        EARLY_KRW_LENGTH
    );

    memcpy(
        writeBuf,
        &new_csflags,
        sizeof(new_csflags)
    );

    LOG("writing CS_DEBUGGED");

    early_kwrite32bytes(
        proc_ro + PROC_RO_CSFLAGS_OFFSET,
        writeBuf
    );

    LOG("csflags write completed");

    flags = 0;

    LOG("verifying with csops()");

    csops_result =
        csops(
            getpid(),
            0,
            &flags,
            sizeof(flags)
        );

    LOG(
        "verification: csops() = %d, flags = 0x%x",
        csops_result,
        flags
    );

    if (
        csops_result == 0 &&
        (flags & CS_DEBUGGED)
    ) {
        LOG("SUCCESS: CS_DEBUGGED is set");
        return 0;
    }

    LOG(
        "WARNING: CS_DEBUGGED is still not visible through csops()"
    );

    return EACCES;
}