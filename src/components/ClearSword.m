#include "ClearSword.h"
#include "../LCUtils/utils.h"
#include "clearsword/kexploit_opa334.h"
#include "clearsword/kutils.h"
#include "clearsword/offsets.h"
#include "clearsword/taskrop/RemoteCall.h"

#include <unistd.h>
#include <errno.h>
#include <os/log.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#define LOG(fmt, ...) os_log(OS_LOG_DEFAULT, "[ClearSword] " fmt, ##__VA_ARGS__)

/* ptrace request codes — from <sys/ptrace.h>, which isn't in the SDK */
#define PT_DETACH       11
#define PT_ATTACHEXC    14

/* We use the Raw syscall directly; <sys/ptrace.h> isn't available. */
extern int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

/* CS_DEBUGGED from <sys/codesign.h>; declared here to avoid pulling it in */
#ifndef CS_DEBUGGED
#define CS_DEBUGGED  0x10000000
#endif

/*
 *  The only test that actually matters: can we get writable+executable
 *  memory now?  mmap(MAP_JIT) is the sanctioned path; the mprotect
 *  fallback is what a process with CS_DEBUGGED will also allow.
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

int enable_self_jit(void)
{
    LOG("======== enable_self_jit ========");

    /* --- 1. kernel R/W --- */
    int r = kexploit_opa334();
    if (r != 0) {
        LOG("kexploit_opa334() failed: %d", r);
        return r;
    }
    LOG("kernel R/W ready");

    /* --- 2. fast path --- */
    int flags = 0;
    int csops_result = csops(getpid(), 0, &flags, sizeof(flags));
    LOG("csops() -> %d, flags=0x%08x", csops_result, flags);
    if (csops_result == 0 && (flags & CS_DEBUGGED)) {
        LOG("CS_DEBUGGED already set — verifying mmap");
        return try_map_jit() == 0 ? 0 : EACCES;
    }

    /* --- 3. RemoteCall into SpringBoard --- */
    LOG("-- initializing RemoteCall on SpringBoard --");
    RemoteCall *proc = [[RemoteCall alloc] initWithProcess:@"SpringBoard"
                                        useMigFilterBypass:NO];
    if (!proc) {
        LOG("RemoteCall init failed: %@", [RemoteCall lastInitError]);
        return EFAULT;
    }
    LOG("RemoteCall ready, SpringBoard pid = %d", proc.pid);

    /* --- 4. sanity check: ask SpringBoard for its own pid --- */
    uint64_t sb_pid = RemoteArbCall(proc, getpid);
    LOG("SpringBoard getpid() -> %llu (expected %d)", sb_pid, proc.pid);
    if (sb_pid == 0) {
        LOG("RemoteCall sanity failed");
        [proc destroyRemoteCall];
        return EFAULT;
    }

    /* --- 5. ptrace attach/detach from SpringBoard to us --- */
    pid_t me = getpid();
    LOG("-- ptrace(PT_ATTACHEXC, %d) via SpringBoard --", me);
    uint64_t r1 = RemoteArbCall(proc, ptrace,
                                (uint64_t)PT_ATTACHEXC,
                                (uint64_t)me,
                                0, 0);
    LOG("ptrace(PT_ATTACHEXC) -> %llu", r1);

    usleep(150 * 1000);

    LOG("-- ptrace(PT_DETACH, %d) via SpringBoard --", me);
    uint64_t r2 = RemoteArbCall(proc, ptrace,
                                (uint64_t)PT_DETACH,
                                (uint64_t)me,
                                0, 0);
    LOG("ptrace(PT_DETACH) -> %llu", r2);

    /* --- 6. verify csops reflects the change --- */
    flags = 0;
    csops_result = csops(getpid(), 0, &flags, sizeof(flags));
    LOG("post-ptrace csops() -> %d, flags=0x%08x, CS_DEBUGGED=%d",
        csops_result, flags, !!(flags & CS_DEBUGGED));

    /* --- 7. the test that actually matters --- */
    int jit_ok = try_map_jit();

    [proc destroyRemoteCall];

    if (jit_ok == 0) {
        LOG("======== JIT ENABLED ========");
        return 0;
    }

    LOG("JIT still refused after ptrace. csops says CS_DEBUGGED=%d.",
        !!(flags & CS_DEBUGGED));
    return EACCES;
}