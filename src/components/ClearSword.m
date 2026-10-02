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
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/machine.h>

#define LOG(fmt, ...) os_log(OS_LOG_DEFAULT, "[ClearSword] " fmt, ##__VA_ARGS__)

#define PT_DETACH       11
#define PT_ATTACHEXC    14

extern int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

#ifndef CS_DEBUGGED
#define CS_DEBUGGED  0x10000000
#endif

/* ================================================================== *
 *  Diagnostics
 * ================================================================== */

static void diag_running_arch(void)
{
    const struct mach_header_64 *h =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!h) {
        LOG("DIAG: _dyld_get_image_header(0) returned NULL");
        return;
    }
    uint32_t sub = h->cpusubtype & ~CPU_SUBTYPE_MASK;
    const char *name =
        (sub == CPU_SUBTYPE_ARM64E)    ? "arm64e" :
        (sub == CPU_SUBTYPE_ARM64_ALL) ? "arm64"  :
        "unknown";
    LOG("DIAG: running as %s (raw cpusubtype=0x%x)", name, sub);
}

static void diag_cpu(void)
{
    char machine[64] = {0};
    size_t msz = sizeof(machine);
    if (sysctlbyname("hw.machine", machine, &msz, NULL, 0) != 0)
        snprintf(machine, sizeof(machine), "?");

    uint32_t cpuSub = 0;
    size_t csz = sizeof(cpuSub);
    if (sysctlbyname("hw.cpusubtype", &cpuSub, &csz, NULL, 0) != 0)
        cpuSub = 0;

    LOG("DIAG: hw.machine=%s hw.cpusubtype=0x%x (ARM64E=%d)",
        machine, cpuSub, cpuSub == CPU_SUBTYPE_ARM64E);
}

static void diag_pac(void)
{
    uint64_t in = 0;
    uint64_t out = 0;

    /* Use getpid's address as a valid code pointer */
    extern int getpid(void);
    in = ((uint64_t)(uintptr_t)&getpid) & 0x7fffffffffULL;

    /* Direct pacia: x16 signed with modifier in x17 */
    __asm__ volatile (
        "mov x16, %[in]\n"
        "mov x17, #0x1000\n"
        "pacia x16, x17\n"
        "mov %[out], x16\n"
        : [out] "=r"(out)
        : [in]  "r"(in)
        : "x16", "x17"
    );

    LOG("DIAG: pacia probe: in=0x%llx out=0x%llx changed=%d",
        in, out, out != in);
}

/* ================================================================== *
 *  JIT memory test
 * ================================================================== */

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
 *  Entry point
 * ================================================================== */

int enable_self_jit(void)
{
    LOG("======== enable_self_jit ========");

    /* --- 0. diagnostics (must run before offsets_init) --- */
    diag_running_arch();
    diag_cpu();

    /* --- 1. kernel R/W --- */
    int r = kexploit_opa334();
    if (r != 0) {
        LOG("kexploit_opa334() failed: %d", r);
        return r;
    }
    LOG("kernel R/W ready");

    /* --- 2. PAC diagnostics (after R/W, before RemoteCall) --- */
    diag_pac();
    LOG("DIAG: gIsPACSupported after offsets_init = %d", gIsPACSupported);

    /* --- 3. fast path --- */
    int flags = 0;
    int csops_result = csops(getpid(), 0, &flags, sizeof(flags));
    LOG("csops() -> %d, flags=0x%08x", csops_result, flags);
    if (csops_result == 0 && (flags & CS_DEBUGGED)) {
        LOG("CS_DEBUGGED already set — verifying mmap");
        return try_map_jit() == 0 ? 0 : EACCES;
    }

    /* --- 4. RemoteCall into SpringBoard --- */
    LOG("-- initializing RemoteCall on SpringBoard --");
    RemoteCall *proc = [[RemoteCall alloc] initWithProcess:@"SpringBoard"
                                        useMigFilterBypass:NO];
    if (!proc) {
        LOG("RemoteCall init failed: %@", [RemoteCall lastInitError]);
        return EFAULT;
    }
    LOG("RemoteCall ready, SpringBoard pid = %d", proc.pid);

    /* --- 5. sanity check --- */
    uint64_t sb_pid = RemoteArbCall(proc, getpid);
    LOG("SpringBoard getpid() -> %llu (expected %d)", sb_pid, proc.pid);
    if (sb_pid == 0) {
        LOG("RemoteCall sanity failed");
        [proc destroyRemoteCall];
        return EFAULT;
    }

    /* --- 6. ptrace attach/detach --- */
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

    /* --- 7. verify csops --- */
    flags = 0;
    csops_result = csops(getpid(), 0, &flags, sizeof(flags));
    LOG("post-ptrace csops() -> %d, flags=0x%08x, CS_DEBUGGED=%d",
        csops_result, flags, !!(flags & CS_DEBUGGED));

    /* --- 8. final JIT test --- */
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