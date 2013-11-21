/*
 * QEMU localhost migration with page flipping
 *
 * Copyright IBM, Corp. 2013
 *
 * Authors:
 *   Lei Li   <lilei@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "config-host.h"
#include "qemu-common.h"
#include "migration/migration.h"
#include "exec/cpu-common.h"
#include "config.h"
#include "exec/cpu-all.h"
#include "exec/memory.h"
#include "exec/memory-internal.h"
#include "monitor/monitor.h"
#include "migration/qemu-file.h"
#include "qemu/iov.h"
#include "sysemu/arch_init.h"
#include "sysemu/sysemu.h"
#include "block/block.h"
#include "qemu/sockets.h"
#include "migration/block.h"
#include "qemu/thread.h"
#include "qmp-commands.h"
#include "trace.h"
#include "qemu/osdep.h"

//#define DEBUG_MIGRATION_LOCAL

#ifdef DEBUG_MIGRATION_LOCAL
#define DPRINTF(fmt, ...) \
    do { printf("migration-local: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif


typedef struct QEMUFileLocal {
    QEMUFile *file;
    int sockfd;
    int pipefd[2];
    bool unix_page_flipping;
} QEMUFileLocal;

static bool pipefd_passed;

static int qemu_local_get_sockfd(void *opaque)
{
    QEMUFileLocal *s = opaque;

    return s->sockfd;
}

static int unix_msgfd_lookup(void *opaque, struct msghdr *msg)
{
    QEMUFileLocal *s = opaque;
    struct cmsghdr *cmsg;
    bool found = false;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
            cmsg->cmsg_level != SOL_SOCKET ||
            cmsg->cmsg_type != SCM_RIGHTS)
            continue;

        /* PIPE file descriptor to be received */
        s->pipefd[0] = *((int *)CMSG_DATA(cmsg));
    }

    if (s->pipefd[0] <= 0) {
        fprintf(stderr, "no pipe fd can be received\n");
        return found;
    }

    DPRINTF("pipefd successfully received\n");
    return s->pipefd[0];
}

static int qemu_local_get_buffer(void *opaque, uint8_t *buf,
                                 int64_t pos, int size)
{
    QEMUFileLocal *s = opaque;
    ssize_t len;
    struct msghdr msg = { NULL, };
    struct iovec iov[1];
    union {
        struct cmsghdr cmsg;
        char control[CMSG_SPACE(sizeof(int))];
    } msg_control;

    iov[0].iov_base = buf;
    iov[0].iov_len = size;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &msg_control;
    msg.msg_controllen = sizeof(msg_control);

    for (;;) {
        if (!pipefd_passed) {
            /*
             * recvmsg is called here to catch the control message for
             * the exchange of PIPE file descriptor until it is received.
             */
            len = recvmsg(s->sockfd, &msg, 0);
            if (len != -1) {
                if (unix_msgfd_lookup(s, &msg) > 0) {
                    pipefd_passed = 1;
                    /*
                     * Do not count one byte taken by the PIPE file
                     * descriptor.
                     */
                    len--;
                } else {
                    len = -1;
                }
                break;
            }
        } else {
            len = qemu_recv(s->sockfd, buf, size, 0);
            if (len != -1) {
                break;
            }
        }

        if (socket_error() == EAGAIN) {
            yield_until_fd_readable(s->sockfd);
        } else if (socket_error() != EINTR) {
            break;
        }
    }

    if (len == -1) {
        len = -socket_error();
    }

    return len;
}

static ssize_t qemu_local_writev_buffer(void *opaque, struct iovec *iov,
                                        int iovcnt, int64_t pos)
{
    QEMUFileLocal *s = opaque;
    ssize_t len;
    ssize_t size = iov_size(iov, iovcnt);

    len = iov_send(s->sockfd, iov, iovcnt, 0, size);
    if (len < size) {
        len = -socket_error();
    }

    return len;
}

static int qemu_local_close(void *opaque)
{
    QEMUFileLocal *s = opaque;

    closesocket(s->sockfd);

    if (s->unix_page_flipping) {
        close(s->pipefd[0]);
        close(s->pipefd[1]);
    }

    g_free(s);

    return 0;
}

static int send_pipefd(int sockfd, int pipefd);

static int qemu_local_send_pipefd(QEMUFile *f, void *opaque,
                                  uint64_t flags)
{
    QEMUFileLocal *s = opaque;
    int ret;

    if (s->unix_page_flipping) {
        /* Avoid sending pipe fd again in ram_save_complete() stage */
        if (flags == RAM_CONTROL_SETUP) {
            qemu_fflush(f);
            ret = send_pipefd(s->sockfd, s->pipefd[0]);
            if (ret < 0) {
                fprintf(stderr, "failed to pass PIPE\n");
                return ret;
            }
            DPRINTF("PIPE fd was sent\n");
        }
    }

    return 0;
}

static size_t qemu_local_save_ram(QEMUFile *f, void *opaque,
                                  MemoryRegion *mr, ram_addr_t offset,
                                  size_t size, int *bytes_sent)
{
    QEMUFileLocal *s = opaque;
    ram_addr_t current_addr = mr->ram_addr + offset;
    void *ram_addr;
    ssize_t ret;

    if (s->unix_page_flipping) {
        qemu_fflush(s->file);
        qemu_put_be64(s->file, RAM_SAVE_FLAG_HOOK);

        /* Write page address to unix socket */
        qemu_put_be64(s->file, current_addr);

        ram_addr = memory_region_get_ram_ptr(mr) + offset;

        /* vmsplice page data to pipe */
        struct iovec iov = {
            .iov_base = ram_addr,
            .iov_len  = size,
        };

        /*
         * The flag SPLICE_F_MOVE is introduced in kernel for the page
         * flipping feature in QEMU, which will movie pages rather than
         * copying, previously unused.
         *
         * If a move is not possible the kernel will transparently falls
         * back to copying data.
         *
         * For older kernels the SPLICE_F_MOVE would be ignored and a copy
         * would occur.
         */
        ret = vmsplice(s->pipefd[1], &iov, 1, SPLICE_F_GIFT | SPLICE_F_MOVE);
        if (ret == -1) {
            if (errno != EAGAIN && errno != EINTR) {
                fprintf(stderr, "vmsplice save error: %s\n", strerror(errno));
                return ret;
            }
        } else {
            if (bytes_sent) {
                *bytes_sent = 1;
            }
            DPRINTF("block_offset: %lu, offset: %lu\n", block_offset, offset);
            return 0;
        }
    }

    return RAM_SAVE_CONTROL_NOT_SUPP;
}

static int qemu_local_ram_load(QEMUFile *f, void *opaque,
                               uint64_t flags)
{
    QEMUFileLocal *s = opaque;
    ram_addr_t addr;
    struct iovec iov;
    ssize_t ret = -EINVAL;

    /*
     * PIPE file descriptor will be received by another callback
     * get_buffer.
     */
    if (pipefd_passed) {
        void *host;
        /*
         * Extract the page address from the 8-byte record and
         * read the page data from the pipe.
         */
        addr = qemu_get_be64(s->file);
        host = qemu_get_ram_ptr(addr);

        iov.iov_base = host;
        iov.iov_len = TARGET_PAGE_SIZE;

        /* The flag SPLICE_F_MOVE is introduced in kernel for the page
         * flipping feature in QEMU, which will movie pages rather than
         * copying, previously unused.
         *
         * If a move is not possible the kernel will transparently falls
         * back to copying data.
         *
         * For older kernels the SPLICE_F_MOVE would be ignored and a copy
         * would occur.
         */
        ret = vmsplice(s->pipefd[0], &iov, 1, SPLICE_F_MOVE);
        if (ret == -1) {
            if (errno != EAGAIN && errno != EINTR) {
                fprintf(stderr, "vmsplice() load error: %s", strerror(errno));
                return ret;
            }
            DPRINTF("vmsplice load error\n");
        } else if (ret == 0) {
            DPRINTF(stderr, "load_page: zero read\n");
        }

        DPRINTF("vmsplice (read): %zu\n", ret);
        return ret;
    }

    return 0;
}



static const QEMUFileOps pipe_read_ops = {
    .get_fd        = qemu_local_get_sockfd,
    .get_buffer    = qemu_local_get_buffer,
    .close         = qemu_local_close,
    .hook_ram_load = qemu_local_ram_load
};

static const QEMUFileOps pipe_write_ops = {
    .get_fd             = qemu_local_get_sockfd,
    .writev_buffer      = qemu_local_writev_buffer,
    .close              = qemu_local_close,
    .before_ram_iterate = qemu_local_send_pipefd,
    .save_page          = qemu_local_save_ram
};

QEMUFile *qemu_fopen_socket_local(int sockfd, const char *mode)
{
    QEMUFileLocal *s;
    int pipefd[2];

    if (qemu_file_mode_is_not_valid(mode)) {
        return NULL;
    }

    s = g_malloc0(sizeof(QEMUFileLocal));
    s->sockfd = sockfd;

    if (migrate_unix_page_flipping()) {
        s->unix_page_flipping = 1;
    }

    if (mode[0] == 'w') {
        if (s->unix_page_flipping) {
            if (pipe(pipefd) < 0) {
                fprintf(stderr, "failed to create PIPE\n");
                goto fail;
            }

            s->pipefd[0] = pipefd[0];
            s->pipefd[1] = pipefd[1];
        }

        qemu_set_block(s->sockfd);
        s->file = qemu_fopen_ops(s, &pipe_write_ops);
    } else {
        s->file = qemu_fopen_ops(s, &pipe_read_ops);
    }

    return s->file;

fail:
    g_free(s);
    return NULL;
}


/*
 * Pass a pipe file descriptor to another process.
 *
 * Return negative value If pipefd < 0. Return 0 on
 * success.
 *
 */
static int send_pipefd(int sockfd, int pipefd)
{
    struct msghdr msg;
    struct iovec iov[1];
    ssize_t ret;

    union {
      struct cmsghdr cm;
      char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;
    char req[1] = { 0x01 };

    if (pipefd < 0) {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        /* Negative status means error */
        req[0] = pipefd;
    } else {
        msg.msg_control = control_un.control;
        msg.msg_controllen = sizeof(control_un.control);

        cmptr = CMSG_FIRSTHDR(&msg);
        cmptr->cmsg_len = CMSG_LEN(sizeof(int));
        cmptr->cmsg_level = SOL_SOCKET;
        cmptr->cmsg_type = SCM_RIGHTS;
        *((int *) CMSG_DATA(cmptr)) = pipefd;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;

        iov[0].iov_base = req;
        iov[0].iov_len = sizeof(req);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
    }

    ret = sendmsg(sockfd, &msg, 0);
    if (ret <= 0) {
        DPRINTF("sendmsg error: %s\n", strerror(errno));
    }

    return ret;
}
