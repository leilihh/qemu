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

static int qemu_local_get_sockfd(void *opaque)
{
    QEMUFileLocal *s = opaque;

    return s->sockfd;
}

static int qemu_local_get_buffer(void *opaque, uint8_t *buf,
                                 int64_t pos, int size)
{
    QEMUFileLocal *s = opaque;
    ssize_t len;

    for (;;) {
        len = qemu_recv(s->sockfd, buf, size, 0);
        if (len != -1) {
            break;
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

static const QEMUFileOps pipe_read_ops = {
    .get_fd        = qemu_local_get_sockfd,
    .get_buffer    = qemu_local_get_buffer,
    .close         = qemu_local_close,
};

static const QEMUFileOps pipe_write_ops = {
    .get_fd             = qemu_local_get_sockfd,
    .writev_buffer      = qemu_local_writev_buffer,
    .close              = qemu_local_close,
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
                fprintf(stderr, "failed to create pipe\n");
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

/*
 * Receive a pipe file descriptor from a source process
 * via unix socket.
 *
 * Return negative value if there has been an recvmsg error or
 * no fd to be received. Return 0 if the connection closed by
 * source. Return file descriptor on success.
 *
 */
static int recv_pipefd(int sockfd)
{
    struct msghdr msg;
    struct iovec iov[1];
    ssize_t n;
    int pipefd = -1;
    char req[1];

    union {
      struct cmsghdr cm;
      char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;

    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    iov[0].iov_base = req;
    iov[0].iov_len = sizeof(req);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if ( (n = recvmsg(sockfd, &msg, 0)) <= 0) {
        fprintf(stderr, "recvmsg error: %s\n", strerror(errno));
        return n;
    }

    /* req 0x01 means there is a file descriptor to receive */
    if (req[0] != 0x01) {
        return pipefd;
    }

    if ( (cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
        cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmptr->cmsg_level != SOL_SOCKET) {
            DPRINTF(stderr, "control level != SOL_SOCKET\n");
            return pipefd;
        } else if (cmptr->cmsg_type != SCM_RIGHTS) {
            DPRINTF(stderr, "control type != SCM_RIGHTS\n");
            return pipefd;
        }
        /* The pipe file descriptor to be received */
        pipefd = *((int *) CMSG_DATA(cmptr));
        DPRINTF("pipefd received successfully: %d\n", pipefd);
    } else {
        /* Descriptor was not passed */
        DPRINTF(stderr, "pipefd was not passed\n");
    }

    return pipefd;
}
