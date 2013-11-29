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
    int pipefd_passed;
    int pipefd_received;
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
