/*
 * Internel common methods for exchange of FD
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef FD_EXCHANGE_H
#define FD_EXCHANGE_H

#include <sys/socket.h>

union MsgControl {
    struct cmsghdr cmsg;
    char control[CMSG_SPACE(sizeof(int))];
};

ssize_t qemu_send_with_fd(int sockfd, int passed_fd,
                          const void *buf, size_t len);

ssize_t qemu_recv_with_fd(int sockfd, int *passed_fd,
                          void *buf, size_t len);

#endif
