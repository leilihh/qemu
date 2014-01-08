/*
 * Internal common methods for exchange of FD
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/fd-exchange.h"
#include "qemu-common.h"


ssize_t qemu_send_with_fd(int sockfd, int passed_fd,
                          const void *buf, size_t len)
{
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmsg;
    union MsgControl msg_control;
    int retval;

    iov.iov_base = (char *)buf;
    iov.iov_len = len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = len;
    msg.msg_control = &msg_control;
    msg.msg_controllen = sizeof(msg_control);

    if (passed_fd < 0) {
        *(char *)buf = passed_fd;
    } else {
        msg.msg_control = &msg_control;
        msg.msg_controllen = sizeof(msg_control);

        cmsg = &msg_control.cmsg;
        cmsg->cmsg_len = CMSG_LEN(sizeof(passed_fd));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(passed_fd));

    }

    do {
        retval = sendmsg(sockfd, &msg, 0);
    } while (retval < 0 && errno == EINTR);

    return retval;
}

ssize_t qemu_recv_with_fd(int sockfd, int *passed_fd,
                          void *buf, size_t len)
{
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    union MsgControl msg_control;
    int retval;
    const char *data = buf;

    iov.iov_base = buf;
    iov.iov_len = len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &msg_control;
    msg.msg_controllen = sizeof(msg_control);

    do {
        retval = recvmsg(sockfd, &msg, 0);
    } while (retval < 0 && errno == EINTR);

    if (retval <= 0) {
        return retval;
    }

    if (*data != *(char *)buf) {
        *passed_fd = *data;
        return 0;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
            cmsg->cmsg_level != SOL_SOCKET ||
            cmsg->cmsg_type != SCM_RIGHTS) {
            continue;
        }

        memcpy(passed_fd, CMSG_DATA(cmsg), sizeof(*passed_fd));
        return 0;
    }

    *passed_fd = -ENFILE;
    return retval;
}
