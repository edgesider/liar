#ifndef LIAR_H_
#define LIAR_H_

#include <sys/user.h>

#define MSGBUF_SIZE (sizeof(struct msghdr) + CMSG_SPACE(sizeof(int)))  // size of recvmsg buffer
#define MAX_SOCKETS_COUNT 256

struct socket_info {
    int fdp;
    int fdc;
};

struct child_info {
    int pid;
    int status;
    struct user_regs_struct regs;
    int curr_call;
    int curr_err;

    int fd_sock[2];  // socket for file descriptors transfer

    struct {
        void *start;
        void *fd_addr;
        char backup[MSGBUF_SIZE];
    } msgbuf;  // recvmsg buffer

    // TODO hash map
    struct socket_info sockets[MAX_SOCKETS_COUNT];
    int binding_fdp;
};

#endif
