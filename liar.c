#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

#define LIAR_DEBUG 1

#include "liar.h"
#include "socks.h"
#include "helper.h"

struct socket_info *find_fdc(struct child_info *ci, int fdc) {
    for (int i = 0; i < MAX_SOCKETS_COUNT; i++) {
        if (ci->sockets[i].fdc == fdc)
            return &ci->sockets[i];
    }
    return NULL;
}

int get_fdp(struct child_info *ci, int fdc) {
    struct socket_info *si = find_fdc(ci, fdc);
    return si ? si->fdp : -1;
}

int bind_fd(struct child_info *ci, int fdp, int fdc) {
    struct socket_info *si = find_fdc(ci, -1);
    if (si == NULL)
        return -1;  // no space
    si->fdp = fdp;
    si->fdc = fdc;
    return 0;
}

int unbind_fd(struct child_info *ci, int fdc) {
    struct socket_info *si = find_fdc(ci, fdc);
    if (si == NULL)
        return -1;
    si->fdp = si->fdc = -1;
    return 0;
}

void start_child(struct child_info *ci, const char *prog, char *argv[]) {
    int pid;
    switch (pid = fork()) {
        case -1:
            err("fork");
        case 0:
            erre_sys(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
            erre_sys(execvp(prog, argv));
        default:
            ci->pid = pid;
    }
}

void on_socket_enter(struct child_info *ci) {
    logd("socket enter");

    int fd;
    arg_t args[3];

    // sendfd
    syscall_args2array(&ci->regs, args, 3);
    if (!(args[0] & AF_INET || args[0] & AF_INET6)) {
        logd("not inet family. ignored");
        return;
    }
    if (args[1] != SOCK_STREAM) {
        logd("not tcp. ignored");
        return;
    }
    fd = socket(args[0], args[1], args[2]);
    if (fd == -1) {
        ci->curr_err = errno;
        struct user_regs_struct regs1 = ci->regs;
        regs1.orig_rax = SYS_nanosleep;
        erre_sys(ptrace(PTRACE_SETREGS, ci->pid, NULL, &regs1));
        return;
    }
    ci->curr_err = 0;
    sendfd(ci->fd_sock[0], fd);
    ci->binding_fdp = fd;

    // backup msgbuf
    ci->msgbuf.start = (void *) ci->regs.rsp - ci->regs.rsp % 4096;
    child_gets(ci->pid, ci->msgbuf.start, ci->msgbuf.backup, MSGBUF_SIZE);

    // prepare for recvmsg
    struct {
        struct msghdr msg;
        char buf[CMSG_SPACE(sizeof(int))];
    } data;
    memset(&data, 0, sizeof(data));
    data.msg.msg_iov = 0;
    data.msg.msg_iovlen = 0;
    data.msg.msg_control = (void *) ci->msgbuf.start + sizeof(struct msghdr);
    data.msg.msg_controllen = sizeof(data.buf);
    ci->msgbuf.fd_addr = CMSG_DATA(CMSG_FIRSTHDR(&data.msg));
    child_puts(ci->pid, ci->msgbuf.start, (char *)&data, sizeof(data));

    // replace syscall
    struct user_regs_struct regs1 = ci->regs;
    args[0] = ci->fd_sock[1];
    args[1] = (arg_t)ci->msgbuf.start;
    args[2] = 0;
    syscall_array2args(&regs1, args, 3);
    regs1.orig_rax = SYS_recvmsg;
    erre_sys(ptrace(PTRACE_SETREGS, ci->pid, NULL, &regs1));
}

void on_socket_exit(struct child_info *ci) {
    logd("socket exit");
    if (ci->curr_err != 0) {
        struct user_regs_struct regs1 = ci->regs;
        regs1.rax = -ci->curr_err;
        erre_sys(ptrace(PTRACE_SETREGS, ci->pid, NULL, &regs1));
        return;
    }
    if (ci->regs.rax == 0) {
        errno = 0;
        int fd = ptrace(PTRACE_PEEKDATA, ci->pid, ci->msgbuf.fd_addr, NULL);
        if (errno != 0)
            err("ptrace");

        struct user_regs_struct regs1 = ci->regs;
        regs1.rax = fd;
        erre_sys(ptrace(PTRACE_SETREGS, ci->pid, NULL, &regs1));
        erre_sys(bind_fd(ci, ci->binding_fdp, fd));
    } else {
        // recvmsg failed
        close(ci->binding_fdp);
    }
    child_puts(ci->pid, ci->msgbuf.start, ci->msgbuf.backup, MSGBUF_SIZE);
    ci->msgbuf.start = NULL;
}

void on_connect_enter(struct child_info *ci) {
    logd("connect");
    arg_t args[3];
    syscall_args2array(&ci->regs, args, 3);

    int fdc = args[0];
    int fdp = get_fdp(ci, fdc);
    if (fdp == -1) {
        logd("not managed fd. ignored");
        return;
    }
    struct sockaddr *origaddr = malloc((socklen_t) args[2]);
    if (origaddr == NULL)
        err("malloc");
    child_gets(ci->pid, (void *) args[1], (void *) origaddr, args[2]);
    if (origaddr->sa_family != AF_INET) {
        // TODO ipv6
        ci->curr_err = 97;  // EAFNOSUPPORT
        goto fin;
    }

    struct sockaddr_in proxyaddr = {
        .sin_family = AF_INET,
        .sin_port = htons(8000),
    };
    inet_aton("127.0.0.1", &proxyaddr.sin_addr);

    int flags = fcntl(fdp, F_GETFL);
    // remove O_NONBLOCK
    if (flags & O_NONBLOCK) {
        fcntl(fdp, F_SETFL, flags & ~O_NONBLOCK);
    }

    // connect to proxy server
    logd("connecting to proxy server...");
    if (connect(fdp, (struct sockaddr *) &proxyaddr, sizeof(proxyaddr)) == -1) {
        perror("[debug] proxy server connect failed...");
        ci->curr_err = errno;
    } else {
        ci->curr_err = 0;
        int err = socks4_connect(fdp,
                ((struct sockaddr_in *) origaddr)->sin_addr.s_addr,
                ntohs(((struct sockaddr_in *) origaddr)->sin_port));
        if (err != 0) {
            logd("socks4 connect failed");
            ci->curr_err = ECONNREFUSED;
        }
    }
    free(origaddr);
    if (flags & O_NONBLOCK) {
        fcntl(fdp, F_SETFL, flags | O_NONBLOCK);
    }

    struct user_regs_struct regs1;
fin:
    // 替换为nanosleep，是否成功不用关心
    regs1 = ci->regs;
    regs1.orig_rax = SYS_nanosleep;
    erre_sys(ptrace(PTRACE_SETREGS, ci->pid, NULL, &regs1));
}

void on_connect_exit(struct child_info *ci) {
    logd("connect exit");

    // 被替换的nanosleep总会失败，所以即使curr_err为0，也需要设置一下
    struct user_regs_struct regs1 = ci->regs;
    regs1.rax = -ci->curr_err;
    erre_sys(ptrace(PTRACE_SETREGS, ci->pid, NULL, &regs1));
}

void on_close_enter(struct child_info *ci) {
    struct socket_info *si;
    arg_t args[1];
    syscall_args2array(&ci->regs, args, 1);

    logd("close enter: %d", args[0]);

    if (args[0] == ci->fd_sock[1]) {
        logd("attemp to close fd_sock, ignored");
        ci->regs.orig_rax = SYS_nanosleep;
        erre_sys(ptrace(PTRACE_SETREGS, ci->pid, NULL, &ci->regs));
    } else {
        si = find_fdc(ci, args[0]);
        if (si != NULL) {
            logd("closing fdp %d", si->fdp);
            close(si->fdp);
        }
    }
}

void stopped(struct child_info *ci) {
    int sig = WSTOPSIG(ci->status);
    if (sig != SIGTRAP) {
        if (sig == SIGCHLD) {
            logd("[child exited]");
            exit(0);
        } else {
            logd("[child stopped by signal (ignored): %s]", strsignal(WSTOPSIG(ci->status)));
            return;
        }
    }

    erre_sys(ptrace(PTRACE_GETREGS, ci->pid, NULL, &ci->regs));
    long long orig_rax = ci->regs.orig_rax;

    if (ci->curr_call == -1) {
        // enter-stop
        switch (orig_rax) {
            case SYS_socket:
                on_socket_enter(ci);
                break;
            case SYS_connect:
                on_connect_enter(ci);
                break;
            case SYS_close:
                on_close_enter(ci);
                break;
            case SYS_close_range:
                break;
            case SYS_clone:
                logd("clone");
                break;
        }
        ci->curr_call = orig_rax;
    } else {
        // exit-stop
        switch (ci->curr_call) {
            case SYS_socket:
                if (orig_rax == SYS_recvmsg)
                    on_socket_exit(ci);
                break;
            case SYS_connect:
                if (orig_rax == SYS_nanosleep)
                    on_connect_exit(ci);
                break;
        }
        ci->curr_call = -1;
        ci->curr_err = 0;
    }

    erre_sys(ptrace(PTRACE_SYSCALL, ci->pid, NULL, NULL));
}

int main(int argc, const char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s [program] [arg0] ...\n", argv[0]);
        exit(0);
    }

    struct child_info ci = { 0 };
    int first_exec = 1;

    for (int i = 0; i < MAX_SOCKETS_COUNT; i++) {
        ci.sockets[i].fdp = -1;
        ci.sockets[i].fdc = -1;
    }

    erre_sys(socketpair(AF_UNIX, SOCK_DGRAM, 0, ci.fd_sock));
    start_child(&ci, argv[1], (char **) &(argv[1]));
    for (;;) {
        erre_sys(waitpid(ci.pid, &ci.status, 0));
        if (WIFEXITED(ci.status)) {
            logd("child exited: %d", WEXITSTATUS(ci.status));
            return 0;
        } else if (WIFSIGNALED(ci.status)) {
            logd("child exited [signal: %s]: %d",
                    strsignal(WSTOPSIG(ci.status)), WEXITSTATUS(ci.status));
            return 0;
        } else if (WIFSTOPPED(ci.status)) {
            if (first_exec) {
                first_exec = 0;
                ci.curr_call = -1;
                erre_sys(ptrace(PTRACE_SETOPTIONS, ci.pid, 0,
                            PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC));
                erre_sys(ptrace(PTRACE_SYSCALL, ci.pid, NULL, NULL));
                continue;
            }
            stopped(&ci);
        } else if (WIFCONTINUED(ci.status)) {
            logd("child continue");
        } else {
            logd("unknown stop");
            return -1;
        }
    }
}
