#ifndef HELPER_H_
#define HELPER_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

typedef long long arg_t;
typedef long word_t;
#define WORD_SIZE sizeof(word_t)  // bytes

#define err(msg) do { perror((msg)); exit(-1); } while (0)
#define erre(exp) do { if (!(exp)) err(#exp); } while (0)
#define erre_sys(exp) erre((exp) >= 0)

#define offsetof(type, field) (&((type *)0)->field)

#define _log(prefix, format, args...) do { \
    fprintf(stderr, "[%s] " format, prefix, ## args); \
    fprintf(stderr, "\n"); \
} while (0)

#if LIAR_DEBUG
#define logd(...) do { \
    _log("debug", __VA_ARGS__); \
} while (0)
#else
#define logd(...)
#endif

void sendfd(int sock, int fd) {
    struct msghdr msg = {0};
    char cbuf[CMSG_SPACE(sizeof(fd))];

    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;
    msg.msg_control = &cbuf;
    msg.msg_controllen = sizeof(cbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = CMSG_SPACE(sizeof(fd));
    erre_sys(sendmsg(sock, &msg, 0));
}

static void child_gets(int pid, void *addr, char *buf, size_t len) {
    const int word_count = (len + WORD_SIZE - 1) / WORD_SIZE;
    const int remaining = len % WORD_SIZE;
    int i;
    word_t *wp = addr;
    for (i = 0; i < word_count; i++) {
        errno = 0;
        ((word_t *)buf)[i] = ptrace(PTRACE_PEEKDATA, pid, wp++, NULL);
        if (errno != 0) err("ptrace");
    }
    if (remaining) {
        errno = 0;
        word_t final = ptrace(PTRACE_PEEKDATA, pid, wp, NULL);
        if (errno != 0) err("ptrace");
        for (int i = 0; i < remaining; i++) {
            buf[word_count * WORD_SIZE + i] = ((char *)&final)[i];
        }
    }
}

static void child_puts(int pid, void *addr, char *buf, size_t len) {
    const int word_count = (len + WORD_SIZE - 1) / WORD_SIZE;
    const int remaining = len % WORD_SIZE;
    int i;
    word_t *wp = addr;
    for (i = 0; i < word_count; i++) {
        erre_sys(ptrace(PTRACE_POKEDATA, pid, wp++, ((word_t *)buf)[i]));
    }
    if (remaining) {
        errno = 0;
        word_t curr = ptrace(PTRACE_PEEKDATA, pid, wp, NULL);
        if (errno != 0) err("ptrace");
        memcpy(&curr, buf, remaining);
        erre_sys(ptrace(PTRACE_POKEDATA, pid, wp, curr));
    }
}

static const char* syscall_name(int syscall_nr) {
    char *call_name;
    switch (syscall_nr) {
        case SYS_read:
            call_name = "read";
            break;
        case SYS_write:
            call_name = "write";
            break;
        case SYS_open:
            call_name = "open";
            break;
        case SYS_close:
            call_name = "close";
            break;
        case SYS_stat:
            call_name = "stat";
            break;
        case SYS_fstat:
            call_name = "fstat";
            break;
        case SYS_lstat:
            call_name = "lstat";
            break;
        case SYS_poll:
            call_name = "poll";
            break;
        case SYS_lseek:
            call_name = "lseek";
            break;
        case SYS_mmap:
            call_name = "mmap";
            break;
        case SYS_mprotect:
            call_name = "mprotect";
            break;
        case SYS_munmap:
            call_name = "munmap";
            break;
        case SYS_brk:
            call_name = "brk";
            break;
        case SYS_rt_sigaction:
            call_name = "rt_sigaction";
            break;
        case SYS_rt_sigprocmask:
            call_name = "rt_sigprocmask";
            break;
        case SYS_rt_sigreturn:
            call_name = "rt_sigreturn";
            break;
        case SYS_ioctl:
            call_name = "ioctl";
            break;
        case SYS_pread64:
            call_name = "pread64";
            break;
        case SYS_pwrite64:
            call_name = "pwrite64";
            break;
        case SYS_readv:
            call_name = "readv";
            break;
        case SYS_writev:
            call_name = "writev";
            break;
        case SYS_access:
            call_name = "access";
            break;
        case SYS_pipe:
            call_name = "pipe";
            break;
        case SYS_select:
            call_name = "select";
            break;
        case SYS_sched_yield:
            call_name = "sched_yield";
            break;
        case SYS_mremap:
            call_name = "mremap";
            break;
        case SYS_msync:
            call_name = "msync";
            break;
        case SYS_mincore:
            call_name = "mincore";
            break;
        case SYS_madvise:
            call_name = "madvise";
            break;
        case SYS_shmget:
            call_name = "shmget";
            break;
        case SYS_shmat:
            call_name = "shmat";
            break;
        case SYS_shmctl:
            call_name = "shmctl";
            break;
        case SYS_dup:
            call_name = "dup";
            break;
        case SYS_dup2:
            call_name = "dup2";
            break;
        case SYS_pause:
            call_name = "pause";
            break;
        case SYS_nanosleep:
            call_name = "nanosleep";
            break;
        case SYS_getitimer:
            call_name = "getitimer";
            break;
        case SYS_alarm:
            call_name = "alarm";
            break;
        case SYS_setitimer:
            call_name = "setitimer";
            break;
        case SYS_getpid:
            call_name = "getpid";
            break;
        case SYS_sendfile:
            call_name = "sendfile";
            break;
        case SYS_socket:
            call_name = "socket";
            break;
        case SYS_connect:
            call_name = "connect";
            break;
        case SYS_accept:
            call_name = "accept";
            break;
        case SYS_sendto:
            call_name = "sendto";
            break;
        case SYS_recvfrom:
            call_name = "recvfrom";
            break;
        case SYS_sendmsg:
            call_name = "sendmsg";
            break;
        case SYS_recvmsg:
            call_name = "recvmsg";
            break;
        case SYS_shutdown:
            call_name = "shutdown";
            break;
        case SYS_bind:
            call_name = "bind";
            break;
        case SYS_listen:
            call_name = "listen";
            break;
        case SYS_getsockname:
            call_name = "getsockname";
            break;
        case SYS_getpeername:
            call_name = "getpeername";
            break;
        case SYS_socketpair:
            call_name = "socketpair";
            break;
        case SYS_setsockopt:
            call_name = "setsockopt";
            break;
        case SYS_getsockopt:
            call_name = "getsockopt";
            break;
        case SYS_clone:
            call_name = "clone";
            break;
        case SYS_fork:
            call_name = "fork";
            break;
        case SYS_vfork:
            call_name = "vfork";
            break;
        case SYS_execve:
            call_name = "execve";
            break;
        case SYS_exit:
            call_name = "exit";
            break;
        case SYS_wait4:
            call_name = "wait4";
            break;
        case SYS_kill:
            call_name = "kill";
            break;
        case SYS_uname:
            call_name = "uname";
            break;
        case SYS_semget:
            call_name = "semget";
            break;
        case SYS_semop:
            call_name = "semop";
            break;
        case SYS_semctl:
            call_name = "semctl";
            break;
        case SYS_shmdt:
            call_name = "shmdt";
            break;
        case SYS_msgget:
            call_name = "msgget";
            break;
        case SYS_msgsnd:
            call_name = "msgsnd";
            break;
        case SYS_msgrcv:
            call_name = "msgrcv";
            break;
        case SYS_msgctl:
            call_name = "msgctl";
            break;
        case SYS_fcntl:
            call_name = "fcntl";
            break;
        case SYS_flock:
            call_name = "flock";
            break;
        case SYS_fsync:
            call_name = "fsync";
            break;
        case SYS_fdatasync:
            call_name = "fdatasync";
            break;
        case SYS_truncate:
            call_name = "truncate";
            break;
        case SYS_ftruncate:
            call_name = "ftruncate";
            break;
        case SYS_getdents:
            call_name = "getdents";
            break;
        case SYS_getcwd:
            call_name = "getcwd";
            break;
        case SYS_chdir:
            call_name = "chdir";
            break;
        case SYS_fchdir:
            call_name = "fchdir";
            break;
        case SYS_rename:
            call_name = "rename";
            break;
        case SYS_mkdir:
            call_name = "mkdir";
            break;
        case SYS_rmdir:
            call_name = "rmdir";
            break;
        case SYS_creat:
            call_name = "creat";
            break;
        case SYS_link:
            call_name = "link";
            break;
        case SYS_unlink:
            call_name = "unlink";
            break;
        case SYS_symlink:
            call_name = "symlink";
            break;
        case SYS_readlink:
            call_name = "readlink";
            break;
        case SYS_chmod:
            call_name = "chmod";
            break;
        case SYS_fchmod:
            call_name = "fchmod";
            break;
        case SYS_chown:
            call_name = "chown";
            break;
        case SYS_fchown:
            call_name = "fchown";
            break;
        case SYS_lchown:
            call_name = "lchown";
            break;
        case SYS_umask:
            call_name = "umask";
            break;
        case SYS_gettimeofday:
            call_name = "gettimeofday";
            break;
        case SYS_getrlimit:
            call_name = "getrlimit";
            break;
        case SYS_getrusage:
            call_name = "getrusage";
            break;
        case SYS_sysinfo:
            call_name = "sysinfo";
            break;
        case SYS_times:
            call_name = "times";
            break;
        case SYS_ptrace:
            call_name = "ptrace";
            break;
        case SYS_getuid:
            call_name = "getuid";
            break;
        case SYS_syslog:
            call_name = "syslog";
            break;
        case SYS_getgid:
            call_name = "getgid";
            break;
        case SYS_setuid:
            call_name = "setuid";
            break;
        case SYS_setgid:
            call_name = "setgid";
            break;
        case SYS_geteuid:
            call_name = "geteuid";
            break;
        case SYS_getegid:
            call_name = "getegid";
            break;
        case SYS_setpgid:
            call_name = "setpgid";
            break;
        case SYS_getppid:
            call_name = "getppid";
            break;
        case SYS_getpgrp:
            call_name = "getpgrp";
            break;
        case SYS_setsid:
            call_name = "setsid";
            break;
        case SYS_setreuid:
            call_name = "setreuid";
            break;
        case SYS_setregid:
            call_name = "setregid";
            break;
        case SYS_getgroups:
            call_name = "getgroups";
            break;
        case SYS_setgroups:
            call_name = "setgroups";
            break;
        case SYS_setresuid:
            call_name = "setresuid";
            break;
        case SYS_getresuid:
            call_name = "getresuid";
            break;
        case SYS_setresgid:
            call_name = "setresgid";
            break;
        case SYS_getresgid:
            call_name = "getresgid";
            break;
        case SYS_getpgid:
            call_name = "getpgid";
            break;
        case SYS_setfsuid:
            call_name = "setfsuid";
            break;
        case SYS_setfsgid:
            call_name = "setfsgid";
            break;
        case SYS_getsid:
            call_name = "getsid";
            break;
        case SYS_capget:
            call_name = "capget";
            break;
        case SYS_capset:
            call_name = "capset";
            break;
        case SYS_rt_sigpending:
            call_name = "rt_sigpending";
            break;
        case SYS_rt_sigtimedwait:
            call_name = "rt_sigtimedwait";
            break;
        case SYS_rt_sigqueueinfo:
            call_name = "rt_sigqueueinfo";
            break;
        case SYS_rt_sigsuspend:
            call_name = "rt_sigsuspend";
            break;
        case SYS_sigaltstack:
            call_name = "sigaltstack";
            break;
        case SYS_utime:
            call_name = "utime";
            break;
        case SYS_mknod:
            call_name = "mknod";
            break;
        case SYS_uselib:
            call_name = "uselib";
            break;
        case SYS_personality:
            call_name = "personality";
            break;
        case SYS_ustat:
            call_name = "ustat";
            break;
        case SYS_statfs:
            call_name = "statfs";
            break;
        case SYS_fstatfs:
            call_name = "fstatfs";
            break;
        case SYS_sysfs:
            call_name = "sysfs";
            break;
        case SYS_getpriority:
            call_name = "getpriority";
            break;
        case SYS_setpriority:
            call_name = "setpriority";
            break;
        case SYS_sched_setparam:
            call_name = "sched_setparam";
            break;
        case SYS_sched_getparam:
            call_name = "sched_getparam";
            break;
        case SYS_sched_setscheduler:
            call_name = "sched_setscheduler";
            break;
        case SYS_sched_getscheduler:
            call_name = "sched_getscheduler";
            break;
        case SYS_sched_get_priority_max:
            call_name = "sched_get_priority_max";
            break;
        case SYS_sched_get_priority_min:
            call_name = "sched_get_priority_min";
            break;
        case SYS_sched_rr_get_interval:
            call_name = "sched_rr_get_interval";
            break;
        case SYS_mlock:
            call_name = "mlock";
            break;
        case SYS_munlock:
            call_name = "munlock";
            break;
        case SYS_mlockall:
            call_name = "mlockall";
            break;
        case SYS_munlockall:
            call_name = "munlockall";
            break;
        case SYS_vhangup:
            call_name = "vhangup";
            break;
        case SYS_modify_ldt:
            call_name = "modify_ldt";
            break;
        case SYS_pivot_root:
            call_name = "pivot_root";
            break;
        case SYS__sysctl:
            call_name = "_sysctl";
            break;
        case SYS_prctl:
            call_name = "prctl";
            break;
        case SYS_arch_prctl:
            call_name = "arch_prctl";
            break;
        case SYS_adjtimex:
            call_name = "adjtimex";
            break;
        case SYS_setrlimit:
            call_name = "setrlimit";
            break;
        case SYS_chroot:
            call_name = "chroot";
            break;
        case SYS_sync:
            call_name = "sync";
            break;
        case SYS_acct:
            call_name = "acct";
            break;
        case SYS_settimeofday:
            call_name = "settimeofday";
            break;
        case SYS_mount:
            call_name = "mount";
            break;
        case SYS_umount2:
            call_name = "umount2";
            break;
        case SYS_swapon:
            call_name = "swapon";
            break;
        case SYS_swapoff:
            call_name = "swapoff";
            break;
        case SYS_reboot:
            call_name = "reboot";
            break;
        case SYS_sethostname:
            call_name = "sethostname";
            break;
        case SYS_setdomainname:
            call_name = "setdomainname";
            break;
        case SYS_iopl:
            call_name = "iopl";
            break;
        case SYS_ioperm:
            call_name = "ioperm";
            break;
        case SYS_create_module:
            call_name = "create_module";
            break;
        case SYS_init_module:
            call_name = "init_module";
            break;
        case SYS_delete_module:
            call_name = "delete_module";
            break;
        case SYS_get_kernel_syms:
            call_name = "get_kernel_syms";
            break;
        case SYS_query_module:
            call_name = "query_module";
            break;
        case SYS_quotactl:
            call_name = "quotactl";
            break;
        case SYS_nfsservctl:
            call_name = "nfsservctl";
            break;
        case SYS_getpmsg:
            call_name = "getpmsg";
            break;
        case SYS_putpmsg:
            call_name = "putpmsg";
            break;
        case SYS_afs_syscall:
            call_name = "afs_syscall";
            break;
        case SYS_tuxcall:
            call_name = "tuxcall";
            break;
        case SYS_security:
            call_name = "security";
            break;
        case SYS_gettid:
            call_name = "gettid";
            break;
        case SYS_readahead:
            call_name = "readahead";
            break;
        case SYS_setxattr:
            call_name = "setxattr";
            break;
        case SYS_lsetxattr:
            call_name = "lsetxattr";
            break;
        case SYS_fsetxattr:
            call_name = "fsetxattr";
            break;
        case SYS_getxattr:
            call_name = "getxattr";
            break;
        case SYS_lgetxattr:
            call_name = "lgetxattr";
            break;
        case SYS_fgetxattr:
            call_name = "fgetxattr";
            break;
        case SYS_listxattr:
            call_name = "listxattr";
            break;
        case SYS_llistxattr:
            call_name = "llistxattr";
            break;
        case SYS_flistxattr:
            call_name = "flistxattr";
            break;
        case SYS_removexattr:
            call_name = "removexattr";
            break;
        case SYS_lremovexattr:
            call_name = "lremovexattr";
            break;
        case SYS_fremovexattr:
            call_name = "fremovexattr";
            break;
        case SYS_tkill:
            call_name = "tkill";
            break;
        case SYS_time:
            call_name = "time";
            break;
        case SYS_futex:
            call_name = "futex";
            break;
        case SYS_sched_setaffinity:
            call_name = "sched_setaffinity";
            break;
        case SYS_sched_getaffinity:
            call_name = "sched_getaffinity";
            break;
        case SYS_set_thread_area:
            call_name = "set_thread_area";
            break;
        case SYS_io_setup:
            call_name = "io_setup";
            break;
        case SYS_io_destroy:
            call_name = "io_destroy";
            break;
        case SYS_io_getevents:
            call_name = "io_getevents";
            break;
        case SYS_io_submit:
            call_name = "io_submit";
            break;
        case SYS_io_cancel:
            call_name = "io_cancel";
            break;
        case SYS_get_thread_area:
            call_name = "get_thread_area";
            break;
        case SYS_lookup_dcookie:
            call_name = "lookup_dcookie";
            break;
        case SYS_epoll_create:
            call_name = "epoll_create";
            break;
        case SYS_epoll_ctl_old:
            call_name = "epoll_ctl_old";
            break;
        case SYS_epoll_wait_old:
            call_name = "epoll_wait_old";
            break;
        case SYS_remap_file_pages:
            call_name = "remap_file_pages";
            break;
        case SYS_getdents64:
            call_name = "getdents64";
            break;
        case SYS_set_tid_address:
            call_name = "set_tid_address";
            break;
        case SYS_restart_syscall:
            call_name = "restart_syscall";
            break;
        case SYS_semtimedop:
            call_name = "semtimedop";
            break;
        case SYS_fadvise64:
            call_name = "fadvise64";
            break;
        case SYS_timer_create:
            call_name = "timer_create";
            break;
        case SYS_timer_settime:
            call_name = "timer_settime";
            break;
        case SYS_timer_gettime:
            call_name = "timer_gettime";
            break;
        case SYS_timer_getoverrun:
            call_name = "timer_getoverrun";
            break;
        case SYS_timer_delete:
            call_name = "timer_delete";
            break;
        case SYS_clock_settime:
            call_name = "clock_settime";
            break;
        case SYS_clock_gettime:
            call_name = "clock_gettime";
            break;
        case SYS_clock_getres:
            call_name = "clock_getres";
            break;
        case SYS_clock_nanosleep:
            call_name = "clock_nanosleep";
            break;
        case SYS_exit_group:
            call_name = "exit_group";
            break;
        case SYS_epoll_wait:
            call_name = "epoll_wait";
            break;
        case SYS_epoll_ctl:
            call_name = "epoll_ctl";
            break;
        case SYS_tgkill:
            call_name = "tgkill";
            break;
        case SYS_utimes:
            call_name = "utimes";
            break;
        case SYS_vserver:
            call_name = "vserver";
            break;
        case SYS_mbind:
            call_name = "mbind";
            break;
        case SYS_set_mempolicy:
            call_name = "set_mempolicy";
            break;
        case SYS_get_mempolicy:
            call_name = "get_mempolicy";
            break;
        case SYS_mq_open:
            call_name = "mq_open";
            break;
        case SYS_mq_unlink:
            call_name = "mq_unlink";
            break;
        case SYS_mq_timedsend:
            call_name = "mq_timedsend";
            break;
        case SYS_mq_timedreceive:
            call_name = "mq_timedreceive";
            break;
        case SYS_mq_notify:
            call_name = "mq_notify";
            break;
        case SYS_mq_getsetattr:
            call_name = "mq_getsetattr";
            break;
        case SYS_kexec_load:
            call_name = "kexec_load";
            break;
        case SYS_waitid:
            call_name = "waitid";
            break;
        case SYS_add_key:
            call_name = "add_key";
            break;
        case SYS_request_key:
            call_name = "request_key";
            break;
        case SYS_keyctl:
            call_name = "keyctl";
            break;
        case SYS_ioprio_set:
            call_name = "ioprio_set";
            break;
        case SYS_ioprio_get:
            call_name = "ioprio_get";
            break;
        case SYS_inotify_init:
            call_name = "inotify_init";
            break;
        case SYS_inotify_add_watch:
            call_name = "inotify_add_watch";
            break;
        case SYS_inotify_rm_watch:
            call_name = "inotify_rm_watch";
            break;
        case SYS_migrate_pages:
            call_name = "migrate_pages";
            break;
        case SYS_openat:
            call_name = "openat";
            break;
        case SYS_mkdirat:
            call_name = "mkdirat";
            break;
        case SYS_mknodat:
            call_name = "mknodat";
            break;
        case SYS_fchownat:
            call_name = "fchownat";
            break;
        case SYS_futimesat:
            call_name = "futimesat";
            break;
        case SYS_newfstatat:
            call_name = "newfstatat";
            break;
        case SYS_unlinkat:
            call_name = "unlinkat";
            break;
        case SYS_renameat:
            call_name = "renameat";
            break;
        case SYS_linkat:
            call_name = "linkat";
            break;
        case SYS_symlinkat:
            call_name = "symlinkat";
            break;
        case SYS_readlinkat:
            call_name = "readlinkat";
            break;
        case SYS_fchmodat:
            call_name = "fchmodat";
            break;
        case SYS_faccessat:
            call_name = "faccessat";
            break;
        case SYS_pselect6:
            call_name = "pselect6";
            break;
        case SYS_ppoll:
            call_name = "ppoll";
            break;
        case SYS_unshare:
            call_name = "unshare";
            break;
        case SYS_set_robust_list:
            call_name = "set_robust_list";
            break;
        case SYS_get_robust_list:
            call_name = "get_robust_list";
            break;
        case SYS_splice:
            call_name = "splice";
            break;
        case SYS_tee:
            call_name = "tee";
            break;
        case SYS_sync_file_range:
            call_name = "sync_file_range";
            break;
        case SYS_vmsplice:
            call_name = "vmsplice";
            break;
        case SYS_move_pages:
            call_name = "move_pages";
            break;
        case SYS_utimensat:
            call_name = "utimensat";
            break;
        case SYS_epoll_pwait:
            call_name = "epoll_pwait";
            break;
        case SYS_signalfd:
            call_name = "signalfd";
            break;
        case SYS_timerfd_create:
            call_name = "timerfd_create";
            break;
        case SYS_eventfd:
            call_name = "eventfd";
            break;
        case SYS_fallocate:
            call_name = "fallocate";
            break;
        case SYS_timerfd_settime:
            call_name = "timerfd_settime";
            break;
        case SYS_timerfd_gettime:
            call_name = "timerfd_gettime";
            break;
        case SYS_accept4:
            call_name = "accept4";
            break;
        case SYS_signalfd4:
            call_name = "signalfd4";
            break;
        case SYS_eventfd2:
            call_name = "eventfd2";
            break;
        case SYS_epoll_create1:
            call_name = "epoll_create1";
            break;
        case SYS_dup3:
            call_name = "dup3";
            break;
        case SYS_pipe2:
            call_name = "pipe2";
            break;
        case SYS_inotify_init1:
            call_name = "inotify_init1";
            break;
        case SYS_preadv:
            call_name = "preadv";
            break;
        case SYS_pwritev:
            call_name = "pwritev";
            break;
        case SYS_rt_tgsigqueueinfo:
            call_name = "rt_tgsigqueueinfo";
            break;
        case SYS_perf_event_open:
            call_name = "perf_event_open";
            break;
        case SYS_recvmmsg:
            call_name = "recvmmsg";
            break;
        case SYS_fanotify_init:
            call_name = "fanotify_init";
            break;
        case SYS_fanotify_mark:
            call_name = "fanotify_mark";
            break;
        case SYS_prlimit64:
            call_name = "prlimit64";
            break;
        case SYS_name_to_handle_at:
            call_name = "name_to_handle_at";
            break;
        case SYS_open_by_handle_at:
            call_name = "open_by_handle_at";
            break;
        case SYS_clock_adjtime:
            call_name = "clock_adjtime";
            break;
        case SYS_syncfs:
            call_name = "syncfs";
            break;
        case SYS_sendmmsg:
            call_name = "sendmmsg";
            break;
        case SYS_setns:
            call_name = "setns";
            break;
        case SYS_getcpu:
            call_name = "getcpu";
            break;
        case SYS_process_vm_readv:
            call_name = "process_vm_readv";
            break;
        case SYS_process_vm_writev:
            call_name = "process_vm_writev";
            break;
        case SYS_kcmp:
            call_name = "kcmp";
            break;
        case SYS_finit_module:
            call_name = "finit_module";
            break;
        case SYS_sched_setattr:
            call_name = "sched_setattr";
            break;
        case SYS_sched_getattr:
            call_name = "sched_getattr";
            break;
        case SYS_renameat2:
            call_name = "renameat2";
            break;
        case SYS_seccomp:
            call_name = "seccomp";
            break;
        case SYS_getrandom:
            call_name = "getrandom";
            break;
        case SYS_memfd_create:
            call_name = "memfd_create";
            break;
        case SYS_kexec_file_load:
            call_name = "kexec_file_load";
            break;
        case SYS_bpf:
            call_name = "bpf";
            break;
        case SYS_execveat:
            call_name = "execveat";
            break;
        case SYS_userfaultfd:
            call_name = "userfaultfd";
            break;
        case SYS_membarrier:
            call_name = "membarrier";
            break;
        case SYS_mlock2:
            call_name = "mlock2";
            break;
        case SYS_copy_file_range:
            call_name = "copy_file_range";
            break;
        case SYS_preadv2:
            call_name = "preadv2";
            break;
        case SYS_pwritev2:
            call_name = "pwritev2";
            break;
        case SYS_pkey_mprotect:
            call_name = "pkey_mprotect";
            break;
        case SYS_pkey_alloc:
            call_name = "pkey_alloc";
            break;
        case SYS_pkey_free:
            call_name = "pkey_free";
            break;
        case SYS_statx:
            call_name = "statx";
            break;
        case SYS_io_pgetevents:
            call_name = "io_pgetevents";
            break;
        case SYS_rseq:
            call_name = "rseq";
            break;
        case SYS_pidfd_send_signal:
            call_name = "pidfd_send_signal";
            break;
        case SYS_io_uring_setup:
            call_name = "io_uring_setup";
            break;
        case SYS_io_uring_enter:
            call_name = "io_uring_enter";
            break;
        case SYS_io_uring_register:
            call_name = "io_uring_register";
            break;
        case SYS_open_tree:
            call_name = "open_tree";
            break;
        case SYS_move_mount:
            call_name = "move_mount";
            break;
        case SYS_fsopen:
            call_name = "fsopen";
            break;
        case SYS_fsconfig:
            call_name = "fsconfig";
            break;
        case SYS_fsmount:
            call_name = "fsmount";
            break;
        case SYS_fspick:
            call_name = "fspick";
            break;
        case SYS_pidfd_open:
            call_name = "pidfd_open";
            break;
        case SYS_clone3:
            call_name = "clone3";
            break;
        case SYS_close_range:
            call_name = "close_range";
            break;
        case SYS_openat2:
            call_name = "openat2";
            break;
        case SYS_pidfd_getfd:
            call_name = "pidfd_getfd";
            break;
        case SYS_faccessat2:
            call_name = "faccessat2";
            break;
        case SYS_process_madvise:
            call_name = "process_madvise";
            break;
        default:
            call_name = "Unknown";
            break;
    }
    return call_name;
}

static int syscall_args_count(int syscall) {
    switch (syscall) {
        case SYS_nanosleep:
            return 2;
        case SYS_clock_nanosleep:
            return 4;
        case SYS_getpid:
            return 0;
        case SYS_write:
            return 3;
        case SYS_ptrace:
            return 4;
        case SYS_brk:
            return 1;
        case SYS_newfstatat:
            return 4;
        case SYS_exit_group:
            return 1;
        case SYS_close:
            return 1;
        case SYS_alarm:
            return 1;
        case SYS_fcntl:
            return 3;
        case SYS_dup:
            return 1;
        case SYS_kill:
            return 2;
        default:
            return 1;
    }
}

static int syscall_args2array(struct user_regs_struct *regs, arg_t *argarr, int args) {
    switch (args) {
        case 6: argarr[5] = regs->r9;
        case 5: argarr[4] = regs->r8;
        case 4: argarr[3] = regs->r10;
        case 3: argarr[2] = regs->rdx;
        case 2: argarr[1] = regs->rsi;
        case 1: argarr[0] = regs->rdi;
        default: return -1;
    }
    return args;
}

static int syscall_array2args(struct user_regs_struct *regs, arg_t *argarr, int args) {
    switch (args) {
        case 6: regs->r9 = argarr[5];
        case 5: regs->r8 = argarr[4];
        case 4: regs->r10 = argarr[3];
        case 3: regs->rdx = argarr[2];
        case 2: regs->rsi = argarr[1];
        case 1: regs->rdi = argarr[0];
        default: return -1;
    }
    return args;
}

static void print_buf(void *buf, size_t len) {
    for (int i = 0; i < len;) {
        for (int j = 0; j < 16 && i < len; j++, i++) {
            printf("%2x ", ((unsigned char *) buf)[i]);
        }
        printf("\n");
    }
    printf("\n");
}

// #pragma GCC diagnostic pop
#endif
