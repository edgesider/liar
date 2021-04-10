# Liar

## 编译运行

```bash
gcc -Wall liar.c -o liar
./liar [prog] [arg] ...
```

## 思路

1. 建立文件描述符发送通道

父进程在fork之前，通过socketpair(AF_UNIX)建立一个unix域套接字，之后通过该套接字进行父子进程间的文件描述符传送。

2. 创建共享文件描述符

使用ptrace来hook子进程的socket调用。
   a. 在wait()到enter-stop时，由父进程创建一个socket（记为fdp），并使用sendmsg发送给子进程；
   b. 接着使用PTRACE_SETREGS把子进程的socket调用替换为recvmsg（一是为了避免只发送不接受造成阻塞，二是为了获取子进程中的文件描述符），然后父进程使用PTRACE_SYSCALL继续子进程；
   c. 使用wait等待这次调用（实际上是被替换来的recvmsg）的exit-stop，这时通过PTRACE_PEEKUSER从recvmsg的buf中获取子进程获得的文件描述符（记为fdc），然后通过PTRACE_SETREGS设置系统调用的返回值为fdc。

至此，父子进程中各有一个文件描述符（fdp和fdc），两者都指向同一个socket。

3. 建立代理

在子进程调用connect之后，父进程查看参数，若需要进行代理，则通过connect中的文件描述符（fdc）查找对应的fdp，然后使用fdp向代理服务器发起连接和代理请求，代理建立完成后，父进程关闭fdp，并将当前的connect调用替换为一个无用的调用，比如sleep(0)，最后继续子进程。


## 问题：

1. 非阻塞IO

如果子进程对描述符使用了O_NONBLOCK，那么在connect时就没法直接通过fdp来建立代理。如果在connect之前将O_NONBLOCK去掉的话，子进程的非阻塞IO就可能明显变慢，尤其是连接非本地代理的时候。

如果要更好地处理非阻塞IO，要么在父进程中使用accept，要么在处理一下epoll、select、poll等调用。用这两种方式可以在父进程中维护文件描述符的就绪状态。
