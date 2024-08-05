#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define err(msg) do { perror((msg)); exit(-1); } while (0)
#define erre(exp) do { if (!(exp)) err(#exp); } while (0)
#define erre_sys(exp) erre((exp) >= 0)

int main(int argc, const char *argv[])
{
    int fd;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8000),
    };
    inet_aton("127.0.0.1", &addr.sin_addr);
    char *msg = "GET /\n\n";

    erre_sys((fd = socket(AF_INET, SOCK_STREAM, 0)));
    erre_sys(connect(fd, (struct sockaddr*) &addr, sizeof(addr)));
    erre_sys(write(fd, msg, strlen(msg)));
    erre_sys(close(fd));

    erre_sys(fd = socket(AF_INET, SOCK_DGRAM, 0));
    erre_sys(connect(fd, (struct sockaddr *) &addr, sizeof(addr)));
    erre_sys(write(fd, msg, strlen(msg)));
    erre_sys(close(fd));

    return 0;
}
