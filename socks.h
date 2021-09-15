#ifndef SOCKS_H_
#define SOCKS_H_

#include <arpa/inet.h>

#include "helper.h"

static int socks4_connect(int fd, int addr, int port) {
    char buf[128];
    char *p = buf;
    int n;

    printf("[socks4 init]: %s:%d\n", inet_ntoa(*(struct in_addr *) &addr), port);
    *p++ = 4;  // socks4
    *p++ = 1;  // connect
    *((short *)p) = htons(port);
    p += 2;
    *((int *)p) = addr;
    p += 4;
    *p++ = 0;

    //write(fd, buf, p - buf);
    for (int n = 0, m; n < p - buf; n += m) {
        m = write(fd, buf + n, p - buf - n);
        if (m < 0 && m != EINTR)
            return -1;
    }
    n = read(fd, buf, sizeof(buf));
    if (n < 8)
        return -1;
    switch (buf[1]) {
        case 90:
            return 0;
        default:
            return -1;
    }
}

#endif
