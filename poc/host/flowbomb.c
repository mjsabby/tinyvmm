// flowbomb: open many flows at once from a guest and hold them.
//   flowbomb udp <ip> <port> <n> <hold-seconds>   n sockets, one datagram each
//   flowbomb tcp <ip> <port> <n> <hold-seconds>   n connections, kept open
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: flowbomb udp|tcp <ip> <port> <n> <hold-seconds>\n");
        return 2;
    }
    int tcp = strcmp(argv[1], "tcp") == 0;
    int n = atoi(argv[4]), hold = atoi(argv[5]);
    struct rlimit rl = {n + 256, n + 256};
    setrlimit(RLIMIT_NOFILE, &rl);
    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[3]))};
    inet_pton(AF_INET, argv[2], &dst.sin_addr);
    int *fds = calloc(n, sizeof(int));
    int opened = 0, sent = 0, connected = 0, failed = 0;
    for (int i = 0; i < n; i++) {
        int fd = socket(AF_INET, (tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK, 0);
        if (fd < 0) break;
        fds[opened++] = fd;
        if (tcp) {
            if (connect(fd, (struct sockaddr *)&dst, sizeof dst) < 0 && errno != EINPROGRESS) failed++;
        } else if (connect(fd, (struct sockaddr *)&dst, sizeof dst) == 0 && send(fd, "x", 1, 0) == 1) {
            sent++;
        }
        // A little air every so often, so the guest's own queues keep up.
        if (tcp ? (i & 63) == 63 : (i & 255) == 255) usleep(tcp ? 30000 : 2000);
    }
    if (tcp) {
        // Give every connection up to 30 s to be answered one way or the other.
        time_t until = time(NULL) + 30;
        char *done = calloc(opened, 1);
        int pending = opened - failed;
        while (pending > 0 && time(NULL) < until) {
            pending = 0;
            for (int i = 0; i < opened; i++) {
                if (done[i]) continue;
                struct pollfd p = {fds[i], POLLOUT, 0};
                if (poll(&p, 1, 0) > 0) {
                    int err = 0;
                    socklen_t len = sizeof err;
                    getsockopt(fds[i], SOL_SOCKET, SO_ERROR, &err, &len);
                    done[i] = 1;
                    if (err == 0 && !(p.revents & (POLLERR | POLLHUP))) connected++; else failed++;
                } else {
                    pending++;
                }
            }
            usleep(200000);
        }
        printf("tcp opened=%d connected=%d failed=%d unanswered=%d\n", opened, connected, failed, pending);
    } else {
        printf("udp opened=%d sent=%d\n", opened, sent);
    }
    fflush(stdout);
    sleep(hold);
    return 0;
}
