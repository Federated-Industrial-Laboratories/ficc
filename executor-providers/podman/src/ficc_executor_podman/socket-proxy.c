/* SPDX-License-Identifier: Apache-2.0 */
/* Fixed loopback connector inside the same isolated network namespace as the engine. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int copy(int from, int to) {
    char data[16384];
    ssize_t n = read(from, data, sizeof data);
    if (n <= 0) return -1;
    for (ssize_t offset = 0; offset < n;) {
        ssize_t wrote = send(to, data + offset, (size_t)(n - offset), MSG_NOSIGNAL);
        if (wrote <= 0) return -1;
        offset += wrote;
    }
    return 0;
}
static void forward(int client, int port) {
    int peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (peer < 0 || connect(peer, (struct sockaddr *)&address, sizeof address)) _exit(1);
    struct timeval timeout = {.tv_sec = 600};
    setsockopt(peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    struct pollfd fds[2] = {{.fd = client, .events = POLLIN}, {.fd = peer, .events = POLLIN}};
    while (poll(fds, 2, 600000) > 0) {
        if ((fds[0].revents & POLLIN) && copy(client, peer)) break;
        if ((fds[1].revents & POLLIN) && copy(peer, client)) break;
        if ((fds[0].revents | fds[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) break;
    }
    close(peer); close(client); _exit(0);
}
int main(int argc, char **argv) {
    if (argc < 6 || strcmp(argv[1], "/work/inference.sock") || strcmp(argv[3], "--")) return 2;
    char *end; long port = strtol(argv[2], &end, 10);
    if (*end || port < 1024 || port > 65535) return 2;
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, argv[1]);
    umask(0077);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof address) || listen(listener, 34)) return 3;
    pid_t engine = fork();
    if (engine < 0) return 4;
    if (!engine) { close(listener); execv(argv[4], argv + 4); _exit(127); }
    unsigned active = 0;
    for (;;) {
        int status; pid_t child;
        while ((child = waitpid(-1, &status, WNOHANG)) > 0) {
            if (child == engine) { unlink(argv[1]); return WIFEXITED(status) ? WEXITSTATUS(status) : 1; }
            if (active) active--;
        }
        struct pollfd selected = {.fd = listener, .events = POLLIN};
        if (poll(&selected, 1, 100) <= 0) continue;
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) continue;
        if (active >= 34) { close(client); continue; }
        child = fork();
        if (!child) { close(listener); forward(client, (int)port); }
        if (child > 0) active++;
        close(client);
    }
}
