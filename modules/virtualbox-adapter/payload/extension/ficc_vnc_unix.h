/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (C) 2026 Federated Industrial Laboratories. */
/* Add an owned Unix listener to the free VirtualBox VNC extension. */
#ifndef FICC_VNC_UNIX_H
#define FICC_VNC_UNIX_H
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct FiccVncSocket {
    char path[sizeof(sockaddr_un::sun_path)] = {};
    dev_t device = 0;
    ino_t inode = 0;

    void clear() {
        struct stat info;
        if (path[0] && lstat(path, &info) == 0 && S_ISSOCK(info.st_mode) &&
            info.st_uid == getuid() && info.st_dev == device && info.st_ino == inode) unlink(path);
        path[0] = 0;
    }

    bool listen(rfbScreenInfoPtr screen, const char *selected) {
        if (!selected || selected[0] != '/' || strlen(selected) >= sizeof(path)) return false;
        char parent[PATH_MAX], resolved[PATH_MAX];
        strcpy(parent, selected);
        char *leaf = strrchr(parent, '/');
        if (!leaf || !leaf[1] || !strcmp(leaf + 1, ".") || !strcmp(leaf + 1, "..")) return false;
        *leaf = 0;
        struct stat info;
        if (!realpath(parent, resolved) || strcmp(parent, resolved) || lstat(parent, &info) ||
            !S_ISDIR(info.st_mode) || info.st_uid != getuid() || (info.st_mode & 077)) return false;
        sockaddr_un address = {};
        address.sun_family = AF_UNIX;
        strcpy(address.sun_path, selected);
        if (lstat(selected, &info) == 0) {
            if (!S_ISSOCK(info.st_mode) || info.st_uid != getuid() || (info.st_mode & 077)) return false;
            int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
            if (probe < 0) return false;
            int result = connect(probe, reinterpret_cast<sockaddr *>(&address), sizeof(address));
            int error = errno;
            close(probe);
            struct stat current;
            if (result == 0 || error != ECONNREFUSED || lstat(selected, &current) ||
                current.st_dev != info.st_dev || current.st_ino != info.st_ino || unlink(selected)) return false;
        } else if (errno != ENOENT) return false;
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return false;
        if (fd >= FD_SETSIZE || bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address))) { close(fd); return false; }
        if (lstat(selected, &info)) { close(fd); return false; }
        strcpy(path, selected); device = info.st_dev; inode = info.st_ino;
        if (chmod(path, 0600) || ::listen(fd, 8)) { close(fd); clear(); return false; }
        /* Initialise RFB without an IPv4, IPv6, HTTP or UDP listener. */
        screen->port = 0; screen->ipv6port = 0; screen->autoPort = FALSE;
        screen->httpPort = 0; screen->http6Port = 0; screen->udpPort = 0;
        rfbInitServer(screen);
        screen->listenSock = fd;
        FD_SET(fd, &screen->allFds);
        screen->maxFd = fd;
        return true;
    }
};
#endif
