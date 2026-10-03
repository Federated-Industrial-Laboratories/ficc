// SPDX-License-Identifier: Apache-2.0
// Wait for the local supervisor before the selected container command starts.
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "--") || argv[2][0] != '/') return 125;
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
    for (;;) {
        int fd = open("/ficc/control/release", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            struct stat info;
            char value[8] = {0};
            int okay = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                       info.st_nlink == 1 && read(fd, value, sizeof(value)) == 8 &&
                       !memcmp(value, "release\n", 8);
            close(fd);
            if (!okay) return 125;
            execv(argv[2], argv + 2);
            return 126;
        }
        if (errno != ENOENT) return 125;
        nanosleep(&delay, 0);
    }
}
