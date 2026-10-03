// SPDX-License-Identifier: Apache-2.0
/* Exercise bounded workload resources without reading host credentials. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double seconds(clockid_t clock) {
    struct timespec value;
    if (clock_gettime(clock, &value)) exit(90);
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static void nap(long ms) {
    struct timespec value = {ms / 1000, (ms % 1000) * 1000000};
    while (nanosleep(&value, &value) && errno == EINTR) {}
}

static uint64_t number(const char *text, uint64_t low, uint64_t high) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !end || *end || value < low || value > high) exit(91);
    return value;
}

static int devices(int argc, char **argv) {
    printf("{\"mode\":\"devices\",\"opens\":[");
    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "/dev/nvidia", 11)) return 91;
        int fd = open(argv[i], O_RDWR | O_NONBLOCK | O_CLOEXEC);
        int error = fd < 0 ? errno : 0;
        if (fd >= 0) close(fd);
        printf("%s{\"index\":%d,\"errno\":%d}", i > 2 ? "," : "", i - 2, error);
    }
    puts("]}");
    return 0;
}

static int isolation(const char *canary, int argc, char **argv) {
    int fd = open("/ficc-root-write", O_WRONLY | O_CREAT | O_EXCL, 0600);
    int root_error = fd < 0 ? errno : 0;
    if (fd >= 0) { close(fd); unlink("/ficc-root-write"); }
    fd = open(canary, O_RDONLY | O_CLOEXEC);
    int canary_error = fd < 0 ? errno : 0;
    if (fd >= 0) close(fd);
    struct ifaddrs *interfaces = NULL;
    int only_loopback = getifaddrs(&interfaces) == 0;
    for (struct ifaddrs *p = interfaces; p; p = p->ifa_next)
        if (!(p->ifa_flags & IFF_LOOPBACK)) only_loopback = 0;
    freeifaddrs(interfaces);
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int network_error = errno;
    if (fd >= 0) {
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(9)};
        inet_pton(AF_INET, "192.0.2.1", &address.sin_addr);
        int status = connect(fd, (struct sockaddr *)&address, sizeof(address));
        network_error = status < 0 ? errno : 0;
        close(fd);
    }
    int no_gpu = 1;
    for (int i = 4; i < argc; ++i) {
        fd = open(argv[i], O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd >= 0) { no_gpu = 0; close(fd); }
        else if (errno != ENOENT && errno != EPERM && errno != EACCES) no_gpu = 0;
    }
    int clean_env = getenv("FICC_PROBE_HOST_SECRET") == NULL;
    int pid_one = getpid() == 1;
    int okay = root_error == EROFS && canary_error == ENOENT && only_loopback &&
        (network_error == ENETUNREACH || network_error == EPERM || network_error == EACCES) &&
        no_gpu && clean_env && pid_one;
    printf("{\"mode\":\"isolation\",\"root_errno\":%d,\"canary_errno\":%d,"
           "\"only_loopback\":%s,\"network_errno\":%d,\"no_gpu\":%s,"
           "\"clean_environment\":%s,\"pid_one\":%s,\"pass\":%s}\n",
           root_error, canary_error, only_loopback ? "true" : "false", network_error,
           no_gpu ? "true" : "false", clean_env ? "true" : "false",
           pid_one ? "true" : "false", okay ? "true" : "false");
    return okay ? 0 : 1;
}

static int cpu(uint64_t milliseconds) {
    volatile uint64_t work = 1;
    double start = seconds(CLOCK_MONOTONIC), before = seconds(CLOCK_PROCESS_CPUTIME_ID);
    do {
        for (int i = 0; i < 65536; ++i) work = work * 1664525u + 1013904223u;
    } while ((seconds(CLOCK_MONOTONIC) - start) * 1000 < milliseconds);
    double wall = seconds(CLOCK_MONOTONIC) - start;
    double used = seconds(CLOCK_PROCESS_CPUTIME_ID) - before;
    printf("{\"mode\":\"cpu\",\"wall_seconds\":%.6f,\"cpu_seconds\":%.6f,"
           "\"ratio\":%.6f,\"work\":%llu}\n", wall, used, used / wall,
           (unsigned long long)work);
    return 0;
}

static int memory(uint64_t bytes) {
    printf("{\"mode\":\"memory\",\"started\":true,\"requested_bytes\":%llu}\n",
           (unsigned long long)bytes);
    unsigned char *data = malloc(bytes);
    if (!data) { puts("{\"mode\":\"memory\",\"malloc_refused\":true}"); return 2; }
    for (uint64_t i = 0; i < bytes; i += 4096) ((volatile unsigned char *)data)[i] = 37;
    nap(500);
    free(data);
    puts("{\"mode\":\"memory\",\"limit_not_observed\":true}");
    return 1;
}

static int pids(void) {
    int pipefd[2];
    if (pipe(pipefd)) return 2;
    pid_t children[128];
    int count = 0, failure = 0;
    for (; count < 128; ++count) {
        pid_t pid = fork();
        if (pid < 0) { failure = errno; break; }
        if (!pid) {
            close(pipefd[1]);
            char byte;
            while (read(pipefd[0], &byte, 1) < 0 && errno == EINTR) {}
            close(pipefd[0]);
            _exit(0);
        }
        children[count] = pid;
    }
    close(pipefd[0]); close(pipefd[1]);
    for (int i = 0; i < count; ++i) while (waitpid(children[i], NULL, 0) < 0 && errno == EINTR) {}
    printf("{\"mode\":\"pids\",\"children\":%d,\"fork_errno\":%d,\"pass\":%s}\n",
           count, failure, count > 0 && failure == EAGAIN ? "true" : "false");
    return count > 0 && failure == EAGAIN ? 0 : 1;
}

static int disk(uint64_t maximum) {
    struct statvfs before, after_full, after_cleanup;
    if (statvfs("/work", &before)) return 2;
    int fd = open("/work/disk-fill", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return 2;
    static unsigned char block[1024 * 1024];
    memset(block, 0x6d, sizeof(block));
    uint64_t total = 0;
    int error = 0;
    while (total <= maximum) {
        ssize_t written = write(fd, block, sizeof(block));
        if (written < 0) { error = errno; break; }
        total += (uint64_t)written;
        if (!written) break;
    }
    if (fsync(fd) && !error) error = errno;
    close(fd);
    if (statvfs("/work", &after_full)) return 2;
    int removed = unlink("/work/disk-fill") == 0;
    fd = open("/work", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0) { fsync(fd); close(fd); }
    if (statvfs("/work", &after_cleanup)) return 2;
    int okay = (error == ENOSPC || error == EDQUOT) && removed && total <= maximum &&
        after_cleanup.f_bavail > after_full.f_bavail;
    printf("{\"mode\":\"disk\",\"written_bytes\":%llu,\"write_errno\":%d,"
           "\"before_available\":%llu,\"full_available\":%llu,\"cleanup_available\":%llu,\"pass\":%s}\n",
           (unsigned long long)total, error,
           (unsigned long long)before.f_bavail * before.f_frsize,
           (unsigned long long)after_full.f_bavail * after_full.f_frsize,
           (unsigned long long)after_cleanup.f_bavail * after_cleanup.f_frsize,
           okay ? "true" : "false");
    return okay ? 0 : 1;
}

static int compute(uint64_t count, uint64_t seed) {
    if (count != 1 && count != 64) return 91;
    FILE *output = fopen("/work/result.json", "wx");
    if (!output) return 2;
    fputs("[", output);
    for (uint64_t index = 0; index < count; ++index) {
        uint64_t value = seed + index;
        fprintf(output, "%s{\"index\":%llu,\"input\":%llu,\"value\":%llu}",
                index ? "," : "", (unsigned long long)index, (unsigned long long)value,
                (unsigned long long)(value * value + 3 * value + 7));
    }
    fputs("]\n", output);
    int result = fflush(output) || fsync(fileno(output));
    fclose(output);
    printf("{\"mode\":\"compute\",\"count\":%llu,\"seed\":%llu,\"pass\":%s}\n",
           (unsigned long long)count, (unsigned long long)seed, result ? "false" : "true");
    return result ? 2 : 0;
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    if (argc >= 2 && !strcmp(argv[1], "devices")) return devices(argc, argv);
    if (argc < 3) return 91;
    uint64_t value = number(argv[2], 1, 3ULL * 1024 * 1024 * 1024);
    if (!strcmp(argv[1], "compute") && argc == 4) return compute(value, number(argv[3], 1, 1000000));
    if (!strcmp(argv[1], "wait")) { for (;;) nap(100); }
    if (!strcmp(argv[1], "crash")) {
        struct rlimit limit;
        if (getrlimit(RLIMIT_CORE, &limit)) return 2;
        printf("{\"mode\":\"crash\",\"core_soft\":%llu,\"core_hard\":%llu}\n",
               (unsigned long long)limit.rlim_cur, (unsigned long long)limit.rlim_max);
        if (limit.rlim_cur || limit.rlim_max) return 3;
        raise(SIGSEGV);
        return 4;
    }
    if (!strcmp(argv[1], "cpu")) return value <= 10000 ? cpu(value) : 91;
    if (!strcmp(argv[1], "memory")) return memory(value);
    if (!strcmp(argv[1], "pids")) return pids();
    if (!strcmp(argv[1], "disk")) return disk(value);
    if (!strcmp(argv[1], "isolation") && argc >= 4) return isolation(argv[3], argc, argv);
    return 91;
}
