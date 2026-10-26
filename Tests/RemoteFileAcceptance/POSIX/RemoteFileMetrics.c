#include "RemoteFileMetrics.h"
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int32_t remote_file_fixture_sockets(void) {
    struct proc_fdinfo descriptors[4096];
    int needed = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (needed <= 0 || needed > (int)sizeof(descriptors)) return -1;
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, descriptors, sizeof(descriptors));
    if (bytes <= 0 || bytes % sizeof(descriptors[0])) return -1;
    int total = 0;
    for (int i = 0; i < bytes / (int)sizeof(descriptors[0]); ++i) {
        if (descriptors[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        struct socket_fdinfo info = {0};
        if (proc_pidfdinfo(getpid(), descriptors[i].proc_fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info)) != sizeof(info)) return -1;
        if (info.psi.soi_family != AF_INET || info.psi.soi_kind != SOCKINFO_TCP) continue;
        const struct in_sockinfo *inet = &info.psi.soi_proto.pri_tcp.tcpsi_ini;
        if (ntohs((uint16_t)inet->insi_fport) == 22221 &&
            ntohl(inet->insi_faddr.ina_46.i46a_addr4.s_addr) == INADDR_LOOPBACK) ++total;
    }
    return total;
}
int32_t remote_file_allocated(int fd, uint64_t *bytes) {
    struct stat info;
    if (!bytes || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_nlink != 1) return -1;
    *bytes = (uint64_t)info.st_blocks * 512;
    return 0;
}
int32_t remote_file_identity(int fd, uint64_t *device, uint64_t *inode) {
    struct stat info;
    if (!device || !inode || fstat(fd, &info)) return -1;
    *device = (uint64_t)info.st_dev; *inode = (uint64_t)info.st_ino;
    return 0;
}
