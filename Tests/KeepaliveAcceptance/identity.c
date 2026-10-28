#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Test-only readonly PID birth metadata. No argv/environment/secret/socket access. */
int main(int argc, char **argv) {
    if (argc != 2 || !argv[1][0]) return 64;
    for (const char *p = argv[1]; *p; ++p) if (*p < '0' || *p > '9') return 64;
    errno = 0;
    char *end = NULL;
    long value = strtol(argv[1], &end, 10);
    if (errno || !end || *end || value <= 1 || value > INT_MAX) return 64;
    struct proc_bsdinfo info;
    memset(&info, 0, sizeof(info));
    if (proc_pidinfo((pid_t)value, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return 1;
    if (info.pbi_pid != value || info.pbi_uid != getuid() || info.pbi_status == SZOMB || (info.pbi_flags & PROC_FLAG_INEXIT)) return 1;
    printf("{\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"startSeconds\":%llu,\"startMicroseconds\":%llu}\n",
           info.pbi_pid, info.pbi_ppid, info.pbi_uid,
           (unsigned long long)info.pbi_start_tvsec, (unsigned long long)info.pbi_start_tvusec);
    return 0;
}
