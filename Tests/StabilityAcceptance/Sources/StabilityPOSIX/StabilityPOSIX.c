#include "StabilityPOSIX.h"
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int stability_fd_no_acl(int fd) {
    filesec_t security = filesec_init();
    if (!security) return -1;
    struct stat info;
    int mode_present = 0, acl_present = 0;
    int result = fstatx_np(fd, &info, security) ||
        filesec_query_property(security, FILESEC_MODE, &mode_present) || !mode_present ||
        filesec_query_property(security, FILESEC_ACL, &acl_present) || acl_present;
    filesec_free(security);
    return result ? -1 : 0; // Distinguishes an absent ACL from an ACL-query error.
}

static int metadata(int fd, int directory) {
    struct stat info;
    if (fstat(fd, &info) || info.st_uid != getuid() ||
        (info.st_mode & 07777) != (directory ? 0700 : 0600) ||
        (directory ? !S_ISDIR(info.st_mode) : (!S_ISREG(info.st_mode) || info.st_nlink != 1)) ||
        stability_fd_no_acl(fd)) return -1;
    return 0;
}

// Traverse from / using openat(O_NOFOLLOW): no parent-component symlink is followed.
// Ancestors may be system/shared directories; the exact material parent is private.
int stability_open_private(const char *path, int directory) {
    if (!path || path[0] != '/' || path[1] == '\0' || strlen(path) >= 4096) { errno = EINVAL; return -1; }
    char *copy = strdup(path + 1);
    if (!copy) return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC), next = -1;
    char *part = copy;
    while (fd >= 0 && part) {
        char *slash = strchr(part, '/');
        if (slash) *slash = '\0';
        if (!*part || !strcmp(part, ".") || !strcmp(part, "..")) { errno = EINVAL; break; }
        int last = slash == NULL;
        if (last && directory != 1 && metadata(fd, 1)) { errno = EACCES; break; }
        int flags = O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK |
            ((last && directory == 2) ? O_EVTONLY : O_RDONLY) |
            ((!last || directory == 1) ? O_DIRECTORY : 0);
        next = openat(fd, part, flags);
        if (next < 0) break;
        close(fd); fd = next; next = -1;
        if (last) {
            free(copy);
            if (metadata(fd, directory == 1)) { close(fd); errno = EACCES; return -1; }
            return fd;
        }
        part = slash + 1;
    }
    if (fd >= 0) close(fd);
    free(copy);
    return -1;
}

int stability_create_private_file(const char *path) {
    char *copy = strdup(path ? path : "");
    if (!copy) return -1;
    char *slash = strrchr(copy, '/');
    if (!slash || !slash[1]) { free(copy); errno = EINVAL; return -1; }
    *slash = '\0';
    int parent = stability_open_private(copy, 1);
    int fd = parent < 0 ? -1 : openat(parent, slash + 1, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0 && metadata(fd, 0)) {
        close(fd); fd = -1;
        // Remove only the single entry we just exclusively created, never recurse.
        unlinkat(parent, slash + 1, 0);
        errno = EACCES;
    }
    if (parent >= 0) close(parent);
    free(copy);
    return fd;
}

static int kernel_identity_query(pid_t pid, struct proc_bsdinfo *out, void *context) {
    (void)context;
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, out, sizeof(*out));
}

static int identity_snapshot(pid_t pid, struct proc_bsdinfo *out,
                             stability_identity_query query, void *context) {
    errno = 0;
    int bytes = query(pid, out, context), query_error = errno;
    // No other error (including EACCES) or short/partial read proves absence.
    if (bytes == 0 && query_error == ESRCH) return STABILITY_IDENTITY_GONE;
    if (bytes != sizeof(*out) || query_error != 0 || out->pbi_pid != (uint32_t)pid ||
        out->pbi_start_tvsec == 0 || out->pbi_start_tvusec >= 1000000) return STABILITY_IDENTITY_UNKNOWN;
    return STABILITY_IDENTITY_PRESENT;
}

int stability_identity_read_using(pid_t pid, stability_process *out,
                                  stability_identity_query query, void *context) {
    if (!out || pid <= 0 || !query) return STABILITY_IDENTITY_UNKNOWN;
    *out = (stability_process){0};
    struct proc_bsdinfo before = {0}, after = {0};
    int first = identity_snapshot(pid, &before, query, context);
    if (first != STABILITY_IDENTITY_PRESENT) return first;
    int second = identity_snapshot(pid, &after, query, context);
    // A process changing/disappearing during the query is unknown, not an empty
    // cleanup result. A later complete query may independently confirm gone.
    if (second != STABILITY_IDENTITY_PRESENT ||
        before.pbi_pid != after.pbi_pid || before.pbi_ppid != after.pbi_ppid ||
        before.pbi_uid != after.pbi_uid || before.pbi_ruid != after.pbi_ruid ||
        before.pbi_start_tvsec != after.pbi_start_tvsec ||
        before.pbi_start_tvusec != after.pbi_start_tvusec) return STABILITY_IDENTITY_UNKNOWN;
    *out = (stability_process){.pid = pid, .ppid = (int32_t)after.pbi_ppid, .uid = after.pbi_uid,
        .start_seconds = after.pbi_start_tvsec, .start_microseconds = after.pbi_start_tvusec,
        .fd_count = -1, .pty_fd_count = -1, .thread_count = -1, .metrics_complete = 0};
    // Zombies/in-exit still have a lifetime identity; they are never reported as
    // confirmed gone merely because they cannot supply live resource metrics.
    return STABILITY_IDENTITY_PRESENT;
}

int stability_identity_read(pid_t pid, stability_process *out) {
    return stability_identity_read_using(pid, out, kernel_identity_query, NULL);
}

int stability_process_read(pid_t pid, stability_process *out) {
    if (stability_identity_read(pid, out) != STABILITY_IDENTITY_PRESENT || out->uid != getuid()) return -1;
    out->metrics_complete = 1;
    struct proc_taskinfo task = {0};
    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task, sizeof(task)) == sizeof(task)) {
        out->rss_bytes = task.pti_resident_size; out->thread_count = task.pti_threadnum;
    } else out->metrics_complete = 0;
    struct proc_fdinfo fds[4096];
    int required = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (required <= 0 || required > (int)sizeof(fds)) out->metrics_complete = 0;
    else {
        int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));
        // The size-only query includes kernel spare capacity, not an exact FD
        // count. Only the actual complete records returned by the read are FDs.
        if (bytes <= 0 || bytes >= (int)sizeof(fds) || bytes % sizeof(struct proc_fdinfo)) out->metrics_complete = 0;
        else {
            out->fd_count = bytes / (int)sizeof(struct proc_fdinfo); out->pty_fd_count = 0;
            for (int i = 0; i < out->fd_count; ++i) {
                if (fds[i].proc_fdtype != PROX_FDTYPE_VNODE) continue;
                struct vnode_fdinfowithpath vnode = {0};
                if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO, &vnode, sizeof(vnode)) != sizeof(vnode)) {
                    out->metrics_complete = 0; out->pty_fd_count = -1; break;
                }
                const char *p = vnode.pvip.vip_path;
                if (!strncmp(p, "/dev/ttys", 9) || !strncmp(p, "/dev/pty", 8) || !strcmp(p, "/dev/ptmx")) out->pty_fd_count++;
            }
        }
    }
    stability_process after = {0};
    if (stability_identity_read(pid, &after) != STABILITY_IDENTITY_PRESENT ||
        out->pid != after.pid || out->ppid != after.ppid || out->uid != after.uid ||
        out->start_seconds != after.start_seconds || out->start_microseconds != after.start_microseconds) return -1;
    return 0;
}

int stability_direct_helpers(pid_t known_ssh, const char *exact_helper, stability_process *out, int capacity) {
    // PROC_PPID_ONLY is not a machine-wide SSH-name scan. Never returns arbitrary descendants.
    pid_t children[64];
    int n = proc_listpids(PROC_PPID_ONLY, (uint32_t)known_ssh, children, sizeof(children));
    if (n < 0 || n >= (int)sizeof(children) || capacity < 1) return -1;
    int count = 0;
    for (int i = 0; i < n / (int)sizeof(pid_t); ++i) {
        char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
        stability_process child;
        if (children[i] <= 0 || proc_pidpath(children[i], path, sizeof(path)) <= 0 || strcmp(path, exact_helper)) continue;
        if (stability_process_read(children[i], &child) || child.ppid != known_ssh) continue;
        if (count >= capacity) return -1;
        out[count++] = child;
    }
    return count;
}

double stability_monotonic_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_UPTIME_RAW, &ts)) return -1;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
double stability_continuous_seconds(void) {
    mach_timebase_info_data_t scale;
    if (mach_timebase_info(&scale)) return -1;
    return (double)mach_continuous_time() * (double)scale.numer / (double)scale.denom / 1e9;
}
