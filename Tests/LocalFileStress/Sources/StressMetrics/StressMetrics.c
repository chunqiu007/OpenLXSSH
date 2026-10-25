#include "StressMetrics.h"
#include <libproc.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

stress_metrics stress_sample(const char *owned_root) {
    stress_metrics result = {0};
    struct mach_task_basic_info task = {0};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    result.rss_status = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                                 (task_info_t)&task, &count);
    if (result.rss_status == KERN_SUCCESS) result.resident_bytes = task.resident_size;
    struct rusage usage = {0};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        // Darwin ru_maxrss is bytes, not the KiB used by Linux.
        result.peak_resident_bytes = (uint64_t)usage.ru_maxrss;
        result.user_cpu_seconds = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6;
        result.system_cpu_seconds = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
    }
    struct proc_fdinfo fds[4096];
    int required = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    result.fd_count = result.owned_fd_count = -1;
    if (required <= 0 || required > (int)sizeof(fds)) return result;
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    if (bytes <= 0) return result;
    result.fd_count = bytes / (int)sizeof(struct proc_fdinfo);
    result.owned_fd_count = 0;
    // Foundation may retain /var while proc vnode paths use /private/var.
    // The final sample can run after removal, so callers also pass the canonical root.
    char canonical_root[PROC_PIDPATHINFO_MAXSIZE];
    const char *root = realpath(owned_root, canonical_root) ? canonical_root : owned_root;
    size_t root_length = strlen(root);
    for (int i = 0; i < result.fd_count; i++) {
        if (fds[i].proc_fdtype != PROX_FDTYPE_VNODE) continue;
        struct vnode_fdinfowithpath info = {0};
        int read = proc_pidfdinfo(getpid(), fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO,
                                 &info, sizeof(info));
        if (read != sizeof(info)) { result.owned_fd_count = -1; break; }
        char canonical_path[PROC_PIDPATHINFO_MAXSIZE];
        const char *path = realpath(info.pvip.vip_path, canonical_path) ? canonical_path : info.pvip.vip_path;
        if (strncmp(path, root, root_length) == 0 &&
            (path[root_length] == '/' || path[root_length] == '\0')) result.owned_fd_count++;
    }
    return result;
}
