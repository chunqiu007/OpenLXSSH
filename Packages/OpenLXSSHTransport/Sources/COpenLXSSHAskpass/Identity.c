// Migrated from reviewed P1-04C. No spawn/reap/PTY ownership here.
#include "COpenLXSSHAskpass.h"
#include <Security/Security.h>
#include <libproc.h>
#include <sys/proc.h>
#include <errno.h>
#include <unistd.h>
int ap_identity_read(pid_t pid, ap_identity *out) {
    struct proc_bsdinfo info = {0};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return ESRCH;
    if (info.pbi_status == SZOMB || (info.pbi_flags & PROC_FLAG_INEXIT)) return ESRCH;
    *out = (ap_identity){(int32_t)info.pbi_pid, (int32_t)info.pbi_ppid,
        info.pbi_uid, info.pbi_ruid, info.pbi_start_tvsec, info.pbi_start_tvusec};
    return 0;
}
int ap_identity_equal(const ap_identity *a, const ap_identity *b) {
    return a->pid == b->pid && a->ppid == b->ppid && a->uid == b->uid && a->ruid == b->ruid &&
        a->seconds == b->seconds && a->microseconds == b->microseconds;
}

int ap_random(void *bytes, size_t size) {
    return SecRandomCopyBytes(kSecRandomDefault, size, bytes) ? EIO : 0;
}
int ap_fd_count(void) { return proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0) / (int)sizeof(struct proc_fdinfo); }
int ap_process_has_ctty(pid_t pid) {
    struct proc_bsdinfo info = {0};
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == sizeof(info) &&
        (info.pbi_flags & PROC_FLAG_CTTY) && info.e_tdev != (uint32_t)-1;
}
