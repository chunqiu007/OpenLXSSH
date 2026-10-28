#ifndef STABILITY_POSIX_H
#define STABILITY_POSIX_H
#include <stdint.h>
#include <sys/types.h>
#include <libproc.h>

typedef struct {
    int32_t pid, ppid;
    uint32_t uid;
    uint64_t start_seconds, start_microseconds;
    uint64_t rss_bytes;
    int32_t fd_count, pty_fd_count, thread_count;
    int32_t metrics_complete;
    int32_t fd_list_resamples;
} stability_process;

// Only the explicit PID is queried. Child discovery is limited to one known SSH parent.
// Identity result: PRESENT = two consistent complete identity reads; GONE =
// explicit zero-byte/ESRCH observation; UNKNOWN = access/error/partial/unstable.
enum { STABILITY_IDENTITY_UNKNOWN = -1, STABILITY_IDENTITY_PRESENT = 0, STABILITY_IDENTITY_GONE = 1 };
typedef int (*stability_identity_query)(pid_t pid, struct proc_bsdinfo *out, void *context);
// Offline injection seam; query returns bytes and errno with proc_pidinfo semantics.
int stability_identity_read_using(pid_t pid, stability_process *out,
                                  stability_identity_query query, void *context);
int stability_identity_read(pid_t pid, stability_process *out);
typedef int (*stability_process_query)(pid_t pid, int flavor, uint64_t arg,
                                       void *out, int size, void *context);
typedef int (*stability_vnode_query)(pid_t pid, int fd,
                                     struct vnode_fdinfowithpath *out, void *context);
// Offline injection seam for the same resource sampler used by the signed driver.
int stability_process_read_using(pid_t pid, stability_process *out,
                                 stability_identity_query identity_query,
                                 stability_process_query process_query,
                                 stability_vnode_query vnode_query, void *context);
int stability_process_read(pid_t pid, stability_process *out);
typedef int (*stability_metric_query)(pid_t pid, stability_process *out, void *context);
// Used only after discovery matched the exact helper path. Sampling failure is
// not absence: only a separate strict initial-ESRCH identity read proves GONE.
int stability_helper_read_using(pid_t pid, pid_t expected_parent, stability_process *out,
                                stability_metric_query metric_query,
                                stability_identity_query identity_query, void *context);
int stability_direct_helpers(pid_t known_ssh, const char *exact_helper,
                             stability_process *out, int capacity, int *confirmed_gone);
int stability_fd_no_acl(int fd);
// kind: 0 public read, 1 private directory, 2 private-file metadata only (O_EVTONLY).
int stability_open_private(const char *path, int kind);
int stability_create_private_file(const char *path);
double stability_monotonic_seconds(void); // CLOCK_UPTIME_RAW, excludes sleep on Darwin.
double stability_continuous_seconds(void); // mach_continuous_time, includes sleep.
#endif
