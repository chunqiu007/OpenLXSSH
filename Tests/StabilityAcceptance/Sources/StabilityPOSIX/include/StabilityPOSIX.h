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
int stability_process_read(pid_t pid, stability_process *out);
int stability_direct_helpers(pid_t known_ssh, const char *exact_helper,
                             stability_process *out, int capacity);
int stability_fd_no_acl(int fd);
// kind: 0 public read, 1 private directory, 2 private-file metadata only (O_EVTONLY).
int stability_open_private(const char *path, int kind);
int stability_create_private_file(const char *path);
double stability_monotonic_seconds(void); // CLOCK_UPTIME_RAW, excludes sleep on Darwin.
double stability_continuous_seconds(void); // mach_continuous_time, includes sleep.
#endif
