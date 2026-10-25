// Short-lived system-tool owner, NOT a PTY owner. Child stays unreaped until
// cancellation/timeout signals finish, so a reused PID can never be signalled.
#include "COpenLXSSHAskpass.h"
#include <spawn.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
struct ap_cancel { atomic_bool cancelled; };
ap_cancel *ap_cancel_create(void) {
    ap_cancel *value = calloc(1, sizeof(ap_cancel));
    if (value) atomic_init(&value->cancelled, 0);
    return value;
}
void ap_cancel_set(ap_cancel *c) { atomic_store(&c->cancelled, 1); }
void ap_cancel_free(ap_cancel *c) { free(c); }
static double monotonic(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}
int ap_tool(const char *path, char *const args[], char *const env[], ap_cancel *cancel,
            double seconds, int include_stderr, void *output, size_t capacity, size_t *count, int *status) {
    *count = 0; *status = -1;
    if (atomic_load(&cancel->cancelled)) return ECANCELED;
    int fds[2]; if (pipe(fds)) return errno;
    if (fcntl(fds[0], F_SETFD, FD_CLOEXEC) || fcntl(fds[1], F_SETFD, FD_CLOEXEC) ||
        fcntl(fds[0], F_SETFL, O_NONBLOCK)) {
        int error = errno; close(fds[0]); close(fds[1]); return error;
    }
    posix_spawn_file_actions_t a; posix_spawnattr_t attr;
    int error = posix_spawn_file_actions_init(&a);
    if (error) { close(fds[0]); close(fds[1]); return error; }
    error = posix_spawnattr_init(&attr);
    if (error) { posix_spawn_file_actions_destroy(&a); close(fds[0]); close(fds[1]); return error; }
    error = posix_spawn_file_actions_addopen(&a, 0, "/dev/null", O_RDONLY, 0);
    if (!error) error = posix_spawn_file_actions_adddup2(&a, fds[1], 1);
    if (!error) error = include_stderr ? posix_spawn_file_actions_adddup2(&a, fds[1], 2) :
        posix_spawn_file_actions_addopen(&a, 2, "/dev/null", O_WRONLY, 0);
    sigset_t empty, defaults; sigemptyset(&empty); sigfillset(&defaults);
    if (!error) error = posix_spawnattr_setsigmask(&attr, &empty);
    if (!error) error = posix_spawnattr_setsigdefault(&attr, &defaults);
    if (!error) error = posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    pid_t pid = -1;
    if (!error) error = posix_spawn(&pid, path, &a, &attr, args, env);
    posix_spawnattr_destroy(&attr); posix_spawn_file_actions_destroy(&a); close(fds[1]);
    if (error) { close(fds[0]); return error; }
    double deadline = monotonic() + seconds;
    int finished = 0, signal_allowed = 1;
    while (!finished && !error) {
        uint8_t buffer[4096]; ssize_t n;
        do {
            n = read(fds[0], buffer, sizeof(buffer));
            if (n > 0) {
                if ((size_t)n > capacity - *count) { error = EMSGSIZE; break; }
                memcpy((uint8_t *)output + *count, buffer, (size_t)n); *count += (size_t)n;
            }
        } while (n > 0 || (n < 0 && errno == EINTR));
        if (n < 0 && errno != EAGAIN && errno != EINTR) error = errno;
        siginfo_t info = {0};
        int observed;
        do { observed = waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT); } while (observed && errno == EINTR);
        if (observed) { error = errno; signal_allowed = 0; }
        finished = info.si_pid == pid;
        if (!finished && atomic_load(&cancel->cancelled)) error = ECANCELED;
        if (!finished && monotonic() >= deadline) error = ETIMEDOUT;
        if (!finished && !error) usleep(2000);
    }
    // This function is the only waiter and has never reaped pid.
    if (error && signal_allowed) kill(pid, SIGKILL);
    int raw = 0; pid_t waited;
    do { waited = waitpid(pid, &raw, 0); } while (waited < 0 && errno == EINTR);
    if (waited != pid && !error) error = ECHILD;
    if (!error) { // Final pipe bytes were written before the child exit observation.
        uint8_t buffer[4096]; ssize_t n;
        while ((n = read(fds[0], buffer, sizeof(buffer))) > 0) {
            if ((size_t)n > capacity - *count) { error = EMSGSIZE; break; }
            memcpy((uint8_t *)output + *count, buffer, (size_t)n); *count += (size_t)n;
        }
    }
    close(fds[0]);
    *status = WIFEXITED(raw) ? WEXITSTATUS(raw) : 255;
    return error;
}
