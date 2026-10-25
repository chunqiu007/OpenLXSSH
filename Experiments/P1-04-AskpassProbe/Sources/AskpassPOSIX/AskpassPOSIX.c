// Process/pipe lifecycle reused from P1-04A. Authentication IPC is Mach-only.
// The former socket/PID authentication path has been removed, not recommended.
#include "AskpassPOSIX.h"
#include <Security/Security.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <spawn.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
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

int ap_spawn(const char *path, char *const argv[], char *const envp[], int suspended, int new_group,
             pid_t *pid, int *input, int *output) {
    int in[2], out[2];
    if (pipe(in)) return errno;
    if (pipe(out)) { int error = errno; close(in[0]); close(in[1]); return error; }
    for (int i = 0; i < 2; i++) {
        if (fcntl(in[i], F_SETFD, FD_CLOEXEC) || fcntl(out[i], F_SETFD, FD_CLOEXEC)) {
            int error = errno; close(in[0]); close(in[1]); close(out[0]); close(out[1]); return error;
        }
    }
    posix_spawn_file_actions_t actions; posix_spawnattr_t attr;
    int error = posix_spawn_file_actions_init(&actions);
    if (error) { close(in[0]); close(in[1]); close(out[0]); close(out[1]); return error; }
    error = posix_spawnattr_init(&attr);
    if (error) { posix_spawn_file_actions_destroy(&actions); close(in[0]); close(in[1]); close(out[0]); close(out[1]); return error; }
    error = posix_spawn_file_actions_adddup2(&actions, in[0], 0);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, out[1], 1);
    if (!error) error = posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
    short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    // A new session prevents unrelated same-UID processes in our own session
    // from joining the cancellation group. Nested fixture helpers stay inside it.
    if (new_group) flags |= POSIX_SPAWN_SETSID;
    if (suspended) flags |= POSIX_SPAWN_START_SUSPENDED;
    if (!error) error = posix_spawnattr_setflags(&attr, flags);
    if (!error) error = posix_spawnattr_setpgroup(&attr, 0);
    sigset_t defaults, empty; sigfillset(&defaults); sigemptyset(&empty);
    if (!error) error = posix_spawnattr_setsigdefault(&attr, &defaults);
    if (!error) error = posix_spawnattr_setsigmask(&attr, &empty);
    if (!error) error = posix_spawn(pid, path, &actions, &attr, argv, envp);
    posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr);
    close(in[0]); close(out[1]);
    if (error) { close(in[1]); close(out[0]); return error; }
    if (fcntl(out[0], F_SETFL, O_NONBLOCK)) {
        int code = errno;
        // This newly spawned child is still ours and unreaped; PID is reserved.
        kill(*pid, SIGKILL); kill(*pid, SIGCONT);
        for (int i = 0; i < 100; i++) { int status; if (waitpid(*pid, &status, WNOHANG) == *pid) break; usleep(5000); }
        close(in[1]); close(out[0]); return code;
    }
    *input = in[1]; *output = out[0];
    return 0;
}
int ap_wait(pid_t pid, int *status) {
    pid_t result;
    do { result = waitpid(pid, status, WNOHANG); } while (result < 0 && errno == EINTR);
    return result > 0 ? 1 : (result == 0 ? 0 : -1);
}
int ap_exited(pid_t pid) {
    siginfo_t info = {0};
    if (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT)) return -1;
    return info.si_pid == pid ? 1 : 0;
}
int ap_group_alive(pid_t pid) {
    // Scan only this dedicated group; ignore zombies, which are no longer running.
    pid_t members[64];
    int size = proc_listpgrppids(pid, members, sizeof(members));
    if (size < 0 || size >= (int)sizeof(members)) return 1; // fail closed on overflow
    for (int i = 0; i < size / (int)sizeof(pid_t); i++) {
        if (members[i] == pid || members[i] <= 0) continue;
        ap_identity identity;
        if (!ap_identity_read(members[i], &identity)) return 1;
    }
    return 0;
}
int ap_exit_status(int status) { return WIFEXITED(status) ? WEXITSTATUS(status) : (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 255); }
int ap_signal_group(pid_t pid, int signal_number) { return kill(-pid, signal_number) ? errno : 0; }
int ap_resume(pid_t pid) { return kill(pid, SIGCONT) ? errno : 0; }
int ap_fd_count(void) { return proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0) / (int)sizeof(struct proc_fdinfo); }
int ap_random(void *bytes, size_t size) { return SecRandomCopyBytes(kSecRandomDefault, size, bytes) ? EIO : 0; }
int ap_executable(char *path, size_t capacity) {
    uint32_t size = (uint32_t)capacity;
    return _NSGetExecutablePath(path, &size) ? ENAMETOOLONG : 0;
}
static volatile sig_atomic_t cancelled;
static void cancellation(int number) { (void)number; cancelled = 1; }
void ap_fixture_signals(void) {
    cancelled = 0;
    struct sigaction action = {0}; action.sa_handler = cancellation; sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
}
int ap_fixture_cancelled(void) { return cancelled; }
