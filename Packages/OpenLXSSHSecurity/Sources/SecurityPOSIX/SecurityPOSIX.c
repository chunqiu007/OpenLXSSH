#include "SecurityPOSIX.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int configure_fd(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return errno;
    return 0;
}

int olxs_spawn_keygen(char *const argv[], pid_t *child, int *input, int *output) {
    int in[2], out[2];
    if (pipe(in) != 0) return errno;
    if (pipe(out) != 0) { int code = errno; close(in[0]); close(in[1]); return code; }
    for (unsigned i = 0; i < 2; ++i) {
        if (fcntl(in[i], F_SETFD, FD_CLOEXEC) < 0 || fcntl(out[i], F_SETFD, FD_CLOEXEC) < 0) {
            int code = errno; close(in[0]); close(in[1]); close(out[0]); close(out[1]); return code;
        }
    }
    int code = configure_fd(in[1]);
    if (code == 0) code = configure_fd(out[0]);
    int enabled = 1;
    if (code == 0 && fcntl(in[1], F_SETNOSIGPIPE, enabled) < 0) code = errno;
    if (code != 0) { close(in[0]); close(in[1]); close(out[0]); close(out[1]); return code; }
    const int max_fd = getdtablesize();
    if (max_fd < 0) { code = errno; close(in[0]); close(in[1]); close(out[0]); close(out[1]); return code; }
    pid_t pid = fork();
    if (pid < 0) { code = errno; close(in[0]); close(in[1]); close(out[0]); close(out[1]); return code; }
    if (pid == 0) {
        // Only async-signal-safe C/POSIX operations after fork, no Swift/Foundation.
        // setsid makes /dev/tty unavailable; RP_ALLOW_STDIN falls back to the input pipe.
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd < 0 || setsid() < 0 || dup2(in[0], STDIN_FILENO) < 0 ||
            dup2(out[1], STDOUT_FILENO) < 0 || dup2(null_fd, STDERR_FILENO) < 0) _exit(126);
        for (int fd = 0; fd <= STDERR_FILENO; ++fd)
            if (fcntl(fd, F_SETFD, 0) < 0) _exit(126);
        for (int fd = STDERR_FILENO + 1; fd < max_fd; ++fd) close(fd);
        umask(0077);
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        struct sigaction action = {0};
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        const int signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGCHLD};
        for (unsigned i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) sigaction(signals[i], &action, NULL);
        char *const environment[] = {"PATH=/usr/bin:/bin", "LC_ALL=C", "SSH_ASKPASS_REQUIRE=never", NULL};
        execve("/usr/bin/ssh-keygen", argv, environment);
        _exit(127);
    }
    close(in[0]); close(out[1]);
    *child = pid; *input = in[1]; *output = out[0];
    return 0;
}

int olxs_exit_code(int status) { return WIFEXITED(status) ? WEXITSTATUS(status) : -1; }
int olxs_exit_signal(int status) { return WIFSIGNALED(status) ? WTERMSIG(status) : 0; }

// The file-based Keychain interaction APIs have no nondeprecated equivalent.
// Suppression is limited to these three reviewed legacy calls, not to the target.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
OSStatus olxs_interaction_get(Boolean *allowed) { return SecKeychainGetUserInteractionAllowed(allowed); }
OSStatus olxs_interaction_set(Boolean allowed) { return SecKeychainSetUserInteractionAllowed(allowed); }
OSStatus olxs_copy_default_keychain(SecKeychainRef *keychain) { return SecKeychainCopyDefault(keychain); }
#pragma clang diagnostic pop
