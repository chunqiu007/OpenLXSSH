// P1-06A: P1-01's reviewed PTY/async-signal-safe child setup, restricted to the
// single fixed system keygen invocation. Never adopts an externally supplied PID.
#include "AskpassPOSIX.h"
#include <libproc.h>
#include <util.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

int ap_keygen_pty(char *const envp[], const char *key_path, pid_t *child, int *master_out) {
    int master = -1, slave = -1;
    struct winsize size = {.ws_row = 24, .ws_col = 80};
    if (openpty(&master, &slave, NULL, NULL, &size)) return errno;
    int flags = fcntl(master, F_GETFL);
    if (flags < 0 || fcntl(master, F_SETFL, flags | O_NONBLOCK) ||
        fcntl(master, F_SETFD, FD_CLOEXEC) || fcntl(slave, F_SETFD, FD_CLOEXEC)) {
        int error = errno; close(master); close(slave); return error;
    }
    int limit = getdtablesize();
    if (limit < 0) { int error = errno; close(master); close(slave); return error; }
    pid_t pid = fork();
    if (pid < 0) { int error = errno; close(master); close(slave); return error; }
    if (!pid) {
        close(master);
        if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) < 0 || dup2(slave, 0) < 0 || dup2(slave, 1) < 0 || dup2(slave, 2) < 0) _exit(126);
        for (int fd = 0; fd < 3; fd++) if (fcntl(fd, F_SETFD, 0) < 0) _exit(126);
        for (int fd = 3; fd < limit; fd++) close(fd);
        sigset_t empty; sigemptyset(&empty); sigprocmask(SIG_SETMASK, &empty, NULL);
        struct sigaction action = {0}; action.sa_handler = SIG_DFL; sigemptyset(&action.sa_mask);
        const int signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGWINCH, SIGCHLD};
        for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) sigaction(signals[i], &action, NULL);
        // Broker records our PID/birth/ctty while stopped and owns the child until
        // waitpid. Only this literal exec is reachable when it resumes us.
        kill(getpid(), SIGSTOP);
        char *const args[] = {"/usr/bin/ssh-keygen", "-y", "-f", (char *)key_path, NULL};
        execve("/usr/bin/ssh-keygen", args, envp); _exit(127);
    }
    close(slave); *child = pid; *master_out = master; return 0;
}
int ap_process_has_ctty(pid_t pid) {
    struct proc_bsdinfo info = {0};
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == sizeof(info) &&
        (info.pbi_flags & PROC_FLAG_CTTY) && info.e_tdev != (uint32_t)-1;
}
int ap_process_stopped(pid_t pid) {
    struct proc_bsdinfo info = {0};
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == sizeof(info) && info.pbi_status == SSTOP;
}
