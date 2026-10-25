#include "ProbePOSIX.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

int probe_spawn_pty(const char *path, char *const argv[], char *const envp[],
                    uint16_t rows, uint16_t columns,
                    pid_t *child_pid, int *master_fd, char *slave_name, size_t name_capacity) {
    int master = -1, slave = -1;
    char name[128] = {0};
    struct winsize size = {.ws_row = rows, .ws_col = columns};
    if (openpty(&master, &slave, name, NULL, &size) == -1) return errno;
    int flags = fcntl(master, F_GETFL);
    if (flags == -1 || fcntl(master, F_SETFL, flags | O_NONBLOCK) == -1 ||
        fcntl(master, F_SETFD, FD_CLOEXEC) == -1 || fcntl(slave, F_SETFD, FD_CLOEXEC) == -1) {
        int code = errno;
        close(master); close(slave);
        return code;
    }
    const int descriptor_limit = getdtablesize();
    if (descriptor_limit < 0) {
        int code = errno;
        close(master); close(slave);
        return code;
    }
    pid_t pid = fork();
    if (pid == -1) {
        int code = errno;
        close(master); close(slave);
        return code;
    }
    if (pid == 0) {
        // No Swift/Foundation, allocation, logging or arbitrary callbacks after fork.
        // setsid + TIOCSCTTY provide a genuine controlling terminal, not just stdio redirection.
        close(master);
        if (setsid() == -1 || ioctl(slave, TIOCSCTTY, 0) == -1 ||
            dup2(slave, STDIN_FILENO) == -1 || dup2(slave, STDOUT_FILENO) == -1 ||
            dup2(slave, STDERR_FILENO) == -1) _exit(126);
        if (slave > STDERR_FILENO) close(slave);
        for (int descriptor = STDIN_FILENO; descriptor <= STDERR_FILENO; ++descriptor)
            if (fcntl(descriptor, F_SETFD, 0) == -1) _exit(126);
        // Do not leak the parent's other PTYs, test descriptors or dispatch descriptors.
        for (int descriptor = STDERR_FILENO + 1; descriptor < descriptor_limit; ++descriptor)
            close(descriptor);
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        struct sigaction action = {0};
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        const int signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGWINCH, SIGCHLD};
        for (size_t index = 0; index < sizeof(signals) / sizeof(signals[0]); ++index)
            sigaction(signals[index], &action, NULL);
        execve(path, argv, envp);
        _exit(127);
    }
    close(slave);
    *child_pid = pid;
    *master_fd = master;
    if (name_capacity > 0) strlcpy(slave_name, name, name_capacity);
    return 0;
}

int probe_exit_code(int wait_status) {
    return WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : -1;
}

int probe_exit_signal(int wait_status) {
    return WIFSIGNALED(wait_status) ? WTERMSIG(wait_status) : 0;
}
