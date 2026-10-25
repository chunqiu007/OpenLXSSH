#ifndef OPENLXSSH_P1_PROBE_POSIX_H
#define OPENLXSSH_P1_PROBE_POSIX_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// Experiment-only Darwin glue. argv/envp are fully prepared by the parent.
int probe_spawn_pty(const char *path, char *const argv[], char *const envp[],
                    uint16_t rows, uint16_t columns,
                    pid_t *child_pid, int *master_fd, char *slave_name, size_t name_capacity);
int probe_exit_code(int wait_status);
int probe_exit_signal(int wait_status);

#endif
