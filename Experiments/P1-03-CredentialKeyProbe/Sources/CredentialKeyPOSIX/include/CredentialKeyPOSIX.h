#ifndef CREDENTIAL_KEY_POSIX_H
#define CREDENTIAL_KEY_POSIX_H
#include <sys/types.h>

// Fixed executable and minimal environment. No shell, inherited tty or secret argv/env.
int ck_spawn_keygen(char *const argv[], pid_t *child, int *input, int *output);
int ck_exit_code(int status);
int ck_exit_signal(int status);
#endif
