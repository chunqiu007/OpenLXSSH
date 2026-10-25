#ifndef OPENLXSSH_SECURITY_POSIX_H
#define OPENLXSSH_SECURITY_POSIX_H
#include <sys/types.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

int olxs_spawn_keygen(char *const argv[], pid_t *child, int *input, int *output);
int olxs_exit_code(int status);
int olxs_exit_signal(int status);
// Legacy file-Keychain operations only; no Keychain configuration or ACL mutation.
OSStatus olxs_interaction_get(Boolean *allowed);
OSStatus olxs_interaction_set(Boolean allowed);
OSStatus olxs_copy_default_keychain(SecKeychainRef *keychain);
#endif
