#ifndef OPENLXSSH_AUTHENTICATION_MATERIAL_PROBE_H
#define OPENLXSSH_AUTHENTICATION_MATERIAL_PROBE_H
#include <stddef.h>
// Test-only offline parse/sign/verify using the existing Files native build. No socket,
// server, key export, Keychain access or production dependency on libssh2 internals.
int olxs_probe_authentication_material(const char *private_bytes, size_t private_length,
                                       const char *passphrase, const char *algorithm,
                                       const unsigned char *expected_public, size_t expected_length);
#endif
