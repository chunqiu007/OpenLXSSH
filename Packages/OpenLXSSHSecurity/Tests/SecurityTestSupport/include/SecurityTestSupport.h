#ifndef OPENLXSSH_SECURITY_TEST_SUPPORT_H
#define OPENLXSSH_SECURITY_TEST_SUPPORT_H
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
// Never linked into the library product. Only the caller-created fixture keychain.
OSStatus olxs_test_keychain_create(const char *path, uint32_t length, const void *password, SecKeychainRef *keychain);
OSStatus olxs_test_keychain_lock(SecKeychainRef keychain);
OSStatus olxs_test_keychain_unlock(SecKeychainRef keychain, uint32_t length, const void *password);
OSStatus olxs_test_keychain_delete(SecKeychainRef keychain);
OSStatus olxs_test_copy_search_list(CFArrayRef *keychains);
OSStatus olxs_test_copy_default(SecKeychainRef *keychain);
// Filesystem ACL fixtures only: descriptors must belong to the test's own UUID tree.
int olxs_test_set_everyone_file_acl(int fd, int inheritable, int deny_only);
int olxs_test_clear_file_acl(int fd);
// Bits: 1 = extended ACL, 2 = inherited ACE, 4 = everyone allow read/write.
int olxs_test_file_acl_state(int fd, int *state);
#endif
