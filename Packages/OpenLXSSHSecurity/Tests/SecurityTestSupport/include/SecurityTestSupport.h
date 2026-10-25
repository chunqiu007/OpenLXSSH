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
#endif
