#include "SecurityTestSupport.h"
// Test-only, explicitly deprecated legacy APIs. No default/search-list setter or ACL edit.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
OSStatus olxs_test_keychain_create(const char *path, uint32_t length, const void *password, SecKeychainRef *keychain) {
    return SecKeychainCreate(path, length, password, false, NULL, keychain);
}
OSStatus olxs_test_keychain_lock(SecKeychainRef keychain) { return SecKeychainLock(keychain); }
OSStatus olxs_test_keychain_unlock(SecKeychainRef keychain, uint32_t length, const void *password) {
    return SecKeychainUnlock(keychain, length, password, true);
}
OSStatus olxs_test_keychain_delete(SecKeychainRef keychain) { return SecKeychainDelete(keychain); }
OSStatus olxs_test_copy_search_list(CFArrayRef *keychains) { return SecKeychainCopySearchList(keychains); }
OSStatus olxs_test_copy_default(SecKeychainRef *keychain) { return SecKeychainCopyDefault(keychain); }
#pragma clang diagnostic pop
