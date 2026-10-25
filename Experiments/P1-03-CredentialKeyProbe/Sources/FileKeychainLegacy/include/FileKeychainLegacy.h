#ifndef FILE_KEYCHAIN_LEGACY_H
#define FILE_KEYCHAIN_LEGACY_H
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// Explicit legacy candidate only. Deprecated calls are isolated here; none changes
// keychain configuration, locks/unlocks a keychain, or creates/modifies an ACL.
OSStatus fkc_begin_no_ui(Boolean *previous);
OSStatus fkc_end_no_ui(Boolean previous, Boolean *restored);
OSStatus fkc_copy_default(SecKeychainRef *keychain);
OSStatus fkc_default_status(SecKeychainRef keychain, Boolean *unlocked);

typedef struct {
    uint32_t decrypt_acl_count;
    uint32_t trusted_application_count;
    uint32_t unrestricted_decrypt_acl_count;
    uint32_t uninspectable_decrypt_acl_count;
    Boolean creator_matches_trusted_application;
    Boolean requires_passphrase_for_decrypt;
    Boolean belongs_to_selected_file_keychain;
} FKCAccessSummary;

CFTypeID fkc_keychain_item_type_id(void);
OSStatus fkc_inspect_own_item(SecKeychainItemRef item, SecKeychainRef selected,
                            FKCAccessSummary *summary);
#endif
