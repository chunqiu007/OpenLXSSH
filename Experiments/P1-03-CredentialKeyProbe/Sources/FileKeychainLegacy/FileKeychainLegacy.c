#include "FileKeychainLegacy.h"
#include <string.h>

// Reviewed legacy-only experiment. These exact APIs have no nondeprecated
// file-based ACL/interaction equivalent. No warning suppression leaks to targets.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
OSStatus fkc_begin_no_ui(Boolean *previous) {
    OSStatus status = SecKeychainGetUserInteractionAllowed(previous);
    if (status != errSecSuccess) return status;
    status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    Boolean current = true;
    status = SecKeychainGetUserInteractionAllowed(&current);
    if (status != errSecSuccess || current) {
        // If verification fails, restore the previous process flag before returning.
        OSStatus restore = SecKeychainSetUserInteractionAllowed(*previous);
        if (restore != errSecSuccess) return restore;
        return status != errSecSuccess ? status : errSecInteractionNotAllowed;
    }
    return errSecSuccess;
}

OSStatus fkc_end_no_ui(Boolean previous, Boolean *restored) {
    *restored = false;
    OSStatus status = SecKeychainSetUserInteractionAllowed(previous);
    if (status != errSecSuccess) return status;
    Boolean current = !previous;
    status = SecKeychainGetUserInteractionAllowed(&current);
    *restored = status == errSecSuccess && current == previous;
    return status;
}

OSStatus fkc_copy_default(SecKeychainRef *keychain) { return SecKeychainCopyDefault(keychain); }
OSStatus fkc_default_status(SecKeychainRef keychain, Boolean *unlocked) {
    SecKeychainStatus flags = 0;
    OSStatus status = SecKeychainGetStatus(keychain, &flags);
    *unlocked = status == errSecSuccess && (flags & kSecUnlockStateStatus) != 0;
    return status;
}

CFTypeID fkc_keychain_item_type_id(void) { return SecKeychainItemGetTypeID(); }

OSStatus fkc_inspect_own_item(SecKeychainItemRef item, SecKeychainRef selected,
                            FKCAccessSummary *summary) {
    memset(summary, 0, sizeof(*summary));
    SecKeychainRef actual = NULL;
    OSStatus status = SecKeychainItemCopyKeychain(item, &actual);
    if (status != errSecSuccess) return status;
    summary->belongs_to_selected_file_keychain = CFEqual(actual, selected);
    CFRelease(actual);
    SecAccessRef access = NULL;
    status = SecKeychainItemCopyAccess(item, &access);
    if (status != errSecSuccess) return status;
    CFArrayRef acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
    if (!acls) { CFRelease(access); return errSecDecode; }
    summary->decrypt_acl_count = (uint32_t)CFArrayGetCount(acls);
    for (CFIndex i = 0; i < CFArrayGetCount(acls); ++i) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
        CFArrayRef applications = NULL;
        CFStringRef description = NULL;
        SecKeychainPromptSelector prompt = 0;
        status = SecACLCopyContents(acl, &applications, &description, &prompt);
        if (description) CFRelease(description); // Never emit item descriptions/identity data.
        if (status != errSecSuccess) {
            summary->uninspectable_decrypt_acl_count++;
            if (applications) CFRelease(applications);
            continue;
        }
        if (!applications) summary->unrestricted_decrypt_acl_count++;
        else {
            summary->trusted_application_count += (uint32_t)CFArrayGetCount(applications);
            // CopyData contains an encoded trusted application representation. It is not
            // a public code-requirement parser. Compare to self as opaque bytes only.
            SecTrustedApplicationRef self = NULL;
            CFDataRef self_data = NULL;
            OSStatus self_status = SecTrustedApplicationCreateFromPath(NULL, &self);
            if (self_status == errSecSuccess) self_status = SecTrustedApplicationCopyData(self, &self_data);
            for (CFIndex j = 0; j < CFArrayGetCount(applications); ++j) {
                CFDataRef data = NULL;
                SecTrustedApplicationRef app = (SecTrustedApplicationRef)CFArrayGetValueAtIndex(applications, j);
                if (self_status == errSecSuccess && SecTrustedApplicationCopyData(app, &data) == errSecSuccess) {
                    if (CFEqual(self_data, data)) summary->creator_matches_trusted_application = true;
                }
                if (data) CFRelease(data);
            }
            if (self_data) CFRelease(self_data);
            if (self) CFRelease(self);
            CFRelease(applications);
        }
        if ((prompt & kSecKeychainPromptRequirePassphase) != 0) summary->requires_passphrase_for_decrypt = true;
    }
    CFRelease(acls);
    CFRelease(access);
    return errSecSuccess;
}
#pragma clang diagnostic pop
