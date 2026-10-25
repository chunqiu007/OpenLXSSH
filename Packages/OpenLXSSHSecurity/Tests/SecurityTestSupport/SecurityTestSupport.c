#include "SecurityTestSupport.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <membership.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/stat.h>
// Test-only legacy Keychain APIs. No user default/search-list setter or Keychain ACL edit.
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

int olxs_test_set_everyone_file_acl(int fd, int inheritable, int deny_only) {
    struct group *everyone = getgrnam("everyone");
    if (everyone == NULL) return ENOENT;
    uuid_t principal;
    int code = mbr_gid_to_uuid(everyone->gr_gid, principal);
    if (code != 0) return code;
    acl_t acl = acl_init(1);
    if (acl == NULL) return errno;
    acl_entry_t entry;
    acl_permset_t permissions;
    acl_flagset_t flags;
    if (acl_create_entry(&acl, &entry) != 0 ||
        acl_set_tag_type(entry, deny_only ? ACL_EXTENDED_DENY : ACL_EXTENDED_ALLOW) != 0 ||
        acl_set_qualifier(entry, principal) != 0 ||
        acl_get_permset(entry, &permissions) != 0 ||
        acl_add_perm(permissions, deny_only ? ACL_WRITE_DATA : ACL_READ_DATA) != 0 ||
        (!deny_only && (acl_add_perm(permissions, ACL_WRITE_DATA) != 0 ||
                       acl_add_perm(permissions, ACL_EXECUTE) != 0)) ||
        acl_get_flagset_np(entry, &flags) != 0 ||
        (inheritable && (acl_add_flag_np(flags, ACL_ENTRY_FILE_INHERIT) != 0 ||
                         acl_add_flag_np(flags, ACL_ENTRY_DIRECTORY_INHERIT) != 0)) ||
        acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) != 0) code = errno;
    else code = 0;
    if (acl_free(acl) != 0 && code == 0) code = errno;
    return code;
}

int olxs_test_clear_file_acl(int fd) {
    filesec_t security = filesec_init();
    if (security == NULL) return errno;
    int code = 0;
    if (filesec_set_property(security, FILESEC_ACL, _FILESEC_REMOVE_ACL) != 0 ||
        fchmodx_np(fd, security) != 0) code = errno;
    filesec_free(security);
    return code;
}

int olxs_test_file_acl_state(int fd, int *state) {
    filesec_t security = filesec_init();
    if (security == NULL) return errno;
    struct stat info;
    int present = 0, code = 0;
    acl_t acl = NULL;
    *state = 0;
    if (fstatx_np(fd, &info, security) != 0 ||
        filesec_query_property(security, FILESEC_ACL, &present) != 0) { code = errno; goto done; }
    if (!present) goto done;
    if (filesec_get_property(security, FILESEC_ACL, &acl) != 0 || acl == NULL) { code = errno; goto done; }
    *state = 1;
    struct group *everyone = getgrnam("everyone");
    uuid_t principal;
    if (everyone == NULL) { code = ENOENT; goto done; }
    code = mbr_gid_to_uuid(everyone->gr_gid, principal);
    if (code != 0) goto done;
    acl_entry_t entry;
    for (int index = 0; acl_get_entry(acl, index, &entry) == 0; ++index) {
        acl_flagset_t flags;
        acl_permset_t permissions;
        acl_tag_t tag;
        if (acl_get_flagset_np(entry, &flags) != 0 || acl_get_permset(entry, &permissions) != 0 ||
            acl_get_tag_type(entry, &tag) != 0) { code = errno; goto done; }
        int inherited = acl_get_flag_np(flags, ACL_ENTRY_INHERITED);
        int read = acl_get_perm_np(permissions, ACL_READ_DATA);
        int write = acl_get_perm_np(permissions, ACL_WRITE_DATA);
        if (inherited < 0 || read < 0 || write < 0) { code = errno; goto done; }
        if (inherited) *state |= 2;
        void *qualifier = acl_get_qualifier(entry);
        if (qualifier == NULL) { code = errno; goto done; }
        if (tag == ACL_EXTENDED_ALLOW && read && write && memcmp(qualifier, principal, sizeof(uuid_t)) == 0) *state |= 4;
        if (acl_free(qualifier) != 0) { code = errno; goto done; }
    }
    // Darwin reports EINVAL at the end of an ACL, unlike Linux's return value 0.
    if (errno != EINVAL) code = errno;
done:
    if (acl != NULL && acl_free(acl) != 0 && code == 0) code = errno;
    filesec_free(security);
    return code;
}
