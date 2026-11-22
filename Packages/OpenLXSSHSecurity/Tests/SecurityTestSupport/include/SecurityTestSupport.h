#ifndef OPENLXSSH_SECURITY_TEST_SUPPORT_H
#define OPENLXSSH_SECURITY_TEST_SUPPORT_H
// Filesystem ACL fixtures only: descriptors must belong to the test's own UUID tree.
int olxs_test_set_everyone_file_acl(int fd, int inheritable, int deny_only);
int olxs_test_clear_file_acl(int fd);
// Bits: 1 = extended ACL, 2 = inherited ACE, 4 = everyone allow read/write.
int olxs_test_file_acl_state(int fd, int *state);
#endif
