#ifndef REAL_INTEGRATION_POSIX_H
#define REAL_INTEGRATION_POSIX_H
#include <membership.h>
// Returns an owned descriptor, or -1. All path components use O_NOFOLLOW.
int ri_open_private(const char *path, int directory);
int ri_create_private(const char *path);
#endif
