#ifndef REMOTE_FILE_METRICS_H
#define REMOTE_FILE_METRICS_H
#include <stdint.h>
// Self only. No process enumeration or network connection.
int32_t remote_file_fixture_sockets(void);
int32_t remote_file_allocated(int fd, uint64_t *bytes);
int32_t remote_file_identity(int fd, uint64_t *device, uint64_t *inode);
#endif
