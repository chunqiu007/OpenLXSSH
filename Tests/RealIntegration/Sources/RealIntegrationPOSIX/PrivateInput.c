#include "RealIntegrationPOSIX.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <unistd.h>

// Same descriptor/ACL policy as StabilityPOSIX, without importing its runner.
static int metadata(int fd, int directory) {
    struct stat info;
    if (fstat(fd, &info) || info.st_uid != getuid() ||
        (info.st_mode & 07777) != (directory ? 0700 : 0600) ||
        (directory ? !S_ISDIR(info.st_mode) : (!S_ISREG(info.st_mode) || info.st_nlink != 1))) return -1;
    filesec_t security = filesec_init();
    if (!security) return -1;
    int mode_present = 0, acl_present = 0;
    int error = fstatx_np(fd, &info, security) ||
        filesec_query_property(security, FILESEC_MODE, &mode_present) || !mode_present ||
        filesec_query_property(security, FILESEC_ACL, &acl_present) || acl_present;
    filesec_free(security);
    return error ? -1 : 0;
}

int ri_open_private(const char *path, int directory) {
    if (!path || path[0] != '/' || !path[1] || strlen(path) >= 4096) { errno = EINVAL; return -1; }
    char *copy = strdup(path + 1);
    if (!copy) return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    char *part = copy;
    while (fd >= 0 && part) {
        char *slash = strchr(part, '/');
        if (slash) *slash = '\0';
        if (!*part || !strcmp(part, ".") || !strcmp(part, "..")) { errno = EINVAL; break; }
        int last = slash == NULL;
        if (last && !directory && metadata(fd, 1)) { errno = EACCES; break; }
        int next = openat(fd, part, O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_RDONLY |
                          ((!last || directory) ? O_DIRECTORY : 0));
        if (next < 0) break;
        close(fd); fd = next;
        if (last) {
            free(copy);
            if (metadata(fd, directory)) { close(fd); errno = EACCES; return -1; }
            return fd;
        }
        part = slash + 1;
    }
    if (fd >= 0) close(fd);
    free(copy); return -1;
}

int ri_create_private(const char *path) {
    char *copy = strdup(path ? path : "");
    if (!copy) return -1;
    char *slash = strrchr(copy, '/');
    if (!slash || !slash[1]) { free(copy); errno = EINVAL; return -1; }
    *slash = '\0';
    int parent = ri_open_private(copy, 1);
    int fd = parent < 0 ? -1 : openat(parent, slash + 1, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0 && metadata(fd, 0)) {
        close(fd); fd = -1;
        unlinkat(parent, slash + 1, 0); // Only our exclusively created entry.
        errno = EACCES;
    }
    if (parent >= 0) close(parent);
    free(copy); return fd;
}
