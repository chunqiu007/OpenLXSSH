#include "NativeLivenessTest.h"
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Metadata of THIS process only; the supervisor independently rechecks birth/UID/actual tuple. */
static struct proc_fdinfo *own_fds(int *count) {
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if(bytes <= 0 || bytes > 1024 * 1024) return NULL;
    size_t capacity = (size_t)bytes + 64 * sizeof(struct proc_fdinfo);
    struct proc_fdinfo *items = calloc(1, capacity);
    if(!items) return NULL;
    int got = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, items, (int)capacity);
    if(got <= 0 || (size_t)got >= capacity || got % sizeof(*items)) { free(items); return NULL; }
    *count = got / (int)sizeof(*items); return items;
}
int ns_test_descriptor_count(void) {
    int count = 0; struct proc_fdinfo *items = own_fds(&count);
    if(!items) return -1;
    free(items); return count;
}
int ns_test_tcp_source_port(void) {
    int count = 0, matched = 0, port = -1;
    struct proc_fdinfo *items = own_fds(&count);
    if(!items) return -1;
    for(int i = 0; i < count; ++i) {
        if(items[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        struct sockaddr_in peer, local; socklen_t size = sizeof(peer);
        memset(&peer, 0, sizeof(peer)); memset(&local, 0, sizeof(local));
        if(getpeername(items[i].proc_fd, (struct sockaddr *)&peer, &size) || peer.sin_family != AF_INET ||
           peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || ntohs(peer.sin_port) != 22221) continue;
        size = sizeof(local);
        if(getsockname(items[i].proc_fd, (struct sockaddr *)&local, &size) || local.sin_family != AF_INET ||
           local.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || ntohs(local.sin_port) < 1024) { matched = 2; break; }
        matched += 1; port = ntohs(local.sin_port);
    }
    free(items); return matched == 1 ? port : -1;
}
#ifndef NATIVE_MAXSESSIONS_TEST_ONLY
int ns_test_instrumented(void) { return 0; }
int ns_test_extra_channels(void) { return 0; }
int ns_test_real_open_code(void) { return 0; }
int ns_test_real_rejections(void) { return 0; }
int ns_test_session_freed(void) { return 0; }
int ns_test_thread_violation(void) { return 0; }
#endif
