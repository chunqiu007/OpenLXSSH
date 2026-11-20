#include "COpenLXSSHFiles.h"
#include <openssl/crypto.h>
#include <stdatomic.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <float.h>
#include <math.h>

struct rf_cancel { atomic_int flag; };
typedef union rf_allocation rf_allocation;
union rf_allocation {
    max_align_t alignment;
    struct { rf_allocation *next; size_t size; } meta;
};
struct rf_connection {
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp;
    LIBSSH2_CHANNEL *shell;
    int shell_pty;
    int shell_started;
    int shell_close_sent;
    int socket;
    int handshaken;
    int trusted;
    atomic_int cancelled;
    rf_keyboard_responder responder;
    void *responder_context;
    int response_failed;
    int measure_interaction;
    double interaction_seconds;
    rf_cancel *operation_cancel;
    rf_allocation *allocations;
    LIBSSH2_SFTP_HANDLE *handles[64];
};
/* Track every session allocation. libssh2 1.11.1 has incomplete SFTP handle cleanup
 * after interrupted operations; after session_free we can reclaim remaining owned blocks,
 * without accessing private upstream structs. All blocks (including auth packets) are wiped. */
static LIBSSH2_ALLOC_FUNC(session_alloc) {
    rf_connection *c = *abstract;
    if(count > SIZE_MAX - sizeof(rf_allocation)) return NULL;
    rf_allocation *p = malloc(sizeof(*p) + count);
    if(!p) return NULL;
    p->meta.size = count; p->meta.next = c->allocations; c->allocations = p;
    return p + 1;
}
static LIBSSH2_FREE_FUNC(session_free_block) {
    if(!ptr) return;
    rf_connection *c = *abstract;
    rf_allocation *p = (rf_allocation *)ptr - 1;
    rf_allocation **cursor = &c->allocations;
    while(*cursor && *cursor != p) cursor = &(*cursor)->meta.next;
    if(*cursor) *cursor = p->meta.next;
    OPENSSL_cleanse(ptr, p->meta.size); free(p);
}
static LIBSSH2_REALLOC_FUNC(session_realloc) {
    if(!ptr) return session_alloc(count, abstract);
    rf_allocation *old = (rf_allocation *)ptr - 1;
    void *next = session_alloc(count, abstract);
    if(!next) return NULL;
    memcpy(next, ptr, old->meta.size < count ? old->meta.size : count);
    session_free_block(ptr, abstract); return next;
}
/* A rejected/cancelled keyboard reply must not accidentally send empty/partial secrets. */
static LIBSSH2_SEND_FUNC(session_send) {
    rf_connection *c = *abstract;
    if(atomic_load(&c->cancelled) || rf_cancelled(c->operation_cancel)) return -ECANCELED;
    ssize_t rc = send(socket, buffer, length, flags);
    return rc < 0 ? -errno : rc;
}
static LIBSSH2_RECV_FUNC(session_recv) {
    rf_connection *c = *abstract;
    if(atomic_load(&c->cancelled) || rf_cancelled(c->operation_cancel)) return -ECANCELED;
    ssize_t rc = recv(socket, buffer, length, flags);
    return rc < 0 ? -errno : rc;
}
static pthread_once_t once = PTHREAD_ONCE_INIT;
static int init_result = -1;
static void init_library(void) {
    if(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) != 1) { init_result = RF_ALLOCATION; return; }
    init_result = libssh2_init(0);
}
rf_cancel *rf_cancel_create(void) {
    rf_cancel *c = malloc(sizeof(*c));
    if(c) atomic_init(&c->flag, 0);
    return c;
}
void rf_cancel_set(rf_cancel *c) { if(c) atomic_store(&c->flag, 1); }
int rf_cancelled(const rf_cancel *c) { return c ? atomic_load(&c->flag) : 0; }
void rf_cancel_destroy(rf_cancel *c) { free(c); }
void rf_wipe(void *bytes, size_t length) { if(bytes && length) OPENSSL_cleanse(bytes, length); }
const char *rf_libssh2_version(void) { return libssh2_version(0); }
const char *rf_openssl_version(void) { return OpenSSL_version(OPENSSL_VERSION); }
const char *rf_architecture(void) {
#if defined(__arm64__) || defined(__aarch64__)
    return "arm64";
#else
#error "OpenLXSSH P3 native probe requires an arm64 target"
#endif
}
int rf_library_smoke(void) {
    pthread_once(&once, init_library);
    if(init_result) return init_result;
    LIBSSH2_SESSION *s = libssh2_session_init();
    if(!s) return RF_ALLOCATION;
    return libssh2_session_free(s);
}
static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static int check(rf_connection *c, rf_cancel *cancel, double deadline) {
    if(!c || !c->session) return RF_CLOSED;
    if(atomic_load(&c->cancelled) || rf_cancelled(cancel)) return RF_CANCELLED;
    return now() >= deadline ? RF_TIMEOUT : 0;
}
static int wait_ready(rf_connection *c, rf_cancel *cancel, double deadline) {
    for(;;) {
        int rc = check(c, cancel, deadline);
        if(rc) return rc;
        int directions = libssh2_session_block_directions(c->session);
        short events = 0;
        if(directions & LIBSSH2_SESSION_BLOCK_INBOUND) events |= POLLIN;
        if(directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) events |= POLLOUT;
        if(!events) events = POLLIN;
        struct pollfd fd = {c->socket, events, 0};
        int ms = (int)((deadline - now()) * 1000);
        if(ms > 20) ms = 20;
        if(ms < 1) ms = 1;
        rc = poll(&fd, 1, ms);
        if(rc > 0) return 0; // Let libssh2 diagnose EOF/error without exposing remote text.
        if(rc < 0 && errno != EINTR) return LIBSSH2_ERROR_SOCKET_RECV;
    }
}
#define RETRY(c, cancel, timeout, expression) do { \
    double deadline = now() + (timeout); \
    int rc; \
    for(;;) { \
        rc = check((c), (cancel), deadline); \
        if(rc) return rc; \
        rc = (int)(expression); \
        if(rc != LIBSSH2_ERROR_EAGAIN) return rc; \
        rc = wait_ready((c), (cancel), deadline); \
        if(rc) return rc; \
    } \
} while(0)

rf_connection *rf_connection_create(int socket_fd) {
    pthread_once(&once, init_library);
    if(init_result) return NULL;
    struct sockaddr_storage address;
    socklen_t len = sizeof(address);
    if(getpeername(socket_fd, (struct sockaddr *)&address, &len)) return NULL;
    int owned = fcntl(socket_fd, F_DUPFD_CLOEXEC, 0);
    if(owned < 0) return NULL;
    int flags = fcntl(owned, F_GETFL);
    int one = 1;
    if(flags < 0 || fcntl(owned, F_SETFL, flags | O_NONBLOCK) ||
       setsockopt(owned, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) {
        close(owned); return NULL;
    }
    rf_connection *c = calloc(1, sizeof(*c));
    if(!c) { close(owned); return NULL; }
    c->socket = owned;
    atomic_init(&c->cancelled, 0);
    c->session = libssh2_session_init_ex(session_alloc, session_free_block, session_realloc, c);
    if(!c->session) { close(owned); free(c); return NULL; }
    libssh2_session_callback_set2(c->session, LIBSSH2_CALLBACK_SEND, (libssh2_cb_generic *)session_send);
    libssh2_session_callback_set2(c->session, LIBSSH2_CALLBACK_RECV, (libssh2_cb_generic *)session_recv);
    libssh2_session_set_blocking(c->session, 0);
    return c;
}
void rf_connection_cancel(rf_connection *c) { if(c) atomic_store(&c->cancelled, 1); }
int rf_handshake(rf_connection *c, rf_cancel *cancel, double timeout) {
    double deadline = now() + timeout;
    for(;;) {
        int rc = check(c, cancel, deadline);
        if(rc) return rc;
        rc = libssh2_session_handshake(c->session, c->socket);
        if(rc == 0) { c->handshaken = 1; return 0; }
        if(rc != LIBSSH2_ERROR_EAGAIN) return rc;
        rc = wait_ready(c, cancel, deadline);
        if(rc) return rc;
    }
}
const char *rf_hostkey(rf_connection *c, size_t *len, int *type) {
    if(!c || !c->session || !c->handshaken) return NULL;
    return libssh2_session_hostkey(c->session, len, type);
}
int rf_trust_hostkey(rf_connection *c, int accepted) {
    if(!c || !c->handshaken) return RF_UNTRUSTED;
    c->trusted = accepted == 1;
    return c->trusted ? 0 : RF_UNTRUSTED;
}
static int auth_guard(rf_connection *c) {
    if(!c || !c->session) return RF_CLOSED;
    return c->trusted ? 0 : RF_UNTRUSTED;
}
int rf_password(rf_connection *c, const char *user, unsigned int ulen,
                const char *secret, unsigned int slen, rf_cancel *cancel, double timeout) {
    int rc = auth_guard(c); if(rc) return rc;
    RETRY(c, cancel, timeout, libssh2_userauth_password_ex(c->session, user, ulen, secret, slen, NULL));
}
int rf_publickey(rf_connection *c, const char *user, size_t ulen,
                 const char *pub, size_t publen, const char *priv, size_t privlen,
                 const char *pass, rf_cancel *cancel, double timeout) {
    int rc = auth_guard(c); if(rc) return rc;
    RETRY(c, cancel, timeout, libssh2_userauth_publickey_frommemory(c->session, user, ulen,
          pub, publen, priv, privlen, pass));
}
static LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(keyboard_callback) {
    rf_connection *c = *abstract;
    double started = c && c->measure_interaction ? now() : 0;
    if(!c || !c->responder || atomic_load(&c->cancelled) ||
       (c->measure_interaction && rf_cancelled(c->operation_cancel)) ||
       c->responder(c->responder_context, name, name_len, instruction, instruction_len,
                    num_prompts, prompts, responses) != 0) {
        if(c) { c->response_failed = 1; rf_connection_cancel(c); }
    }
    if(c && c->measure_interaction) c->interaction_seconds += now() - started;
}
int rf_keyboard_set_response(rf_connection *c, LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses, int index,
                             const uint8_t *bytes, size_t length) {
    if(!c || !responses || index < 0 || length > UINT_MAX) return RF_INVALID;
    void *abstract = c;
    char *p = session_alloc(length + 1, &abstract);
    if(!p) return RF_ALLOCATION;
    if(length) memcpy(p, bytes, length);
    p[length] = 0;
    responses[index].text = p;
    responses[index].length = (unsigned int)length;
    return 0;
}
int rf_keyboard(rf_connection *c, const char *user, unsigned int ulen,
                rf_keyboard_responder responder, void *ctx, rf_cancel *cancel, double timeout) {
    int rc = auth_guard(c); if(rc) return rc;
    c->responder = responder; c->responder_context = ctx; c->response_failed = 0;
    c->operation_cancel = cancel;
    double deadline = now() + timeout;
    for(;;) {
        rc = check(c, cancel, deadline); if(rc) break;
        rc = libssh2_userauth_keyboard_interactive_ex(c->session, user, ulen, keyboard_callback);
        if(c->response_failed) { rc = RF_CANCELLED; break; }
        if(rc != LIBSSH2_ERROR_EAGAIN) break;
        rc = wait_ready(c, cancel, deadline); if(rc) break;
    }
    c->responder = NULL; c->responder_context = NULL; c->operation_cancel = NULL;
    return rc;
}
int rf_shell_packet_read_timeout(rf_connection *c, int seconds) {
    int rc = auth_guard(c); if(rc) return rc;
    if(seconds < 1 || seconds > 36002) return RF_INVALID;
    libssh2_session_set_read_timeout(c->session, seconds);
    return (int)libssh2_session_get_read_timeout(c->session);
}
int rf_shell_keyboard(rf_connection *c, const char *user, unsigned int ulen,
                      rf_keyboard_responder responder, void *ctx, rf_cancel *cancel,
                      double network_timeout, double overall_timeout) {
    int rc = auth_guard(c); if(rc) return rc;
    if(!user || !ulen || !responder || !isfinite(network_timeout) || network_timeout <= 0 || network_timeout > 300 ||
       !isfinite(overall_timeout) || overall_timeout <= 0 || overall_timeout > 300) return RF_INVALID;
    c->responder = responder; c->responder_context = ctx; c->response_failed = 0;
    c->operation_cancel = cancel; c->measure_interaction = 1; c->interaction_seconds = 0;
    const double started = now(), overall_deadline = started + overall_timeout;
    /* Public packet timeout includes human time inside libssh2's callback. The Swift owner
     * enforces the tighter monotonic overall deadline, never silently truncating it at 60s. */
    long previous_read_timeout = libssh2_session_get_read_timeout(c->session);
    int packet_seconds = (int)ceil(overall_timeout) + 2;
    libssh2_session_set_read_timeout(c->session, packet_seconds);
    for(;;) {
        double network_deadline = started + network_timeout + c->interaction_seconds;
        double deadline = fmin(network_deadline, overall_deadline);
        rc = check(c, cancel, deadline); if(rc) break;
        rc = libssh2_userauth_keyboard_interactive_ex(c->session, user, ulen, keyboard_callback);
        if(c->response_failed) { rc = RF_CANCELLED; break; }
        /* No API success after the native callback consumed the remaining overall budget. */
        deadline = fmin(started + network_timeout + c->interaction_seconds, overall_deadline);
        int interrupted = check(c, cancel, deadline);
        if(interrupted) { rc = interrupted; break; }
        if(rc != LIBSSH2_ERROR_EAGAIN) break;
        rc = wait_ready(c, cancel, deadline); if(rc) break;
    }
    c->responder = NULL; c->responder_context = NULL; c->operation_cancel = NULL;
    c->measure_interaction = 0; c->interaction_seconds = 0;
    libssh2_session_set_read_timeout(c->session, previous_read_timeout);
    return rc;
}
int rf_authenticated(rf_connection *c) {
    return c && c->session && c->trusted && libssh2_userauth_authenticated(c->session);
}
int rf_auth_methods(rf_connection *c, const char *user, unsigned int ulen,
                    char *bytes, size_t capacity, size_t *length, rf_cancel *cancel, double timeout) {
    int rc = auth_guard(c); if(rc) return rc;
    if(!user || !ulen || ulen > 1024 || !bytes || !capacity || capacity > 65536 || !length ||
       !isfinite(timeout) || timeout <= 0 || timeout > 300) return RF_INVALID;
    *length = 0;
    double deadline = now() + timeout;
    for(;;) {
        rc = check(c, cancel, deadline); if(rc) return rc;
        const char *methods = libssh2_userauth_list(c->session, user, ulen);
        if(methods) {
            size_t len = strnlen(methods, capacity + 1);
            if(len > capacity) return RF_INVALID;
            memcpy(bytes, methods, len); *length = len; return 0;
        }
        if(rf_authenticated(c)) return 0;
        rc = libssh2_session_last_errno(c->session);
        if(rc != LIBSSH2_ERROR_EAGAIN) return rc ? rc : LIBSSH2_ERROR_AUTHENTICATION_FAILED;
        rc = wait_ready(c, cancel, deadline); if(rc) return rc;
    }
}
static int shell_guard(rf_connection *c, rf_cancel *cancel) {
    int rc = check(c, cancel, DBL_MAX); if(rc) return rc;
    if(!c->trusted) return RF_UNTRUSTED;
    if(!rf_authenticated(c)) return LIBSSH2_ERROR_AUTHENTICATION_FAILED;
    return 0;
}
static int shell_channel_guard(rf_connection *c, rf_cancel *cancel) {
    int rc = shell_guard(c, cancel); if(rc) return rc;
    return c->shell ? 0 : RF_CLOSED;
}
int rf_shell_open(rf_connection *c, rf_cancel *cancel, double timeout) {
    int rc = shell_guard(c, cancel); if(rc) return rc;
    if(c->sftp || c->shell || !isfinite(timeout) || timeout <= 0 || timeout > 300) return RF_INVALID;
    double deadline = now() + timeout;
    for(;;) {
        rc = check(c, cancel, deadline); if(rc) return rc;
        /* Bound the SSH receive window as well as the Swift pull buffer. No SFTP init. */
        c->shell = libssh2_channel_open_ex(c->session, "session", 7, RF_SHELL_WINDOW,
                                          RF_SHELL_MAX_WRITE, NULL, 0);
        if(c->shell) return 0;
        rc = libssh2_session_last_errno(c->session);
        if(rc != LIBSSH2_ERROR_EAGAIN) return rc ? rc : LIBSSH2_ERROR_CHANNEL_FAILURE;
        rc = wait_ready(c, cancel, deadline); if(rc) return rc;
    }
}
int rf_shell_request_pty(rf_connection *c, int columns, int rows, rf_cancel *cancel, double timeout) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    if(columns < 1 || columns > 65535 || rows < 1 || rows > 65535 || c->shell_pty ||
       !isfinite(timeout) || timeout <= 0 || timeout > 300) return RF_INVALID;
    double deadline = now() + timeout;
    for(;;) {
        rc = check(c, cancel, deadline); if(rc) return rc;
        rc = libssh2_channel_request_pty_ex(c->shell, "xterm-256color", 14, NULL, 0, columns, rows, 0, 0);
        if(rc == 0) { c->shell_pty = 1; return 0; }
        if(rc != LIBSSH2_ERROR_EAGAIN) return rc;
        rc = wait_ready(c, cancel, deadline); if(rc) return rc;
    }
}
int rf_shell_start(rf_connection *c, rf_cancel *cancel, double timeout) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    if(c->shell_started || !c->shell_pty || !isfinite(timeout) || timeout <= 0 || timeout > 300) return RF_INVALID;
    double deadline = now() + timeout;
    for(;;) {
        rc = check(c, cancel, deadline); if(rc) return rc;
        /* Merge extended data for a terminal, never discard stderr bytes. */
        rc = libssh2_channel_handle_extended_data2(c->shell, LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);
        if(rc == 0) break;
        if(rc != LIBSSH2_ERROR_EAGAIN) return rc;
        rc = wait_ready(c, cancel, deadline); if(rc) return rc;
    }
    for(;;) {
        rc = check(c, cancel, deadline); if(rc) return rc;
        rc = libssh2_channel_process_startup(c->shell, "shell", 5, NULL, 0);
        if(rc == 0) { c->shell_started = 1; return 0; }
        if(rc != LIBSSH2_ERROR_EAGAIN) return rc;
        rc = wait_ready(c, cancel, deadline); if(rc) return rc;
    }
}
int rf_shell_poll(rf_connection *c, rf_cancel *cancel) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    int result = 0;
    struct pollfd fd = {c->socket, POLLIN | POLLOUT, 0};
    rc = poll(&fd, 1, 0);
    if(rc < 0 && errno != EINTR) return LIBSSH2_ERROR_SOCKET_RECV;
    if(fd.revents & POLLIN) result |= RF_SHELL_POLL_READABLE;
    if(fd.revents & POLLOUT) result |= RF_SHELL_POLL_WRITABLE;
    if(fd.revents & (POLLHUP | POLLERR | POLLNVAL)) result |= RF_SHELL_POLL_HANGUP;
    if(libssh2_poll_channel_read(c->shell, 0)) result |= RF_SHELL_POLL_BUFFERED;
    int directions = libssh2_session_block_directions(c->session);
    if(directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) result |= RF_SHELL_POLL_OUTBOUND;
    if(directions & LIBSSH2_SESSION_BLOCK_INBOUND) result |= RF_SHELL_POLL_INBOUND;
    return result;
}
int rf_shell_read_step(rf_connection *c, char *bytes, size_t length, rf_cancel *cancel) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    if(!c->shell_started || !bytes || length < 1 || length > RF_SHELL_MAX_CHUNK) return RF_INVALID;
    return (int)libssh2_channel_read_ex(c->shell, 0, bytes, length);
}
int rf_shell_write_step(rf_connection *c, const char *bytes, size_t length, rf_cancel *cancel) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    if(!c->shell_started || !bytes || length < 1 || length > RF_SHELL_MAX_WRITE) return RF_INVALID;
    return (int)libssh2_channel_write_ex(c->shell, 0, bytes, length);
}
int rf_shell_resize_step(rf_connection *c, int columns, int rows, rf_cancel *cancel) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    if(!c->shell_started || columns < 1 || columns > 65535 || rows < 1 || rows > 65535) return RF_INVALID;
    return libssh2_channel_request_pty_size_ex(c->shell, columns, rows, 0, 0);
}
int rf_shell_send_eof_step(rf_connection *c, rf_cancel *cancel) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    if(!c->shell_started) return RF_INVALID;
    return libssh2_channel_send_eof(c->shell);
}
int rf_shell_eof(rf_connection *c, rf_cancel *cancel) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    return libssh2_channel_eof(c->shell);
}
int rf_shell_exit_step(rf_connection *c, rf_shell_exit *result, rf_cancel *cancel) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    if(!result) return RF_INVALID;
    if(!libssh2_channel_eof(c->shell)) return LIBSSH2_ERROR_EAGAIN;
    /* Do not call libssh2_poll here: fixed 1.11.1 may drive transport I/O even at timeout=0.
     * wait_closed is the public nonblocking EOF->close API and retains its own EAGAIN state. */
    rc = libssh2_channel_wait_closed(c->shell);
    if(rc) return rc;
    memset(result, 0, sizeof(*result));
    result->status = libssh2_channel_get_exit_status(c->shell);
    char *signal = NULL; size_t length = 0;
    rc = libssh2_channel_get_exit_signal(c->shell, &signal, &length, NULL, NULL, NULL, NULL);
    if(rc == 0 && length > sizeof(result->signal)) rc = RF_INVALID;
    if(rc == 0 && signal) { memcpy(result->signal, signal, length); result->signal_length = length; }
    if(signal) libssh2_free(c->session, signal);
    return rc;
}
int rf_shell_close_step(rf_connection *c, rf_cancel *cancel) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    rc = libssh2_channel_close(c->shell);
    if(rc == 0) c->shell_close_sent = 1;
    return rc;
}
int rf_shell_free_step(rf_connection *c, rf_cancel *cancel) {
    int rc = shell_channel_guard(c, cancel); if(rc) return rc;
    if(!c->shell_close_sent) return RF_INVALID;
    rc = libssh2_channel_free(c->shell);
    if(rc == 0) { c->shell = NULL; c->shell_started = 0; c->shell_pty = 0; }
    return rc;
}
static int read_socket_option(int fd, int level, int name, int *value) {
    socklen_t length = sizeof(*value);
    if(getsockopt(fd, level, name, value, &length) != 0) return 0;
    if(length != sizeof(*value)) { errno = EIO; return 0; }
    return 1;
}
int rf_tcp_keepalive_configure(int fd, int interval, int count,
                              rf_tcp_keepalive *actual, int *system_error) {
    if(system_error) *system_error = 0;
    if(actual) memset(actual, 0, sizeof(*actual));
    if(fd < 0 || !actual || !system_error || interval < 0 || interval > 3600 ||
       count < 1 || count > 10) return RF_INVALID;
    int domain = 0;
    if(!read_socket_option(fd, SOL_SOCKET, SO_TYPE, &domain)) goto option_failed;
    if(domain != SOCK_STREAM) { *system_error = EPROTOTYPE; return RF_SOCKET_OPTION; }
    struct sockaddr_storage address; socklen_t address_length = sizeof(address);
    if(getsockname(fd, (struct sockaddr *)&address, &address_length) != 0) goto option_failed;
    if(interval > 0 && address.ss_family != AF_INET && address.ss_family != AF_INET6) {
        *system_error = EAFNOSUPPORT; return RF_SOCKET_OPTION;
    }
    int enabled = interval > 0;
    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) != 0) goto option_failed;
    if(enabled && (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &interval, sizeof(interval)) != 0 ||
                   setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) != 0 ||
                   setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)) != 0)) goto option_failed;
    if(!read_socket_option(fd, SOL_SOCKET, SO_KEEPALIVE, &actual->enabled)) goto option_failed;
    if((actual->enabled != 0) != enabled) { *system_error = EIO; return RF_SOCKET_OPTION; }
    actual->enabled = enabled; /* SO_KEEPALIVE is a boolean; BSD may expose its nonzero option bit. */
    if(enabled) {
        if(!read_socket_option(fd, IPPROTO_TCP, TCP_KEEPALIVE, &actual->idle_seconds) ||
           !read_socket_option(fd, IPPROTO_TCP, TCP_KEEPINTVL, &actual->retry_seconds) ||
           !read_socket_option(fd, IPPROTO_TCP, TCP_KEEPCNT, &actual->failed_probes)) goto option_failed;
        if(actual->idle_seconds != interval || actual->retry_seconds != interval || actual->failed_probes != count) {
            *system_error = EIO; return RF_SOCKET_OPTION;
        }
    }
    return 0;
option_failed:
    *system_error = errno; return RF_SOCKET_OPTION;
}
int rf_start_sftp(rf_connection *c, rf_cancel *cancel, double timeout) {
    if(!rf_authenticated(c)) return RF_UNTRUSTED;
    if(c->shell) return RF_INVALID;
    double deadline = now() + timeout;
    for(;;) {
        int rc = check(c, cancel, deadline); if(rc) return rc;
        c->sftp = libssh2_sftp_init(c->session);
        if(c->sftp) return 0;
        rc = libssh2_session_last_errno(c->session);
        if(rc != LIBSSH2_ERROR_EAGAIN) return rc;
        rc = wait_ready(c, cancel, deadline); if(rc) return rc;
    }
}
uint64_t rf_sftp_error(rf_connection *c) { return c && c->sftp ? libssh2_sftp_last_error(c->sftp) : 0; }
int rf_lstat(rf_connection *c, const char *path, unsigned int len, LIBSSH2_SFTP_ATTRIBUTES *a,
             rf_cancel *cancel, double timeout) {
    if(!c || !c->sftp) return RF_CLOSED;
    RETRY(c, cancel, timeout, libssh2_sftp_stat_ex(c->sftp, path, len, LIBSSH2_SFTP_LSTAT, a));
}
int rf_readlink(rf_connection *c, const char *path, unsigned int len, char *target, unsigned int capacity,
                rf_cancel *cancel, double timeout) {
    if(!c || !c->sftp) return RF_CLOSED;
    RETRY(c, cancel, timeout, libssh2_sftp_symlink_ex(c->sftp, path, len, target, capacity, LIBSSH2_SFTP_READLINK));
}
int rf_symlink(rf_connection *c, const char *first, unsigned int first_len, char *second, unsigned int second_len,
               rf_cancel *cancel, double timeout) {
    if(!c || !c->sftp) return RF_CLOSED;
    RETRY(c, cancel, timeout, libssh2_sftp_symlink_ex(c->sftp, first, first_len, second, second_len, LIBSSH2_SFTP_SYMLINK));
}
int rf_fstat(rf_connection *c, LIBSSH2_SFTP_HANDLE *h, LIBSSH2_SFTP_ATTRIBUTES *a,
             rf_cancel *cancel, double timeout) {
    if(!c || !c->sftp || !h) return RF_CLOSED;
    RETRY(c, cancel, timeout, libssh2_sftp_fstat_ex(h, a, 0));
}
LIBSSH2_SFTP_HANDLE *rf_open(rf_connection *c, const char *path, unsigned int len, int kind,
                            int *error, rf_cancel *cancel, double timeout) {
    *error = RF_CLOSED;
    if(!c || !c->sftp) return NULL;
    size_t slot = 0;
    while(slot < 64 && c->handles[slot]) ++slot;
    if(slot == 64) { *error = RF_INVALID; return NULL; }
    double deadline = now() + timeout;
    for(;;) {
        *error = check(c, cancel, deadline); if(*error) return NULL;
        unsigned long flags = kind == 1 ? (LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_EXCL) : LIBSSH2_FXF_READ;
        LIBSSH2_SFTP_HANDLE *h = libssh2_sftp_open_ex(c->sftp, path, len, flags, 0600,
                                                    kind == 2 ? LIBSSH2_SFTP_OPENDIR : LIBSSH2_SFTP_OPENFILE);
        if(h) { c->handles[slot] = h; *error = 0; return h; }
        *error = libssh2_session_last_errno(c->session);
        if(*error != LIBSSH2_ERROR_EAGAIN) return NULL;
        *error = wait_ready(c, cancel, deadline); if(*error) return NULL;
    }
}
int rf_readdir(rf_connection *c, LIBSSH2_SFTP_HANDLE *h, char *b, size_t len,
               LIBSSH2_SFTP_ATTRIBUTES *a, rf_cancel *cancel, double timeout) {
    RETRY(c, cancel, timeout, libssh2_sftp_readdir_ex(h, b, len, NULL, 0, a));
}
int rf_read(rf_connection *c, LIBSSH2_SFTP_HANDLE *h, char *b, size_t len, rf_cancel *cancel, double timeout) {
    RETRY(c, cancel, timeout, libssh2_sftp_read(h, b, len));
}
int rf_write(rf_connection *c, LIBSSH2_SFTP_HANDLE *h, const char *b, size_t len, rf_cancel *cancel, double timeout) {
    RETRY(c, cancel, timeout, libssh2_sftp_write(h, b, len));
}
int rf_fsync(rf_connection *c, LIBSSH2_SFTP_HANDLE *h, rf_cancel *cancel, double timeout) {
    RETRY(c, cancel, timeout, libssh2_sftp_fsync(h));
}
int rf_close_handle(rf_connection *c, LIBSSH2_SFTP_HANDLE *h, rf_cancel *cancel, double timeout) {
    double deadline = now() + timeout;
    int rc;
    for(;;) {
        rc = check(c, cancel, deadline); if(rc) return rc;
        rc = libssh2_sftp_close_handle(h);
        if(rc != LIBSSH2_ERROR_EAGAIN) break;
        rc = wait_ready(c, cancel, deadline); if(rc) return rc;
    }
    for(size_t i = 0; i < 64; ++i) if(c->handles[i] == h) c->handles[i] = NULL;
    return rc;
}
int rf_mkdir(rf_connection *c, const char *p, unsigned int len, long mode, rf_cancel *cancel, double timeout) {
    if(!c || !c->sftp) return RF_CLOSED;
    RETRY(c, cancel, timeout, libssh2_sftp_mkdir_ex(c->sftp, p, len, mode));
}
int rf_rename_no_replace(rf_connection *c, const char *a, unsigned int alen, const char *b,
                          unsigned int blen, rf_cancel *cancel, double timeout) {
    if(!c || !c->sftp) return RF_CLOSED;
    RETRY(c, cancel, timeout, libssh2_sftp_rename_ex(c->sftp, a, alen, b, blen, 0));
}
int rf_posix_replace(rf_connection *c, const char *a, unsigned int alen, const char *b,
                     unsigned int blen, rf_cancel *cancel, double timeout) {
    if(!c || !c->sftp) return RF_CLOSED;
    /* libssh2 1.11.1 returns positive SFTP FX_OP_UNSUPPORTED when the negotiated
     * extension is absent. Normalize it to a negative API error: never false-success. */
    double deadline = now() + timeout;
    for(;;) {
        int rc = check(c, cancel, deadline); if(rc) return rc;
        rc = libssh2_sftp_posix_rename_ex(c->sftp, a, alen, b, blen);
        if(rc == LIBSSH2_FX_OP_UNSUPPORTED) return LIBSSH2_ERROR_METHOD_NOT_SUPPORTED;
        if(rc != LIBSSH2_ERROR_EAGAIN) return rc;
        rc = wait_ready(c, cancel, deadline); if(rc) return rc;
    }
}
int rf_remove(rf_connection *c, const char *p, unsigned int len, int dir, rf_cancel *cancel, double timeout) {
    if(!c || !c->sftp) return RF_CLOSED;
    RETRY(c, cancel, timeout, dir ? libssh2_sftp_rmdir_ex(c->sftp, p, len) : libssh2_sftp_unlink_ex(c->sftp, p, len));
}
void rf_connection_close(rf_connection *c) {
    if(!c || !c->session) return;
    /* Cancellation is terminal: no reuse of partially completed libssh2 state. */
    atomic_store(&c->cancelled, 1);
    shutdown(c->socket, SHUT_RDWR);
    libssh2_session_set_blocking(c->session, 1);
    libssh2_session_set_timeout(c->session, 100);
    for(size_t i = 0; i < 64; ++i) {
        if(c->handles[i]) { libssh2_sftp_close_handle(c->handles[i]); c->handles[i] = NULL; }
    }
    if(c->sftp) { libssh2_sftp_shutdown(c->sftp); c->sftp = NULL; }
    int free_rc = libssh2_session_free(c->session); // Also frees an independently opened shell channel.
    c->shell = NULL; c->shell_started = 0; c->shell_pty = 0;
    if(free_rc == 0) {
        while(c->allocations) {
            void *abstract = c;
            session_free_block(c->allocations + 1, &abstract);
        }
    }
    c->session = NULL;
    close(c->socket); c->socket = -1;
}
void rf_connection_destroy(rf_connection *c) { rf_connection_close(c); free(c); }

/* SFTP login-directory capability; no terminal cwd, shell command or guessed root. */
int rf_sftp_initial_directory(rf_connection *c, char *bytes, size_t capacity,
                              rf_cancel *cancel, double timeout) {
    if(!bytes || capacity < 2 || capacity > RF_SFTP_REALPATH_CAPACITY ||
       !isfinite(timeout) || timeout <= 0 || timeout > 300) return RF_INVALID;
    int rc = check(c, cancel, DBL_MAX); if(rc) return rc;
    if(!c->sftp) return RF_CLOSED;
    double deadline = now() + timeout;
    for(;;) {
        rc = check(c, cancel, deadline); if(rc) return rc;
        /* Public libssh2 1.11.1 macro: symlink_ex with LIBSSH2_SFTP_REALPATH.
         * It fails BUFFER_TOO_SMALL rather than silently truncating the byte path. */
        rc = libssh2_sftp_realpath(c->sftp, ".", bytes, (unsigned int)capacity);
        if(rc != LIBSSH2_ERROR_EAGAIN) {
            int interrupted = check(c, cancel, deadline);
            return interrupted ? interrupted : rc;
        }
        rc = wait_ready(c, cancel, deadline); if(rc) return rc;
    }
}
