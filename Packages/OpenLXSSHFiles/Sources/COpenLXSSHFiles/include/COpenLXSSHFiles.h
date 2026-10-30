#ifndef OPENLXSSH_REMOTE_BRIDGE_H
#define OPENLXSSH_REMOTE_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
#include <libssh2.h>
#include <libssh2_sftp.h>

typedef struct rf_cancel rf_cancel;
typedef struct rf_connection rf_connection;
rf_cancel *rf_cancel_create(void);
void rf_cancel_set(rf_cancel *);
int rf_cancelled(const rf_cancel *);
void rf_cancel_destroy(rf_cancel *);
const char *rf_libssh2_version(void);
const char *rf_openssl_version(void);
const char *rf_architecture(void);
int rf_library_smoke(void);
void rf_wipe(void *, size_t);

#define RF_CANCELLED (-10001)
#define RF_TIMEOUT (-10002)
#define RF_CLOSED (-10003)
#define RF_UNTRUSTED (-10004)
#define RF_INVALID (-10005)
#define RF_ALLOCATION (-10006)

/* Adopts a DUPLICATE of an already connected socket. Does not connect or resolve DNS.
 * Must have exclusive use of the socket's underlying open-file description.
 * All methods except cancel must be invoked on the same serial owner queue. */
rf_connection *rf_connection_create(int connected_socket);
void rf_connection_cancel(rf_connection *);
int rf_handshake(rf_connection *, rf_cancel *, double timeout);
const char *rf_hostkey(rf_connection *, size_t *length, int *type);
int rf_trust_hostkey(rf_connection *, int accepted);
int rf_password(rf_connection *, const char *user, unsigned int user_len,
                const char *secret, unsigned int secret_len, rf_cancel *, double);
int rf_publickey(rf_connection *, const char *user, size_t user_len,
                 const char *public_key, size_t public_len,
                 const char *private_key, size_t private_len, const char *passphrase,
                 rf_cancel *, double);
typedef int (*rf_keyboard_responder)(void *, const char *, int, const char *, int, int,
                                     const LIBSSH2_USERAUTH_KBDINT_PROMPT *,
                                     LIBSSH2_USERAUTH_KBDINT_RESPONSE *);
int rf_keyboard(rf_connection *, const char *user, unsigned int user_len,
                rf_keyboard_responder, void *context, rf_cancel *, double);
/* Shell only: excludes measured manual callback time from network timeout, but not overall.
 * Existing SFTP rf_keyboard retains its original single timeout semantics. */
int rf_shell_keyboard(rf_connection *, const char *user, unsigned int user_len,
                      rf_keyboard_responder, void *context, rf_cancel *, double network_timeout,
                      double overall_timeout);
/* Public libssh2 packet-read timeout in seconds; protects a longer monotonic owner deadline
 * from the fixed library's default 60s cutoff. Returns the public API's actual readback. */
int rf_shell_packet_read_timeout(rf_connection *, int seconds);
int rf_keyboard_set_response(rf_connection *, LIBSSH2_USERAUTH_KBDINT_RESPONSE *, int index,
                             const uint8_t *bytes, size_t length);
int rf_authenticated(rf_connection *);
/* Mature "none" method discovery, not a password attempt. Copies at most capacity bytes.
 * A successful none authentication returns an empty list; query rf_authenticated separately. */
int rf_auth_methods(rf_connection *, const char *user, unsigned int user_len,
                    char *bytes, size_t capacity, size_t *length, rf_cancel *, double timeout);

/* One shell channel per private connection, independent of SFTP. Setup calls retry EAGAIN
 * with a deadline; all *_step calls are nonblocking and return LIBSSH2_ERROR_EAGAIN.
 * The serial owner MUST retain the identical write pointer/length until a non-EAGAIN result,
 * and resume a pending outbound operation before starting another outbound operation. */
#define RF_SHELL_MAX_CHUNK 65536
#define RF_SHELL_MAX_WRITE 32768
#define RF_SHELL_WINDOW 262144
#define RF_SHELL_POLL_READABLE 1
#define RF_SHELL_POLL_WRITABLE 2
#define RF_SHELL_POLL_HANGUP 4
#define RF_SHELL_POLL_BUFFERED 8
#define RF_SHELL_POLL_OUTBOUND 16
#define RF_SHELL_POLL_INBOUND 32
int rf_shell_open(rf_connection *, rf_cancel *, double timeout);
int rf_shell_request_pty(rf_connection *, int columns, int rows, rf_cancel *, double timeout);
int rf_shell_start(rf_connection *, rf_cancel *, double timeout);
int rf_shell_poll(rf_connection *, rf_cancel *);
int rf_shell_read_step(rf_connection *, char *, size_t, rf_cancel *);
int rf_shell_write_step(rf_connection *, const char *, size_t, rf_cancel *);
int rf_shell_resize_step(rf_connection *, int columns, int rows, rf_cancel *);
int rf_shell_send_eof_step(rf_connection *, rf_cancel *);
int rf_shell_eof(rf_connection *, rf_cancel *);
typedef struct {
    int status; /* libssh2 returns zero also when the peer omitted exit-status. */
    size_t signal_length;
    char signal[256];
} rf_shell_exit;
/* After actual EOF, continues public libssh2_channel_wait_closed nonblocking; no close request.
 * A would-block result must resume this API, respecting session block directions. */
int rf_shell_exit_step(rf_connection *, rf_shell_exit *, rf_cancel *);
int rf_shell_close_step(rf_connection *, rf_cancel *);
int rf_shell_free_step(rf_connection *, rf_cancel *);
/* Optional liveness candidate: one same-session auxiliary session channel, no PTY/startup.
 * OPEN_CONFIRMATION and precisely gated fixed-1.11.1 OPEN_FAILURE both prove an SSH reply.
 * An EAGAIN call MUST continue the original API; no second helper open may be started.
 * Close/free also retain their own stable state. Cancellation/timeout destroys the session. */
#define RF_SHELL_PROBE_CONFIRMED 1
#define RF_SHELL_PROBE_REJECTED 2
int rf_shell_probe_open_step(rf_connection *, rf_cancel *);
int rf_shell_probe_close_step(rf_connection *, rf_cancel *);
int rf_shell_probe_free_step(rf_connection *, rf_cancel *);
/* Pure fixed-source classifier, not evidence of a packet by itself. Only the open step may
 * call it immediately after its own libssh2_channel_open_ex NULL result. */
int rf_shell_probe_rejection_is_reply(int code, const char *message, size_t length);
int rf_start_sftp(rf_connection *, rf_cancel *, double);
uint64_t rf_sftp_error(rf_connection *);
int rf_lstat(rf_connection *, const char *, unsigned int, LIBSSH2_SFTP_ATTRIBUTES *, rf_cancel *, double);
int rf_fstat(rf_connection *, LIBSSH2_SFTP_HANDLE *, LIBSSH2_SFTP_ATTRIBUTES *, rf_cancel *, double);
LIBSSH2_SFTP_HANDLE *rf_open(rf_connection *, const char *, unsigned int, int kind, int *error,
                            rf_cancel *, double);
int rf_readdir(rf_connection *, LIBSSH2_SFTP_HANDLE *, char *, size_t,
               LIBSSH2_SFTP_ATTRIBUTES *, rf_cancel *, double);
int rf_read(rf_connection *, LIBSSH2_SFTP_HANDLE *, char *, size_t, rf_cancel *, double);
int rf_write(rf_connection *, LIBSSH2_SFTP_HANDLE *, const char *, size_t, rf_cancel *, double);
int rf_fsync(rf_connection *, LIBSSH2_SFTP_HANDLE *, rf_cancel *, double);
int rf_close_handle(rf_connection *, LIBSSH2_SFTP_HANDLE *, rf_cancel *, double);
int rf_mkdir(rf_connection *, const char *, unsigned int, long mode, rf_cancel *, double);
int rf_rename_no_replace(rf_connection *, const char *, unsigned int, const char *, unsigned int,
                          rf_cancel *, double);
int rf_posix_replace(rf_connection *, const char *, unsigned int, const char *, unsigned int,
                     rf_cancel *, double);
int rf_remove(rf_connection *, const char *, unsigned int, int directory, rf_cancel *, double);
void rf_connection_close(rf_connection *);
void rf_connection_destroy(rf_connection *);

/* SFTP login-directory capability, independent of the shell channel. The public libssh2
 * realpath(".") API returns an exact byte count, excluding its terminating NUL.
 * The fixed upper bound includes one NUL byte for RemotePath's 32768-byte path limit.
 * Invoke only on the SFTP connection's existing serial owner queue. */
#define RF_SFTP_REALPATH_CAPACITY 32769
int rf_sftp_initial_directory(rf_connection *, char *bytes, size_t capacity, rf_cancel *, double timeout);
#endif
