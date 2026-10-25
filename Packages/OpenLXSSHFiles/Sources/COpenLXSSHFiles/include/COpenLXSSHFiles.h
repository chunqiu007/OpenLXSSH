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
int rf_keyboard_set_response(rf_connection *, LIBSSH2_USERAUTH_KBDINT_RESPONSE *, int index,
                             const uint8_t *bytes, size_t length);
int rf_authenticated(rf_connection *);
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
#endif
