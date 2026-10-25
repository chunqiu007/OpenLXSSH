#ifndef ASKPASS_POSIX_H
#define ASKPASS_POSIX_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <mach/message.h>

typedef struct {
    int32_t pid, ppid;
    uint32_t uid, ruid;
    uint64_t seconds, microseconds;
} ap_identity;
#define AP_FRAME_BYTES 12288
#define AP_MACH_REQUEST 10401
#define AP_MACH_REPLY 10402
// Successful receive transfers exactly one send-once right to caller for a
// request, none for a reply. Tokens come only from the kernel trailer.
typedef struct {
    audit_token_t token;
    uint32_t reply_right;
    uint32_t count;
    uint8_t bytes[AP_FRAME_BYTES];
} ap_mach_message;
int ap_mach_start(char *name, size_t capacity, uint32_t *receive);
int ap_mach_stop(uint32_t receive, const char *name);
int ap_mach_name_unknown(const char *name);
int ap_mach_send_request(const char *name, const void *bytes, size_t count, uint32_t *reply_receive);
int ap_mach_send_reply(uint32_t send_once, const void *bytes, size_t count); // consumes right, including failure
int ap_mach_receive(uint32_t receive, int reply, int timeout_ms, ap_mach_message *message);
const uint8_t *ap_mach_bytes(const ap_mach_message *message);
void ap_mach_drop_reply(uint32_t send_once);
void ap_mach_drop_receive(uint32_t receive);
int ap_mach_reply_alive(uint32_t send_once);
int ap_mach_validate_request(const audit_token_t *token, ap_identity *identity);
int ap_mach_validate_reply(const audit_token_t *token, ap_identity *identity);
int ap_mach_test_invalid(const char *name, int kind); // hostile fixture only
int ap_mach_test_current_broker(const audit_token_t *token); // diagnostic, never authorization
int ap_port_count(void);
int ap_identity_read(pid_t pid, ap_identity *identity);
int ap_identity_equal(const ap_identity *a, const ap_identity *b);
int ap_self_signed(void); // fixed broker identity
int ap_signed_process(const ap_identity *identity); // registered broker fixture parent
int ap_signed_keygen(const ap_identity *identity); // exact Apple-signed /usr/bin/ssh-keygen only
int ap_signed_bundled_helper(const char *path);
int ap_keygen_pty(char *const envp[], const char *key_path, pid_t *pid, int *master);
int ap_process_has_ctty(pid_t pid);
int ap_process_stopped(pid_t pid);
int ap_spawn(const char *path, char *const argv[], char *const envp[], int suspended, int new_group,
             pid_t *pid, int *input, int *output);
int ap_wait(pid_t pid, int *status);
int ap_exited(pid_t pid);
int ap_group_alive(pid_t pid);
int ap_exit_status(int status);
int ap_signal_group(pid_t pid, int signal_number);
int ap_resume(pid_t pid);
int ap_fd_count(void);
int ap_random(void *bytes, size_t size);
int ap_executable(char *path, size_t capacity);
void ap_fixture_signals(void);
int ap_fixture_cancelled(void);
#endif
