#ifndef C_OPENLXSSH_ASKPASS_H
#define C_OPENLXSSH_ASKPASS_H
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
typedef struct {
    audit_token_t token;
    uint32_t reply_right, count;
    uint8_t bytes[AP_FRAME_BYTES];
} ap_mach_message;
int ap_identity_read(pid_t, ap_identity *);
int ap_identity_equal(const ap_identity *, const ap_identity *);
int ap_process_has_ctty(pid_t);
int ap_self_signed(void);
int ap_signed_ssh(const ap_identity *);
int ap_system_ssh_signed(void);
int ap_signed_bundled_helper(const char *);
int ap_mach_start(char *, size_t, uint32_t *);
int ap_mach_stop(uint32_t, const char *);
int ap_mach_name_unknown(const char *);
int ap_mach_send_request(const char *, const void *, size_t, uint32_t *);
int ap_mach_send_reply(uint32_t, const void *, size_t);
int ap_mach_receive(uint32_t, int, int, ap_mach_message *);
const uint8_t *ap_mach_bytes(const ap_mach_message *);
void ap_mach_drop_reply(uint32_t);
void ap_mach_drop_receive(uint32_t);
int ap_mach_reply_alive(uint32_t);
int ap_mach_validate_request(const audit_token_t *, ap_identity *);
int ap_mach_validate_reply(const audit_token_t *, ap_identity *);
typedef struct ap_cancel ap_cancel;
ap_cancel *ap_cancel_create(void);
void ap_cancel_set(ap_cancel *);
void ap_cancel_free(ap_cancel *);
int ap_tool(const char *, char *const [], char *const [], ap_cancel *, double, int, void *, size_t, size_t *, int *);
int ap_random(void *, size_t);
int ap_fd_count(void);
int ap_port_count(void);
#ifdef TRANSPORT_HOST_PROBE
int ap_signed_probe_parent(const ap_identity *);
int ap_signed_probe_keygen(const ap_identity *);
#endif
#endif
