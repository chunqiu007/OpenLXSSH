// P1-04C: bounded inline Mach transport; trust logic extracted from P1-04B.
#include "AskpassPOSIX.h"
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define BROKER_ID "org.openlxssh.p104c.broker"
#define HELPER_ID "org.openlxssh.p104c.helper"
#define ADVERSARY_ID "org.openlxssh.p104c.adversary"
typedef struct { mach_msg_header_t header; uint32_t count; uint8_t bytes[AP_FRAME_BYTES]; } wire_message;
typedef union { uint64_t alignment; uint8_t bytes[sizeof(wire_message) + MAX_TRAILER_SIZE]; } receive_buffer;

static int hardened(SecCodeRef code) {
    CFDictionaryRef info = NULL;
    int error = (int)SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    if (!error) {
        int32_t bits = 0; CFNumberRef flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
        CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
        if (!flags || !CFNumberGetValue(flags, kCFNumberSInt32Type, &bits) || !(bits & kSecCodeSignatureRuntime) ||
            (entitlements && CFDictionaryGetCount(entitlements))) error = EACCES;
    }
    if (info) CFRelease(info);
    return error;
}
static int requirement(const char *team, const char *identifier, SecRequirementRef *out) {
    CFStringRef string = CFStringCreateWithFormat(NULL, NULL,
        CFSTR("anchor apple generic and certificate leaf[subject.OU] = \"%s\" and identifier \"%s\""), team, identifier);
    int error = (int)SecRequirementCreateWithString(string, kSecCSDefaultFlags, out);
    CFRelease(string); return error;
}
static int own_team(const char *identifier, char team[11]) {
    SecCodeRef own = NULL; SecRequirementRef policy = NULL; CFDictionaryRef info = NULL;
    CFStringRef text = CFStringCreateWithFormat(NULL, NULL, CFSTR("anchor apple generic and identifier \"%s\""), identifier);
    int error = (int)SecRequirementCreateWithString(text, kSecCSDefaultFlags, &policy); CFRelease(text);
    if (!error) error = (int)SecCodeCopySelf(kSecCSDefaultFlags, &own);
    if (!error) error = (int)SecCodeCheckValidity(own, kSecCSDefaultFlags, policy);
    if (!error) error = hardened(own);
    if (!error) error = (int)SecCodeCopySigningInformation(own, kSecCSSigningInformation, &info);
    if (!error) {
        CFStringRef value = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
        if (!value || !CFStringGetCString(value, team, 11, kCFStringEncodingASCII) || strlen(team) != 10) error = EACCES;
        for (int i = 0; !error && i < 10; i++) if (!((team[i] >= 'A' && team[i] <= 'Z') || (team[i] >= '0' && team[i] <= '9'))) error = EACCES;
    }
    if (info) CFRelease(info); if (own) CFRelease(own); if (policy) CFRelease(policy);
    return error;
}
static int validate(CFDictionaryRef attributes, const char *own_id, const char *peer_id) {
    char team[11] = {0}; SecRequirementRef policy = NULL; SecCodeRef code = NULL;
    int error = own_team(own_id, team);
    if (!error) error = requirement(team, peer_id, &policy);
    if (!error) error = (int)SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    if (!error) error = (int)SecCodeCheckValidity(code, kSecCSDefaultFlags, policy);
    if (!error) error = hardened(code);
    if (code) CFRelease(code); if (policy) CFRelease(policy);
    return error;
}
int ap_self_signed(void) { char team[11]; return own_team(BROKER_ID, team); }
int ap_signed_process(const ap_identity *expected) {
    ap_identity before, after;
    if (ap_identity_read(expected->pid, &before) || !ap_identity_equal(expected, &before)) return EACCES;
    int32_t pid = expected->pid; CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
    const void *keys[] = {kSecGuestAttributePid}, *values[] = {number};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int error = validate(attributes, BROKER_ID, BROKER_ID); CFRelease(attributes); CFRelease(number);
    if (ap_identity_read(expected->pid, &after) || !ap_identity_equal(expected, &after)) return EACCES;
    return error;
}
int ap_signed_bundled_helper(const char *path) {
    char team[11] = {0}; SecRequirementRef policy = NULL; SecStaticCodeRef code = NULL;
    int error = own_team(BROKER_ID, team);
    if (!error) error = requirement(team, HELPER_ID, &policy);
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    if (!error) error = (int)SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (!error) error = (int)SecStaticCodeCheckValidity(code, kSecCSStrictValidate, policy);
    if (code) CFRelease(code); if (policy) CFRelease(policy); if (url) CFRelease(url);
    return error;
}
int ap_signed_keygen(const ap_identity *expected) {
    ap_identity before, after; char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (ap_identity_read(expected->pid, &before) || !ap_identity_equal(expected, &before) ||
        proc_pidpath(expected->pid, path, sizeof(path)) <= 0 || strcmp(path, "/usr/bin/ssh-keygen")) return EACCES;
    char team[11]; int error = own_team(BROKER_ID, team); // do not widen caller trust
    SecRequirementRef policy = NULL; SecCodeRef code = NULL;
    if (!error) error = (int)SecRequirementCreateWithString(CFSTR("anchor apple and identifier \"com.apple.ssh-keygen\""), kSecCSDefaultFlags, &policy);
    int32_t pid = expected->pid; CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
    const void *keys[] = {kSecGuestAttributePid}, *values[] = {number};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!error) error = (int)SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    if (!error) error = (int)SecCodeCheckValidity(code, kSecCSDefaultFlags, policy);
    if (code) CFRelease(code); if (policy) CFRelease(policy); CFRelease(attributes); CFRelease(number);
    if (ap_identity_read(expected->pid, &after) || !ap_identity_equal(expected, &after)) return EACCES;
    return error;
}
static int token_validate(const audit_token_t *token, int reply, ap_identity *out) {
    pid_t pid = audit_token_to_pid(*token); ap_identity before, after;
    if (pid <= 0 || audit_token_to_euid(*token) != getuid() || audit_token_to_ruid(*token) != getuid() ||
        ap_identity_read(pid, &before) || before.uid != getuid() || before.ruid != getuid()) return EACCES;
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)token, sizeof(*token));
    const void *keys[] = {kSecGuestAttributeAudit}, *values[] = {data};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int error = validate(attributes, reply ? HELPER_ID : BROKER_ID, reply ? BROKER_ID : HELPER_ID);
    CFRelease(attributes); CFRelease(data);
    if (error || ap_identity_read(pid, &after) || !ap_identity_equal(&before, &after)) return EACCES;
    *out = after; return 0;
}
int ap_mach_test_current_broker(const audit_token_t *token) {
    int32_t pid = audit_token_to_pid(*token); CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
    const void *keys[] = {kSecGuestAttributePid}, *values[] = {number};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int error = validate(attributes, BROKER_ID, BROKER_ID); CFRelease(attributes); CFRelease(number);
    return !error;
}
int ap_mach_validate_request(const audit_token_t *token, ap_identity *identity) { return token_validate(token, 0, identity); }
int ap_mach_validate_reply(const audit_token_t *token, ap_identity *identity) { return token_validate(token, 1, identity); }

int ap_mach_start(char *name, size_t capacity, uint32_t *receive) {
    if (capacity < BOOTSTRAP_MAX_NAME_LEN) return ENAMETOOLONG;
    uint8_t random[16]; if (ap_random(random, sizeof(random))) return EIO;
    size_t offset = (size_t)snprintf(name, capacity, "org.openlxssh.p104c.%d.", getpid());
    for (size_t i = 0; i < sizeof(random); i++) offset += (size_t)snprintf(name + offset, capacity - offset, "%02x", random[i]);
    mach_port_t port = MACH_PORT_NULL;
    int error = (int)mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (error) return error;
    error = (int)mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (!error) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        // Public but deprecated. P1-04B establishes host-only availability; no plist.
        error = (int)bootstrap_register(bootstrap_port, name, port);
#pragma clang diagnostic pop
    }
    if (error) { ap_mach_drop_receive(port); mach_port_deallocate(mach_task_self(), port); return error; }
    *receive = port; return 0;
}
int ap_mach_name_unknown(const char *name) {
    mach_port_t found = MACH_PORT_NULL;
    int result = (int)bootstrap_look_up(bootstrap_port, name, &found);
    if (MACH_PORT_VALID(found)) mach_port_deallocate(mach_task_self(), found);
    return result == BOOTSTRAP_UNKNOWN_SERVICE;
}
int ap_mach_stop(uint32_t receive, const char *name) {
    ap_mach_drop_receive(receive); (void)mach_port_deallocate(mach_task_self(), receive);
    for (int i = 0; i < 100; i++) { if (ap_mach_name_unknown(name)) return 0; usleep(5000); }
    return EBUSY;
}
void ap_mach_drop_receive(uint32_t receive) { if (MACH_PORT_VALID(receive)) (void)mach_port_mod_refs(mach_task_self(), receive, MACH_PORT_RIGHT_RECEIVE, -1); }
void ap_mach_drop_reply(uint32_t send_once) { if (MACH_PORT_VALID(send_once)) (void)mach_port_deallocate(mach_task_self(), send_once); }
int ap_mach_reply_alive(uint32_t send_once) {
    mach_port_type_t type = 0;
    return !mach_port_type(mach_task_self(), send_once, &type) && (type & MACH_PORT_TYPE_SEND_ONCE);
}
static int send_message(mach_port_t destination, mach_port_t receive, const void *bytes, size_t count, int reply) {
    if (!count || count > AP_FRAME_BYTES) { if (reply) ap_mach_drop_reply(destination); return EMSGSIZE; }
    wire_message message = {0};
    message.header.msgh_bits = MACH_MSGH_BITS(reply ? MACH_MSG_TYPE_MOVE_SEND_ONCE : MACH_MSG_TYPE_COPY_SEND, reply ? 0 : MACH_MSG_TYPE_MAKE_SEND_ONCE);
    message.header.msgh_size = (mach_msg_size_t)((offsetof(wire_message, bytes) + count + 3u) & ~3u);
    message.header.msgh_remote_port = destination; message.header.msgh_local_port = receive;
    message.header.msgh_id = reply ? AP_MACH_REPLY : AP_MACH_REQUEST;
    message.count = (uint32_t)count; memcpy(message.bytes, bytes, count);
    int error = (int)mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, message.header.msgh_size, 0, MACH_PORT_NULL, 250, MACH_PORT_NULL);
    // On a failed send Mach has pseudo-received owned header rights back into the
    // message. Destroy that returned message instead of guessing a port name.
    if (error) mach_msg_destroy(&message.header);
    memset_s(&message, sizeof(message), 0, sizeof(message)); return error;
}
int ap_mach_send_request(const char *name, const void *bytes, size_t count, uint32_t *reply_receive) {
    mach_port_t destination = MACH_PORT_NULL, receive = MACH_PORT_NULL;
    int error = (int)bootstrap_look_up(bootstrap_port, name, &destination);
    if (error || !MACH_PORT_VALID(destination)) return ENOENT;
    error = (int)mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive);
    if (!error) error = send_message(destination, receive, bytes, count, 0);
    (void)mach_port_deallocate(mach_task_self(), destination);
    if (error) ap_mach_drop_receive(receive); else *reply_receive = receive;
    return error;
}
int ap_mach_send_reply(uint32_t send_once, const void *bytes, size_t count) { return send_message(send_once, MACH_PORT_NULL, bytes, count, 1); }
int ap_mach_receive(uint32_t receive, int reply, int timeout_ms, ap_mach_message *out) {
    (void)memset_s(out, sizeof(*out), 0, sizeof(*out));
    receive_buffer buffer = {0}; mach_msg_header_t *header = (mach_msg_header_t *)buffer.bytes;
    mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
    int error = (int)mach_msg(header, options, 0, sizeof(buffer.bytes), receive, (mach_msg_timeout_t)(timeout_ms < 0 ? 0 : timeout_ms), MACH_PORT_NULL);
    if (error) {
        // RCV_TOO_LARGE without MACH_RCV_LARGE consumes and destroys the oversized
        // message in the kernel. Partial-copyout errors may leave owned rights.
        if (error != MACH_RCV_TIMED_OUT && error != MACH_RCV_TOO_LARGE && header->msgh_size >= sizeof(*header)) mach_msg_destroy(header);
        (void)memset_s(&buffer, sizeof(buffer), 0, sizeof(buffer));
        return error == MACH_RCV_TIMED_OUT ? ETIMEDOUT : (error == MACH_RCV_TOO_LARGE ? EMSGSIZE : EIO);
    }
    wire_message *message = (wire_message *)buffer.bytes;
    size_t prefix = offsetof(wire_message, bytes), size = header->msgh_size;
    int invalid = (header->msgh_bits & MACH_MSGH_BITS_COMPLEX) || header->msgh_id != (reply ? AP_MACH_REPLY : AP_MACH_REQUEST) ||
        header->msgh_voucher_port != MACH_PORT_NULL ||
        MACH_MSGH_BITS_LOCAL(header->msgh_bits) != (reply ? MACH_MSG_TYPE_PORT_SEND_ONCE : MACH_MSG_TYPE_PORT_SEND) ||
        size < prefix || size > sizeof(wire_message);
    if (!invalid) invalid = !message->count || message->count > AP_FRAME_BYTES || size != ((prefix + message->count + 3u) & ~3u);
    if (!invalid) invalid = reply ? (header->msgh_remote_port != MACH_PORT_NULL || MACH_MSGH_BITS_REMOTE(header->msgh_bits) != 0) :
        (!MACH_PORT_VALID(header->msgh_remote_port) || MACH_MSGH_BITS_REMOTE(header->msgh_bits) != MACH_MSG_TYPE_PORT_SEND_ONCE);
    mach_msg_audit_trailer_t trailer; size_t trailer_offset = (size + 3u) & ~3u;
    if (!invalid && trailer_offset + sizeof(trailer) <= sizeof(buffer.bytes)) {
        memcpy(&trailer, buffer.bytes + trailer_offset, sizeof(trailer));
        invalid = trailer.msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 || trailer.msgh_trailer_size < sizeof(trailer);
    } else invalid = 1;
    if (invalid) { mach_msg_destroy(header); memset_s(&buffer, sizeof(buffer), 0, sizeof(buffer)); return EPROTO; }
    out->token = trailer.msgh_audit; out->reply_right = header->msgh_remote_port; out->count = message->count;
    memcpy(out->bytes, message->bytes, message->count);
    memset_s(&buffer, sizeof(buffer), 0, sizeof(buffer)); return 0;
}
const uint8_t *ap_mach_bytes(const ap_mach_message *message) { return message->bytes; }
int ap_port_count(void) {
    mach_port_name_array_t names = NULL; mach_port_type_array_t types = NULL; mach_msg_type_number_t n = 0, t = 0;
    if (mach_port_names(mach_task_self(), &names, &n, &types, &t)) return -1;
    vm_deallocate(mach_task_self(), (vm_address_t)names, n * sizeof(*names));
    vm_deallocate(mach_task_self(), (vm_address_t)types, t * sizeof(*types)); return (int)n;
}
// Intentionally malformed messages for the real-process adversarial tests only.
int ap_mach_test_invalid(const char *name, int kind) {
    mach_port_t destination = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, name, &destination) || !MACH_PORT_VALID(destination)) return ENOENT;
    union { wire_message plain; struct { mach_msg_header_t header; mach_msg_body_t body; mach_msg_port_descriptor_t descriptor; } complex;
        struct { mach_msg_header_t header; mach_msg_body_t body; mach_msg_ool_descriptor_t descriptor; } ool; } message = {0};
    mach_port_t extra = MACH_PORT_NULL;
    mach_msg_header_t *header = &message.plain.header;
    header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0); header->msgh_remote_port = destination; header->msgh_id = AP_MACH_REQUEST;
    uint8_t public_marker[16] = {0};
    if (kind == 2) { // receiver must destroy the kernel-mapped OOL region too
        header->msgh_bits |= MACH_MSGH_BITS_COMPLEX; header->msgh_size = sizeof(message.ool);
        message.ool.body.msgh_descriptor_count = 1; message.ool.descriptor.address = public_marker;
        message.ool.descriptor.size = sizeof(public_marker); message.ool.descriptor.copy = MACH_MSG_VIRTUAL_COPY;
        message.ool.descriptor.type = MACH_MSG_OOL_DESCRIPTOR;
    } else if (kind == 1) { // real transferred descriptor must be destroyed by receiver
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &extra)) return EIO;
        header->msgh_bits |= MACH_MSGH_BITS_COMPLEX; header->msgh_size = sizeof(message.complex);
        message.complex.body.msgh_descriptor_count = 1; message.complex.descriptor.name = extra;
        message.complex.descriptor.disposition = MACH_MSG_TYPE_MAKE_SEND; message.complex.descriptor.type = MACH_MSG_PORT_DESCRIPTOR;
    } else { header->msgh_size = sizeof(wire_message); message.plain.count = AP_FRAME_BYTES + 1; }
    int error = (int)mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, header->msgh_size, 0, MACH_PORT_NULL, 250, MACH_PORT_NULL);
    if (error) mach_msg_destroy(header);
    (void)mach_port_deallocate(mach_task_self(), destination); ap_mach_drop_receive(extra); return error;
}
