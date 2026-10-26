// Host-only bounded message construction. All parsing, audit and trust checks use
// COpenLXSSHAskpass/OpenLXSSHAskpass, never an alternate transport implementation.
#include "CTransportAdversary.h"
#include "COpenLXSSHAskpass.h"
#include <Security/Security.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/notify.h>
#include <mach/mach_voucher_types.h>
#include <servers/bootstrap.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t parent_cancelled = 0;
static void parent_signal(int signal_number) { (void)signal_number; parent_cancelled = 1; }
void ap_adv_parent_signals(void) {
    struct sigaction action = {0}; action.sa_handler = parent_signal; sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGHUP, &action, NULL);
}
int ap_adv_parent_cancelled(void) { return parent_cancelled != 0; }

typedef struct { mach_msg_header_t header; uint32_t count; uint8_t bytes[AP_FRAME_BYTES + 1024]; } adversarial_wire;
typedef struct { mach_msg_header_t header; mach_msg_body_t body; mach_msg_port_descriptor_t descriptor; } port_wire;
typedef struct { mach_msg_header_t header; mach_msg_body_t body; mach_msg_ool_descriptor_t descriptor; } ool_wire;
typedef struct { mach_msg_header_t header; mach_msg_body_t body; mach_msg_ool_ports_descriptor_t descriptor; } ool_ports_wire;

static int send_invalid(mach_port_t destination, int kind, const void *payload, size_t payload_size, uint32_t *reply_out, uint32_t *extra_out) {
    if (kind < 0 || kind >= ADV_CASE_COUNT || !payload_size || payload_size > AP_FRAME_BYTES) return EINVAL;
    *reply_out = *extra_out = MACH_PORT_NULL;
    mach_port_t reply = MACH_PORT_NULL, extra = MACH_PORT_NULL, voucher = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply)) return EIO;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &extra)) { ap_mach_drop_receive(reply); return EIO; }
    union { adversarial_wire plain; port_wire port; ool_wire ool; ool_ports_wire ports; } message = {0};
    mach_msg_header_t *header = &message.plain.header;
    header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    header->msgh_remote_port = destination; header->msgh_local_port = reply;
    header->msgh_id = AP_MACH_REQUEST; header->msgh_size = (mach_msg_size_t)((offsetof(adversarial_wire, bytes) + payload_size + 3u) & ~3u);
    message.plain.count = (uint32_t)payload_size; memcpy(message.plain.bytes, payload, payload_size);
    // Descriptor storage overlaps inline payload; clear it before constructing
    // complex forms, especially deallocate (never unmap the sender's stack).
    if (kind <= ADV_OOL_PORTS) memset((uint8_t *)&message + sizeof(*header), 0, sizeof(message) - sizeof(*header));
    uint8_t public_marker[16] = {0}; mach_port_t port_list[] = {extra};
    switch (kind) {
        case ADV_COMPLEX:
            header->msgh_bits |= MACH_MSGH_BITS_COMPLEX; header->msgh_size = sizeof(*header) + sizeof(mach_msg_body_t);
            message.port.body.msgh_descriptor_count = 0; break;
        case ADV_PORT:
            header->msgh_bits |= MACH_MSGH_BITS_COMPLEX; header->msgh_size = sizeof(port_wire);
            message.port.body.msgh_descriptor_count = 1; message.port.descriptor.name = extra;
            message.port.descriptor.disposition = MACH_MSG_TYPE_MAKE_SEND; message.port.descriptor.type = MACH_MSG_PORT_DESCRIPTOR; break;
        case ADV_OOL:
            header->msgh_bits |= MACH_MSGH_BITS_COMPLEX; header->msgh_size = sizeof(ool_wire);
            message.ool.body.msgh_descriptor_count = 1; message.ool.descriptor.address = public_marker;
            message.ool.descriptor.size = sizeof(public_marker); message.ool.descriptor.copy = MACH_MSG_VIRTUAL_COPY;
            message.ool.descriptor.type = MACH_MSG_OOL_DESCRIPTOR; break;
        case ADV_OOL_PORTS:
            header->msgh_bits |= MACH_MSGH_BITS_COMPLEX; header->msgh_size = sizeof(ool_ports_wire);
            message.ports.body.msgh_descriptor_count = 1; message.ports.descriptor.address = port_list;
            message.ports.descriptor.count = 1; message.ports.descriptor.copy = MACH_MSG_VIRTUAL_COPY;
            message.ports.descriptor.disposition = MACH_MSG_TYPE_MAKE_SEND; message.ports.descriptor.type = MACH_MSG_OOL_PORTS_DESCRIPTOR; break;
        case ADV_VOUCHER: {
            union { uint64_t alignment; uint8_t bytes[sizeof(mach_voucher_attr_recipe_data_t) + 4]; } recipe = {0};
            mach_voucher_attr_recipe_t value = (mach_voucher_attr_recipe_t)recipe.bytes;
            value->key = MACH_VOUCHER_ATTR_KEY_USER_DATA; value->command = MACH_VOUCHER_ATTR_USER_DATA_STORE; value->content_size = 4;
            mach_port_t host = mach_host_self();
            int error = (int)host_create_mach_voucher(host, recipe.bytes, sizeof(recipe.bytes), &voucher);
            mach_port_deallocate(mach_task_self(), host);
            if (error) { ap_mach_drop_receive(reply); ap_mach_drop_receive(extra); return error; }
            header->msgh_voucher_port = voucher;
            header->msgh_bits |= MACH_MSGH_BITS_SET(0, 0, MACH_MSG_TYPE_COPY_SEND, 0); break;
        }
        case ADV_WRONG_ID: header->msgh_id = AP_MACH_REPLY; break;
        case ADV_NO_REPLY:
            header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0); header->msgh_local_port = MACH_PORT_NULL;
            ap_mach_drop_receive(reply); reply = MACH_PORT_NULL; break;
        case ADV_SEND_REPLY: header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND); break;
        case ADV_SHORT: header->msgh_size = sizeof(*header); break;
        case ADV_INLINE_LONG: header->msgh_size = offsetof(adversarial_wire, bytes) + AP_FRAME_BYTES + 4; break;
        case ADV_ZERO_COUNT: message.plain.count = 0; break;
        case ADV_HIGH_COUNT: message.plain.count = AP_FRAME_BYTES + 1; break;
        case ADV_SIZE_MISMATCH: message.plain.count = 5; break;
        case ADV_RECEIVE_TOO_LARGE: header->msgh_size = sizeof(message.plain); break;
    }
    int error = (int)mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, header->msgh_size, 0, MACH_PORT_NULL, 250, MACH_PORT_NULL);
    if (error) mach_msg_destroy(header);
    if (MACH_PORT_VALID(voucher)) mach_port_deallocate(mach_task_self(), voucher);
    if (error) { ap_mach_drop_receive(reply); ap_mach_drop_receive(extra); return error; }
    *reply_out = reply; *extra_out = extra; return 0;
}
int ap_adv_send_invalid(const char *name, int kind, const void *payload, size_t payload_size, uint32_t *reply, uint32_t *extra) {
    mach_port_t destination = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, name, &destination) || !MACH_PORT_VALID(destination)) return ENOENT;
    int error = send_invalid(destination, kind, payload, payload_size, reply, extra);
    mach_port_deallocate(mach_task_self(), destination); return error;
}
int ap_adv_finish_invalid(uint32_t reply, uint32_t extra, int kind) {
    int error = 0;
    if (MACH_PORT_VALID(reply)) {
        // A rejected request destroys the transferred send-once right, generating
        // this kernel notification, not an application answer or secret.
        union { uint64_t alignment; uint8_t bytes[512]; } notification = {0};
        mach_msg_header_t *header = (mach_msg_header_t *)notification.bytes;
        int received = (int)mach_msg(header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(notification.bytes), reply, kind == ADV_SEND_REPLY ? 20 : 1500, MACH_PORT_NULL);
        if (kind == ADV_SEND_REPLY ? received != MACH_RCV_TIMED_OUT : (received != 0 || header->msgh_id != MACH_NOTIFY_SEND_ONCE)) error = EPROTO;
        if (!received) mach_msg_destroy(header);
        mach_port_status_t status = {0}; mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
        if (mach_port_get_attributes(mach_task_self(), reply, MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &count) || status.mps_sorights || status.mps_srights) error = EBUSY;
        ap_mach_drop_receive(reply);
    }
    if (MACH_PORT_VALID(extra)) {
        mach_port_status_t status = {0}; mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
        if (mach_port_get_attributes(mach_task_self(), extra, MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &count) || status.mps_srights) error = EBUSY;
        ap_mach_drop_receive(extra);
    }
    return error;
}
static uint64_t virtual_size(void) {
    task_vm_info_data_t info = {0}; mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    return task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) ? 0 : info.virtual_size;
}
int ap_adv_check_local_ownership(int kind) {
    char name[128]; uint32_t listener = 0;
    if (ap_mach_start(name, sizeof(name), &listener)) return EIO;
    int error = 0;
    // One warm-up plus two measured messages per kind; never fill the queue.
    for (int index = 0; index < 3 && !error; index++) {
        int before = ap_port_count(); uint64_t vm_before = virtual_size();
        uint32_t reply = 0, extra = 0; ap_mach_message received;
        error = send_invalid(listener, kind, "{}", 2, &reply, &extra);
        if (error) break;
        int result = ap_mach_receive(listener, 0, 250, &received);
        int wanted = kind == ADV_RECEIVE_TOO_LARGE ? EMSGSIZE : EPROTO;
        int released = ap_adv_finish_invalid(reply, extra, kind);
        // Preserve cleanup even when this regression catches an unexpected
        // production acceptance; never leave the observed send-once right owned.
        if (result == 0) ap_mach_drop_reply(received.reply_right);
        if (result != wanted || released) { fprintf(stderr, "raw kind=%d receive=%d expected=%d release=%d\n", kind, result, wanted, released); error = EPROTO; }
        if (index && (ap_port_count() != before || !vm_before || virtual_size() != vm_before)) {
            fprintf(stderr, "raw ownership kind=%d index=%d ports=%d vm=%lld\n", kind, index, ap_port_count() - before, (long long)(virtual_size() - vm_before)); error = EBUSY;
        }
    }
    if (ap_mach_stop(listener, name)) error = EBUSY;
    return error;
}
int ap_adv_check_send_once(void) {
    char name[128]; uint32_t listener = 0;
    if (ap_mach_start(name, sizeof(name), &listener)) return EIO;
    int baseline = ap_port_count(), error = 0;
    const uint8_t public_marker[] = "{}";
    for (int mode = 0; mode < 3 && !error; mode++) {
        uint32_t inbox = 0; ap_mach_message request, reply;
        if (ap_mach_send_request(name, public_marker, 2, &inbox) || ap_mach_receive(listener, 0, 250, &request)) { error = EIO; break; }
        if (mode == 0) {
            if (ap_mach_send_reply(request.reply_right, public_marker, 2) || ap_mach_receive(inbox, 1, 250, &reply)) error = EPROTO;
        } else if (mode == 1) {
            // Mach silently discards a send-once message to an already-dead
            // destination on this host. The consumed right must still disappear.
            ap_mach_drop_receive(inbox); inbox = 0;
            if (ap_mach_reply_alive(request.reply_right)) error = EPROTO;
            (void)ap_mach_send_reply(request.reply_right, public_marker, 2);
        } else if (ap_mach_send_reply(request.reply_right, public_marker, AP_FRAME_BYTES + 1) != EMSGSIZE) error = EPROTO;
        ap_mach_drop_receive(inbox);
        int delta = ap_port_count() - baseline;
        if (delta != 0) error = EBUSY;
        if (error) fprintf(stderr, "sendonce mode=%d error=%d port-delta=%d\n", mode, error, delta);
    }
    if (!error) {
        // Send-once bypasses qlimit, so exercise send_message's shared failure
        // cleanup via a request: limit one, one marker, ONE request timeout.
        mach_port_limits_t limits = { .mpl_qlimit = 1 };
        if (mach_port_set_attributes(mach_task_self(), listener, MACH_PORT_LIMITS_INFO, (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT)) error = EIO;
        mach_msg_header_t marker = {0}; marker.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        marker.msgh_remote_port = listener; marker.msgh_size = sizeof(marker);
        if (mach_msg(&marker, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(marker), 0, MACH_PORT_NULL, 20, MACH_PORT_NULL)) error = EIO;
        mach_port_name_array_t names_before = NULL, names_after = NULL;
        mach_port_type_array_t types_before = NULL, types_after = NULL;
        mach_msg_type_number_t nb = 0, tb = 0, na = 0, ta = 0;
        mach_port_names(mach_task_self(), &names_before, &nb, &types_before, &tb);
        uint32_t inbox = 0;
        int sent = ap_mach_send_request(name, public_marker, 2, &inbox);
        mach_port_names(mach_task_self(), &names_after, &na, &types_after, &ta);
        if (sent != MACH_SEND_TIMED_OUT || inbox != 0 || ap_port_count() != baseline) error = EPROTO;
        if (error) {
            fprintf(stderr, "request timeout sent=%d port-delta=%d\n", sent, ap_port_count() - baseline);
            for (mach_msg_type_number_t i = 0; i < na; i++) {
                int found = 0;
                for (mach_msg_type_number_t j = 0; j < nb; j++) if (names_after[i] == names_before[j]) found = 1;
                if (!found) fprintf(stderr, "request timeout new-right type=%u\n", types_after[i]);
            }
        }
        vm_deallocate(mach_task_self(), (vm_address_t)names_before, nb * sizeof(*names_before));
        vm_deallocate(mach_task_self(), (vm_address_t)types_before, tb * sizeof(*types_before));
        vm_deallocate(mach_task_self(), (vm_address_t)names_after, na * sizeof(*names_after));
        vm_deallocate(mach_task_self(), (vm_address_t)types_after, ta * sizeof(*types_after));
    }
    if (ap_mach_stop(listener, name)) error = EBUSY;
    return error;
}
int ap_adv_current_identifier(pid_t pid, const char *identifier) {
    // Diagnostic only: show the CURRENT image passes a PID-based identifier
    // check after exec. This is never used by the broker's authorization path.
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
    const void *keys[] = {kSecGuestAttributePid}, *values[] = {number};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecCodeRef code = NULL; SecRequirementRef requirement = NULL;
    CFStringRef text = CFStringCreateWithFormat(NULL, NULL, CFSTR("anchor apple generic and identifier \"%s\""), identifier);
    int error = (int)SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement);
    if (!error) error = (int)SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    if (!error) error = (int)SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    if (code) CFRelease(code); if (requirement) CFRelease(requirement);
    CFRelease(text); CFRelease(attributes); CFRelease(number); return error;
}
