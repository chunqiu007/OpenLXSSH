// P1-04B feasibility only, NOT the Askpass authentication protocol.
// Only public markers cross this channel. No password/input/answer is accepted.
#include <mach/mach.h>
#include <mach/message.h>
#include <servers/bootstrap.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define BROKER_ID "org.openlxssh.p104b.broker"
#define HELPER_ID "org.openlxssh.p104b.helper"
#ifdef P104B_HELPER
#define OWN_ID HELPER_ID
#define PEER_ID BROKER_ID
#else
#define OWN_ID BROKER_ID
#define PEER_ID HELPER_ID
#endif

typedef struct {
    mach_msg_header_t header;
    uint32_t public_marker;
    int32_t claimed_pid; // Deliberately false, never used for authorization.
} probe_message;
typedef union {
    uint64_t alignment;
    unsigned char bytes[sizeof(probe_message) + MAX_TRAILER_SIZE];
} receive_buffer;

static volatile sig_atomic_t stopping;
static void stop_signal(int value) { (void)value; stopping = 1; }
static void signals(void) {
    struct sigaction action = {0}; action.sa_handler = stop_signal; sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL);
}
static int bsd(pid_t pid, struct proc_bsdinfo *info) {
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, sizeof(*info)) == sizeof(*info) &&
        info->pbi_status != SZOMB && !(info->pbi_flags & PROC_FLAG_INEXIT);
}
static int unchanged(const struct proc_bsdinfo *a, const struct proc_bsdinfo *b) {
    return a->pbi_pid == b->pbi_pid && a->pbi_ppid == b->pbi_ppid && a->pbi_uid == b->pbi_uid &&
        a->pbi_ruid == b->pbi_ruid && a->pbi_start_tvsec == b->pbi_start_tvsec && a->pbi_start_tvusec == b->pbi_start_tvusec;
}
static int same_process(const struct proc_bsdinfo *expected) {
    struct proc_bsdinfo current = {0};
    return bsd((pid_t)expected->pbi_pid, &current) && unchanged(expected, &current);
}
static int make_requirement(const char *team, const char *identifier, SecRequirementRef *requirement) {
    CFStringRef string = CFStringCreateWithFormat(NULL, NULL,
        CFSTR("anchor apple generic and certificate leaf[subject.OU] = \"%s\" and identifier \"%s\""), team, identifier);
    OSStatus result = SecRequirementCreateWithString(string, kSecCSDefaultFlags, requirement);
    CFRelease(string); return (int)result;
}
static int trust_root(char team[11]) {
    SecCodeRef own = NULL; SecRequirementRef apple = NULL; CFDictionaryRef info = NULL;
    CFStringRef policy = CFStringCreateWithFormat(NULL, NULL, CFSTR("anchor apple generic and identifier \"%s\""), OWN_ID);
    int error = (int)SecRequirementCreateWithString(policy, kSecCSDefaultFlags, &apple);
    CFRelease(policy);
    if (!error) error = (int)SecCodeCopySelf(kSecCSDefaultFlags, &own);
    if (!error) error = (int)SecCodeCheckValidity(own, kSecCSDefaultFlags, apple);
    if (!error) error = (int)SecCodeCopySigningInformation(own, kSecCSSigningInformation, &info);
    if (!error) {
        CFStringRef value = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
        CFNumberRef flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
        CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
        int32_t bits = 0;
        if (!value || !CFStringGetCString(value, team, 11, kCFStringEncodingASCII) || strlen(team) != 10 ||
            !flags || !CFNumberGetValue(flags, kCFNumberSInt32Type, &bits) || !(bits & kSecCodeSignatureRuntime) ||
            (entitlements && CFDictionaryGetCount(entitlements))) error = -1;
        for (int i = 0; !error && i < 10; i++) if (!((team[i] >= 'A' && team[i] <= 'Z') || (team[i] >= '0' && team[i] <= '9'))) error = -1;
    }
    if (info) CFRelease(info); if (own) CFRelease(own); if (apple) CFRelease(apple);
    // Team/signing subject/hash are never logged. Nothing comes from env/IPC.
    return error;
}
static int validate_attributes(CFDictionaryRef attributes, const char *team, const char *identifier) {
    SecRequirementRef requirement = NULL; SecCodeRef code = NULL;
    int error = make_requirement(team, identifier, &requirement);
    if (!error) error = (int)SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    if (!error) error = (int)SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    if (!error) {
        CFDictionaryRef info = NULL;
        error = (int)SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
        if (!error) {
            int32_t bits = 0;
            CFNumberRef flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
            CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
            if (!flags || !CFNumberGetValue(flags, kCFNumberSInt32Type, &bits) || !(bits & kSecCodeSignatureRuntime) ||
                (entitlements && CFDictionaryGetCount(entitlements))) error = -2;
        }
        if (info) CFRelease(info);
    }
    if (code) CFRelease(code); if (requirement) CFRelease(requirement);
    return error;
}
static int validate_token(audit_token_t token, const char *team, const char *identifier) {
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
    const void *keys[] = {kSecGuestAttributeAudit}, *values[] = {data};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int error = validate_attributes(attributes, team, identifier);
    CFRelease(attributes); CFRelease(data); return error;
}
// Diagnostic only: proves the current post-exec PID refers to a different image.
// This function's success is NEVER used to authorize a message or response.
static int current_pid_is_broker(pid_t pid, const char *team) {
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
    const void *keys[] = {kSecGuestAttributePid}, *values[] = {number};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int error = validate_attributes(attributes, team, BROKER_ID);
    CFRelease(attributes); CFRelease(number); return !error;
}
static int receive_one(mach_port_t port, probe_message *message, audit_token_t *token) {
    receive_buffer buffer = {0};
    mach_msg_header_t *header = (mach_msg_header_t *)buffer.bytes;
    mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_TIMEOUT |
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
    kern_return_t result = mach_msg(header, options, 0, sizeof(buffer.bytes), port, 1500, MACH_PORT_NULL);
    if (result) return (int)result;
    if ((header->msgh_bits & MACH_MSGH_BITS_COMPLEX) || header->msgh_size != sizeof(probe_message)) { mach_msg_destroy(header); return -3; }
    size_t offset = (header->msgh_size + 3u) & ~3u;
    if (offset + sizeof(mach_msg_audit_trailer_t) > sizeof(buffer.bytes)) { mach_msg_destroy(header); return -4; }
    mach_msg_audit_trailer_t trailer; memcpy(&trailer, buffer.bytes + offset, sizeof(trailer));
    if (trailer.msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 || trailer.msgh_trailer_size < sizeof(trailer)) { mach_msg_destroy(header); return -5; }
    memcpy(message, buffer.bytes, sizeof(*message)); *token = trailer.msgh_audit; return 0;
}
static int send_one(mach_port_t destination, mach_port_t reply, int is_reply) {
    probe_message message = {0};
    message.header.msgh_bits = MACH_MSGH_BITS(is_reply ? MACH_MSG_TYPE_MOVE_SEND_ONCE : MACH_MSG_TYPE_COPY_SEND,
        is_reply ? 0 : MACH_MSG_TYPE_MAKE_SEND_ONCE);
    message.header.msgh_size = sizeof(message); message.header.msgh_remote_port = destination;
    message.header.msgh_local_port = reply; message.header.msgh_id = is_reply ? 42 : 41;
    message.public_marker = 0x50423034; message.claimed_pid = -12345;
    int code = (int)mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(message), 0, MACH_PORT_NULL, 500, MACH_PORT_NULL);
    if (code && is_reply) (void)mach_port_deallocate(mach_task_self(), destination);
    return code;
}
static void release_receive(mach_port_t receive) { (void)mach_port_mod_refs(mach_task_self(), receive, MACH_PORT_RIGHT_RECEIVE, -1); }
static int child_wait(pid_t child, int *status, unsigned attempts) {
    for (unsigned i = 0; i < attempts; i++) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 1;
        if (result < 0 && errno != EINTR) return 0;
        usleep(10000);
    }
    return 0;
}
static int spawn_process(const char *path, char *const argv[], int suspended, int new_session, pid_t *child) {
    posix_spawnattr_t attr; posix_spawn_file_actions_t actions;
    int code = posix_spawnattr_init(&attr); if (code) return code;
    code = posix_spawn_file_actions_init(&actions);
    if (code) { posix_spawnattr_destroy(&attr); return code; }
    // Explicitly retain only stdio: no inherited rendezvous FD or Mach endpoint.
    code = posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDOUT_FILENO);
    if (!code) code = posix_spawn_file_actions_adddup2(&actions, STDERR_FILENO, STDERR_FILENO);
    if (code) { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr); return code; }
    short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    if (suspended) flags |= POSIX_SPAWN_START_SUSPENDED;
    if (new_session) flags |= POSIX_SPAWN_SETSID;
    sigset_t defaults, mask; sigfillset(&defaults); sigemptyset(&mask);
    code = posix_spawnattr_setflags(&attr, flags);
    if (!code) code = posix_spawnattr_setsigdefault(&attr, &defaults);
    if (!code) code = posix_spawnattr_setsigmask(&attr, &mask);
    char *environment[] = {"PATH=/usr/bin:/bin", NULL};
    if (!code) code = posix_spawn(child, path, &actions, &attr, argv, environment);
    posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr); return code;
}
static int own_path(char path[4096]) { uint32_t size = 4096; return _NSGetExecutablePath(path, &size); }
static int standby(void) { signals(); for (int i = 0; i < 300 && !stopping; i++) usleep(10000); return 0; }
static int parent(const char *name, const char *helper, const char *mode, const char *broker) {
    signals();
    char *arguments[] = {(char *)helper, "--send", (char *)name, (char *)mode, (char *)broker, NULL};
    pid_t child = -1;
    int code = spawn_process(helper, arguments, 0, 0, &child); if (code) return 30;
    int status = 0;
    for (int i = 0; i < 300; i++) {
        if (waitpid(child, &status, WNOHANG) == child) return WIFEXITED(status) ? WEXITSTATUS(status) : 31;
        if (stopping) kill(child, SIGTERM);
        usleep(10000);
    }
    kill(child, SIGKILL); if (!child_wait(child, &status, 50)) return 32;
    return 33;
}
static int client(const char *name, const char *mode, const char *broker_path) {
    char team[11] = {0};
    if (trust_root(team)) return 40;
    mach_port_t destination = MACH_PORT_NULL, reply = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, name, &destination) || !MACH_PORT_VALID(destination)) return 41;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply)) { mach_port_deallocate(mach_task_self(), destination); return 42; }
    int code = send_one(destination, reply, 0); mach_port_deallocate(mach_task_self(), destination);
    if (!code && !strcmp(mode, "queued-exec")) {
        release_receive(reply);
        char *arguments[] = {(char *)broker_path, "--standby", NULL}; char *env[] = {"PATH=/usr/bin:/bin", NULL};
        execve(broker_path, arguments, env); return 43;
    }
    if (!code) {
        probe_message response; audit_token_t token = INVALID_AUDIT_TOKEN_VALUE;
        code = receive_one(reply, &response, &token);
        if (!code) {
            int signature = validate_token(token, team, PEER_ID);
            int valid = audit_token_to_euid(token) == getuid() && audit_token_to_ruid(token) == getuid() &&
                response.header.msgh_id == 42 && response.public_marker == 0x50423034 && !signature;
            printf("reply trailer_identity_used=1 body_identity_ignored=1 peer_signature_ok=%d\n", !signature);
            if (!strcmp(mode, "fake-broker")) code = valid ? 44 : 0;
            else if (!valid) code = 45;
        }
    }
    release_receive(reply); return code;
}
static int server(const char *helper_path, const char *mode) {
    signals(); char team[11] = {0}, path[4096];
    if (trust_root(team) || own_path(path)) return 50;
    uint8_t random[16]; if (SecRandomCopyBytes(kSecRandomDefault, sizeof(random), random)) return 51;
    name_t name = {0}; size_t offset = (size_t)snprintf(name, sizeof(name), "org.openlxssh.p104b.%d.", getpid());
    for (size_t i = 0; i < sizeof(random); i++) offset += (size_t)snprintf(name + offset, sizeof(name) - offset, "%02x", random[i]);
    mach_port_t receive = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive)) return 52;
    if (mach_port_insert_right(mach_task_self(), receive, receive, MACH_MSG_TYPE_MAKE_SEND)) { release_receive(receive); return 53; }
    kern_return_t registered = bootstrap_register(bootstrap_port, name, receive);
    printf("service_name=%s register_ok=%d self_apple_team_runtime_ok=1\n", name, !registered);
    if (registered) { release_receive(receive); mach_port_deallocate(mach_task_self(), receive); return 54; }
    pid_t controlled = -1, outsider = -1; struct proc_bsdinfo registered_parent = {0};
    char *arguments[] = {path, "--parent", name, (char *)helper_path, (char *)mode, path, NULL};
    int wrong_parent = !strcmp(mode, "wrong-parent");
    char *hold[] = {path, "--standby", NULL};
    int code = spawn_process(path, wrong_parent ? hold : arguments, 1, 1, &controlled);
    if (!code && (!bsd(controlled, &registered_parent) || registered_parent.pbi_ppid != (uint32_t)getpid() ||
        registered_parent.pbi_uid != getuid() || registered_parent.pbi_ruid != getuid())) code = 55;
    if (!code) kill(controlled, SIGCONT);
    if (!code && wrong_parent) {
        char *external[] = {(char *)helper_path, "--send", name, "normal", path, NULL};
        code = spawn_process(helper_path, external, 0, 1, &outsider);
    }
    if (!code) {
        probe_message request; audit_token_t token = INVALID_AUDIT_TOKEN_VALUE;
        code = receive_one(receive, &request, &token);
        if (!code) {
            pid_t pid = audit_token_to_pid(token); struct proc_bsdinfo before = {0}, after = {0};
            int helper_alive = bsd(pid, &before);
            if (!strcmp(mode, "queued-exec")) {
                int current_broker = 0;
                for (int i = 0; i < 100 && !current_broker; i++) { current_broker = current_pid_is_broker(pid, team); if (!current_broker) usleep(10000); }
                int frozen_token_matches_new_image = !validate_token(token, team, BROKER_ID);
                printf("queued_exec current_pid_is_new_broker_image=%d frozen_token_matches_new_image=%d\n", current_broker, frozen_token_matches_new_image);
                if (!current_broker || frozen_token_matches_new_image) code = 56;
            }
            int signature = validate_token(token, team, PEER_ID);
            int belongs = helper_alive && before.pbi_ppid == (uint32_t)controlled && same_process(&registered_parent) &&
                bsd(pid, &after) && unchanged(&before, &after);
            int valid = !code && audit_token_to_euid(token) == getuid() && audit_token_to_ruid(token) == getuid() &&
                belongs && !signature && request.header.msgh_id == 41 && request.public_marker == 0x50423034;
            printf("request trailer_identity_used=1 body_identity_ignored=1 parent_registered_and_live=%d peer_signature_ok=%d audit_validation_status=%d\n", belongs, !signature, signature);
            int expected_reject = wrong_parent || !strcmp(mode, "wrong-identifier") || !strcmp(mode, "queued-exec");
            int malicious_broker = !strcmp(mode, "fake-broker");
            if ((expected_reject && valid) || (!expected_reject && !malicious_broker && !valid)) code = 57;
            if (!code && (valid || malicious_broker)) code = send_one(request.header.msgh_remote_port, MACH_PORT_NULL, 1);
            else if (MACH_PORT_VALID(request.header.msgh_remote_port)) mach_port_deallocate(mach_task_self(), request.header.msgh_remote_port);
            if (!code && expected_reject) printf("PASS rejected_before_response=1\n");
        }
    }
    // Keep our child unreaped (and its PID reserved) throughout all message checks.
    // End only our dedicated session group; parent reaps helper on SIGTERM.
    int status = 0, reaped = 0;
    if (controlled > 0) {
        if (!strcmp(mode, "normal") || !strcmp(mode, "fake-broker")) reaped = child_wait(controlled, &status, 50);
        if (!reaped) {
            kill(-controlled, SIGTERM); kill(controlled, SIGCONT);
            for (int i = 0; i < 30; i++) {
                siginfo_t info = {0};
                if (!waitid(P_PID, (id_t)controlled, &info, WEXITED | WNOHANG | WNOWAIT) && info.si_pid == controlled) break;
                usleep(10000);
            }
            // Still unreaped: no PID/PGID reuse between this escalation and waitpid.
            kill(-controlled, SIGKILL); reaped = child_wait(controlled, &status, 50);
        }
        if (!reaped) code = 58;
        if (!code && (!strcmp(mode, "normal") || !strcmp(mode, "fake-broker")) && (!WIFEXITED(status) || WEXITSTATUS(status))) code = 59;
    }
    if (outsider > 0) { kill(-outsider, SIGTERM); if (!child_wait(outsider, &status, 30)) { kill(-outsider, SIGKILL); if (!child_wait(outsider, &status, 50)) code = 60; } }
    release_receive(receive); mach_port_deallocate(mach_task_self(), receive);
    kern_return_t lookup = BOOTSTRAP_SUCCESS;
    for (int i = 0; i < 50; i++) {
        mach_port_t found = MACH_PORT_NULL; lookup = bootstrap_look_up(bootstrap_port, name, &found);
        if (MACH_PORT_VALID(found)) mach_port_deallocate(mach_task_self(), found);
        if (lookup == BOOTSTRAP_UNKNOWN_SERVICE) break; usleep(10000);
    }
    printf("cleanup_name_unknown=%d controlled_parent_reaped=%d\n", lookup == BOOTSTRAP_UNKNOWN_SERVICE, reaped);
    if (!code && lookup != BOOTSTRAP_UNKNOWN_SERVICE) code = 61;
    if (!code) printf("PASS Mach-feasibility scenario=%s\n", mode);
    return code;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--standby")) return standby();
    if (argc == 6 && !strcmp(argv[1], "--parent")) return parent(argv[2], argv[3], argv[4], argv[5]);
    if (argc == 5 && !strcmp(argv[1], "--send")) return client(argv[2], argv[3], argv[4]);
    if (argc == 4 && !strcmp(argv[1], "--receive")) return server(argv[2], argv[3]);
    return 64;
}
