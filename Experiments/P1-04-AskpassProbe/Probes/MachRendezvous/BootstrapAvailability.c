// P1-04B step 1 only: public temporary bootstrap registration and cleanup.
// No authentication data, network, persistent launchd job or private API.
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <Security/Security.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static void release_port(mach_port_t port) {
    // Release only rights owned by this probe; do not use deprecated destroy().
    (void)mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
    (void)mach_port_deallocate(mach_task_self(), port);
}
static kern_return_t lookup_name(const char *name, const char *stage) {
    mach_port_t found = MACH_PORT_NULL;
    kern_return_t result = bootstrap_look_up(bootstrap_port, name, &found);
    mach_port_type_t type = 0;
    kern_return_t type_result = MACH_PORT_VALID(found) ? mach_port_type(mach_task_self(), found, &type) : KERN_INVALID_NAME;
    printf("%s lookup=%d (%s) valid=%d type_result=%d type=0x%x\n", stage, result, bootstrap_strerror(result), MACH_PORT_VALID(found), type_result, type);
    if (MACH_PORT_VALID(found)) (void)mach_port_deallocate(mach_task_self(), found);
    return result;
}
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--lookup")) {
        return lookup_name(argv[2], "after_process_exit") == BOOTSTRAP_UNKNOWN_SERVICE ? 0 : 6;
    }
    uint8_t random[16];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(random), random)) return 1;
    name_t name = {0};
    size_t used = (size_t)snprintf(name, sizeof(name), "org.openlxssh.p104b.%d.", getpid());
    for (size_t i = 0; i < sizeof(random); i++) used += (size_t)snprintf(name + used, sizeof(name) - used, "%02x", random[i]);
    printf("service_name=%s\n", name);
    mach_port_t receive = MACH_PORT_NULL;
    kern_return_t result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive);
    printf("mach_port_allocate=%d\n", result);
    if (result) return 2;
    result = mach_port_insert_right(mach_task_self(), receive, receive, MACH_MSG_TYPE_MAKE_SEND);
    printf("mach_port_insert_right=%d\n", result);
    if (result) { release_port(receive); return 3; }
    result = bootstrap_register(bootstrap_port, name, receive);
    printf("bootstrap_register=%d (%s)\n", result, bootstrap_strerror(result));
    if (result) { release_port(receive); return 4; }
    kern_return_t lookup = lookup_name(name, "while_registered");
    result = bootstrap_register(bootstrap_port, name, MACH_PORT_NULL);
    printf("bootstrap_unregister_via_null=%d (%s)\n", result, bootstrap_strerror(result));
    release_port(receive);
    kern_return_t after = BOOTSTRAP_SUCCESS;
    for (int attempt = 0; attempt < 20; attempt++) {
        after = lookup_name(name, "after_port_release");
        if (after == BOOTSTRAP_UNKNOWN_SERVICE) break;
        usleep(100000);
    }
    if (lookup || after != BOOTSTRAP_UNKNOWN_SERVICE) return 5;
    puts("PASS temporary-bootstrap-register-lookup-port-release");
    return 0;
}
