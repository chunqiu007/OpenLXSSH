#include "NativeLivenessTest.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>

/* Instrumented test object ONLY. This file is never linked into normal/DROP consumers.
 * The frozen Bridge.c test object alone is compiled with public open/free symbol remapping.
 * No vendor changes, packet construction, startup requests or second SSH connection. */
static LIBSSH2_SESSION *owner;
static atomic_flag in_call = ATOMIC_FLAG_INIT;
static LIBSSH2_CHANNEL *occupied[7];
static int next_slot;
static atomic_int count;
static atomic_int code;
static atomic_int rejections;
static atomic_int freed;
static atomic_int violation;
int ns_test_instrumented(void) { return 1; }
int ns_test_extra_channels(void) { return atomic_load(&count); }
int ns_test_real_open_code(void) { return atomic_load(&code); }
int ns_test_real_rejections(void) { return atomic_load(&rejections); }
int ns_test_session_freed(void) { return atomic_load(&freed); }
int ns_test_thread_violation(void) { return atomic_load(&violation); }
LIBSSH2_CHANNEL *ns_test_channel_open_ex(LIBSSH2_SESSION *session, const char *type, unsigned int length,
    unsigned int window, unsigned int packet, const char *message, unsigned int message_length) {
    if(atomic_flag_test_and_set(&in_call)) { atomic_store(&violation, 1); return NULL; }
    if(!owner) owner = session;
    if(owner != session) { atomic_store(&violation, 1); atomic_flag_clear(&in_call); return NULL; }
    const int helper = length == 7 && memcmp(type, "session", 7) == 0 && window == 1024 && packet == 1024 && !message && !message_length;
    if(helper) {
        /* Every EAGAIN resumes this exact slot with stable parameters. Once seven slots are
         * confirmed no later helper retries can restart the sequence or allocate more slots. */
        while(next_slot < 7) {
            LIBSSH2_CHANNEL *channel = libssh2_channel_open_ex(session, "session", 7, 1024, 1024, NULL, 0);
            if(!channel) {
                atomic_store(&code, libssh2_session_last_errno(session)); atomic_flag_clear(&in_call); return NULL;
            }
            occupied[next_slot++] = channel; atomic_store(&count, next_slot);
        }
    }
    LIBSSH2_CHANNEL *result = libssh2_channel_open_ex(session, type, length, window, packet, message, message_length);
    if(helper) {
        int actual = result ? 0 : libssh2_session_last_errno(session);
        atomic_store(&code, actual);
        if(!result && actual == LIBSSH2_ERROR_CHANNEL_FAILURE) atomic_fetch_add(&rejections, 1);
        /* Code alone is not alive proof. Frozen runtime's exact source/error gate still decides. */
    }
    atomic_flag_clear(&in_call); return result;
}
int ns_test_session_free(LIBSSH2_SESSION *session) {
    if(atomic_flag_test_and_set(&in_call)) { atomic_store(&violation, 1); return LIBSSH2_ERROR_BAD_USE; }
    if(owner && owner != session) atomic_store(&violation, 1);
    /* Mature public session_free closes/frees every channel on this same owner queue. We do not
     * send seven close operations during the measured helper deadline. */
    int result = libssh2_session_free(session);
    if(result == 0 && session == owner) {
        for(int i = 0; i < 7; ++i) occupied[i] = NULL;
        atomic_store(&count, 0); atomic_store(&freed, 1);
    }
    atomic_flag_clear(&in_call); return result;
}
