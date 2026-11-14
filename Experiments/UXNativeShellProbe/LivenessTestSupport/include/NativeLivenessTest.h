#ifndef OPENLXSSH_NATIVE_LIVENESS_TEST_H
#define OPENLXSSH_NATIVE_LIVENESS_TEST_H
#include <stdint.h>
#include <libssh2.h>
/* Standalone readonly consumer metadata. No libssh2 private state or production API changes. */
int ns_test_tcp_source_port(void);
int ns_test_descriptor_count(void);
int ns_test_instrumented(void);
int ns_test_extra_channels(void);
int ns_test_real_open_code(void);
int ns_test_real_rejections(void);
int ns_test_session_freed(void);
int ns_test_thread_violation(void);
LIBSSH2_CHANNEL *ns_test_channel_open_ex(LIBSSH2_SESSION *, const char *, unsigned int,
    unsigned int, unsigned int, const char *, unsigned int);
int ns_test_session_free(LIBSSH2_SESSION *);
#endif
