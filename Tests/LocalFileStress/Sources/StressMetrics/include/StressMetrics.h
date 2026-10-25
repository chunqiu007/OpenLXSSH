#ifndef OPENLXSSH_STRESS_METRICS_H
#define OPENLXSSH_STRESS_METRICS_H
#include <stdint.h>

typedef struct {
    uint64_t resident_bytes;
    uint64_t peak_resident_bytes;
    double user_cpu_seconds;
    double system_cpu_seconds;
    int32_t rss_status;
    int32_t fd_count;
    int32_t owned_fd_count;
} stress_metrics;

// Only this process is inspected. No network, process spawning, or product-private diagnostics.
stress_metrics stress_sample(const char *owned_root);
#endif
