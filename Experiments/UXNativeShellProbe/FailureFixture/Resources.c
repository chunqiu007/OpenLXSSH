#include "NativeFailureResources.h"
#include <libproc.h>
#include <sys/types.h>
#include <unistd.h>

int nf_test_child_count(void) {
    pid_t children[1024];
    int bytes = proc_listchildpids(getpid(), children, (int)sizeof(children));
    if(bytes < 0 || (size_t)bytes >= sizeof(children) || (size_t)bytes % sizeof(pid_t)) return -1;
    return bytes / (int)sizeof(pid_t);
}
