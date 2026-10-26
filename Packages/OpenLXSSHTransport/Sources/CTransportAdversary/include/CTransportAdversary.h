#ifndef C_TRANSPORT_ADVERSARY_H
#define C_TRANSPORT_ADVERSARY_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
// This entire target is absent from the shipping package graph.
enum {
    ADV_COMPLEX, ADV_PORT, ADV_OOL, ADV_OOL_PORTS, ADV_VOUCHER,
    ADV_WRONG_ID, ADV_NO_REPLY, ADV_SEND_REPLY, ADV_SHORT,
    ADV_INLINE_LONG, ADV_ZERO_COUNT, ADV_HIGH_COUNT, ADV_SIZE_MISMATCH,
    ADV_RECEIVE_TOO_LARGE, ADV_CASE_COUNT
};
int ap_adv_send_invalid(const char *, int, const void *, size_t, uint32_t *, uint32_t *);
int ap_adv_finish_invalid(uint32_t, uint32_t, int);
void ap_adv_parent_signals(void);
int ap_adv_parent_cancelled(void);
int ap_adv_check_local_ownership(int);
int ap_adv_check_send_once(void);
int ap_adv_current_identifier(pid_t, const char *);
#endif
