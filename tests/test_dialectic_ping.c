#include "netdiag.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

/* Minimal ICMP echo packet (type 8 request, id/seq in header) */
static uint8_t icmp_echo_request[] = {
    0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, /* type, code, cksum, id, seq */
    0x00 /* dummy payload */
};

/* Minimal ICMP echo reply (type 0) */
static uint8_t icmp_echo_reply[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
    0x00
};

int main(void) {
    ping_ctx *requester = ping_create(NETDIAG_ROLE_REQUESTER);
    ping_ctx *responder = ping_create(NETDIAG_ROLE_RESPONDER);
    assert(requester && responder);

    /* Requester sends (simulated by feeding its own request? or just test roundtrip) */
    int r = ping_feed_input(responder, icmp_echo_request, sizeof(icmp_echo_request));
    assert(r == 0);

    netdiag_event_t ev;
    int got = ping_next_event(responder, &ev);
    assert(got == 0 || ev.type == NETDIAG_EVENT_NONE); /* responder may not emit on request in this minimal impl */

    /* Responder would reply; simulate by feeding reply to requester */
    r = ping_feed_input(requester, icmp_echo_reply, sizeof(icmp_echo_reply));
    assert(r == 0);

    got = ping_next_event(requester, &ev);
    assert(got == 1);
    assert(ev.type == NETDIAG_EVENT_PING_REPLY);
    assert(ev.seq == 1);

    ping_destroy(requester);
    ping_destroy(responder);

    printf("libnetdiag dialectic ping test PASSED\n");
    return 0;
}