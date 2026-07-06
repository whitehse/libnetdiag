#include "netdiag.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

/* Minimal IPv4 + ICMP Time Exceeded for traceroute hop (type 11 at offset 20) */
static uint8_t icmp_time_exceeded[] = {
    /* IP header (20B) + ICMP type 11 */
    0x45,0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x40,0x01,0x00,0x00,0x0a,0x00,0x00,0x01,
    0x0a,0x00,0x00,0x02,
    0x0b,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* ICMP type 11, code 0 */
    0x45,0x00,0x00,0x1c,0x00,0x01,0x00,0x00,0x40,0x11,0x00,0x00 /* embedded */
};

int main(void) {
    traceroute_ctx *requester = traceroute_create(NETDIAG_ROLE_REQUESTER);
    traceroute_ctx *responder = traceroute_create(NETDIAG_ROLE_RESPONDER);
    assert(requester && responder);

    int r = traceroute_feed_input(requester, icmp_time_exceeded, sizeof(icmp_time_exceeded));
    assert(r == 0);

    netdiag_event_t ev;
    int got = traceroute_next_event(requester, &ev);
    assert(got == 1);
    assert(ev.type == NETDIAG_EVENT_TRACEROUTE_HOP);

    traceroute_destroy(requester);
    traceroute_destroy(responder);

    printf("libnetdiag dialectic traceroute test PASSED\n");
    return 0;
}