#include "netdiag.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

/* Very minimal Ethernet + ARP reply frame (opcode 2) for bootstrap */
static uint8_t arp_reply_frame[] = {
    0xff,0xff,0xff,0xff,0xff,0xff, /* dst mac */
    0x00,0x11,0x22,0x33,0x44,0x55, /* src mac */
    0x08,0x06, /* eth type ARP */
    /* ARP header (simplified for test) */
    0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x02, /* htype, ptype, hlen, plen, opcode=2 reply */
    0x00,0x11,0x22,0x33,0x44,0x55, /* sender mac */
    0x0a,0x00,0x00,0x01, /* sender ip */
    0x00,0x00,0x00,0x00,0x00,0x00, /* target mac */
    0x0a,0x00,0x00,0x02  /* target ip */
};

int main(void) {
    arping_ctx *requester = arping_create(NETDIAG_ROLE_REQUESTER);
    arping_ctx *responder = arping_create(NETDIAG_ROLE_RESPONDER);
    assert(requester && responder);

    int r = arping_feed_input(requester, arp_reply_frame, sizeof(arp_reply_frame));
    assert(r == 0);

    netdiag_event_t ev;
    int got = arping_next_event(requester, &ev);
    assert(got == 1);
    assert(ev.type == NETDIAG_EVENT_ARP_REPLY);

    arping_destroy(requester);
    arping_destroy(responder);

    printf("libnetdiag dialectic arping test PASSED\n");
    return 0;
}