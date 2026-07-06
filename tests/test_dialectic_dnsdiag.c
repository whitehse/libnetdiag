#include "netdiag.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

/* Minimal DNS response (QR=1, ID in first 2 bytes) */
static uint8_t dns_response[] = {
    0x00,0x01, /* ID */
    0x81,0x80, /* flags: response, recursion */
    0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 /* counts */
};

int main(void) {
    dnsdiag_ctx *requester = dnsdiag_create(NETDIAG_ROLE_REQUESTER);
    dnsdiag_ctx *responder = dnsdiag_create(NETDIAG_ROLE_RESPONDER);
    assert(requester && responder);

    int r = dnsdiag_feed_input(requester, dns_response, sizeof(dns_response));
    assert(r == 0);

    netdiag_event_t ev;
    int got = dnsdiag_next_event(requester, &ev);
    assert(got == 1);
    assert(ev.type == NETDIAG_EVENT_DNS_REPLY);

    dnsdiag_destroy(requester);
    dnsdiag_destroy(responder);

    printf("libnetdiag dialectic dnsdiag test PASSED\n");
    return 0;
}