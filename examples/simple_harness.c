/* Simple reference harness for libnetdiag (P3)
 * Demonstrates: create, feed_input_with_ts, process, next_event, get_stats, event_to_string.
 * Caller owns all I/O and timestamps (as required by architecture).
 */
#include "netdiag.h"
#include <stdio.h>
#include <stdint.h>

int main(void) {
    /* Ping example */
    ping_ctx *p = ping_create_with_config(NETDIAG_ROLE_REQUESTER,
        &(netdiag_config_t){.event_queue_size = 16});
    if (!p) return 1;

    /* Simulate sending a probe and receiving a reply with timestamps */
    uint8_t reply[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2a};
    ping_feed_input_with_ts(p, reply, sizeof(reply), 1000);
    ping_process(p, 1012);

    netdiag_event_t ev;
    while (ping_next_event(p, &ev) > 0) {
        char buf[128];
        ping_event_to_string(&ev, buf, sizeof(buf));
        printf("PING EVENT: %s\n", buf);
    }

    netdiag_stats_t stats;
    ping_get_stats(p, &stats);
    printf("PING STATS: replies=%u avg_lat=%u\n", stats.replies, stats.avg_latency_ms);

    ping_destroy(p);

    /* Traceroute placeholder */
    traceroute_ctx *t = traceroute_create(NETDIAG_ROLE_REQUESTER);
    traceroute_destroy(t);

    printf("libnetdiag simple harness finished\n");
    return 0;
}