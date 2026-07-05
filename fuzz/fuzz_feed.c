/* libFuzzer harness for libnetdiag feed_input parsers
 * Build: clang -fsanitize=fuzzer,address -Iinclude fuzz/fuzz_feed.c \
 *        -o fuzz_feed $(find build -name libnetdiag.a)
 * Run: ./fuzz_feed corpus/ -max_len=256 -timeout=1
 */
#include "netdiag.h"
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Ping */
    ping_ctx *p = ping_create(NETDIAG_ROLE_REQUESTER);
    if (p) {
        ping_feed_input(p, data, size);
        netdiag_event_t ev;
        ping_next_event(p, &ev);
        ping_destroy(p);
    }

    /* Arping */
    arping_ctx *a = arping_create(NETDIAG_ROLE_REQUESTER);
    if (a) {
        arping_feed_input(a, data, size);
        netdiag_event_t ev;
        arping_next_event(a, &ev);
        arping_destroy(a);
    }

    /* Traceroute */
    traceroute_ctx *t = traceroute_create(NETDIAG_ROLE_REQUESTER);
    if (t) {
        traceroute_feed_input(t, data, size);
        netdiag_event_t ev;
        traceroute_next_event(t, &ev);
        traceroute_destroy(t);
    }

    return 0;
}