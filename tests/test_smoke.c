#include "netdiag.h"
#include <stdio.h>
#include <assert.h>

int main(void) {
    netdiag_ctx *ctx = netdiag_create(NETDIAG_ROLE_REQUESTER);
    assert(ctx != NULL);

    uint8_t dummy[8] = {0};
    int r = netdiag_feed_input(ctx, dummy, sizeof(dummy));
    assert(r == 0);

    netdiag_event_t ev;
    int n = netdiag_next_event(ctx, &ev);
    /* smoke just checks no crash and basic calls succeed */
    (void)n;

    netdiag_destroy(ctx);

    /* ping */
    ping_ctx *pctx = ping_create(NETDIAG_ROLE_REQUESTER);
    assert(pctx != NULL);
    ping_destroy(pctx);

    /* arping */
    arping_ctx *actx = arping_create(NETDIAG_ROLE_REQUESTER);
    assert(actx != NULL);
    arping_destroy(actx);

    /* eBPF */
    size_t cnt = netdiag_ebpf_script_count();
    assert(cnt == 2);

    printf("libnetdiag smoke test PASSED\n");
    return 0;
}