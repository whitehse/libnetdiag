#include "netdiag.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct arping_ctx {
    netdiag_role_t role;
    size_t queue_size;
    int state;
    uint32_t last_seq; /* repurposed as transaction id or seq */
    uint8_t last_mac[6];
};

arping_ctx *arping_create(netdiag_role_t role) {
    return arping_create_with_config(role, NULL);
}

arping_ctx *arping_create_with_config(netdiag_role_t role, const netdiag_config_t *config) {
    arping_ctx *ctx = (arping_ctx *)calloc(1, sizeof(arping_ctx));
    if (!ctx) return NULL;
    ctx->role = role;
    ctx->queue_size = config ? config->event_queue_size : 8;
    ctx->state = 0;
    memset(ctx->last_mac, 0, 6);
    return ctx;
}

void arping_destroy(arping_ctx *ctx) {
    if (ctx) free(ctx);
}

void arping_reset(arping_ctx *ctx) {
    if (ctx) {
        ctx->state = 0;
        memset(ctx->last_mac, 0, 6);
    }
}

int arping_feed_input(arping_ctx *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data || len < 14) return -1; /* minimal Ethernet + ARP */

    /* Naive ARP reply detection (opcode 2 at offset ~6 in ARP header after eth) */
    /* Ethernet type 0x0806 at offset 12, ARP op at offset 20 (6+14? simplified) */
    if (len > 21 && data[12] == 0x08 && data[13] == 0x06 && data[21] == 2) {
        if (ctx->role == NETDIAG_ROLE_REQUESTER) {
            ctx->state = 1;
            memcpy(ctx->last_mac, data + 22, 6); /* simplistic */
            return 0;
        }
    }
    if (len > 21 && data[12] == 0x08 && data[13] == 0x06 && data[21] == 1) {
        if (ctx->role == NETDIAG_ROLE_RESPONDER) {
            ctx->state = 1;
            return 0;
        }
    }
    return 0;
}

int arping_next_event(arping_ctx *ctx, netdiag_event_t *event) {
    if (!ctx || !event) return -1;
    if (ctx->state == 1) {
        event->type = (ctx->role == NETDIAG_ROLE_REQUESTER) ? NETDIAG_EVENT_ARP_REPLY : NETDIAG_EVENT_NONE;
        event->seq = ctx->last_seq;
        memcpy(event->src_mac, ctx->last_mac, 6);
        ctx->state = 0;
        return 1;
    }
    event->type = NETDIAG_EVENT_NONE;
    return 0;
}