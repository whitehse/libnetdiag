#include "netdiag.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct ping_ctx {
    netdiag_role_t role;
    size_t queue_size;
    int state; /* 0 idle, 1 waiting_reply */
    uint32_t last_seq;
    uint8_t last_icmp_id[2];
};

ping_ctx *ping_create(netdiag_role_t role) {
    return ping_create_with_config(role, NULL);
}

ping_ctx *ping_create_with_config(netdiag_role_t role, const netdiag_config_t *config) {
    ping_ctx *ctx = (ping_ctx *)calloc(1, sizeof(ping_ctx));
    if (!ctx) return NULL;
    ctx->role = role;
    ctx->queue_size = config ? config->event_queue_size : 8;
    ctx->state = 0;
    ctx->last_seq = 0;
    return ctx;
}

void ping_destroy(ping_ctx *ctx) {
    if (ctx) free(ctx);
}

void ping_reset(ping_ctx *ctx) {
    if (ctx) {
        ctx->state = 0;
        ctx->last_seq = 0;
    }
}

int ping_feed_input(ping_ctx *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data || len < 8) return -1; /* minimal ICMP header */

    /* Very naive ICMP echo reply detection for bootstrap (type 0) */
    if (data[0] == 0 && ctx->role == NETDIAG_ROLE_REQUESTER) {
        ctx->state = 1;
        ctx->last_seq = (data[6] << 8) | data[7];
        return 0;
    }
    if (data[0] == 8 && ctx->role == NETDIAG_ROLE_RESPONDER) {
        /* echo request received */
        ctx->state = 1;
        ctx->last_seq = (data[6] << 8) | data[7];
        return 0;
    }
    return 0;
}

int ping_next_event(ping_ctx *ctx, netdiag_event_t *event) {
    if (!ctx || !event) return -1;
    if (ctx->state == 1) {
        event->type = (ctx->role == NETDIAG_ROLE_REQUESTER) ? NETDIAG_EVENT_PING_REPLY : NETDIAG_EVENT_NONE;
        event->seq = ctx->last_seq;
        event->latency_ms = 5; /* placeholder */
        ctx->state = 0;
        return 1;
    }
    event->type = NETDIAG_EVENT_NONE;
    return 0;
}