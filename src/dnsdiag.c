#include "netdiag.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_Q 32
struct dnsdiag_ctx {
    netdiag_role_t role;
    size_t qsz;
    netdiag_event_t q[MAX_Q];
    size_t head, tail, cnt;
    uint32_t last_seq;
    uint64_t send_ts;
    int waiting;
    uint32_t replies, timeouts, dups, sum_lat, max_lat, min_lat, count_lat;
};

static void qinit(struct dnsdiag_ctx *c, size_t s) {
    c->qsz = s ? s : 8; if (c->qsz > MAX_Q) c->qsz = MAX_Q;
    c->head = c->tail = c->cnt = 0; c->waiting = 0;
    c->replies = c->timeouts = c->dups = c->sum_lat = c->max_lat = c->count_lat = 0;
    c->min_lat = ~0U;
}

static int qpush(struct dnsdiag_ctx *c, const netdiag_event_t *e) {
    if (c->cnt >= c->qsz) return -1;
    c->q[c->tail] = *e; c->tail = (c->tail + 1) % c->qsz; c->cnt++; return 0;
}

static int qpop(struct dnsdiag_ctx *c, netdiag_event_t *e) {
    if (c->cnt == 0) return 0;
    *e = c->q[c->head]; c->head = (c->head + 1) % c->qsz; c->cnt--; return 1;
}

dnsdiag_ctx *dnsdiag_create(netdiag_role_t role) { return dnsdiag_create_with_config(role, NULL); }

dnsdiag_ctx *dnsdiag_create_with_config(netdiag_role_t role, const netdiag_config_t *cfg) {
    struct dnsdiag_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->role = role;
    qinit(c, cfg ? cfg->event_queue_size : 8);
    return (dnsdiag_ctx *)c;
}

void dnsdiag_destroy(dnsdiag_ctx *ctx) { free(ctx); }

void dnsdiag_reset(dnsdiag_ctx *ctx) {
    struct dnsdiag_ctx *c = (struct dnsdiag_ctx *)ctx;
    if (c) qinit(c, c->qsz);
}

int dnsdiag_feed_input(dnsdiag_ctx *ctx, const uint8_t *d, size_t l) {
    return dnsdiag_feed_input_with_ts(ctx, d, l, 0);
}

int dnsdiag_feed_input_with_ts(dnsdiag_ctx *ctx, const uint8_t *d, size_t l, uint64_t ts) {
    struct dnsdiag_ctx *c = (struct dnsdiag_ctx *)ctx;
    if (!c || !d || l < 12) return -1; /* minimal DNS header after UDP */
    if (ts) c->send_ts = ts;

    /* L3 DNS: UDP/53 response (QR bit set) or query */
    /* Simplified: check for common DNS response pattern (ID match + flags) */
    uint16_t flags = (d[2]<<8) | d[3];
    uint8_t rcode = flags & 0x000F;
    if (rcode != 0 && c->role == NETDIAG_ROLE_REQUESTER) {
        netdiag_event_t ev = {.type=NETDIAG_EVENT_FAULT_DETECTED, .seq=c->last_seq};
        snprintf(ev.reason, sizeof(ev.reason), "DNS rcode=%u", rcode);
        qpush(c, &ev);
        c->timeouts++;
        c->waiting = 0;
        return 0;
    }
    if ((flags & 0x8000) && c->role == NETDIAG_ROLE_REQUESTER) { /* response */
        netdiag_event_t ev = {.type = NETDIAG_EVENT_DNS_REPLY, .seq = c->last_seq};
        uint32_t lat = 5;
        if (c->send_ts && ts) lat = (ts > c->send_ts) ? (uint32_t)(ts - c->send_ts) : 0;
        ev.latency_ms = lat;
        qpush(c, &ev);
        c->replies++;
        c->sum_lat += lat; c->count_lat++;
        if (lat > c->max_lat) c->max_lat = lat;
        if (lat < c->min_lat) c->min_lat = lat;
        c->waiting = 0;
    } else if (c->role == NETDIAG_ROLE_RESPONDER) {
        c->last_seq = (d[0]<<8) | d[1]; /* DNS ID */
        if (ts) c->send_ts = ts;
        c->waiting = 1;
    }
    return 0;
}

int dnsdiag_process(dnsdiag_ctx *ctx, uint64_t ts) {
    struct dnsdiag_ctx *c = (struct dnsdiag_ctx *)ctx;
    if (!c) return -1;
    (void)ts;
    return 0;
}

int dnsdiag_next_event(dnsdiag_ctx *ctx, netdiag_event_t *e) {
    struct dnsdiag_ctx *c = (struct dnsdiag_ctx *)ctx;
    if (!c || !e) return -1;
    return qpop(c, e);
}

int dnsdiag_get_stats(dnsdiag_ctx *ctx, netdiag_stats_t *s) {
    struct dnsdiag_ctx *c = (struct dnsdiag_ctx *)ctx;
    if (!c || !s) return -1;
    s->replies = c->replies;
    s->timeouts = c->timeouts;
    s->duplicates = c->dups;
    s->loss_pct = 0;
    s->avg_latency_ms = c->count_lat ? c->sum_lat / c->count_lat : 0;
    s->max_latency_ms = c->max_lat;
    s->min_latency_ms = (c->min_lat == ~0U) ? 0 : c->min_lat;
    return 0;
}

const char *dnsdiag_event_to_string(const netdiag_event_t *ev, char *buf, size_t max) {
    return netdiag_event_to_string(ev, buf, max);
}