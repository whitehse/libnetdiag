#include "netdiag.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_Q 32

struct nmapdiag_ctx {
    netdiag_role_t role;
    size_t qsz;
    netdiag_event_t q[MAX_Q];
    size_t head, tail, cnt;
    uint32_t last_seq;
    uint64_t send_ts;
    int waiting;
    uint32_t replies, timeouts, dups, sum_lat, max_lat, min_lat, count_lat;
};

static void qinit(struct nmapdiag_ctx *c, size_t s) {
    c->qsz = s ? s : 8; if (c->qsz > MAX_Q) c->qsz = MAX_Q;
    c->head = c->tail = c->cnt = 0; c->waiting = 0;
    c->replies = c->timeouts = c->dups = c->sum_lat = c->max_lat = c->count_lat = 0;
    c->min_lat = ~0U;
}

static int qpush(struct nmapdiag_ctx *c, const netdiag_event_t *e) {
    if (c->cnt >= c->qsz) return -1;
    c->q[c->tail] = *e; c->tail = (c->tail + 1) % c->qsz; c->cnt++; return 0;
}

static int qpop(struct nmapdiag_ctx *c, netdiag_event_t *e) {
    if (c->cnt == 0) return 0;
    *e = c->q[c->head]; c->head = (c->head + 1) % c->qsz; c->cnt--; return 1;
}

nmapdiag_ctx *nmapdiag_create(netdiag_role_t role) { return nmapdiag_create_with_config(role, NULL); }

nmapdiag_ctx *nmapdiag_create_with_config(netdiag_role_t role, const netdiag_config_t *cfg) {
    struct nmapdiag_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->role = role;
    qinit(c, cfg ? cfg->event_queue_size : 8);
    return (nmapdiag_ctx *)c;
}

void nmapdiag_destroy(nmapdiag_ctx *ctx) { free(ctx); }

void nmapdiag_reset(nmapdiag_ctx *ctx) {
    struct nmapdiag_ctx *c = (struct nmapdiag_ctx *)ctx;
    if (c) qinit(c, c->qsz);
}

int nmapdiag_feed_input(nmapdiag_ctx *ctx, const uint8_t *d, size_t l) {
    return nmapdiag_feed_input_with_ts(ctx, d, l, 0);
}

int nmapdiag_feed_input_with_ts(nmapdiag_ctx *ctx, const uint8_t *d, size_t l, uint64_t ts) {
    struct nmapdiag_ctx *c = (struct nmapdiag_ctx *)ctx;
    if (!c || !d || l < 20) return -1;
    if (ts) c->send_ts = ts;

    /* Nmap-style: TCP SYN/ACK (port open) or RST (closed), UDP + ICMP unreachable */
    uint8_t proto = d[9];
    if (proto == 6 && c->role == NETDIAG_ROLE_REQUESTER) { /* TCP */
        uint8_t flags = d[33];
        if (flags & 0x12) { /* SYN+ACK */
            netdiag_event_t ev = {.type=NETDIAG_EVENT_PROBE_REPLY, .seq=c->last_seq};
            uint32_t lat = 5;
            if (c->send_ts && ts) lat = (ts > c->send_ts) ? (uint32_t)(ts - c->send_ts) : 0;
            ev.latency_ms = lat;
            qpush(c, &ev);
            c->replies++;
            c->sum_lat += lat; c->count_lat++;
            if (lat > c->max_lat) c->max_lat = lat;
            if (lat < c->min_lat) c->min_lat = lat;
            c->waiting = 0;
        }
    } else if (proto == 1 && (d[20] == 3 || d[20] == 11) && c->role == NETDIAG_ROLE_REQUESTER) {
        /* ICMP unreachable / time-exceeded from UDP probe */
        netdiag_event_t ev = {.type=NETDIAG_EVENT_PROBE_REPLY, .seq=c->last_seq};
        qpush(c, &ev);
        c->replies++;
        c->waiting = 0;
    }
    return 0;
}

int nmapdiag_process(nmapdiag_ctx *ctx, uint64_t ts) {
    struct nmapdiag_ctx *c = (struct nmapdiag_ctx *)ctx;
    if (!c) return -1;
    if (c->waiting && c->send_ts && ts > c->send_ts + 1000) {
        netdiag_event_t ev = {.type=NETDIAG_EVENT_FAULT_DETECTED, .seq=c->last_seq};
        snprintf(ev.reason, sizeof(ev.reason), "nmap probe timeout");
        qpush(c, &ev);
        c->timeouts++;
        c->waiting = 0;
    }
    return 0;
}

int nmapdiag_next_event(nmapdiag_ctx *ctx, netdiag_event_t *e) {
    struct nmapdiag_ctx *c = (struct nmapdiag_ctx *)ctx;
    if (!c || !e) return -1;
    return qpop(c, e);
}

int nmapdiag_get_stats(nmapdiag_ctx *ctx, netdiag_stats_t *s) {
    struct nmapdiag_ctx *c = (struct nmapdiag_ctx *)ctx;
    if (!c || !s) return -1;
    s->replies = c->replies;
    s->timeouts = c->timeouts;
    s->duplicates = c->dups;
    s->loss_pct = (c->replies + c->timeouts) ? (c->timeouts * 100) / (c->replies + c->timeouts) : 0;
    s->avg_latency_ms = c->count_lat ? c->sum_lat / c->count_lat : 0;
    s->max_latency_ms = c->max_lat;
    s->min_latency_ms = (c->min_lat == ~0U) ? 0 : c->min_lat;
    return 0;
}

const char *nmapdiag_event_to_string(const netdiag_event_t *ev, char *buf, size_t max) {
    return netdiag_event_to_string(ev, buf, max);
}