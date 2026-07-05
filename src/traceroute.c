#include "netdiag.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_Q 32
struct traceroute_ctx {
    netdiag_role_t role;
    size_t qsz;
    netdiag_event_t q[MAX_Q];
    size_t head, tail, cnt;
    uint32_t last_seq;
    uint64_t send_ts;
    int waiting;
    uint32_t replies, timeouts, dups, sum_lat, max_lat, min_lat, count_lat;
};

static void qinit(struct traceroute_ctx *c, size_t s) {
    c->qsz = s ? s : 8; if (c->qsz > MAX_Q) c->qsz = MAX_Q;
    c->head = c->tail = c->cnt = 0; c->waiting = 0;
    c->replies = c->timeouts = c->dups = c->sum_lat = c->max_lat = c->count_lat = 0;
    c->min_lat = ~0U;
}

static int qpush(struct traceroute_ctx *c, const netdiag_event_t *e) {
    if (c->cnt >= c->qsz) return -1;
    c->q[c->tail] = *e; c->tail = (c->tail + 1) % c->qsz; c->cnt++; return 0;
}

static int qpop(struct traceroute_ctx *c, netdiag_event_t *e) {
    if (c->cnt == 0) return 0;
    *e = c->q[c->head]; c->head = (c->head + 1) % c->qsz; c->cnt--; return 1;
}

traceroute_ctx *traceroute_create(netdiag_role_t role) { return traceroute_create_with_config(role, NULL); }

traceroute_ctx *traceroute_create_with_config(netdiag_role_t role, const netdiag_config_t *cfg) {
    struct traceroute_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->role = role;
    qinit(c, cfg ? cfg->event_queue_size : 8);
    return (traceroute_ctx *)c;
}

void traceroute_destroy(traceroute_ctx *ctx) { free(ctx); }

void traceroute_reset(traceroute_ctx *ctx) {
    struct traceroute_ctx *c = (struct traceroute_ctx *)ctx;
    if (c) qinit(c, c->qsz);
}

int traceroute_feed_input(traceroute_ctx *ctx, const uint8_t *d, size_t l) {
    return traceroute_feed_input_with_ts(ctx, d, l, 0);
}

int traceroute_feed_input_with_ts(traceroute_ctx *ctx, const uint8_t *d, size_t l, uint64_t ts) {
    struct traceroute_ctx *c = (struct traceroute_ctx *)ctx;
    if (!c || !d) return -1;
    (void)l;
    if (ts) c->send_ts = ts;
    return 0;
}

int traceroute_process(traceroute_ctx *ctx, uint64_t ts) {
    struct traceroute_ctx *c = (struct traceroute_ctx *)ctx;
    if (!c) return -1;
    (void)ts;
    return 0;
}

int traceroute_next_event(traceroute_ctx *ctx, netdiag_event_t *e) {
    struct traceroute_ctx *c = (struct traceroute_ctx *)ctx;
    if (!c || !e) return -1;
    return qpop(c, e);
}

int traceroute_get_stats(traceroute_ctx *ctx, netdiag_stats_t *s) {
    struct traceroute_ctx *c = (struct traceroute_ctx *)ctx;
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

const char *traceroute_event_to_string(const netdiag_event_t *ev, char *buf, size_t max) {
    return netdiag_event_to_string(ev, buf, max);
}