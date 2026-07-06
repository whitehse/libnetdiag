#include "netdiag.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_Q 32

struct bwdiag_ctx {
    netdiag_role_t role;
    size_t qsz;
    netdiag_event_t q[MAX_Q];
    size_t head, tail, cnt;
    uint64_t last_ts;
    uint32_t bytes;
    uint32_t replies, timeouts, dups, sum_lat, max_lat, min_lat, count_lat;
};

static void qinit(struct bwdiag_ctx *c, size_t s) {
    c->qsz = s ? s : 8; if (c->qsz > MAX_Q) c->qsz = MAX_Q;
    c->head = c->tail = c->cnt = 0;
    c->last_ts = 0; c->bytes = 0;
    c->replies = c->timeouts = c->dups = c->sum_lat = c->max_lat = c->count_lat = 0;
    c->min_lat = ~0U;
}

static int qpush(struct bwdiag_ctx *c, const netdiag_event_t *e) {
    if (c->cnt >= c->qsz) return -1;
    c->q[c->tail] = *e; c->tail = (c->tail + 1) % c->qsz; c->cnt++; return 0;
}

static int qpop(struct bwdiag_ctx *c, netdiag_event_t *e) {
    if (c->cnt == 0) return 0;
    *e = c->q[c->head]; c->head = (c->head + 1) % c->qsz; c->cnt--; return 1;
}

bwdiag_ctx *bwdiag_create(netdiag_role_t role) { return bwdiag_create_with_config(role, NULL); }

bwdiag_ctx *bwdiag_create_with_config(netdiag_role_t role, const netdiag_config_t *cfg) {
    struct bwdiag_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->role = role;
    qinit(c, cfg ? cfg->event_queue_size : 8);
    return (bwdiag_ctx *)c;
}

void bwdiag_destroy(bwdiag_ctx *ctx) { free(ctx); }

void bwdiag_reset(bwdiag_ctx *ctx) {
    struct bwdiag_ctx *c = (struct bwdiag_ctx *)ctx;
    if (c) qinit(c, c->qsz);
}

int bwdiag_feed_input(bwdiag_ctx *ctx, const uint8_t *d, size_t l) {
    return bwdiag_feed_input_with_ts(ctx, d, l, 0);
}

int bwdiag_feed_input_with_ts(bwdiag_ctx *ctx, const uint8_t *d, size_t l, uint64_t ts) {
    struct bwdiag_ctx *c = (struct bwdiag_ctx *)ctx;
    if (!c || !d || l == 0) return -1;
    if (ts && c->last_ts) {
        uint32_t dt = (ts > c->last_ts) ? (uint32_t)(ts - c->last_ts) : 1;
        uint32_t bps = (l * 1000) / dt; /* bytes/sec estimate */
        netdiag_event_t ev = {.type=NETDIAG_EVENT_BW_SAMPLE, .seq=c->bytes, .latency_ms=bps};
        qpush(c, &ev);
        c->replies++;
        c->bytes += l;
    }
    c->last_ts = ts ? ts : c->last_ts;
    return 0;
}

int bwdiag_process(bwdiag_ctx *ctx, uint64_t ts) {
    (void)ctx; (void)ts; return 0;
}

int bwdiag_next_event(bwdiag_ctx *ctx, netdiag_event_t *e) {
    struct bwdiag_ctx *c = (struct bwdiag_ctx *)ctx;
    if (!c || !e) return -1;
    return qpop(c, e);
}

int bwdiag_get_stats(bwdiag_ctx *ctx, netdiag_stats_t *s) {
    struct bwdiag_ctx *c = (struct bwdiag_ctx *)ctx;
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

const char *bwdiag_event_to_string(const netdiag_event_t *ev, char *buf, size_t max) {
    return netdiag_event_to_string(ev, buf, max);
}