#include "netdiag.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_Q 32
struct netdiag_ctx {
    netdiag_role_t role;
    size_t qsz;
    netdiag_event_t q[MAX_Q];
    size_t head, tail, cnt;
    uint64_t last;
    /* P1 stats */
    uint32_t replies, timeouts, dups, sum_lat, max_lat, min_lat, count_lat;
};

static void qinit(struct netdiag_ctx *c, size_t s) {
    c->qsz = s ? s : 8; if (c->qsz > MAX_Q) c->qsz = MAX_Q;
    c->head = c->tail = c->cnt = 0; c->last = 0;
    c->replies = c->timeouts = c->dups = c->sum_lat = c->max_lat = c->count_lat = 0;
    c->min_lat = ~0U;
}

static int qpush(struct netdiag_ctx *c, const netdiag_event_t *e) {
    if (c->cnt >= c->qsz) return -1;
    c->q[c->tail] = *e; c->tail = (c->tail + 1) % c->qsz; c->cnt++; return 0;
}

static int qpop(struct netdiag_ctx *c, netdiag_event_t *e) {
    if (c->cnt == 0) return 0;
    *e = c->q[c->head]; c->head = (c->head + 1) % c->qsz; c->cnt--; return 1;
}

netdiag_ctx *netdiag_create(netdiag_role_t role) { return netdiag_create_with_config(role, NULL); }

netdiag_ctx *netdiag_create_with_config(netdiag_role_t role, const netdiag_config_t *cfg) {
    struct netdiag_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->role = role;
    qinit(c, cfg ? cfg->event_queue_size : 8);
    return (netdiag_ctx *)c;
}

void netdiag_destroy(netdiag_ctx *ctx) { free(ctx); }

void netdiag_reset(netdiag_ctx *ctx) {
    struct netdiag_ctx *c = (struct netdiag_ctx *)ctx;
    if (c) qinit(c, c->qsz);
}

int netdiag_feed_input(netdiag_ctx *ctx, const uint8_t *d, size_t l) {
    return netdiag_feed_input_with_ts(ctx, d, l, 0);
}

int netdiag_feed_input_with_ts(netdiag_ctx *ctx, const uint8_t *d, size_t l, uint64_t ts) {
    struct netdiag_ctx *c = (struct netdiag_ctx *)ctx;
    if (!c || !d) return -1;
    (void)l; if (ts) c->last = ts;
    return 0;
}

int netdiag_process(netdiag_ctx *ctx, uint64_t ts) {
    struct netdiag_ctx *c = (struct netdiag_ctx *)ctx;
    if (!c) return -1;
    c->last = ts;
    return 0;
}

int netdiag_next_event(netdiag_ctx *ctx, netdiag_event_t *e) {
    struct netdiag_ctx *c = (struct netdiag_ctx *)ctx;
    if (!c || !e) return -1;
    return qpop(c, e);
}

int netdiag_get_stats(netdiag_ctx *ctx, netdiag_stats_t *s) {
    struct netdiag_ctx *c = (struct netdiag_ctx *)ctx;
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

const char *netdiag_event_to_string(const netdiag_event_t *ev, char *buf, size_t max) {
    if (!ev || !buf) return NULL;
    const char *t = "NONE";
    switch (ev->type) {
        case NETDIAG_EVENT_PING_REPLY: t = "PING_REPLY"; break;
        case NETDIAG_EVENT_PING_TIMEOUT: t = "PING_TIMEOUT"; break;
        case NETDIAG_EVENT_ARP_REPLY: t = "ARP_REPLY"; break;
        case NETDIAG_EVENT_ARP_DUPLICATE: t = "ARP_DUP"; break;
        case NETDIAG_EVENT_FAULT_DETECTED: t = "FAULT"; break;
        default: break;
    }
    snprintf(buf, max, "%s seq=%u lat=%u reason=%s", t, ev->seq, ev->latency_ms, ev->reason);
    return buf;
}

/* eBPF stubs */
static const char *ebpf_names[] = {"ping_trace.bpf.o", "arp_monitor.bpf.o"};
static const char *ebpf_sources[] = {"/* ping */", "/* arp */"};

size_t netdiag_ebpf_script_count(void) { return 2; }
const char *netdiag_get_ebpf_script_name(size_t i) { return i < 2 ? ebpf_names[i] : NULL; }
const char *netdiag_get_ebpf_script_source(const char *n, size_t *l) {
    if (!n || !l) return NULL;
    for (size_t i=0; i<2; i++) if (!strcmp(n, ebpf_names[i])) { *l = strlen(ebpf_sources[i]); return ebpf_sources[i]; }
    return NULL;
}