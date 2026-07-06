#include "netdiag.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_Q 32
#define MAX_NEIGH 64

struct arprecon_ctx {
    netdiag_role_t role;
    size_t qsz;
    netdiag_event_t q[MAX_Q];
    size_t head, tail, cnt;
    uint8_t last_mac[6];
    uint64_t send_ts;
    int waiting;
    uint32_t replies, timeouts, dups, sum_lat, max_lat, min_lat, count_lat;
    /* Passive recon state */
    uint8_t neigh_macs[MAX_NEIGH][6];
    uint32_t neigh_ips[MAX_NEIGH];
    int neigh_count;
};

static void qinit(struct arprecon_ctx *c, size_t s) {
    c->qsz = s ? s : 8; if (c->qsz > MAX_Q) c->qsz = MAX_Q;
    c->head = c->tail = c->cnt = 0; c->waiting = 0; memset(c->last_mac, 0, 6);
    c->replies = c->timeouts = c->dups = c->sum_lat = c->max_lat = c->count_lat = 0;
    c->min_lat = ~0U;
    c->neigh_count = 0;
}

static int qpush(struct arprecon_ctx *c, const netdiag_event_t *e) {
    if (c->cnt >= c->qsz) return -1;
    c->q[c->tail] = *e; c->tail = (c->tail + 1) % c->qsz; c->cnt++; return 0;
}

static int qpop(struct arprecon_ctx *c, netdiag_event_t *e) {
    if (c->cnt == 0) return 0;
    *e = c->q[c->head]; c->head = (c->head + 1) % c->qsz; c->cnt--; return 1;
}

arprecon_ctx *arprecon_create(netdiag_role_t role) { return arprecon_create_with_config(role, NULL); }

arprecon_ctx *arprecon_create_with_config(netdiag_role_t role, const netdiag_config_t *cfg) {
    struct arprecon_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->role = role;
    qinit(c, cfg ? cfg->event_queue_size : 8);
    return (arprecon_ctx *)c;
}

void arprecon_destroy(arprecon_ctx *ctx) { free(ctx); }

void arprecon_reset(arprecon_ctx *ctx) {
    struct arprecon_ctx *c = (struct arprecon_ctx *)ctx;
    if (c) qinit(c, c->qsz);
}

int arprecon_feed_input(arprecon_ctx *ctx, const uint8_t *d, size_t l) {
    return arprecon_feed_input_with_ts(ctx, d, l, 0);
}

int arprecon_feed_input_with_ts(arprecon_ctx *ctx, const uint8_t *d, size_t l, uint64_t ts) {
    struct arprecon_ctx *c = (struct arprecon_ctx *)ctx;
    if (!c || !d || l < 14) return -1;

    /* Classic ARP */
    if (l > 21 && d[12]==0x08 && d[13]==0x06) {
        uint16_t op = (d[20]<<8)|d[21];
        if (op == 2 && c->role == NETDIAG_ROLE_REQUESTER) {
            netdiag_event_t ev = {.type=NETDIAG_EVENT_ARP_REPLY};
            memcpy(ev.src_mac, d+22, 6);
            uint32_t lat = 5;
            if (c->send_ts && ts) lat = (ts > c->send_ts) ? (uint32_t)(ts - c->send_ts) : 0;
            ev.latency_ms = lat;
            qpush(c, &ev);
            c->replies++;
            c->sum_lat += lat; c->count_lat++;
            if (lat > c->max_lat) c->max_lat = lat;
            if (lat < c->min_lat) c->min_lat = lat;
            c->waiting = 0;

            /* Passive neighbor accumulation */
            if (c->neigh_count < MAX_NEIGH) {
                memcpy(c->neigh_macs[c->neigh_count], d+22, 6);
                c->neigh_ips[c->neigh_count] = (d[28]<<24)|(d[29]<<16)|(d[30]<<8)|d[31];
                c->neigh_count++;
            /* Spoof detection */
            for (int i = 0; i < c->neigh_count-1; i++) {
                if (c->neigh_ips[i] == c->neigh_ips[c->neigh_count-1] && memcmp(c->neigh_macs[i], d+22, 6) != 0) {
                    netdiag_event_t ev = {.type=NETDIAG_EVENT_ARP_SPOOF};
                    snprintf(ev.reason, sizeof(ev.reason), "spoof detected");
                    qpush(c, &ev);
                    c->dups++;
                }
            }
            }
        } else if (op == 1 && c->role == NETDIAG_ROLE_RESPONDER) {
            if (ts) c->send_ts = ts;
            c->waiting = 1;
        }
    }
    return 0;
}

int arprecon_process(arprecon_ctx *ctx, uint64_t ts) {
    struct arprecon_ctx *c = (struct arprecon_ctx *)ctx;
    if (!c) return -1;
    if (c->waiting && c->send_ts && ts > c->send_ts + 1000) {
        netdiag_event_t ev = {.type=NETDIAG_EVENT_ARP_ANOMALY};
        snprintf(ev.reason, sizeof(ev.reason), "arp recon timeout");
        qpush(c, &ev);
        c->timeouts++;
        c->waiting = 0;
    }
    return 0;
}

int arprecon_next_event(arprecon_ctx *ctx, netdiag_event_t *e) {
    struct arprecon_ctx *c = (struct arprecon_ctx *)ctx;
    if (!c || !e) return -1;
    return qpop(c, e);
}

int arprecon_get_stats(arprecon_ctx *ctx, netdiag_stats_t *s) {
    struct arprecon_ctx *c = (struct arprecon_ctx *)ctx;
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

const char *arprecon_event_to_string(const netdiag_event_t *ev, char *buf, size_t max) {
    return netdiag_event_to_string(ev, buf, max);
}