#ifndef NETDIAG_H
#define NETDIAG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NETDIAG_ROLE_REQUESTER = 0,
    NETDIAG_ROLE_RESPONDER = 1
} netdiag_role_t;

typedef struct {
    size_t event_queue_size;
} netdiag_config_t;

typedef enum {
    NETDIAG_EVENT_NONE = 0,
    NETDIAG_EVENT_PING_REPLY,
    NETDIAG_EVENT_PING_TIMEOUT,
    NETDIAG_EVENT_ARP_REPLY,
    NETDIAG_EVENT_ARP_DUPLICATE,
    NETDIAG_EVENT_FAULT_DETECTED,
    NETDIAG_EVENT_TRACEROUTE_HOP,
    NETDIAG_EVENT_DNS_REPLY,
    NETDIAG_EVENT_ARP_ANOMALY,
    NETDIAG_EVENT_ARP_SPOOF,
    NETDIAG_EVENT_DNS_SPOOF,
    NETDIAG_EVENT_BW_SAMPLE
} netdiag_event_type_t;

typedef struct {
    netdiag_event_type_t type;
    uint32_t seq;
    uint32_t latency_ms;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint32_t src_ip;   /* IPv4; 0 if unknown */
    uint32_t dst_ip;
    char reason[128];
    uint32_t flags;    /* bit 0 = duplicate, etc. */
} netdiag_event_t;

/* Common / shared API (minimal for bootstrap) */
typedef struct netdiag_ctx netdiag_ctx;

netdiag_ctx *netdiag_create(netdiag_role_t role);
netdiag_ctx *netdiag_create_with_config(netdiag_role_t role, const netdiag_config_t *config);
void netdiag_destroy(netdiag_ctx *ctx);
void netdiag_reset(netdiag_ctx *ctx);

int netdiag_feed_input(netdiag_ctx *ctx, const uint8_t *data, size_t len);
int netdiag_feed_input_with_ts(netdiag_ctx *ctx, const uint8_t *data, size_t len, uint64_t now_ms);
int netdiag_process(netdiag_ctx *ctx, uint64_t now_ms);
int netdiag_next_event(netdiag_ctx *ctx, netdiag_event_t *event);

/* Stats + helpers (P1) */
typedef struct {
    uint32_t replies;
    uint32_t timeouts;
    uint32_t duplicates;
    uint32_t loss_pct;      /* 0-100 */
    uint32_t avg_latency_ms;
    uint32_t max_latency_ms;
    uint32_t min_latency_ms;
} netdiag_stats_t;

int netdiag_get_stats(netdiag_ctx *ctx, netdiag_stats_t *stats);
const char *netdiag_event_to_string(const netdiag_event_t *ev, char *buf, size_t max);

/* eBPF script accessors (scripts installed by caller) */
size_t netdiag_ebpf_script_count(void);
const char *netdiag_get_ebpf_script_name(size_t index);
const char *netdiag_get_ebpf_script_source(const char *name, size_t *len_out);

/* Ping-specific (ICMP) */
typedef struct ping_ctx ping_ctx;

ping_ctx *ping_create(netdiag_role_t role);
ping_ctx *ping_create_with_config(netdiag_role_t role, const netdiag_config_t *config);
void ping_destroy(ping_ctx *ctx);
void ping_reset(ping_ctx *ctx);
int ping_feed_input(ping_ctx *ctx, const uint8_t *data, size_t len);
int ping_feed_input_with_ts(ping_ctx *ctx, const uint8_t *data, size_t len, uint64_t now_ms);
int ping_process(ping_ctx *ctx, uint64_t now_ms);
int ping_next_event(ping_ctx *ctx, netdiag_event_t *event);
int ping_get_stats(ping_ctx *ctx, netdiag_stats_t *stats);
const char *ping_event_to_string(const netdiag_event_t *ev, char *buf, size_t max);

/* Arping-specific (ARP) */
typedef struct arping_ctx arping_ctx;

arping_ctx *arping_create(netdiag_role_t role);
arping_ctx *arping_create_with_config(netdiag_role_t role, const netdiag_config_t *config);
void arping_destroy(arping_ctx *ctx);
void arping_reset(arping_ctx *ctx);
int arping_feed_input(arping_ctx *ctx, const uint8_t *data, size_t len);
int arping_feed_input_with_ts(arping_ctx *ctx, const uint8_t *data, size_t len, uint64_t now_ms);
int arping_process(arping_ctx *ctx, uint64_t now_ms);
int arping_next_event(arping_ctx *ctx, netdiag_event_t *event);
int arping_get_stats(arping_ctx *ctx, netdiag_stats_t *stats);
const char *arping_event_to_string(const netdiag_event_t *ev, char *buf, size_t max);

/* Traceroute skeleton (P2) + MTR helpers */
typedef struct traceroute_ctx traceroute_ctx;

traceroute_ctx *traceroute_create(netdiag_role_t role);
traceroute_ctx *traceroute_create_with_config(netdiag_role_t role, const netdiag_config_t *config);
void traceroute_destroy(traceroute_ctx *ctx);
void traceroute_reset(traceroute_ctx *ctx);
int traceroute_feed_input(traceroute_ctx *ctx, const uint8_t *data, size_t len);
int traceroute_feed_input_with_ts(traceroute_ctx *ctx, const uint8_t *data, size_t len, uint64_t now_ms);
int traceroute_process(traceroute_ctx *ctx, uint64_t now_ms);
int traceroute_next_event(traceroute_ctx *ctx, netdiag_event_t *event);
int traceroute_get_stats(traceroute_ctx *ctx, netdiag_stats_t *stats);
const char *traceroute_event_to_string(const netdiag_event_t *ev, char *buf, size_t max);

/* MTR helpers */
void traceroute_record_hop(traceroute_ctx *ctx, int hop, int success, uint32_t latency_ms);
int traceroute_hop_loss_pct(traceroute_ctx *ctx, int hop);

/* DNS diagnostic skeleton (P2) */
typedef struct dnsdiag_ctx dnsdiag_ctx;

dnsdiag_ctx *dnsdiag_create(netdiag_role_t role);
dnsdiag_ctx *dnsdiag_create_with_config(netdiag_role_t role, const netdiag_config_t *config);
void dnsdiag_destroy(dnsdiag_ctx *ctx);
void dnsdiag_reset(dnsdiag_ctx *ctx);
int dnsdiag_feed_input(dnsdiag_ctx *ctx, const uint8_t *data, size_t len);
int dnsdiag_feed_input_with_ts(dnsdiag_ctx *ctx, const uint8_t *data, size_t len, uint64_t now_ms);
int dnsdiag_process(dnsdiag_ctx *ctx, uint64_t now_ms);
int dnsdiag_next_event(dnsdiag_ctx *ctx, netdiag_event_t *event);
int dnsdiag_get_stats(dnsdiag_ctx *ctx, netdiag_stats_t *stats);
const char *dnsdiag_event_to_string(const netdiag_event_t *ev, char *buf, size_t max);

/* Enhanced ARP Recon (P4 - ADR 004) */
typedef struct arprecon_ctx arprecon_ctx;

arprecon_ctx *arprecon_create(netdiag_role_t role);
arprecon_ctx *arprecon_create_with_config(netdiag_role_t role, const netdiag_config_t *config);
void arprecon_destroy(arprecon_ctx *ctx);
void arprecon_reset(arprecon_ctx *ctx);
int arprecon_feed_input(arprecon_ctx *ctx, const uint8_t *data, size_t len);
int arprecon_feed_input_with_ts(arprecon_ctx *ctx, const uint8_t *data, size_t len, uint64_t now_ms);
int arprecon_process(arprecon_ctx *ctx, uint64_t now_ms);
int arprecon_next_event(arprecon_ctx *ctx, netdiag_event_t *event);
int arprecon_get_stats(arprecon_ctx *ctx, netdiag_stats_t *stats);
const char *arprecon_event_to_string(const netdiag_event_t *ev, char *buf, size_t max);

#ifdef __cplusplus
}
#endif

#endif /* NETDIAG_H */