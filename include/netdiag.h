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
    NETDIAG_EVENT_FAULT_DETECTED
} netdiag_event_type_t;

typedef struct {
    netdiag_event_type_t type;
    uint32_t seq;
    uint32_t latency_ms;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    char reason[128];
} netdiag_event_t;

/* Common / shared API (minimal for bootstrap) */
typedef struct netdiag_ctx netdiag_ctx;

netdiag_ctx *netdiag_create(netdiag_role_t role);
netdiag_ctx *netdiag_create_with_config(netdiag_role_t role, const netdiag_config_t *config);
void netdiag_destroy(netdiag_ctx *ctx);
void netdiag_reset(netdiag_ctx *ctx);

int netdiag_feed_input(netdiag_ctx *ctx, const uint8_t *data, size_t len);
int netdiag_next_event(netdiag_ctx *ctx, netdiag_event_t *event);

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
int ping_next_event(ping_ctx *ctx, netdiag_event_t *event);

/* Arping-specific (ARP) */
typedef struct arping_ctx arping_ctx;

arping_ctx *arping_create(netdiag_role_t role);
arping_ctx *arping_create_with_config(netdiag_role_t role, const netdiag_config_t *config);
void arping_destroy(arping_ctx *ctx);
void arping_reset(arping_ctx *ctx);
int arping_feed_input(arping_ctx *ctx, const uint8_t *data, size_t len);
int arping_next_event(arping_ctx *ctx, netdiag_event_t *event);

#ifdef __cplusplus
}
#endif

#endif /* NETDIAG_H */