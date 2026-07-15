/**
 * @file nfct.h
 * @brief Syscall-free Netfilter conntrack event parser (nfnetlink payload).
 *
 * Parses caller-supplied nfnetlink/conntrack message buffers into structured
 * NAT 5-tuple events for CPE forensics. No sockets, no libmnl, no callbacks.
 *
 * The OpenWrt CPE daemon owns the AF_NETLINK socket (NETLINK_NETFILTER) and
 * feeds multicast NEW/DESTROY payloads into nfct_feed_input().
 */
#ifndef NETDIAG_NFCT_H
#define NETDIAG_NFCT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NFCT_ROLE_COLLECTOR = 0  /**< Parse conntrack events only. */
} nfct_role_t;

typedef struct {
    size_t event_queue_size; /**< 0 = default (32). */
} nfct_config_t;

typedef enum {
    NFCT_EVENT_NONE = 0,
    NFCT_EVENT_NEW,          /**< Connection created (NFCT_GROUP_NEW). */
    NFCT_EVENT_UPDATE,       /**< Connection updated. */
    NFCT_EVENT_DESTROY,      /**< Connection destroyed. */
    NFCT_EVENT_ERROR,        /**< Malformed message. */
    NFCT_EVENT_PARTIAL       /**< Recognized header but incomplete attrs. */
} nfct_event_type_t;

/**
 * Minimal NAT 5-tuple for forensics correlation.
 * LAN side = original (pre-NAT); WAN side = reply (post-NAT) when present.
 */
typedef struct {
    nfct_event_type_t type;
    uint8_t  protocol;       /**< IPPROTO_* */
    uint32_t lan_src_ip;     /**< Host order IPv4. */
    uint16_t lan_src_port;
    uint32_t lan_dst_ip;
    uint16_t lan_dst_port;
    uint32_t wan_src_ip;     /**< Post-NAT source (reply dest typically). */
    uint16_t wan_src_port;
    uint32_t wan_dst_ip;
    uint16_t wan_dst_port;
    uint64_t mark;           /**< Optional connmark. */
    uint32_t zone;
    int      has_lan;
    int      has_wan;
    int      is_ipv6;        /**< 1 if addresses are truncated IPv6 stubs (v0). */
    char     reason[96];     /**< Error / partial reason. */
} nfct_event_t;

typedef struct nfct_ctx nfct_ctx;

nfct_ctx *nfct_create(nfct_role_t role);
nfct_ctx *nfct_create_with_config(nfct_role_t role, const nfct_config_t *config);
void nfct_destroy(nfct_ctx *ctx);
void nfct_reset(nfct_ctx *ctx);

/**
 * Feed one or more raw netlink messages (caller may pass a recv buffer).
 * Returns 0 on success, negative on hard error.
 */
int nfct_feed_input(nfct_ctx *ctx, const uint8_t *data, size_t len);

/**
 * Dequeue next event. Returns 1 if event filled, 0 if empty, negative on error.
 */
int nfct_next_event(nfct_ctx *ctx, nfct_event_t *event);

/** Format event as dense one-line summary for JSON/NDJSON emitters. */
const char *nfct_event_to_string(const nfct_event_t *ev, char *buf, size_t max);

/**
 * Extract only the forensics 5-tuple fields into out (lan + wan + protocol).
 * Returns 1 if lan+protocol present, 0 if incomplete, negative on error.
 */
int nfct_event_forensics_tuple(const nfct_event_t *ev,
                               uint32_t *lan_src_ip, uint16_t *lan_src_port,
                               uint32_t *wan_src_ip, uint16_t *wan_src_port,
                               uint8_t *protocol);

#ifdef __cplusplus
}
#endif

#endif /* NETDIAG_NFCT_H */
