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

#define NFCT_IPV6_LEN 16

/**
 * Minimal NAT 5-tuple for forensics correlation.
 * LAN side = original (pre-NAT); WAN side = reply (post-NAT) when present.
 * IPv4 uses host-order uint32; IPv6 uses network-order 16-byte arrays.
 */
typedef struct {
    nfct_event_type_t type;
    uint8_t  protocol;       /**< IPPROTO_* */
    /* IPv4 */
    uint32_t lan_src_ip;     /**< Host order IPv4. */
    uint16_t lan_src_port;
    uint32_t lan_dst_ip;
    uint16_t lan_dst_port;
    uint32_t wan_src_ip;     /**< Post-NAT source (reply dest typically). */
    uint16_t wan_src_port;
    uint32_t wan_dst_ip;
    uint16_t wan_dst_port;
    /* IPv6 (valid when is_ipv6) */
    uint8_t  lan_src_ip6[NFCT_IPV6_LEN];
    uint8_t  lan_dst_ip6[NFCT_IPV6_LEN];
    uint8_t  wan_src_ip6[NFCT_IPV6_LEN];
    uint8_t  wan_dst_ip6[NFCT_IPV6_LEN];
    uint64_t mark;           /**< Optional connmark. */
    uint32_t zone;
    uint32_t id;             /**< CTA_ID when present (DESTROY correlation). */
    uint32_t status;         /**< CTA_STATUS bitfield when present. */
    int      has_lan;
    int      has_wan;
    int      has_id;
    int      has_status;
    int      is_ipv6;        /**< 1 = IPv6 tuples filled. */
    int      is_destroy;     /**< 1 = DESTROY event (alias of type for callers). */
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
 * Extract IPv4 forensics 5-tuple (lan + wan + protocol).
 * Returns 1 if lan+protocol present, 0 if incomplete, negative on error.
 */
int nfct_event_forensics_tuple(const nfct_event_t *ev,
                               uint32_t *lan_src_ip, uint16_t *lan_src_port,
                               uint32_t *wan_src_ip, uint16_t *wan_src_port,
                               uint8_t *protocol);

/**
 * Extract IPv6 forensics endpoints (16-byte addresses, network order).
 * Returns 1 if lan IPv6 + protocol present, 0 incomplete, negative on error.
 */
int nfct_event_forensics_tuple_v6(const nfct_event_t *ev,
                                  uint8_t lan_src[NFCT_IPV6_LEN],
                                  uint16_t *lan_src_port,
                                  uint8_t wan_src[NFCT_IPV6_LEN],
                                  uint16_t *wan_src_port,
                                  uint8_t *protocol);

#ifdef __cplusplus
}
#endif

#endif /* NETDIAG_NFCT_H */
