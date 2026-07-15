/**
 * @file nl80211_parse.h
 * @brief Syscall-free nl80211 attribute parser for Wi-Fi client telemetry.
 *
 * Parses caller-supplied nl80211 netlink message buffers (station dump /
 * survey responses). The CPE daemon owns the generic-netlink socket and
 * feeds reply bytes into nl80211_feed_input().
 */
#ifndef NETDIAG_NL80211_PARSE_H
#define NETDIAG_NL80211_PARSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NL80211_PARSE_ROLE_COLLECTOR = 0
} nl80211_parse_role_t;

typedef struct {
    size_t event_queue_size; /**< 0 = default (32). */
} nl80211_parse_config_t;

typedef enum {
    NL80211_EVENT_NONE = 0,
    NL80211_EVENT_STATION,   /**< Per-client station info. */
    NL80211_EVENT_SURVEY,    /**< Channel survey sample. */
    NL80211_EVENT_ERROR
} nl80211_event_type_t;

typedef struct {
    nl80211_event_type_t type;
    uint8_t  client_mac[6];
    int32_t  signal_dbm;     /**< RSSI; 0 if unknown. */
    int32_t  signal_avg_dbm;
    uint32_t tx_retries;
    uint32_t tx_failed;
    uint32_t rx_bytes;
    uint32_t tx_bytes;
    uint8_t  mcs_index;      /**< 0xFF if unknown. */
    int8_t   snr_db;         /**< Approximate SNR when available; 0 unknown. */
    uint32_t frequency_mhz;
    int      has_mac;
    int      has_signal;
    int      has_mcs;
    char     reason[96];
} nl80211_event_t;

typedef struct nl80211_parse_ctx nl80211_parse_ctx;

nl80211_parse_ctx *nl80211_parse_create(nl80211_parse_role_t role);
nl80211_parse_ctx *nl80211_parse_create_with_config(nl80211_parse_role_t role,
                                                    const nl80211_parse_config_t *config);
void nl80211_parse_destroy(nl80211_parse_ctx *ctx);
void nl80211_parse_reset(nl80211_parse_ctx *ctx);

int nl80211_parse_feed_input(nl80211_parse_ctx *ctx, const uint8_t *data, size_t len);
int nl80211_parse_next_event(nl80211_parse_ctx *ctx, nl80211_event_t *event);

const char *nl80211_event_to_string(const nl80211_event_t *ev, char *buf, size_t max);

#ifdef __cplusplus
}
#endif

#endif /* NETDIAG_NL80211_PARSE_H */
