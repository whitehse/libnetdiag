/**
 * @file nl80211_parse.c
 * @brief Minimal nl80211 station telemetry parser (plumbing).
 *
 * Supports:
 *  1) Synthetic station frames (tests / early emitters)
 *  2) Real generic-netlink messages with nested STA_INFO attributes
 */

#include "nl80211_parse.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NL80211_MAX_Q 32
#define NL80211_SYNTH_MAGIC 0x38323131u /* '8211' */

/* linux/nl80211.h attribute numbers (stable subset) */
#define NL80211_ATTR_MAC           6
#define NL80211_ATTR_STA_INFO      21
#define NL80211_ATTR_WIPHY_FREQ    38

#define NL80211_STA_INFO_RX_BYTES    2
#define NL80211_STA_INFO_TX_BYTES    3
#define NL80211_STA_INFO_SIGNAL      7
#define NL80211_STA_INFO_TX_BITRATE  8
#define NL80211_STA_INFO_TX_RETRIES  11
#define NL80211_STA_INFO_TX_FAILED   12
#define NL80211_STA_INFO_SIGNAL_AVG  13

#define NL80211_RATE_INFO_MCS        2
#define NL80211_RATE_INFO_VHT_MCS    4

#define NLA_HDRLEN 4
#define NLA_ALIGN(len) (((len) + 3u) & ~3u)

struct nl80211_parse_ctx {
    nl80211_parse_role_t role;
    size_t qsz;
    nl80211_event_t q[NL80211_MAX_Q];
    size_t head, tail, cnt;
};

static void qinit(struct nl80211_parse_ctx *c, size_t s)
{
    c->qsz = s ? s : 16;
    if (c->qsz > NL80211_MAX_Q) {
        c->qsz = NL80211_MAX_Q;
    }
    c->head = c->tail = c->cnt = 0;
}

static int qpush(struct nl80211_parse_ctx *c, const nl80211_event_t *e)
{
    if (c->cnt >= c->qsz) {
        return -1;
    }
    c->q[c->tail] = *e;
    c->tail = (c->tail + 1) % c->qsz;
    c->cnt++;
    return 0;
}

static int qpop(struct nl80211_parse_ctx *c, nl80211_event_t *e)
{
    if (c->cnt == 0) {
        return 0;
    }
    *e = c->q[c->head];
    c->head = (c->head + 1) % c->qsz;
    c->cnt--;
    return 1;
}

static uint32_t rd32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int32_t rd32_be_s(const uint8_t *p)
{
    return (int32_t)rd32_be(p);
}

static uint16_t rd16_le(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

nl80211_parse_ctx *nl80211_parse_create(nl80211_parse_role_t role)
{
    return nl80211_parse_create_with_config(role, NULL);
}

nl80211_parse_ctx *nl80211_parse_create_with_config(nl80211_parse_role_t role,
                                                    const nl80211_parse_config_t *config)
{
    struct nl80211_parse_ctx *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->role = role;
    qinit(c, config ? config->event_queue_size : 16);
    return c;
}

void nl80211_parse_destroy(nl80211_parse_ctx *ctx)
{
    free(ctx);
}

void nl80211_parse_reset(nl80211_parse_ctx *ctx)
{
    struct nl80211_parse_ctx *c = (struct nl80211_parse_ctx *)ctx;
    if (c) {
        qinit(c, c->qsz);
    }
}

/**
 * Synthetic station frame (tests / early emitters):
 *   magic(4) mac(6) signal_dbm(4 BE signed) snr(1) mcs(1) tx_retries(4 BE)
 * Total 20 bytes.
 */
static int try_synth(struct nl80211_parse_ctx *c, const uint8_t *data, size_t len)
{
    nl80211_event_t ev;
    if (len < 20) {
        return 0;
    }
    if (rd32_be(data) != NL80211_SYNTH_MAGIC) {
        return 0;
    }
    memset(&ev, 0, sizeof(ev));
    ev.type = NL80211_EVENT_STATION;
    memcpy(ev.client_mac, data + 4, 6);
    ev.signal_dbm = rd32_be_s(data + 10);
    ev.snr_db = (int8_t)data[14];
    ev.mcs_index = data[15];
    ev.tx_retries = rd32_be(data + 16);
    ev.has_mac = 1;
    ev.has_signal = 1;
    ev.has_mcs = (ev.mcs_index != 0xFF);
    (void)qpush(c, &ev);
    return 1;
}

static void parse_rate_info(const uint8_t *data, size_t len, nl80211_event_t *ev)
{
    size_t off = 0;
    while (off + NLA_HDRLEN <= len) {
        uint16_t alen = rd16_le(data + off);
        uint16_t atype = rd16_le(data + off + 2) & 0x3fffu; /* strip NLA_F_* */
        size_t plen;
        const uint8_t *payload;
        if (alen < NLA_HDRLEN || off + alen > len) {
            break;
        }
        plen = (size_t)alen - NLA_HDRLEN;
        payload = data + off + NLA_HDRLEN;
        if ((atype == NL80211_RATE_INFO_MCS || atype == NL80211_RATE_INFO_VHT_MCS) &&
            plen >= 1) {
            ev->mcs_index = payload[0];
            ev->has_mcs = 1;
        }
        off += NLA_ALIGN(alen);
    }
}

static void parse_sta_info(const uint8_t *data, size_t len, nl80211_event_t *ev)
{
    size_t off = 0;
    while (off + NLA_HDRLEN <= len) {
        uint16_t alen = rd16_le(data + off);
        uint16_t atype = rd16_le(data + off + 2) & 0x3fffu;
        size_t plen;
        const uint8_t *payload;
        if (alen < NLA_HDRLEN || off + alen > len) {
            break;
        }
        plen = (size_t)alen - NLA_HDRLEN;
        payload = data + off + NLA_HDRLEN;
        switch (atype) {
        case NL80211_STA_INFO_SIGNAL:
            if (plen >= 1) {
                ev->signal_dbm = (int32_t)(int8_t)payload[0];
                ev->has_signal = 1;
            }
            break;
        case NL80211_STA_INFO_SIGNAL_AVG:
            if (plen >= 1) {
                ev->signal_avg_dbm = (int32_t)(int8_t)payload[0];
            }
            break;
        case NL80211_STA_INFO_TX_RETRIES:
            if (plen >= 4) {
                ev->tx_retries = rd32_le(payload);
            }
            break;
        case NL80211_STA_INFO_TX_FAILED:
            if (plen >= 4) {
                ev->tx_failed = rd32_le(payload);
            }
            break;
        case NL80211_STA_INFO_RX_BYTES:
            if (plen >= 4) {
                ev->rx_bytes = rd32_le(payload);
            }
            break;
        case NL80211_STA_INFO_TX_BYTES:
            if (plen >= 4) {
                ev->tx_bytes = rd32_le(payload);
            }
            break;
        case NL80211_STA_INFO_TX_BITRATE:
            parse_rate_info(payload, plen, ev);
            break;
        default:
            break;
        }
        off += NLA_ALIGN(alen);
    }
}

static void parse_top_attrs(const uint8_t *data, size_t len, nl80211_event_t *ev)
{
    size_t off = 0;
    while (off + NLA_HDRLEN <= len) {
        uint16_t alen = rd16_le(data + off);
        uint16_t atype = rd16_le(data + off + 2) & 0x3fffu;
        size_t plen;
        const uint8_t *payload;
        if (alen < NLA_HDRLEN || off + alen > len) {
            break;
        }
        plen = (size_t)alen - NLA_HDRLEN;
        payload = data + off + NLA_HDRLEN;
        switch (atype) {
        case NL80211_ATTR_MAC:
            if (plen >= 6) {
                memcpy(ev->client_mac, payload, 6);
                ev->has_mac = 1;
            }
            break;
        case NL80211_ATTR_STA_INFO:
            parse_sta_info(payload, plen, ev);
            break;
        case NL80211_ATTR_WIPHY_FREQ:
            if (plen >= 4) {
                ev->frequency_mhz = rd32_le(payload);
            }
            break;
        default:
            break;
        }
        off += NLA_ALIGN(alen);
    }
}

/**
 * Parse one or more generic-netlink messages (station get/dump replies).
 * Layout: nlmsghdr(16) + genlmsghdr(4) + nlattrs...
 * Also accepts a bare attribute stream (no headers) for unit tests.
 */
static void parse_nl80211_messages(struct nl80211_parse_ctx *c,
                                   const uint8_t *data, size_t len)
{
    size_t off = 0;

    /* Bare attribute stream (no nlmsghdr): length field would be small / LE type */
    if (len >= NLA_HDRLEN) {
        uint32_t maybe_nl = rd32_le(data);
        if (maybe_nl < 16 || maybe_nl > len) {
            /* Treat whole buffer as attribute stream */
            nl80211_event_t ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = NL80211_EVENT_STATION;
            ev.mcs_index = 0xFF;
            parse_top_attrs(data, len, &ev);
            if (ev.has_mac || ev.has_signal) {
                (void)qpush(c, &ev);
            } else {
                ev.type = NL80211_EVENT_ERROR;
                snprintf(ev.reason, sizeof(ev.reason),
                         "nl80211 attrs without MAC/signal (%zu bytes)", len);
                (void)qpush(c, &ev);
            }
            return;
        }
    }

    while (off + 16 <= len) {
        uint32_t nl_len = rd32_le(data + off);
        nl80211_event_t ev;
        size_t attr_off;
        size_t attr_len;

        if (nl_len < 16 || off + nl_len > len) {
            break;
        }
        /* Need genlmsghdr (4 bytes) after nlmsghdr */
        if (nl_len < 20) {
            off += NLA_ALIGN(nl_len);
            continue;
        }
        memset(&ev, 0, sizeof(ev));
        ev.type = NL80211_EVENT_STATION;
        ev.mcs_index = 0xFF;
        attr_off = off + 20; /* nlmsghdr + genlmsghdr */
        attr_len = (size_t)nl_len - 20;
        if (attr_off + attr_len > off + nl_len) {
            attr_len = (off + nl_len > attr_off) ? (off + nl_len - attr_off) : 0;
        }
        parse_top_attrs(data + attr_off, attr_len, &ev);
        if (ev.has_mac || ev.has_signal) {
            (void)qpush(c, &ev);
        }
        off += NLA_ALIGN(nl_len);
    }
}

int nl80211_parse_feed_input(nl80211_parse_ctx *ctx, const uint8_t *data, size_t len)
{
    struct nl80211_parse_ctx *c = (struct nl80211_parse_ctx *)ctx;
    if (!c || !data) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (try_synth(c, data, len)) {
        return 0;
    }
    parse_nl80211_messages(c, data, len);
    return 0;
}

int nl80211_parse_next_event(nl80211_parse_ctx *ctx, nl80211_event_t *event)
{
    struct nl80211_parse_ctx *c = (struct nl80211_parse_ctx *)ctx;
    if (!c || !event) {
        return -1;
    }
    return qpop(c, event);
}

const char *nl80211_event_to_string(const nl80211_event_t *ev, char *buf, size_t max)
{
    if (!ev || !buf || max == 0) {
        return NULL;
    }
    if (ev->type == NL80211_EVENT_STATION && ev->has_mac) {
        snprintf(buf, max,
                 "sta %02x:%02x:%02x:%02x:%02x:%02x rssi=%d snr=%d mcs=%u retries=%u",
                 ev->client_mac[0], ev->client_mac[1], ev->client_mac[2],
                 ev->client_mac[3], ev->client_mac[4], ev->client_mac[5],
                 (int)ev->signal_dbm, (int)ev->snr_db,
                 (unsigned)ev->mcs_index, (unsigned)ev->tx_retries);
    } else {
        snprintf(buf, max, "nl80211 type=%d %s", (int)ev->type,
                 ev->reason[0] ? ev->reason : "");
    }
    return buf;
}
