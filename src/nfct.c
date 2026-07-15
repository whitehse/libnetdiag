/**
 * @file nfct.c
 * @brief nfnetlink conntrack message parser (plumbing).
 *
 * Decodes real kernel CTA_* nested attributes for IPv4 ORIG/REPLY tuples
 * plus synthetic test frames. Syscall-free; caller feeds netlink payloads.
 */

#include "nfct.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Mirror linux/netfilter/nfnetlink_conntrack.h numeric IDs (ABI stable). */
enum {
    CTA_UNSPEC = 0,
    CTA_TUPLE_ORIG = 1,
    CTA_TUPLE_REPLY = 2,
    CTA_STATUS = 3,
    CTA_MARK = 8,
    CTA_ZONE = 18
};

enum {
    CTA_TUPLE_IP = 1,
    CTA_TUPLE_PROTO = 2
};

enum {
    CTA_IP_V4_SRC = 1,
    CTA_IP_V4_DST = 2,
    CTA_IP_V6_SRC = 3,
    CTA_IP_V6_DST = 4
};

enum {
    CTA_PROTO_NUM = 1,
    CTA_PROTO_SRC_PORT = 2,
    CTA_PROTO_DST_PORT = 3
};

/* nfnetlink message types (subset) */
enum {
    IPCTNL_MSG_CT_NEW = 0,
    IPCTNL_MSG_CT_GET = 1,
    IPCTNL_MSG_CT_DELETE = 2
};

#define NFCT_MAX_Q 32
#define NFCT_SYNTH_MAGIC 0x4E464354u /* 'NFCT' */

#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif
#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK 0x3fff
#endif

struct nfct_ctx {
    nfct_role_t role;
    size_t qsz;
    nfct_event_t q[NFCT_MAX_Q];
    size_t head, tail, cnt;
};

static void qinit(struct nfct_ctx *c, size_t s)
{
    c->qsz = s ? s : 16;
    if (c->qsz > NFCT_MAX_Q) {
        c->qsz = NFCT_MAX_Q;
    }
    c->head = c->tail = c->cnt = 0;
}

static int qpush(struct nfct_ctx *c, const nfct_event_t *e)
{
    if (c->cnt >= c->qsz) {
        return -1;
    }
    c->q[c->tail] = *e;
    c->tail = (c->tail + 1) % c->qsz;
    c->cnt++;
    return 0;
}

static int qpop(struct nfct_ctx *c, nfct_event_t *e)
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

static uint16_t rd16_be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint16_t rd16_le(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Host-order IPv4 from network-order 4 bytes (conntrack uses BE on wire). */
static uint32_t ipv4_from_nlattr(const uint8_t *p)
{
    return rd32_be(p);
}

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    int      has_ip;
    int      has_proto;
    int      has_ports;
} tuple_t;

static void parse_tuple_ip(const uint8_t *data, uint16_t len, tuple_t *t)
{
    size_t off = 0;
    while (off + 4 <= len) {
        uint16_t alen = rd16_le(data + off);
        uint16_t atype = rd16_le(data + off + 2) & NLA_TYPE_MASK;
        uint16_t plen;
        const uint8_t *payload;
        size_t aligned;

        if (alen < 4 || off + alen > len) {
            break;
        }
        plen = (uint16_t)(alen - 4);
        payload = data + off + 4;
        if (atype == CTA_IP_V4_SRC && plen >= 4) {
            t->src_ip = ipv4_from_nlattr(payload);
            t->has_ip = 1;
        } else if (atype == CTA_IP_V4_DST && plen >= 4) {
            t->dst_ip = ipv4_from_nlattr(payload);
            t->has_ip = 1;
        }
        aligned = (alen + 3u) & ~3u;
        off += aligned;
    }
}

static void parse_tuple_proto(const uint8_t *data, uint16_t len, tuple_t *t)
{
    size_t off = 0;
    while (off + 4 <= len) {
        uint16_t alen = rd16_le(data + off);
        uint16_t atype = rd16_le(data + off + 2) & NLA_TYPE_MASK;
        uint16_t plen;
        const uint8_t *payload;
        size_t aligned;

        if (alen < 4 || off + alen > len) {
            break;
        }
        plen = (uint16_t)(alen - 4);
        payload = data + off + 4;
        if (atype == CTA_PROTO_NUM && plen >= 1) {
            t->proto = payload[0];
            t->has_proto = 1;
        } else if (atype == CTA_PROTO_SRC_PORT && plen >= 2) {
            t->src_port = rd16_be(payload);
            t->has_ports = 1;
        } else if (atype == CTA_PROTO_DST_PORT && plen >= 2) {
            t->dst_port = rd16_be(payload);
            t->has_ports = 1;
        }
        aligned = (alen + 3u) & ~3u;
        off += aligned;
    }
}

static void parse_tuple(const uint8_t *data, uint16_t len, tuple_t *t)
{
    size_t off = 0;
    memset(t, 0, sizeof(*t));
    while (off + 4 <= len) {
        uint16_t alen = rd16_le(data + off);
        uint16_t atype = rd16_le(data + off + 2) & NLA_TYPE_MASK;
        uint16_t plen;
        const uint8_t *payload;
        size_t aligned;

        if (alen < 4 || off + alen > len) {
            break;
        }
        plen = (uint16_t)(alen - 4);
        payload = data + off + 4;
        if (atype == CTA_TUPLE_IP) {
            parse_tuple_ip(payload, plen, t);
        } else if (atype == CTA_TUPLE_PROTO) {
            parse_tuple_proto(payload, plen, t);
        }
        aligned = (alen + 3u) & ~3u;
        off += aligned;
    }
}

static void parse_ct_attrs(const uint8_t *data, size_t len, nfct_event_t *ev)
{
    size_t off = 0;
    tuple_t orig, reply;

    memset(&orig, 0, sizeof(orig));
    memset(&reply, 0, sizeof(reply));

    while (off + 4 <= len) {
        uint16_t alen = rd16_le(data + off);
        uint16_t atype = rd16_le(data + off + 2) & NLA_TYPE_MASK;
        uint16_t plen;
        const uint8_t *payload;
        size_t aligned;

        if (alen < 4 || off + alen > len) {
            break;
        }
        plen = (uint16_t)(alen - 4);
        payload = data + off + 4;

        if (atype == CTA_TUPLE_ORIG) {
            parse_tuple(payload, plen, &orig);
        } else if (atype == CTA_TUPLE_REPLY) {
            parse_tuple(payload, plen, &reply);
        } else if (atype == CTA_MARK && plen >= 4) {
            ev->mark = rd32_be(payload);
        } else if (atype == CTA_ZONE && plen >= 2) {
            ev->zone = rd16_be(payload);
        }
        aligned = (alen + 3u) & ~3u;
        off += aligned;
    }

    /*
     * ORIG = pre-NAT direction as seen by conntrack (usually LAN client →
     * remote). REPLY flips addresses: for SNAT, reply.dst is the WAN IP
     * the outside world sees.
     *
     * Forensics 5-tuple (design):
     *   lan_src = orig.src
     *   wan_src = reply.dst  (post-SNAT source)
     */
    if (orig.has_ip) {
        ev->lan_src_ip = orig.src_ip;
        ev->lan_dst_ip = orig.dst_ip;
        ev->has_lan = 1;
    }
    if (orig.has_ports) {
        ev->lan_src_port = orig.src_port;
        ev->lan_dst_port = orig.dst_port;
    }
    if (orig.has_proto) {
        ev->protocol = orig.proto;
    } else if (reply.has_proto) {
        ev->protocol = reply.proto;
    }
    if (reply.has_ip) {
        /* Post-SNAT: public source is reply destination */
        ev->wan_src_ip = reply.dst_ip;
        ev->wan_dst_ip = reply.src_ip;
        ev->has_wan = 1;
    }
    if (reply.has_ports) {
        ev->wan_src_port = reply.dst_port;
        ev->wan_dst_port = reply.src_port;
    }
}

nfct_ctx *nfct_create(nfct_role_t role)
{
    return nfct_create_with_config(role, NULL);
}

nfct_ctx *nfct_create_with_config(nfct_role_t role, const nfct_config_t *config)
{
    struct nfct_ctx *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->role = role;
    qinit(c, config ? config->event_queue_size : 16);
    return c;
}

void nfct_destroy(nfct_ctx *ctx)
{
    free(ctx);
}

void nfct_reset(nfct_ctx *ctx)
{
    struct nfct_ctx *c = (struct nfct_ctx *)ctx;
    if (c) {
        qinit(c, c->qsz);
    }
}

static int try_synth(struct nfct_ctx *c, const uint8_t *data, size_t len)
{
    nfct_event_t ev;
    if (len < 32) {
        return 0;
    }
    if (rd32_be(data) != NFCT_SYNTH_MAGIC) {
        return 0;
    }
    memset(&ev, 0, sizeof(ev));
    switch (data[4]) {
    case 1: ev.type = NFCT_EVENT_NEW; break;
    case 2: ev.type = NFCT_EVENT_UPDATE; break;
    case 3: ev.type = NFCT_EVENT_DESTROY; break;
    default: ev.type = NFCT_EVENT_PARTIAL; break;
    }
    ev.protocol = data[5];
    ev.lan_src_ip = rd32_be(data + 8);
    ev.lan_src_port = rd16_be(data + 12);
    ev.lan_dst_ip = rd32_be(data + 14);
    ev.lan_dst_port = rd16_be(data + 18);
    ev.wan_src_ip = rd32_be(data + 20);
    ev.wan_src_port = rd16_be(data + 24);
    ev.wan_dst_ip = rd32_be(data + 26);
    ev.wan_dst_port = rd16_be(data + 30);
    ev.has_lan = 1;
    ev.has_wan = 1;
    (void)qpush(c, &ev);
    return 1;
}

/**
 * Walk netlink messages and decode conntrack attributes.
 * nlmsg layout (LE): len(4) type(2) flags(2) seq(4) pid(4) [nfgenmsg 4] attrs...
 */
static void parse_netlink(struct nfct_ctx *c, const uint8_t *data, size_t len)
{
    size_t off = 0;

    while (off + 16 <= len) {
        uint32_t nl_len = rd32_le(data + off);
        uint16_t nl_type = rd16_le(data + off + 4);
        uint16_t nl_flags = rd16_le(data + off + 6);
        uint8_t nfgen_type;
        uint8_t nfgen_family;
        size_t attr_off;
        size_t attr_len;
        nfct_event_t ev;

        (void)nl_flags;
        if (nl_len < 16 || off + nl_len > len) {
            break;
        }

        /* nfgenmsg follows nlmsghdr: family(1) version(1) res_id(2) */
        if (nl_len < 16 + 4) {
            off += (nl_len + 3u) & ~3u;
            continue;
        }
        nfgen_family = data[off + 16];
        nfgen_type = (uint8_t)(nl_type & 0xff); /* low byte is msg type within subsystem */

        memset(&ev, 0, sizeof(ev));
        /*
         * nl_type for nfnetlink is (subsys << 8) | msg.
         * Conntrack subsystem is NFNL_SUBSYS_CTNETLINK (1).
         * Message: NEW=0, GET=1, DELETE=2.
         */
        {
            uint8_t subsys = (uint8_t)((nl_type >> 8) & 0xff);
            uint8_t msg = (uint8_t)(nl_type & 0xff);
            (void)subsys;
            if (msg == IPCTNL_MSG_CT_NEW) {
                /* NEW events also used for updates depending on flags */
                if (nl_flags & 0x200 /* NLM_F_CREATE heuristic */) {
                    ev.type = NFCT_EVENT_NEW;
                } else {
                    ev.type = NFCT_EVENT_NEW;
                }
            } else if (msg == IPCTNL_MSG_CT_DELETE) {
                ev.type = NFCT_EVENT_DESTROY;
            } else {
                ev.type = NFCT_EVENT_UPDATE;
            }
        }
        (void)nfgen_type;
        (void)nfgen_family;

        attr_off = off + 16 + 4;
        attr_len = nl_len - 16 - 4;
        if (attr_off + attr_len <= off + nl_len) {
            parse_ct_attrs(data + attr_off, attr_len, &ev);
        }

        if (!ev.has_lan && !ev.has_wan) {
            ev.type = NFCT_EVENT_PARTIAL;
            snprintf(ev.reason, sizeof(ev.reason),
                     "nlmsg type=%u len=%u (no IPv4 tuples)",
                     (unsigned)nl_type, (unsigned)nl_len);
        }
        (void)qpush(c, &ev);
        off += (nl_len + 3u) & ~3u;
    }
}

int nfct_feed_input(nfct_ctx *ctx, const uint8_t *data, size_t len)
{
    struct nfct_ctx *c = (struct nfct_ctx *)ctx;
    if (!c || !data) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (try_synth(c, data, len)) {
        return 0;
    }
    parse_netlink(c, data, len);
    return 0;
}

int nfct_next_event(nfct_ctx *ctx, nfct_event_t *event)
{
    struct nfct_ctx *c = (struct nfct_ctx *)ctx;
    if (!c || !event) {
        return -1;
    }
    return qpop(c, event);
}

const char *nfct_event_to_string(const nfct_event_t *ev, char *buf, size_t max)
{
    const char *t;
    if (!ev || !buf || max == 0) {
        return NULL;
    }
    switch (ev->type) {
    case NFCT_EVENT_NEW: t = "NEW"; break;
    case NFCT_EVENT_UPDATE: t = "UPDATE"; break;
    case NFCT_EVENT_DESTROY: t = "DESTROY"; break;
    case NFCT_EVENT_ERROR: t = "ERROR"; break;
    case NFCT_EVENT_PARTIAL: t = "PARTIAL"; break;
    default: t = "NONE"; break;
    }
    snprintf(buf, max,
             "nfct %s proto=%u lan=%u.%u.%u.%u:%u wan=%u.%u.%u.%u:%u",
             t, (unsigned)ev->protocol,
             (unsigned)((ev->lan_src_ip >> 24) & 0xFF),
             (unsigned)((ev->lan_src_ip >> 16) & 0xFF),
             (unsigned)((ev->lan_src_ip >> 8) & 0xFF),
             (unsigned)(ev->lan_src_ip & 0xFF),
             (unsigned)ev->lan_src_port,
             (unsigned)((ev->wan_src_ip >> 24) & 0xFF),
             (unsigned)((ev->wan_src_ip >> 16) & 0xFF),
             (unsigned)((ev->wan_src_ip >> 8) & 0xFF),
             (unsigned)(ev->wan_src_ip & 0xFF),
             (unsigned)ev->wan_src_port);
    return buf;
}

int nfct_event_forensics_tuple(const nfct_event_t *ev,
                               uint32_t *lan_src_ip, uint16_t *lan_src_port,
                               uint32_t *wan_src_ip, uint16_t *wan_src_port,
                               uint8_t *protocol)
{
    if (!ev) {
        return -1;
    }
    if (lan_src_ip) {
        *lan_src_ip = ev->lan_src_ip;
    }
    if (lan_src_port) {
        *lan_src_port = ev->lan_src_port;
    }
    if (wan_src_ip) {
        *wan_src_ip = ev->wan_src_ip;
    }
    if (wan_src_port) {
        *wan_src_port = ev->wan_src_port;
    }
    if (protocol) {
        *protocol = ev->protocol;
    }
    return (ev->has_lan && ev->protocol) ? 1 : 0;
}
