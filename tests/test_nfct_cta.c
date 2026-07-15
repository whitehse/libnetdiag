/**
 * Dialectic-style test: synthetic CTA-like netlink buffer → forensics 5-tuple.
 */

#include "nfct.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void wr16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)(v >> 8);
}

static void wr32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void wr16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void wr32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

/* Align nla length */
static size_t nla_put(uint8_t *buf, size_t off, uint16_t type,
                      const uint8_t *data, uint16_t dlen)
{
    uint16_t total = (uint16_t)(4 + dlen);
    size_t aligned = (total + 3u) & ~3u;
    wr16_le(buf + off, total);
    wr16_le(buf + off + 2, type);
    if (dlen && data) {
        memcpy(buf + off + 4, data, dlen);
    }
    if (aligned > total) {
        memset(buf + off + total, 0, aligned - total);
    }
    return off + aligned;
}

/**
 * Build a minimal ctnetlink NEW message:
 * ORIG: 192.168.1.50:12345 -> 8.8.8.8:53 TCP
 * REPLY: 8.8.8.8:53 -> 203.0.113.9:54321  (SNAT wan)
 */
static size_t build_ct_new(uint8_t *buf, size_t cap)
{
    uint8_t body[512];
    size_t boff = 0;
    uint8_t ip4[4];
    uint8_t port[2];
    uint8_t proto[1];
    uint8_t nest[256];
    size_t noff;
    size_t total;

    /* Build ORIG tuple nest */
    noff = 0;
    {
        uint8_t ipnest[64];
        size_t io = 0;
        wr32_be(ip4, 0xC0A80132u); /* 192.168.1.50 */
        io = nla_put(ipnest, io, 1 /* CTA_IP_V4_SRC */, ip4, 4);
        wr32_be(ip4, 0x08080808u);
        io = nla_put(ipnest, io, 2 /* CTA_IP_V4_DST */, ip4, 4);
        noff = nla_put(nest, noff, 1 /* CTA_TUPLE_IP */, ipnest, (uint16_t)io);

        {
            uint8_t pnest[32];
            size_t po = 0;
            proto[0] = 6;
            po = nla_put(pnest, po, 1 /* NUM */, proto, 1);
            wr16_be(port, 12345);
            po = nla_put(pnest, po, 2 /* SRC_PORT */, port, 2);
            wr16_be(port, 53);
            po = nla_put(pnest, po, 3 /* DST_PORT */, port, 2);
            noff = nla_put(nest, noff, 2 /* CTA_TUPLE_PROTO */, pnest, (uint16_t)po);
        }
    }
    boff = nla_put(body, boff, 1 /* CTA_TUPLE_ORIG */, nest, (uint16_t)noff);

    /* REPLY tuple nest */
    noff = 0;
    {
        uint8_t ipnest[64];
        size_t io = 0;
        wr32_be(ip4, 0x08080808u);
        io = nla_put(ipnest, io, 1, ip4, 4);
        wr32_be(ip4, 0xCB007109u); /* 203.0.113.9 WAN */
        io = nla_put(ipnest, io, 2, ip4, 4);
        noff = nla_put(nest, noff, 1, ipnest, (uint16_t)io);
        {
            uint8_t pnest[32];
            size_t po = 0;
            proto[0] = 6;
            po = nla_put(pnest, po, 1, proto, 1);
            wr16_be(port, 53);
            po = nla_put(pnest, po, 2, port, 2);
            wr16_be(port, 54321);
            po = nla_put(pnest, po, 3, port, 2);
            noff = nla_put(nest, noff, 2, pnest, (uint16_t)po);
        }
    }
    boff = nla_put(body, boff, 2 /* CTA_TUPLE_REPLY */, nest, (uint16_t)noff);

    total = 16 + 4 + boff; /* nlmsg + nfgenmsg + attrs */
    assert(total <= cap);
    memset(buf, 0, total);
    wr32_le(buf, (uint32_t)total);
    /* type: subsys CTNETLINK(1) << 8 | NEW(0) = 0x0100 */
    wr16_le(buf + 4, 0x0100);
    wr16_le(buf + 6, 0);
    wr32_le(buf + 8, 0);
    wr32_le(buf + 12, 0);
    buf[16] = 2; /* AF_INET */
    buf[17] = 0;
    wr16_be(buf + 18, 0); /* res_id */
    memcpy(buf + 20, body, boff);
    return total;
}

int main(void)
{
    nfct_ctx *ctx = nfct_create(NFCT_ROLE_COLLECTOR);
    uint8_t buf[1024];
    size_t n;
    nfct_event_t ev;
    uint32_t lan_ip, wan_ip;
    uint16_t lan_port, wan_port;
    uint8_t proto;
    int got = 0;

    assert(ctx);
    n = build_ct_new(buf, sizeof(buf));
    assert(nfct_feed_input(ctx, buf, n) == 0);
    while (nfct_next_event(ctx, &ev) == 1) {
        got = 1;
        assert(ev.type == NFCT_EVENT_NEW);
        assert(ev.has_lan && ev.has_wan);
        assert(ev.lan_src_ip == 0xC0A80132u);
        assert(ev.lan_src_port == 12345);
        assert(ev.wan_src_ip == 0xCB007109u);
        assert(ev.wan_src_port == 54321);
        assert(ev.protocol == 6);
        assert(nfct_event_forensics_tuple(&ev, &lan_ip, &lan_port,
                                          &wan_ip, &wan_port, &proto) == 1);
        assert(lan_ip == 0xC0A80132u && wan_ip == 0xCB007109u);
        assert(proto == 6);
    }
    assert(got);
    printf("nfct CTA decode test PASSED\n");
    nfct_destroy(ctx);
    return 0;
}
