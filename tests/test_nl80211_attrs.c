/**
 * Dialectic: synthetic + nested nl80211 STA_INFO attribute decode.
 */

#include "nl80211_parse.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void wr16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void wr32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void wr32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

/** Append nlattr; returns bytes written (aligned). */
static size_t put_nla(uint8_t *buf, size_t cap, size_t off,
                      uint16_t type, const void *payload, size_t plen)
{
    size_t alen = 4 + plen;
    size_t total = (alen + 3u) & ~3u;
    if (off + total > cap) {
        return 0;
    }
    wr16_le(buf + off, (uint16_t)alen);
    wr16_le(buf + off + 2, type);
    if (plen && payload) {
        memcpy(buf + off + 4, payload, plen);
    }
    if (total > alen) {
        memset(buf + off + alen, 0, total - alen);
    }
    return total;
}

static void test_synth(void)
{
    nl80211_parse_ctx *ctx = nl80211_parse_create(NL80211_PARSE_ROLE_COLLECTOR);
    uint8_t frame[20];
    nl80211_event_t ev;

    assert(ctx);
    memset(frame, 0, sizeof(frame));
    wr32_be(frame, 0x38323131u);
    frame[4] = 0x11;
    frame[5] = 0x22;
    frame[6] = 0x33;
    frame[7] = 0x44;
    frame[8] = 0x55;
    frame[9] = 0x66;
    wr32_be(frame + 10, (uint32_t)(int32_t)-70);
    frame[14] = 20;
    frame[15] = 9;
    wr32_be(frame + 16, 5);
    assert(nl80211_parse_feed_input(ctx, frame, sizeof(frame)) == 0);
    assert(nl80211_parse_next_event(ctx, &ev) == 1);
    assert(ev.type == NL80211_EVENT_STATION);
    assert(ev.has_mac && ev.client_mac[0] == 0x11);
    assert(ev.signal_dbm == -70);
    assert(ev.mcs_index == 9);
    assert(ev.tx_retries == 5);
    nl80211_parse_destroy(ctx);
    printf("  PASS: synth station\n");
}

static void test_nested_attrs(void)
{
    nl80211_parse_ctx *ctx = nl80211_parse_create(NL80211_PARSE_ROLE_COLLECTOR);
    uint8_t msg[256];
    uint8_t sta_nest[128];
    uint8_t rate_nest[32];
    size_t off = 0, nest_off = 0, rate_off = 0;
    uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    int8_t signal = -62;
    uint32_t retries = 7;
    uint32_t freq = 5180;
    uint8_t mcs = 11;
    nl80211_event_t ev;
    size_t n;

    assert(ctx);

    /* rate nest: MCS */
    n = put_nla(rate_nest, sizeof(rate_nest), rate_off, 2 /* MCS */, &mcs, 1);
    assert(n > 0);
    rate_off += n;

    /* STA_INFO nest */
    n = put_nla(sta_nest, sizeof(sta_nest), nest_off, 7 /* SIGNAL */, &signal, 1);
    nest_off += n;
    {
        uint8_t rb[4];
        wr32_le(rb, retries);
        n = put_nla(sta_nest, sizeof(sta_nest), nest_off, 11 /* TX_RETRIES */, rb, 4);
        nest_off += n;
    }
    n = put_nla(sta_nest, sizeof(sta_nest), nest_off, 8 /* TX_BITRATE */,
                rate_nest, rate_off);
    nest_off += n;

    /* Full genl message */
    memset(msg, 0, sizeof(msg));
    off = 20; /* leave room for headers */
    n = put_nla(msg, sizeof(msg), off, 6 /* MAC */, mac, 6);
    off += n;
    n = put_nla(msg, sizeof(msg), off, 21 /* STA_INFO */, sta_nest, nest_off);
    off += n;
    {
        uint8_t fb[4];
        wr32_le(fb, freq);
        n = put_nla(msg, sizeof(msg), off, 38 /* WIPHY_FREQ */, fb, 4);
        off += n;
    }
    /* nlmsghdr */
    wr32_le(msg + 0, (uint32_t)off);
    wr16_le(msg + 4, 0); /* type */
    wr16_le(msg + 6, 0);
    wr32_le(msg + 8, 0);
    wr32_le(msg + 12, 0);
    /* genlmsghdr */
    msg[16] = 13; /* cmd dummy */
    msg[17] = 0;
    wr16_le(msg + 18, 0);

    assert(nl80211_parse_feed_input(ctx, msg, off) == 0);
    assert(nl80211_parse_next_event(ctx, &ev) == 1);
    assert(ev.type == NL80211_EVENT_STATION);
    assert(ev.has_mac);
    assert(ev.client_mac[0] == 0xaa && ev.client_mac[5] == 0xff);
    assert(ev.has_signal);
    assert(ev.signal_dbm == -62);
    assert(ev.tx_retries == 7);
    assert(ev.has_mcs && ev.mcs_index == 11);
    assert(ev.frequency_mhz == 5180);

    nl80211_parse_destroy(ctx);
    printf("  PASS: nested STA_INFO attrs\n");
}

int main(void)
{
    test_synth();
    test_nested_attrs();
    printf("nl80211 attrs tests PASSED\n");
    return 0;
}
