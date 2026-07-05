#include "netdiag.h"
#include <stdlib.h>
#include <string.h>

/* Minimal common implementation for bootstrap - opaque ctx is just a placeholder */
struct netdiag_ctx {
    netdiag_role_t role;
    size_t queue_size;
    int dummy_state;
};

netdiag_ctx *netdiag_create(netdiag_role_t role) {
    return netdiag_create_with_config(role, NULL);
}

netdiag_ctx *netdiag_create_with_config(netdiag_role_t role, const netdiag_config_t *config) {
    netdiag_ctx *ctx = (netdiag_ctx *)calloc(1, sizeof(netdiag_ctx));
    if (!ctx) return NULL;
    ctx->role = role;
    ctx->queue_size = config ? config->event_queue_size : 8;
    ctx->dummy_state = 0;
    return ctx;
}

void netdiag_destroy(netdiag_ctx *ctx) {
    if (ctx) free(ctx);
}

void netdiag_reset(netdiag_ctx *ctx) {
    if (ctx) ctx->dummy_state = 0;
}

int netdiag_feed_input(netdiag_ctx *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) return -1;
    (void)len;
    ctx->dummy_state = 1;
    return 0;
}

int netdiag_next_event(netdiag_ctx *ctx, netdiag_event_t *event) {
    if (!ctx || !event) return -1;
    if (ctx->dummy_state == 1) {
        event->type = NETDIAG_EVENT_NONE;
        ctx->dummy_state = 0;
        return 1;
    }
    return 0;
}

/* eBPF stubs */
static const char *ebpf_names[] = { "ping_trace.bpf.o", "arp_monitor.bpf.o" };
static const char *ebpf_sources[] = { "/* ping eBPF source placeholder */", "/* arp eBPF source placeholder */" };

size_t netdiag_ebpf_script_count(void) { return 2; }

const char *netdiag_get_ebpf_script_name(size_t index) {
    if (index >= 2) return NULL;
    return ebpf_names[index];
}

const char *netdiag_get_ebpf_script_source(const char *name, size_t *len_out) {
    if (!name || !len_out) return NULL;
    for (size_t i = 0; i < 2; i++) {
        if (strcmp(name, ebpf_names[i]) == 0) {
            *len_out = strlen(ebpf_sources[i]);
            return ebpf_sources[i];
        }
    }
    return NULL;
}