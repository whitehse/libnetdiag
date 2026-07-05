/* Placeholder eBPF source for ARP monitoring - installed by caller */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int arp_monitor(struct xdp_md *ctx) {
    /* real implementation would parse ARP and emit events to ringbuf */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";