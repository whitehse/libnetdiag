/* Placeholder eBPF source for ping tracing - installed by caller via bpftool or libbpf */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/net/net_dev_xmit")
int ping_trace(struct pt_regs *ctx) {
    /* real implementation would capture ICMP echo packets */
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";