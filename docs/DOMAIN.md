# DOMAIN.md — libnetdiag

## Key Concepts
- **Ping emulation (ICMP)**: State machine for echo request/reply. Events: PING_REPLY, PING_TIMEOUT, FAULT_DETECTED (loss, latency).
- **Arping emulation (ARP)**: State machine for ARP request/reply. Events: ARP_REPLY, ARP_DUPLICATE.
- **eBPF scripts**: Kernel-assisted packet capture/tracing. Scripts (ping_trace.bpf.o, arp_monitor.bpf.o, ...) are provided as data; caller attaches them.
- **Dialectic testing**: Requester + Responder contexts exchanging raw packet buffers to validate protocol behavior without sockets.
- **Fault analysis**: Higher-level events derived from protocol state (duplicate replies, missing replies, latency spikes).

## Workflow on Edge Device
1. Application creates ping_ctx / arping_ctx (or unified netdiag_ctx).
2. Uses io_uring/raw socket/eBPF ring to obtain packets.
3. Feeds packets via feed_input().
4. Drains events via next_event() and reacts (log, alert, store in Honcho, etc.).
5. eBPF programs installed via bpftool or libbpf by the application for advanced tracing.

All design decisions recorded as ADRs before code changes.