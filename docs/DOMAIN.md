# DOMAIN.md — libnetdiag

## Key Concepts
- **Ping emulation (ICMP)**: State machine for echo request/reply. Events: PING_REPLY, PING_TIMEOUT, FAULT_DETECTED (loss, latency).
- **Arping emulation (ARP)**: State machine for ARP request/reply. Events: ARP_REPLY, ARP_DUPLICATE.
- **Traceroute skeleton (P2)**: UDP/ICMP time-exceeded state machine for hop discovery and path latency.
- **eBPF scripts**: Kernel-assisted packet capture/tracing. Scripts (ping_trace.bpf.o, arp_monitor.bpf.o, ...) are provided as data; caller attaches them.
- **Dialectic testing**: Requester + Responder contexts exchanging raw packet buffers to validate protocol behavior without sockets.
- **Fault analysis**: Higher-level events derived from protocol state (duplicate replies, missing replies, latency spikes).
- **Statistics (P1)**: Per-context `get_stats()` returning replies, timeouts, loss%, avg/max/min latency.
- **Event helpers (P1)**: `*_event_to_string()` for logging/AI harness consumption.

## Workflow on Edge Device
1. Application creates ping_ctx / arping_ctx / traceroute_ctx (or unified netdiag_ctx).
2. Uses io_uring/raw socket/eBPF ring to obtain packets.
3. Feeds packets via `feed_input_with_ts()` with caller monotonic timestamps.
4. Calls `process(now_ms)` periodically for timeout/fault logic.
5. Drains events via `next_event()` and reacts (log, alert, store in Honcho, etc.).
6. Queries `get_stats()` for operator dashboards or AI analysis.
7. eBPF programs installed via bpftool or libbpf by the application for advanced tracing.

See `examples/simple_harness.c` for a minimal reference implementation.

All design decisions recorded as ADRs before code changes.