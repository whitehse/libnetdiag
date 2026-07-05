# ADR 002: Event Model, Timestamping, Ring-Buffer Queue, and Enhanced netdiag_event_t

## Status
Accepted

## Context
The initial bootstrap (ADR 001) used dummy single-state "events" and placeholder latency/seq in ping/arping. Real network troubleshooting requires:
- Accurate RTT/latency using caller-supplied monotonic timestamps (library must remain clock-free).
- Proper event queuing to handle bursts without dropping or blocking (config-driven size).
- Rich, structured events for operators (fault reasons, dups, loss) and AI harnesses (machine-readable fields including IPs).
- Safe public API evolution that stays FFI-friendly and opaque.

Current naive byte-offset parsing and lack of validation also block robustness.

This ADR defines the concrete shape for P0 items while preserving all invariants (no syscalls, no malloc in hot paths, dialectic tests, etc.).

## Decision
1. **Timestamp support**:
   - Add `*_process(ctx, uint64_t now_ms)` to all contexts (netdiag, ping, arping). Caller calls this periodically with monotonic time.
   - Extend feed with timestamp variants: `*_feed_input_with_ts(ctx, data, len, now_ms)` (or keep original `feed_input` as alias to ts=0 meaning "no time").
   - RTT calculated as `now_ms - send_ts` stored per-probe in internal state (fixed array of recent probes).

2. **Event queue**:
   - Internal fixed-size ring buffer (size = config.event_queue_size or default 16) in each ctx.
   - `next_event` dequeues; returns 0 when empty (always `NETDIAG_EVENT_NONE` when no event).
   - Backpressure: oldest dropped if full (documented).

3. **Enhanced netdiag_event_t** (public, FFI-safe):
   ```c
   typedef struct {
       netdiag_event_type_t type;
       uint32_t seq;
       uint32_t latency_ms;
       uint8_t src_mac[6];
       uint8_t dst_mac[6];
       uint32_t src_ip;   /* IPv4 for now; 0 if unknown */
       uint32_t dst_ip;
       char reason[128];
       uint32_t flags;    /* bitfield for DUP, TIMEOUT, etc. */
   } netdiag_event_t;
   ```
   - Backward-compatible size/layout for existing fields; new fields appended.
   - New event types added: `NETDIAG_EVENT_PING_TIMEOUT`, `NETDIAG_EVENT_ARP_DUPLICATE`, `NETDIAG_EVENT_FAULT_DETECTED`.

4. **Parsing & validation**:
   - Introduce internal `struct icmp_hdr`, `struct arp_hdr`, `struct eth_hdr` (or use linux headers if available, but self-contained for portability).
   - Proper checksum verification (ICMP), length checks, opcode/type validation.
   - Malformed packets → ignored or emit FAULT with reason (no crash).

5. **Fault / duplicate / loss logic**:
   - Track sent probes with timestamps + seq.
   - On reply: match seq, compute RTT, detect dups.
   - Periodic `process(now)`: scan for timeouts → emit TIMEOUT + update loss stats.
   - Emit `FAULT_DETECTED` with populated reason for patterns.

6. **Implementation notes**:
   - Common queue and probe-tracking helpers in `src/netdiag.c` (or internal .h).
   - ping.c / arping.c use the shared mechanisms.
   - All new public functions follow existing create/feed/next/destroy pattern.
   - Dialectic tests updated to exercise new paths (requester/responder with time simulation).

## Consequences
- Public header `include/netdiag.h` will be updated (new functions + extended event struct).
- Existing minimal tests will be extended; new dialectic tests for timeout, dup, malformed.
- No change to eBPF accessor or core philosophy.
- Enables P1 stats export later (histograms built on same probe tracking).
- Requires new ADR only for further major expansions (e.g. IPv6 event fields).

## References
- ADR 001 (scope)
- AGENTS.md (interface direction, definition of done)
- ARCHITECTURE.md (event model section)
- TODO.md (P0 items)