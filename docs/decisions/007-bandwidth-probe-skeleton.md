# ADR 007: iperf3-like Bandwidth Probe Skeleton

**Date**: 2026-07-06
**Status**: Proposed

## Context
Kali includes `iperf3` for bandwidth, jitter, and packet-loss benchmarking. The library is passive (no active generation inside core). A lightweight skeleton can track timing-derived throughput and loss from fed probe responses.

## Decision
Add `src/bwdiag.c` with a minimal ctx that:
- Records inter-packet timing on `feed_input`
- Emits `NETDIAG_EVENT_BW_SAMPLE` events (bytes/sec, jitter estimate)
- Reuses existing `netdiag_stats_t` fields

Caller supplies the probe packets and timestamps.

## Consequences
- New event type only if needed.
- No active I/O or socket code.
- Dialectic test optional (timing-based).

Implementation follows acceptance.