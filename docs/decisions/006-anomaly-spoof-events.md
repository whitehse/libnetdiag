# ADR 006: Anomaly/Spof Detection Events

**Date**: 2026-07-06
**Status**: Proposed

## Context
Existing modules emit `FAULT_DETECTED` and `ARP_ANOMALY` for timeouts and rcode errors. Kali tools (ettercap, responder, bettercap) highlight ARP/DNS spoof and duplicate MAC/IP detection as critical for edge fault analysis.

## Decision
Extend event model with dedicated anomaly events:
- `NETDIAG_EVENT_ARP_SPOOF` (multiple MACs for one IP)
- `NETDIAG_EVENT_DNS_SPOOF` (unexpected response)
- `NETDIAG_EVENT_LATENCY_OUTLIER`

Reuse existing `netdiag_event_t` fields (`flags`, `reason`). Add helper in `netdiag.c` or per-module.

## Consequences
- Minimal new event constants.
- Dialectic tests for spoof scenarios.
- No change to core invariants.

Implementation follows acceptance.