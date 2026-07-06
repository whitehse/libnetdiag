# ADR 005: Nmap-style Probe/Response Parsers

**Date**: 2026-07-06
**Status**: Proposed

## Context
Kali's `nmap` excels at host discovery and service identification via SYN/ACK, UDP, and ICMP timestamp probes. The library already has basic ICMP/ARP/DNS handling. Adding lightweight state machines for common nmap probe types enables richer fault analysis (port state, service reachability, OS hints) while staying syscall-free.

## Decision
Introduce `src/nmapdiag.c` (or extend traceroute/ping) with parsers for:
- TCP SYN/ACK responses (port open/closed/filtered)
- UDP responses (ICMP unreachable vs. no response)
- ICMP timestamp / echo variants

Emit structured events (`NETDIAG_EVENT_PROBE_REPLY`, reuse/extend existing). Keep the module thin: `feed_input` only; caller decides probe timing and source ports.

## Consequences
- New ctx + API following existing pattern.
- Dialectic test pair required.
- Minimal new event types only if existing ones are insufficient.
- Preserves all invariants (pure state machine, no I/O, `-Werror`).

## Alternatives
- Full nmap script engine — rejected (too heavy for edge library).
- Pure extension of ping/traceroute — rejected for separation of concerns.

Implementation follows ADR acceptance.