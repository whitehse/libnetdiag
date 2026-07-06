# ADR 004: Enhanced ARP Recon State Machine (netdiscover/arp-scan patterns)

**Date**: 2026-07-06
**Status**: Proposed

## Context
The current `arping.c` implements basic ARP request/reply + NDP handling for simple arping use-cases. Kali tools such as `netdiscover` and `arp-scan` provide active/passive reconnaissance, vendor fingerprinting (OUI lookup), and auto-scan for DHCP-less networks. These patterns are valuable for edge-device fault analysis (rogue devices, ARP spoof detection, neighbor inventory).

## Decision
Add an enhanced ARP recon module (`src/arprecon.c` / `arprecon_ctx`) that extends the existing arping patterns with:
- Passive listen mode (accumulate neighbors without active probes)
- Active sweep mode (periodic ARP requests for a CIDR range, controlled by caller)
- OUI/vendor fingerprinting (embedded small table or accessor)
- Duplicate detection + spoof events (multiple MACs for same IP)
- Integration with existing `netdiag_event_t` (reuse/extend `ARP_REPLY` / new `ARP_ANOMALY`)

The module remains a pure state machine: `feed_input` consumes raw Ethernet frames; `next_event` emits structured events; caller supplies timestamps and decides when to send probes.

## Consequences
- New public API follows existing shape (`arprecon_create`, `feed_input_with_ts`, `process`, `next_event`, `get_stats`).
- Dialectic test pair required (requester/responder exchanging ARP frames).
- Small OUI table embedded as data (no external deps).
- No syscalls, no callbacks, no active I/O inside the library.
- New event type `NETDIAG_EVENT_ARP_ANOMALY` added to `netdiag.h`.
- ADR 010 (C interfaces) and ADR 006 (thin plumbing) remain satisfied.

## Alternatives Considered
- Extend `arping_ctx` in place — rejected for clarity and to keep the simple arping path unchanged.
- Full nmap-style host discovery — deferred to later P4 item.

Implementation will follow after this ADR is accepted.