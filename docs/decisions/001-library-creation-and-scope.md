# ADR 001: Creation of libnetdiag and Overall Scope

## Status
Accepted

## Context
The sibling pure-C protocol and utility libraries (librest, shaggy/libhttp2, libdiscord, libslack, libnetconf, libyaml, libdom, libjsparse, libcdp, libharness) follow a strict syscall-free, callback-free, event-driven state-machine design (ADR 006). The user requires a new library for network troubleshooting on edge devices (OpenWRT routers, Debian hosts) that can emulate common utilities (starting with ping and arping) for analysis purposes and integrate eBPF scripts (installed and managed by the caller).

Existing Lua experiments (arping.lua, bpftool.lua) exist in the workspace, indicating a need for both C plumbing and higher-level (Lua) policy layers.

## Decision
We create a new sibling library named **libnetdiag** (network diagnostics) under /home/dwhite/libnetdiag/.

- It will follow the exact agent-ready, pure state-machine patterns established by shaggy and other siblings.
- Core library: thin PDU parsing and event emission for ICMP (ping) and ARP (arping) protocols, plus future utilities.
- eBPF scripts: stored in the repo (bpf/); library provides read-only accessors; caller performs all bpftool/libbpf operations.
- No syscalls, no callbacks, no policy, no I/O in the C core.
- Dialectic testing, strict warnings, Valgrind, fuzzing required.
- Major decisions recorded as ADRs before implementation.
- Inherits MIT license, ADR numbering and cross-references from the ecosystem.

## Consequences
- New directory structure with AGENTS.md, ARCHITECTURE.md, docs/decisions/, src/, include/, tests/, examples/, bpf/.
- First implementation will provide minimal ping and arping state machines emitting analysis-oriented events (replies, timeouts, duplicates, basic fault signals).
- Calling applications (edge daemons, Lua scripts via FFI, or full harnesses) own packet I/O, eBPF lifecycle, timestamping, and reaction to events.
- This library becomes the canonical C foundation for all future network-fault-analysis utilities in the ecosystem.
- Documentation (this ADR, ARCHITECTURE.md, DOMAIN.md) must be kept in sync with any expansion of scope.

## References
- ADR 006 (syscall-free plumbing) — inherited
- ADR 002, 003, 004, 010 — inherited
- Existing Lua arping/bpf experiments in workspace root
- OpenWRT + LuaJIT + io_uring context from prior analysis documents