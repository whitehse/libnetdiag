# ARCHITECTURE.md — libnetdiag

## Project Scope
Pure C library providing deterministic state machines for network protocol analysis and troubleshooting utilities. Primary consumers are edge-device applications running on OpenWRT, Debian, or similar constrained Linux environments. The library enables analysis of networking faults by emulating the packet-level behavior and event emission of common tools (ping, arping) and future utilities, while remaining completely syscall-free and callback-free.

## Core Philosophy (ADR 006 alignment)
- **Thin plumbing only**: The library parses raw packet buffers (ICMP, ARP, future protocols) and emits structured events (`protocol_event_t` or specialized `netdiag_event_t`). It does **not** perform I/O, manage sockets, install eBPF programs, or make policy decisions.
- **Caller owns everything**: The application supplies timestamps, packet buffers (from io_uring, libpcap, raw sockets, or eBPF ring buffers), and decides what to do with emitted events (log, react, escalate, etc.).
- **No hidden behavior**: No auto-replies, no automatic retransmits, no connection management inside the library.

## Module Boundaries
- `include/netdiag.h` — Public opaque types, config structs, event enums, and common API (`netdiag_create`, `feed_input`, `next_event`, eBPF accessors).
- `src/ping.c` — ICMP echo request/reply state machine (for ping emulation and analysis).
- `src/arping.c` — ARP request/reply state machine (for arping emulation and analysis).
- `src/traceroute.c` — Traceroute skeleton (UDP/ICMP time-exceeded, hop discovery).
- `src/ebpf.c` or embedded data — Accessors for eBPF script sources (the scripts themselves live in a `bpf/` subdirectory as .o or source; library only provides const char* pointers or lengths).
- Future: `src/dnsdiag.c`, etc. as separate compilation units inside the same library or future sibling libs.

## Deliberate Absences (Invariants)
- No `socket`, `send`, `recv`, `bind`, `ioctl`, `bpf` syscalls or wrappers.
- No `malloc`/`free` in hot paths (caller provides all buffers or uses fixed-size internal state).
- No function pointers or callbacks for event delivery.
- No threading, locking, or clock access (`time`, `clock_gettime`).
- No file I/O or dynamic loading of eBPF objects.
- No automatic timeout handling (caller supplies monotonic timestamps via `process(ctx, now_ms)` pattern if needed).
- eBPF programs are **not** compiled, loaded, or attached by the library.

## Event Model
All utilities emit events via a unified or per-utility `next_event` mechanism:
- `NETDIAG_EVENT_PING_REPLY`
- `NETDIAG_EVENT_PING_TIMEOUT`
- `NETDIAG_EVENT_ARP_REPLY`
- `NETDIAG_EVENT_ARP_DUPLICATE`
- `NETDIAG_EVENT_FAULT_DETECTED` (with reason codes for loss, latency spike, etc.)
- Future events for new utilities.

Events use embedded arrays for payload safety in ring buffers.

P1 additions: `get_stats()` (replies, timeouts, loss%, latency histogram summary), `*_event_to_string()` for logging/AI harnesses.

## Dialectic Testing
Every protocol module ships with paired requester/responder test contexts that exchange raw packet buffers directly in memory. This verifies correctness without any network dependency and matches the pattern used across all sibling libraries (libdiscord, shaggy, librest, etc.).

## eBPF Integration Strategy
- eBPF source or object files are stored in the repository under `bpf/`.
- The C library exposes `netdiag_ebpf_script_count()`, `netdiag_get_ebpf_script_name(idx)`, `netdiag_get_ebpf_script_source(name, &len)` or equivalent.
- The **calling application** is responsible for:
  - Compiling .bpf.c → .o (via clang or bpftool)
  - Loading via libbpf or bpftool
  - Attaching to interfaces/XDP/TC
  - Reading events from ring buffers or perf events
  - Feeding relevant raw packets or metadata into the libnetdiag state machines for higher-level analysis.

This separation keeps the core library portable and pure while enabling powerful kernel-assisted capture on edge devices.

## Build & Packaging
- Single static library `libnetdiag.a`
- Public headers in `include/`
- CMake with strict warnings, C11, no extensions.
- Optional `BUILD_EXAMPLES` for liburing/epoll reference callers.
- pkg-config and CMake config export supported.

## Relationship to Sibling Libraries
- Inherits ADR 006 (syscall-free plumbing), ADR 002 (event-loop compatibility), ADR 003 (testing/fuzz/valgrind), ADR 004 (dialectic testing), ADR 010 (C interfaces) from the ecosystem.
- Complements LuaJIT FFI work (arping.lua, bpftool.lua) by providing a C foundation that Lua code can call into. All public functions (create*, feed*, process, next_event, get_stats, event_to_string) are FFI-friendly (opaque pointers, simple scalars, no bitfields).
- Can be used alongside librest/shaggy for reporting faults to central systems, or libharness for AI-driven analysis loops.

## Future Evolution
New utilities are added as additional `.c`/`.h` pairs inside the library or, when they represent entirely new protocols, as new sibling repositories following the same bootstrap pattern. All decisions that affect the shared event model or eBPF accessor API must be recorded in ADRs before implementation.