# AGENTS.md — libnetdiag

**Project identity**: Pure C state-machine network diagnostics and troubleshooting library. System-call free, callback free. All I/O, networking, packet capture, and event handling lives exclusively in the calling application (typically an io_uring or epoll event loop on edge devices such as OpenWRT or Debian hosts). The library only consumes/produces byte buffers (raw packets) and explicit state transitions for emulated utilities (ping, arping, and future ones). It also provides access to eBPF script sources that the calling application installs and manages. Designed for analyzing networking faults on resource-constrained edge devices.

**Key commands** (run from repo root):
- `cmake -B build -S . && cmake --build build` — configure and build the static library + tests
- `ctest --test-dir build` — run verification tests
- `cmake --build build --target install` — install (optional)

**Documentation map** (progressive disclosure):
- AGENTS.md (this file) — start here for every task
- ARCHITECTURE.md — module boundaries, invariants, deliberate absences
- docs/README.md — full documentation index
- docs/DOMAIN.md — network diagnostics domain glossary and workflows (ICMP/ping, ARP/arping, eBPF integration points, fault analysis events)
- docs/decisions/ — Architecture Decision Records (ADRs)

**Operating rules**:
- Never introduce system calls, callbacks, or hidden I/O inside the library core.
- State machine design follows libassh patterns: explicit states, deterministic transitions driven only by input buffers and caller-supplied context.
- Every change must keep the library buildable with `-Wall -Wextra -Wpedantic -Werror` (or MSVC equivalent) and pass existing tests.
- Prefer small, reviewable patches. Update relevant docs/ADRs when architecture or domain assumptions change.
- Hermes agent (or any coding agent) must consult AGENTS.md before editing code or docs.
- eBPF scripts are treated as data/resources; the library provides accessors or embedded strings but the calling application is responsible for loading, attaching, and managing them via bpftool or libbpf.
- Dialectic testing style is mandatory for all protocol modules (paired client/server or requester/responder contexts exchanging raw packet buffers).

**Definition of done** (for any ticket):
- Code compiles cleanly under strict warnings.
- Tests pass (`ctest`).
- AGENTS.md, ARCHITECTURE.md, and relevant docs remain accurate.
- No new syscalls or callbacks introduced.
- State machine remains pure (inputs → state/output only).
- New utilities or eBPF integration points are accompanied by ADRs and dialectic tests.

**Current status**: Bootstrap phase. Core CMake, documentation scaffold, and minimal state-machine skeleton for ping (ICMP echo) and arping (ARP) emulation in place. Ready for iterative addition of fault-analysis events, eBPF script management, and additional utilities.

**Testing, Fuzzing & Valgrind Policy** (see ADR 003):
- Every change to core source must add or update tests in `tests/`.
- Run `ctest` before considering any change complete.
- Packet parser changes require libFuzzer runs with no crashes.
- All tests must pass under Valgrind with no leaks or memory errors.
- Dialectic tests (requester + responder exchanging buffers) are the primary verification method.

**Current Interface Direction (as of ADR 001)**:
- Consistent shape across utilities:
  - `*_config_t` (with `event_queue_size`)
  - `*_create(role)` and `*_create_with_config(role, config)`
  - `*_feed_input(ctx, data, len)` for raw packet bytes
  - `*_next_event(ctx, &event)` returning `protocol_event_t` (or netdiag_event_t)
  - `*_get_output(ctx, buf, max)` if generation of probe packets is supported
- Roles distinguish requester vs responder for dialectic testing.
- eBPF scripts exposed via `netdiag_get_ebpf_script(name, &len)` or similar.

**Known Limitations / Areas for Improvement**:
- Initial implementation covers only ping and arping skeletons.
- Full fault detection logic (latency histograms, duplicate detection, loss patterns) to be added iteratively.
- eBPF script embedding and versioning pending.
- No hardware offload or platform-specific optimizations yet.

When making changes, prefer extending the event-driven path and maintaining dialectic test coverage.

**ADR 010 Alignment (C Interfaces and Implementations + Language Bindings)**:
- All public interfaces follow opaque type principles from Hanson's *C Interfaces and Implementations*.
- Public headers are designed to be FFI-friendly (simple types, no complex macros or bitfields).
- LuaJIT FFI bindings (via sibling patterns) are supported for OpenWRT/Lua-based callers.
- Consistent naming and clear ownership semantics are maintained.
- When adding or modifying public functions, prefer designs that are easy to consume from C, Lua, and other languages.