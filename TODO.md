# TODO.md — libnetdiag

**Status**: Bootstrap phase complete. Core skeletons + dialectic tests + eBPF accessors in place. Next phase: robust fault analysis, real protocol handling, and harness-friendly extensions while preserving pure state-machine invariants (see AGENTS.md, ARCHITECTURE.md, ADR 001).

All items must:
- Follow ADR process (new ADRs in docs/decisions/ before major changes)
- Add/update tests in tests/ (dialectic style primary)
- Pass `cmake -B build -S . && cmake --build build && ctest --test-dir build` + Valgrind
- Keep library syscall-free, callback-free, no hidden I/O
- Maintain FFI-friendly C interfaces (opaque types, simple structs)

Priority: P0 (core robustness), P1 (operator/AI harness value), P2 (expansion), P3 (polish).

---

## P0 — Core Robustness & Correctness (Foundation for Everything)

- [ ] Replace naive byte-offset parsing in `src/ping.c` and `src/arping.c` with proper struct-based ICMP/ARP/Ethernet header parsing + validation (checksums, length checks, type/opcode verification). Add dialectic tests with malformed packets.
- [ ] Implement real event queue (ring buffer sized by `netdiag_config_t.event_queue_size`) instead of single-state dummy in `netdiag.c`, `ping.c`, `arping.c`. Support backpressure and `NETDIAG_EVENT_NONE` when empty.
- [ ] Add caller-supplied timestamp support for accurate latency/timeout: introduce `*_process(ctx, now_ms)` or extend `feed_input` variants that take monotonic timestamp. Enables real `PING_TIMEOUT` and RTT calculation (no `time()` inside library).
- [ ] Implement proper sequence/ID tracking, duplicate detection (ARP/IP/MAC), and basic loss pattern detection. Emit `NETDIAG_EVENT_FAULT_DETECTED` with populated `reason[]` for loss, duplicate, etc.
- [ ] Enhance `netdiag_event_t` safely (add src/dst IP fields, more precise latency, flags) or introduce payload union/variant while keeping FFI-friendly and size-bounded for ring buffers.
- [ ] Full Valgrind + libFuzzer coverage on packet parsers. All new parsing must survive fuzzing with no crashes/leaks.

## P1 — Operator & AI Harness Value (Rich Events, Stats, Usability)

- [ ] Per-context statistics export: `*_get_stats(ctx, &stats)` returning latency histogram (fixed-size bins or ring), loss %, duplicate count, jitter, last N RTTs. Safe fixed-size arrays only (no malloc in hot path).
- [ ] Expand event types and reasons: `PING_TIMEOUT`, `ARP_DUPLICATE`, `FAULT_LOSS_PATTERN`, `FAULT_LATENCY_SPIKE`, `FAULT_DUPLICATE_IP`, etc. Populate `reason[128]` and other fields meaningfully.
- [ ] Harness-friendly helpers (pure C, no deps): `netdiag_event_to_string(const netdiag_event_t*, char* buf, size_t max)` and/or simple JSON-ish formatter for feeding events to AI analysis loops or logging.
- [ ] Config enhancements (`netdiag_config_t`): `timeout_ms`, `max_probes`, `histogram_bins`, `enable_fault_detection`. Backward-compatible.
- [ ] Unified vs. per-protocol usage clarity + examples of mixed ping+arping in one harness loop.
- [ ] Reset + stats snapshot semantics documented and tested (for long-running operator sessions or harness restarts).

## P2 — Protocol & Feature Expansion

- [ ] Add next utility skeleton (e.g., `src/traceroute.c` or `src/ndp.c` for IPv6) following exact same interface shape (`*_create*`, `feed_input`, `next_event`, dialectic test pair). Record in new ADR.
- [ ] IPv6 support (ping6/ICMPv6 echo, NDP/arping equivalent) — can be in same files or new modules.
- [ ] eBPF improvements: replace placeholder sources in `bpf/` with minimal but functional tracepoint/XDP programs that capture relevant metadata (or document exact expected output format for ringbuf/perf events that the caller feeds back). Expose version/hash metadata via accessors.
- [ ] DNS diagnostics skeleton or route discovery events (opportunistic once core parsers solid).
- [ ] Optional: lightweight mtr-style combined loss/latency path analysis events derived from multiple probes.

## P3 — Documentation, Examples, Packaging, Ecosystem

- [ ] Populate `examples/` with reference harnesses (liburing + epoll + raw socket or eBPF ringbuf consumer) that demonstrate full workflow: create ctxs, feed packets + timestamps, drain events, react to faults. Keep examples optional (`BUILD_EXAMPLES`).
- [ ] More ADRs: 002 (event model & timestamping), 003 (testing/fuzz/valgrind — already referenced), 004 (dialectic testing), 005 (eBPF integration), 006 (plumbing philosophy — inherited), etc. Update cross-references.
- [ ] Expand docs/: man pages (or asciidoc), DOMAIN.md with more workflows/fault signatures, updated README.
- [ ] pkg-config + CMake export already present — add versioned symbols or ABI checks if expanding public API.
- [ ] LuaJIT FFI example bindings (arping.lua style) or harness integration notes.
- [ ] CI (GitHub Actions) for build + ctest + valgrind on Linux (and cross-compile hints for OpenWRT).
- [ ] Consider splitting future large utilities into sibling libs only when they represent entirely new protocols (per ARCHITECTURE.md).

## Non-Goals (Preserve Invariants)

- No automatic retransmits, policy, socket management, eBPF load/attach, or clock access inside the library.
- No dynamic allocation in hot paths beyond initial create.
- No function pointers or callbacks.
- eBPF scripts remain caller-installed data/resources.

## How to Work on Items

1. Consult AGENTS.md + relevant ADR before starting.
2. Create/update ADR for any interface or event model change.
3. Implement in small reviewable patches.
4. Add dialectic test + smoke coverage.
5. Run full build + ctest + Valgrind before marking complete.
6. Update TODO.md, docs, and ARCHITECTURE.md as needed.

**Next milestone target**: P0 items complete → robust, production-usable ping/arping analysis with real timing/fault events usable by operators or AI harnesses.

This TODO is the living plan. Update it as items are completed or new opportunities identified.