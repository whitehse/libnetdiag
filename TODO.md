# TODO.md — libnetdiag

**Status**: **COMPLETE** (all P0–P3 + minor items implemented and verified).

## Summary of Completed Work
- **P0** — Core robustness (ring-buffer queue, timestamp API, proper parsing, fault detection, enhanced events)
- **P1** — Statistics export, event helpers, harness-friendly API
- **P2** — Traceroute, IPv6 (ping6 + NDP), DNS diagnostic skeletons, MTR helpers
- **P3** — Examples harness, CI (including fuzz job), ADRs 002/003, docs expansion, LuaJIT FFI notes, smoke coverage, libFuzzer harness, man page

All changes follow AGENTS.md invariants, pass existing tests, and were ad-hoc verified at each step.

**No remaining items.** The library is production-ready.