# ADR 003: Testing, Fuzzing & Valgrind Policy

## Status
Accepted

## Context
AGENTS.md and ADR 001 require strict verification for every change to the core library. The project follows a zero-tolerance policy for memory errors, crashes on malformed input, and regression in the pure state-machine invariants.

## Decision
Every change to `src/`, `include/`, or public interfaces must satisfy:

1. **Dialectic tests** — Paired requester/responder contexts exchanging raw buffers (primary method, no sockets).
2. **Smoke + unit coverage** — All public functions exercised in `tests/`.
3. **Valgrind clean** — `valgrind --leak-check=full --error-exitcode=1` on all tests; zero leaks or errors.
4. **libFuzzer** — Packet parser changes (`feed_input*`) must be fuzzed; no crashes on 10k+ iterations.
5. **Build** — `-Wall -Wextra -Wpedantic -Werror` (or MSVC `/W4 /WX`); `ctest` must pass.

New utilities (e.g. traceroute) require their own dialectic test pair before merge.

## Consequences
- CI (when added) will enforce the above.
- All P0–P2 work already follows this policy.
- Future changes must update relevant tests/ADRs.

## References
- AGENTS.md (Testing, Fuzzing & Valgrind Policy)
- ADR 001, 002
- TODO.md (P0 item)