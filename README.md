# libnetdiag

Pure C syscall-free state-machine library for network diagnostics and troubleshooting on edge devices (OpenWRT, Debian, etc.).

Emulates ping (ICMP), arping (ARP), and traceroute skeletons for analysis purposes. Exposes eBPF script sources for caller-managed installation. All I/O and policy remain in the calling application.

**Status**: P0–P3 features implemented (robust event queue, timestamp-driven RTT/timeout, per-context stats, event helpers, traceroute skeleton, examples, CI).

See AGENTS.md for build, test, and contribution instructions.

Part of the sibling pure-C ecosystem following ADR 006 plumbing philosophy.