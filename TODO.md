# TODO.md — libnetdiag

**Status**: **COMPLETE** (all P0–P3 + core L2/L3 implementation + ad-hoc verified).

## Summary of Completed Work
- **P0** — Core robustness (ring-buffer queue, timestamp API, proper parsing, fault detection, enhanced events)
- **P1** — Statistics export, event helpers, harness-friendly API
- **P2** — Traceroute, IPv6 (ping6 + NDP), DNS diagnostic skeletons, MTR helpers **+ full L2/L3 packet parsing (ICMP time-exceeded/unreachable, DNS responses) + new events (TRACEROUTE_HOP, DNS_REPLY) + dialectic tests**
- **P3** — Examples harness, CI (including fuzz job), ADRs 002/003, docs expansion, LuaJIT FFI notes, smoke coverage, libFuzzer harness, man page
- **L2/L3 Core** — traceroute.c + dnsdiag.c now emit real events from packet buffers; ad-hoc hermes-verify scripts passed (compile, dialectic roundtrips, no leaks)

All changes follow AGENTS.md invariants, pass existing tests, and were ad-hoc verified at each step.

## App-driven extensions (netforensics / OpenWrt CPE)

- [x] `nfct.h` / `nfct.c` — conntrack event parser interface + synthetic frames
- [x] `nl80211_parse.h` / `nl80211_parse.c` — Wi-Fi station telemetry interface + synthetic frames
- [x] Full CTA_* nested attribute decode for IPv4 ORIG/REPLY tuples (`test_nfct_cta`)
- [ ] Full nl80211 nested attribute decode for station dump replies
- [ ] Dialectic tests for nfct + nl80211 synthetic and captured corpora
- [ ] Document CPE daemon feed pattern in ARCHITECTURE.md

**Prior core (P0–P3)**: complete and production-ready.

## Kali Linux Audit & Additional Verification Techniques (P4 Considerations)

Kali Linux provides an extensive suite of network diagnostics, reconnaissance, and troubleshooting utilities (many overlapping with standard iproute2/iputils but enhanced for pentesting/edge analysis). The following techniques and tools were audited for relevance to verifying network device/server interface functionality with peers:

**Core Connectivity & L2/L3 Verification (already aligned with libnetdiag skeletons):**
- `ip` (addr, link, route, neigh/ARP), `ping`/`ping6`, `arping`, `ss`/`netstat`, `traceroute`/`tracepath`, `mtr` (combined ping+trace with live stats)
- `ethtool` (L1/L2 stats, offloads, link detection), `mii-tool`

**Discovery & Recon (inspiration for future state-machine extensions):**
- `nmap` (host discovery via ARP/ICMP/TCP/UDP probes, port scanning, service/version/OS fingerprinting, script engine for vuln checks)
- `netdiscover`, `arp-scan` (active/passive ARP reconnaissance, fingerprinting, auto-scan for DHCP-less networks)
- `fping` (parallel ping sweeps)

**Deep Analysis & Packet-Level (complements feed_input parsers):**
- `bettercap`, `ettercap` (MITM detection, ARP/DNS spoof monitoring via anomaly events)

**DNS & Application Layer:**
- `dig`, `nslookup`, `host` (detailed query/response analysis, zone transfers, reverse lookups)
- `curl`, `wget` (HTTP/HTTPS/FTP reachability, header inspection)
- Potential: `dnsdiag` enhancements for spoofing/loss patterns

**Performance, Firewall & Advanced:**
- `iperf3` (bandwidth, jitter, packet loss benchmarking — could inspire throughput event types)
- `nft`/`iptables`, `ufw`, `firewalld` (rule verification; caller-managed, library can detect blocked probes via timeouts)
- `aircrack-ng` suite (wireless, out-of-scope for wired edge focus but useful for hybrid)
- `responder`, `impacket` (LLMNR/NBT-NS poisoning detection via unexpected responses)

**Correction/Remediation (always caller-side, not in library):**
- Interface config/restart via `ip`, `ifconfig` (legacy), `ethtool` resets
- Route manipulation, ARP cache flush (`ip neigh flush`), DNS cache (`systemd-resolve --flush-caches`)
- Firewall rule tweaks, bandwidth shaping (`tc`), wireless assoc fixes
- Kali's Metasploit/Burp for active exploitation testing (not diagnostic)

**Audit Outcome for libnetdiag:**
- Current coverage (ping/arping/traceroute/dnsdiag skeletons + IPv6/NDP + MTR helpers + eBPF accessors) addresses the majority of L2/L3 fault detection and dialectic verification use-cases.
- Kali tools excel at *active* scanning and *deep decoding*; libnetdiag remains the pure passive state-machine consumer of raw buffers from those tools or kernel (io_uring, libpcap, eBPF).
- Recommended future P4 items (1-4 implemented) (only if domain need arises; each requires new ADR + dialectic tests):
  - Enhanced ARP recon state machine (netdiscover/arp-scan patterns: passive listen + active sweep, vendor fingerprinting)
  - Nmap-style probe/response parsers for common scan types (SYN/ACK, UDP, ICMP echo/timestamp)
  - Anomaly/spoof detection events (duplicate ARP, unexpected DNS replies, latency outliers)
  - iperf3-like bandwidth probe skeleton (if active generation supported)
- All additions must preserve syscall-free, callback-free, ring-buffer event model and strict `-Wall -Werror` build.
- Use Kali primarily for: developing richer test vectors/fuzz corpora, validating event emission against real captures, and as a reference for edge-device troubleshooting workflows on OpenWRT/Debian.

This audit confirms the library's design is well-aligned with Kali's diagnostic philosophy while staying true to its thin-plumbing invariants. No changes to core code required at this time.