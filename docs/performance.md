# Performance baseline

This measures an in-memory BoringTun transport roundtrip: encryption, decryption,
tag verification, replay-window update, IP validation, and transport framing/copies.
Inner IP bytes are counted once, including the IP header. Each operation processes
those bytes twice (seal and open); the reported Gbit/s does **not** double-count
them. There is no utun, socket, peer dispatch, packet pool, or queue work in this
benchmark. These numbers are not tunnel throughput or a hardware ceiling.

## Recorded conditions

- Apple M2 Pro, 12 logical CPUs; Darwin 27.0.0, aarch64.
- Battery power with Low Power Mode enabled; inherited default thread QoS.
- Rust 1.94.0 / LLVM 21.1.8; ring 0.17.14; pinned cipher fork `d60ac564`.
- Release build, thin LTO, one codegen unit, debug symbols; no target-cpu override.
- Five samples at every worker count from 1 through 12, two packet sizes.
- 100,000 measured records per worker; 10,000 warmup records per worker.
- Independent keys, counters, state, and buffers for each worker. Setup excluded.
- A start barrier and common start timestamp; completion is the slowest worker.
- Cipher order alternates between samples. Ordinary desktop scheduling remains
  part of this observation; CPU residency, temperature, and frequency are not fixed.

The linked benchmark contains ring AES-GCM symbols and ARM AES instructions.
No primitive implementation, assembly, or QoS setting was changed. The comparison
uses the same full transport work for both cipher suites. Functional gates include
an AES-256-GCM known answer, altered tags, replay, suite mismatch, and counter limits.
No new sanitizer or independent constant-time/protocol audit was performed.

## Results

At 1420 bytes and one worker, AES measured **14.96 Gbit/s**, versus
**4.21 Gbit/s** for ChaCha: **3.55×** the transport-roundtrip rate.
Values below are medians of five samples, in Gbit/s.

| Workers | AES 64 B | ChaCha 64 B | AES 1420 B | ChaCha 1420 B |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 3.01 | 0.96 | 14.96 | 4.21 |
| 2 | 6.03 | 1.93 | 30.04 | 8.47 |
| 3 | 9.03 | 2.89 | 44.98 | 12.71 |
| 4 | 11.96 | 3.85 | 59.98 | 16.91 |
| 5 | 14.98 | 4.82 | 75.11 | 21.18 |
| 6 | 17.94 | 5.79 | 89.75 | 25.44 |
| 7 | 20.88 | 6.73 | 104.91 | 29.61 |
| 8 | 22.74 | 7.47 | 114.17 | 32.88 |
| 9 | 21.38 | 7.79 | 109.84 | 34.08 |
| 10 | 24.01 | 8.44 | 121.23 | 36.55 |
| 11 | 22.84 | 8.98 | 125.92 | 38.54 |
| 12 | 24.66 | 8.87 | 126.87 | 38.37 |

Sample ranges at 1420 bytes:

| Suite / workers | Min–max Gbit/s | Scaling versus one worker | Efficiency |
| --- | ---: | ---: | ---: |
| Aes256Gcm / 1 | 14.91–15.02 | 1.00× | 100.0% |
| Aes256Gcm / 12 | 117.05–135.67 | 8.48× | 70.7% |
| ChaCha20Poly1305 / 1 | 4.21–4.23 | 1.00× | 100.0% |
| ChaCha20Poly1305 / 12 | 35.00–39.48 | 9.10× | 75.9% |

CSV `ns_per_packet` is the reciprocal aggregate packet rate; with multiple
workers it is not per-packet latency. Packet rate is `packets / seconds`.

[Raw CSV](benchmarks/m2-pro-low-power.csv) and
[machine/build metadata](benchmarks/m2-pro-low-power.json) include all samples,
power settings, timestamps, and lockfile/harness hashes.

## Reproduce

```sh
python3 scripts/bench.py --max-workers 12 --samples 5 --packets 100000 \
  --output transport.csv
```

For end-to-end measurements, use two separate hosts with the same cipher mode,
real utun interfaces, and matching routes. Measure 64/1420-byte traffic, one flow
and many flows, one peer and increasing peer counts, bidirectionally. Record
offered/received packet rates, loss, CPU use, syscall batch sizes, context switches,
and latency under load. Use iperf3 for TCP/UDP baseline traffic and Instruments
for CPU attribution. Repeat on AC power and record QoS/power conditions explicitly.

The next likely limits are the shared utun reader, shared packet-pool atomics,
cross-worker dispatch, and kernel utun/socket locking. Full stack attribution on a real tunnel is still pending. Real-utun integration testing now passes on Darwin
27.0.0 with two local BoringTun echo peers, both ciphers, IPv4/IPv6, and packet
bursts. This establishes
functional packet flow, not network throughput or interoperability with an
independent WireGuard implementation.


## macOS readiness handling: two-host TCP observation

On 2026-09-27, a macOS M2 Pro peer and a separate Windows interestun peer
exchanged AES-256-GCM traffic with MTU 1420 over a LAN that previously measured
9.40/9.41 Gbit/s without the tunnel. The Mac used en8 (10Gbase-T), AC power,
Low Power Mode disabled for AC, and inherited thread QoS. The macOS release
build used the same compiler, cipher dependency, and release profile above.
Windows hardware, build provenance, and power settings were not captured.

The baseline was macOS commit a660fb9. The changed build uses kqueue readiness
instead of probing every descriptor on each iteration and waits for writable
readiness after WouldBlock. The same keys, ports, peer, cipher, and addresses
were retained across a daemon restart.

Each sample used one TCP stream, five measured seconds after one omitted second,
with three samples per direction. Rates count receiver TCP payload bytes.
All baseline samples preceded the changed build; send/receive alternated.
These are short desktop observations, not isolated laboratory results. A brief
local correctness test overlapped part of baseline collection, and background
workloads were not controlled. Treat small deltas cautiously; no maximum
throughput or precise kernel/crypto attribution is established.

| Direction | Baseline median Gbit/s | Readiness median Gbit/s | Change |
| --- | ---: | ---: | ---: |
| Mac to Windows | 1.021 | 1.288 | +26.2% |
| Windows to Mac | 2.303 | 2.492 | +8.2% |

[All twelve samples](benchmarks/macos-readiness.csv) retain receiver bytes,
measurement durations, rates, and sender retransmits when reported.
Commands (add `-R` for Windows to Mac):

```sh
iperf3 -c 10.20.0.1 -t 5 -O 1 --connect-timeout 3000 -J
```

Validation includes 192-packet bursts exceeding the 128-packet worker drain
budget, traffic resuming after idle, two peers, IPv4/IPv6, endpoint roaming,
both ciphers, pool exhaustion versus kernel WouldBlock, and the opt-in real-utun
integration test. Crypto and thread ownership were not changed.
