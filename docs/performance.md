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
cross-worker dispatch, and kernel utun/socket locking. They have not yet been
profiled on a real tunnel. The current root-free tests establish correctness of
the user-space I/O path, not end-to-end performance.
