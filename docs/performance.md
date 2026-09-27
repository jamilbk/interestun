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


## In-place transport API

The in-place fork (`74e450f`) preserves the cipher, transcript, framing, counters,
replay policy, timers, and IP validation. It removes the payload copies performed
by BoringTun's separate-buffer API. The macOS worker also avoids acquiring and
recycling a second pooled buffer for every transport packet.

The following comparison uses the in-memory harness on the same M2 Pro, on AC
power with AC Low Power Mode disabled, inherited QoS, one worker, three samples,
one million measured roundtrips and 10,000 warmup records per sample. Payload
bytes (including IP headers) are counted once. These rates include both seal and
open; they are not tunnel throughput. The copy run preceded the in-place run;
background load, core placement, and thermal state were not fixed. The in-place
harness recycles the decrypted payload for the next record; it does not measure
kernel receive, send, pools, or inter-worker dispatch.

| Cipher / IP bytes | Copy Gbit/s | In-place Gbit/s | Change |
| --- | ---: | ---: | ---: |
| Aes256Gcm / 64 | 3.791 | 4.445 | +17.3% |
| Aes256Gcm / 1420 | 18.437 | 20.875 | +13.2% |
| ChaCha20Poly1305 / 64 | 1.204 | 1.258 | +4.5% |
| ChaCha20Poly1305 / 1420 | 5.229 | 5.383 | +2.9% |

Raw measurements and environment/build metadata:
[copy CSV](benchmarks/transport-copy-ac.csv),
[copy metadata](benchmarks/transport-copy-ac.json),
[in-place CSV](benchmarks/transport-inplace-ac.csv),
[in-place metadata](benchmarks/transport-inplace-ac.json).

```sh
python3 scripts/bench.py --samples 3 --packets 1000000 --output copy.csv
python3 scripts/bench.py --in-place --samples 3 --packets 1000000 --output inplace.csv
```

Correctness gates: the fork's default and no-default-feature suites, 512
payload/alignment differential cases per cipher against the existing API,
known-answer coverage, invalid tags, wrong indices, replay, size/nonce boundaries,
public API/session/statistics behavior, interestun's two-peer dataplane/roaming
tests, maximum-MTU header-space roundtrip, and real-utun IPv4/IPv6 tests using
both ciphers. No AEAD primitive/assembly was changed and no new constant-time
or sanitizer audit was performed. Fork library/test clippy passes; its existing
x25519 benchmark has an unrelated redundant-closure lint under all-target clippy.

Two-host testing was interrupted when the Windows tunnel address stopped
responding; LAN iperf remained reachable and handshakes continued. No two-host
throughput improvement is claimed for this change.

### Measure actual batch utilization

A diagnostic build reports per-thread utun/UDP receive/send counts to stderr every
five seconds; `peer` and `worker` identify the owner. Production builds compile out the counters and thread-local state.

```sh
CARGO_TARGET_DIR=target cargo build --release --locked --features io-metrics
sudo ./target/release/interestun utun
```

Each row reports `calls`, `requested`, `packets`, `would_block`, and `errors` for
one direction over that interval. `packets / calls` is effective syscall batch
size including unsuccessful calls. For sends, compare packets with requested
messages to spot partial writes/backpressure. Receive requests describe slot
capacity, not known queued packets. UDP counters combine connected and wildcard
sockets on that receive worker. Counters measure completed kernel I/O, not successful
packet authentication or application delivery. Fallback per-message calls are
counted individually. Handshake cookie `send_to` calls are outside these counters.
Use diagnostic runs for attribution; compare production builds for throughput.

### utun pending queue and XNU audit

Raising the verified utun pending-packet limit from one to 128 produced median
TCP throughput of 2.014 Gbit/s Mac → Windows and 2.557 Gbit/s Windows → Mac
in three diagnostic samples per direction. A send-heavy interval averaged
13.18 UDP messages per send syscall. See the [XNU audit](xnu-performance-audit.md)
for source links, measurement limitations, and the next optimization experiments.

### Syscall batches 128, utun pending limit 1024

The same single-stream AES-256-GCM test, MTU 1420, three alternating samples
per direction, one second warmup and five measured seconds, with `io-metrics`:

| Direction | Samples, Gbit/s | Median | Previous batch 32 / pending 128 median |
| --- | --- | ---: | ---: |
| Mac → Windows | 2.018, 1.725, 2.022 | 2.018 | 2.014 |
| Windows → Mac | 2.539, 2.565, 2.566 | 2.565 | 2.557 |

There is no clear throughput improvement in these short sequential runs. The
per-direction packet budget remains 128, now one batch instead of four, to
avoid increasing drain bursts beyond the 256-packet userspace queues. This also
changes syscall scheduling frequency; the experiment does not isolate the two
capacity settings. A send-heavy counter interval averaged 10.23 UDP messages
per syscall (681,052 / 66,582), so capacity 128 does not imply full batches.
The requested pending limit is verified by getsockopt, but byte-buffer capacity
can constrain the effective backlog before 1024 MTU-sized packets accumulate.

[Raw samples](benchmarks/macos-batch128-pending1024.csv). Normal tests, clippy
with all targets/features, and real-utun tests for both ciphers and IP families
passed. No loaded-latency or multi-peer throughput comparison was performed.

### Separate macOS send and receive threads

macOS now has one TX and one RX thread per peer, using the exclusive sender
handoff in fork `ea898e7`. A TX key/counter moves once; RX retains replay and
handshake state. No cipher operation holds a shared tunnel mutex. The Windows
peer used for these measurements was not rebuilt during this experiment.

With AES-256-GCM, MTU 1420, batch 128, pending limit 1024, and `io-metrics`:

| One-way direction | Split-thread samples, Gbit/s | Split median | Previous median |
| --- | --- | ---: | ---: |
| Mac → Windows | 2.025, 2.019, 1.976 | 2.019 | 2.018 |
| Windows → Mac | 2.514, 2.542, 2.553 | 2.542 | 2.565 |

Each sample measured five seconds after one second warmup. There is no clear
one-way throughput improvement. To check simultaneous traffic, the previous
`18d7bc5` build was rebuilt separately and run on the same interface, followed
by the split-thread build. Each bidirectional sample measured ten seconds after
two seconds warmup, one TCP stream each way:

| Build | Mac → Windows samples, Gbit/s | Windows → Mac samples, Gbit/s | Median aggregate |
| --- | --- | --- | ---: |
| Previous combined worker | 1.104, 1.809, 1.125 | 1.176, 0.403, 1.201 | 2.280 |
| Split TX/RX | 1.113, 1.121, 1.115 | 1.177, 1.175, 1.184 | 2.296 |

This also does not establish a throughput gain. The asymmetric second baseline
sample illustrates run-to-run variation. Neither endpoint was CPU-pinned;
Windows worker CPU and kernel attribution were not measured. These results do
not identify which endpoint limits throughput. The thread split permits
independent processing but does not establish a faster end-to-end ceiling.

[Raw samples](benchmarks/macos-duplex.csv). The adapter and peer cipher remain
wire-compatible with the previous build. Correctness gates include concurrent
two-peer bidirectional traffic, authenticated roaming, real-utun tests with both
ciphers and IP families, and fork tests for concurrent transport, exclusive
nonce handoff, replay, expiry/revocation, rekey replacement, deferred keepalives,
and delayed activity reporting. Fork suites passed 82 default / 80 no-default
checks. Shared-utun injection is serialized per batch only with multiple peers;
see the [kernel finding](xnu-performance-audit.md#follow-up-concurrent-writes-on-a-shared-descriptor).

A subsequent 130-second send transfer completed with fresh handshakes observed
while traffic continued (including AES message-budget rekeys). Receiver rate was
2.060 Gbit/s; TCP reported 4,313 retransmissions, so this is not a loss-free
result. No measured one-second interval stopped transferring data. This was a
sustained correctness check, not a controlled performance comparison.
[Intervals](benchmarks/macos-duplex-sustained.csv) and
[summary](benchmarks/macos-duplex-sustained.json) preserve the evidence.

### Send-path attribution and reusable descriptors

The [bottleneck investigation](bottleneck-investigation.md) records descriptor
preallocation, TCP versus UDP probes, per-thread CPU deltas, and opt-in sampled
stage timing. UDP delivered 2.99 Gbit/s at a 3 Gbit/s offered rate with about
0.4% loss, while TCP remained near 2.07 Gbit/s. At the UDP rate, sampled timing
attributes roughly 73% of a Mac core to UDP sends, 15% to utun reads, and 9% to
the complete encryption batch. These are diagnostic estimates, not exact totals.
