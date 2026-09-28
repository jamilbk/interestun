# Network.framework tunnel measurements against Windows

For the newer native event loop, coalescing and utun byte-buffer sweep, see
[native worker performance](native-worker-performance.md).

Before the receive bridge optimization on September 27, 2026, the
Network.framework-only macOS daemon sustained about
**4.1 Gbit/s TCP payload throughput to Windows**. The reverse direction remained
near **0.47 Gbit/s**. The optimized bridge subsequently reached **2.64 Gbit/s**
in that direction; see the 30-second comparison below. These tests send ordinary iperf traffic through the tunnel:
TCP or UDP is the inner protocol; the encrypted outer transport is always UDP.

The Mac was an M2 Pro on macOS 27.0 (26A428), using en8 at 10 GbE. Its tunnel
address was 10.20.0.2, with the Windows peer at 10.20.0.1 and outer endpoint
192.168.1.226:51820. Cipher was AES-256-GCM, MTU 1420. The daemon startup log
confirmed `UDP backend Network` and the connection identified en8. This does
not identify which internal Network.framework transport implementation it used.
The Windows binary revision was not independently verified during this sweep.

## TCP inside the tunnel

Three sequential repetitions per mode, eight measured seconds after one second
warmup. Values are receiver payload rates, not link rates.

| Mode | Mac → Windows Gbit/s | Windows → Mac Gbit/s |
| --- | ---: | ---: |
| One direction at a time, median | 4.087 | 0.463 |
| One direction at a time, range | 3.919–4.094 | 0.456–0.478 |
| Simultaneous directions, median | 0.266 | 0.429 |

The Mac daemon used roughly 1.7–1.9 CPU cores during forward tests and 2.2 during
reverse tests. These are whole-process CPU-time deltas divided by the command's
wall time, including warmup. They include framework work, but not Windows daemon
CPU or the separate iperf processes. WireGuard transfer counters increased by
multiple gigabytes, confirming the traffic traversed the tunnel.

A fresh restart of the same Network.framework build produced:

| Check | Receiver Gbit/s | Mac daemon CPU cores | RSS after test |
| --- | ---: | ---: | ---: |
| Mac → Windows, one stream | 4.126 | 1.90 | 17.1 MiB |
| Windows → Mac, one stream | 0.483 | 2.20 | 18.7 MiB |
| Windows → Mac, four streams | 0.465 | 2.19 | 26.6 MiB |

Restarting did not remove the directional difference, and four reverse streams
did not improve throughput. The Windows tunnel send path and Mac tunnel receive path are both candidates.
These observations isolate the direction, not which endpoint causes the limit.
The Mac CPU reading is not sufficient to distinguish them. In particular, the Mac bridge
at that revision serialized receive callbacks and send work on one dispatch queue,
passed received packets through a staging ring, and checked out up to 128 packet
buffers on every receive call even when few packets are available.

The earlier 0.681 Gbit/s forward TCP sample in
[the initial experiment](apple-udp-backends.md) is not representative of these
later runs. The Mac dataplane code was unchanged; these measurements do not
establish why that earlier short sample was lower. They also do not constitute
a controlled comparison against BSD or establish a macOS-wide UDP ceiling.

## UDP inside the tunnel

These preceding diagnostic samples measured five seconds after one second
warmup, with a 1360-byte UDP payload. Requested bitrate can exceed what the
load generator actually sends.

| Direction | Requested Gbit/s | Actual sender Gbit/s | Receiver Gbit/s | iperf reported loss |
| --- | ---: | ---: | ---: | ---: |
| Mac → Windows | 1.0 | 1.000 | 1.000 | 0% |
| Mac → Windows | 3.0 | 3.000 | 2.938 | 2.077% |
| Mac → Windows | 5.0 | 3.304 | 3.179 | 3.791% |
| Windows → Mac | 0.25 | 0.250 | 0.250 | 0% |
| Windows → Mac | 0.5 | 0.501 | 0.500 | 0.003% |
| Windows → Mac | 1.0 | 1.000 | 0.774 | 1.964% |

The final reverse UDP sample had substantial buffering: its delivery shortfall
is larger than the reported sequence-gap loss. Do not interpret that loss field
as complete end-to-end accounting. During receive overload, observed Mac daemon
RSS grew from approximately 15 MiB to approximately 587 MiB; it later declined.
This is evidence of buffering/retention beyond the bridge's small fixed receive
ring, not proof of a permanent leak. The exact owner and queue are unprofiled.
The clean-restart TCP checks above avoid that retained state.

## Direct LAN control

The same Windows iperf server, reached at 192.168.1.226 instead of its tunnel
address, delivered 9.375 Gbit/s forward TCP and 9.412 Gbit/s reverse TCP. Reverse
UDP at 1 Gbit/s delivered 1.000 Gbit/s with no reported loss. These eight-second
samples bypass both tunnel implementations. They narrow the problem to the
tunnel path; they do **not** distinguish Windows tunnel TX from macOS tunnel RX.

## Receive wakeups

An `io-profile` build added bridge notification/packet counters, kqueue event
counts, and sampled CPU/wall timing around the bridge, buffer handling, and poll.
During a steady five-second window of the Windows-to-Mac TCP test:

- 222,142 received packets; 166,305 successful bridge drains: **1.336 packets per drain**.
- 166,305 notification bytes consumed and 149,450 UDP-token kqueue events.
- 168,993 poll calls, only 2,688 with a nonzero timeout, **zero blocking-poll timeouts**.
- No reported bridge I/O errors or utun write backpressure.
- Sampled mean bridge-call wall time was approximately **12.3 µs**; buffer setup
  averaged 2.5 µs and unused-buffer release 1.5 µs. These sampled spans include
  scheduling effects and clock overhead; they are diagnostic estimates.

The worker is receiving notifications and repeatedly making progress. This
window does not show a lost-wakeup stall. Readiness events are not necessarily
thread wakeups: many arrive during zero-timeout polling while the worker is
already running. What is visible is poor amortization: the 128-packet capacity
usually delivers batches close to one packet. The same dispatch queue services
callbacks and synchronous Rust bridge calls. Mac-side queue handoffs and buffer
churn warrant investigation, without treating this as proof against a Windows
contribution.

The normal race invariant is preserved: draining notification bytes precedes
checking the serialized receive ring; successful drains retain runtime
readiness until `WouldBlock`; a new empty-to-nonempty transition signals again.
The audit did find an error-path hole: interrupted notification writes were
ignored. They now retry `EINTR`. A full notification socket remains coalesced
(`EAGAIN`); other write failures shut down its write side so the worker sees EOF
instead of silently sleeping. A fault-injection test verifies all three cases.
This robustness fix is not claimed to explain the measured throughput limit.

The instrumented TCP results were 0.495 Gbit/s reverse and 4.001 Gbit/s forward.
[Diagnostic logs and iperf summaries](benchmarks/macos-network-framework-wakeups/iperf.json)
are saved alongside the per-mode worker logs. Regular builds contain none of
the opt-in counter or sampled-clock instrumentation.

## Batched bridge: 30-second comparison

The revised bridge removes hot-path `dispatch_sync`, retains framework messages
in a bounded 1024-slot ring, posts up to 128 reserved receives in batches, and
copies directly into cached Rust packet buffers. Coalesced dispatch notification
lets already-queued callbacks accumulate without a timer. See
[ownership and readiness](apple-udp-backends.md#ownership-and-readiness).

Same Mac, Windows endpoint, AES-256-GCM, MTU 1420, and `io-profile` build feature.
Each iperf TCP run measured 30 seconds after one second of warmup. These are
sequential before/after samples, not an interleaved statistical study.

| Direction | Before Gbit/s | After Gbit/s | Before daemon CPU | After daemon CPU |
| --- | ---: | ---: | ---: | ---: |
| Mac → Windows | 3.996 | 3.800 | 189.0% | 168.3% |
| Windows → Mac | 0.463 | 2.638 | 219.9% | 203.8% |

CPU is process CPU-time delta over approximately 27 seconds of steady traffic,
using one-second snapshots within seconds 2–30 of the command; 100% means one
CPU core. It includes framework work within the Mac daemon and excludes iperf
and Windows CPU. Sampled peak daemon RSS after the change was 16.1 MiB forward
and 19.1 MiB reverse.

Reverse throughput improved **5.7×**, with slightly lower process CPU. Forward
throughput was about 5% lower, with about 11% less CPU; this run does not show a
forward throughput improvement. Steady reverse profile windows now averaged
**17.3 packets per utun write**, compared with 1.34 previously. The framework
bridge had been a substantial receive bottleneck. These results do not locate
the remaining limit or prove a framework-internal offload path.

A subsequent 30-second simultaneous-direction test delivered 2.572 Gbit/s
Mac → Windows and 1.050 Gbit/s Windows → Mac at 186.5% daemon CPU. Earlier
8-second duplex tests had medians of 0.266 and 0.429 Gbit/s respectively; the
different durations and sequential runs limit that comparison.

`MAX_PENDING_PACKETS=1024` is the utun queue used for kernel-to-userspace reads
(our tunnel transmit path). It does not size the decrypted userspace-to-kernel
write queue. The new 1024-slot framework receive ring is a separate bound.

Native tests cover retained-message ownership, FIFO wraparound, partial drains,
empty/error propagation, interrupted notification writes, full notification
channels, and EOF wakeups. They also pass under AddressSanitizer. Rust tests and
Clippy pass with all features; no-default-feature tests retain BSD coverage.
No local two-utun performance test was used for these measurements.

[Raw iperf results, CPU snapshots, and daemon profile](benchmarks/macos-network-framework-batched/)
preserve the before/after measurements.

## Reproduce

Build with the default `apple-network` feature and start/configure the tunnel
normally. Confirm `UDP backend Network` in the startup log. Run these tests
sequentially against an existing Windows iperf server:

```sh
iperf3 -c 10.20.0.1 -t 8 -O 1 -J
iperf3 -c 10.20.0.1 -t 8 -O 1 -J -R
iperf3 -c 10.20.0.1 -t 8 -O 1 -J --bidir
iperf3 -c 10.20.0.1 -t 8 -O 1 -J -R -P 4
iperf3 -c 10.20.0.1 -u -b 3G -l 1360 -t 5 -O 1 -J
```

The Network.framework daemon was left running and connected to Windows.
[Measurements and iperf end summaries](benchmarks/macos-network-framework-windows-followup.json)
include every completed sample used here. Interrupted samples are excluded.
