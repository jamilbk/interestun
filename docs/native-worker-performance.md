# Native macOS worker optimization sweep

Measurements use an M2 Pro, macOS 27.0 (26A428), en8 at 10 GbE,
AES-256-GCM, MTU 1420, and the existing Windows endpoint
192.168.1.226:51820 / tunnel address 10.20.0.1. TCP iperf3 runs through the
tunnel; encrypted outer traffic remains UDP. No local two-utun throughput tests
or live BSD fallback were used. Windows revision/CPU were not independently
verified. These sequential experiments establish observations on this pair,
not an absolute platform ceiling or a randomized A/B study.

## Implementation retained

- macOS no longer depends on mio or Tokio. A native kqueue driver handles utun
  descriptor readiness and an atomic pending-work mask handles callbacks.
- Callbacks trigger `EVFILT_USER` only when a worker has armed its sleep.
  Sequentially consistent publication/arm/recheck prevents a lost-wakeup race.
  Signals own the queue through `Arc`; C callbacks own their Rust signal context
  until the retained framework flow is deallocated.
- Active work collects callback bits without a syscall, checking descriptor
  events every 32 batches to bound starvation. Idle workers block against their
  existing control/timer deadline. There are no notification socketpairs.
- Compatible authenticated TCP segments for local delivery are coalesced before
  batched utun injection. Checksums, headers, sequence continuity, TCP options,
  PSH boundaries and ordering are respected. Forwarded/incompatible packets are
  passed separately. No timer delays aggregation. Scratch storage is preallocated.
- Utun's socket receive buffer is independently enlarged to 4 MiB and read back
  at startup. The pending-packet threshold remains 1024. Published XNU sets the
  [default control-socket receive buffer to 512 KiB](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L1663); increasing the packet limit
  alone does not increase that byte capacity. The byte limit can be exhausted
  before packet-count flow control stops output.

Network.framework still uses `nw_connection_batch` for send submissions and
receive replenishment, with separate UDP datagrams and per-message callbacks.
The receive window remains 128 and its retained-message ring remains 1024.
Grouping API calls is not a guarantee of one kernel syscall for the group.

## Experiment record

Initial sweeps measured ten seconds after a one-second warmup, with `io-profile`
enabled. The later release runs disable instrumentation. CPU is daemon process
CPU time divided by steady wall time, from half-second `ps` snapshots within
seconds 2 through the end of the measured interval. One core equals 100%; iperf
and Windows CPU are excluded. Rates are receiver TCP payload goodput.

| Variant | Send Gbit/s | Receive Gbit/s | Send cores | Receive cores |
| --- | ---: | ---: | ---: | ---: |
| Direct callback signals, native kqueue | 4.153 | 2.631 | 1.73 | 1.97 |
| Also skip most active kqueue calls | 4.190 | 2.667 | 1.73 | 1.77 |
| Also coalesce local TCP delivery | 4.219 | 2.736 | 1.74 | 1.50 |
| Higher worker/dispatch QoS, rejected | 3.917 | 2.624 | 1.68 | 1.76 |
| Shared weak completion blocks, rejected | 3.679 | 2.564 | 1.67 | 1.39 |
| Shared strong completion blocks, rejected | 3.708 | 2.633 | 1.67 | 1.42 |
| Transfer send-buffer ownership, rejected | 3.430 | 2.709 | 1.90 | 1.62 |
| 512 outstanding receives, rejected | 3.967 | 1.673 | 1.69 | 1.15 |

The ownership-transfer experiment removed a payload copy but added per-message
ownership allocation and asynchronous buffer destruction; measured total CPU
increased and throughput fell. The retained implementation copies sends into
framework-owned dispatch data. It is not zero-copy.

Four/eight TCP streams did not improve aggregate throughput (send 3.32/3.38,
receive 2.43/1.75 Gbit/s). A 2 MiB iperf socket window, application zero-copy,
and offered-rate pacing also failed to establish a higher sustained ceiling.
The IPv4 no-UDP-checksum experiment nearly stalled data traffic and was reverted;
its precise failure location was not established. Normal checksums remain enabled.

Before enlarging the utun byte buffer, two 30-second release repeats ranged from
3.626–4.071 Gbit/s send and 2.714–2.753 Gbit/s receive. The interface accumulated
2878 output errors across those tests, and send retransmissions increased.
This led to the separate socket-buffer investigation instead of treating the
first short-run maximum as stable throughput.

## Selected build: repeated 30-second results

The selected release build uses native signaling, 128-packet I/O batches,
a 128-request receive window, local TCP coalescing, and the verified 4 MiB utun
receive buffer. It was left running against the Windows peer.

| Direction | First run Gbit/s | Repeat Gbit/s | Repeat daemon CPU cores |
| --- | ---: | ---: | ---: |
| Mac → Windows | 4.322 | 4.309 | 1.73 |
| Windows → Mac | 2.504 | 2.519 | 1.45 |
| Simultaneous Mac → Windows | 3.008 | 2.959 | 1.80 combined |
| Simultaneous Windows → Mac | 0.878 | 0.885 | same process |

Utun output errors remained **zero** over each complete send/receive/duplex
sequence. TCP still reported retransmissions; zero utun output errors does not
mean zero tunnel loss. A 64-packet batch delivered 4.273 Gbit/s send with slightly
more CPU in a ten-second sample, so 128 was retained.

The highest 30-second send measurement was **4.322 Gbit/s**. The highest
30-second reverse measurement across the sweep was **2.753 Gbit/s**, before the
byte-buffer change; the final configuration did not match that earlier reverse
rate. Its roughly 1.45 receive CPU cores compare with 2.04 in the preceding
[batched-bridge baseline](network-framework-windows-testing.md#batched-bridge-30-second-comparison),
which delivered 2.638 Gbit/s with profiling enabled. This is a substantial CPU
reduction, not proof of a reverse throughput improvement. Windows-side daemon
profiling remains necessary to distinguish the remaining endpoint limits.

The repeated send results now establish an observed plateau around 4.3 Gbit/s
on this setup. They do not establish an absolute maximum for Network.framework,
macOS UDP, other peer implementations, different MTUs, or other hardware.

## Validation and reproduction

Tests cover callback races with sleep (10,000 iterations), coalesced signals,
kqueue descriptor edges, descriptor progress during active work, retained C
message/signal lifetime, local-versus-forwarded TCP injection, error-prefix
handling, ciphers, configured peers, endpoint families, and UAPI. Native ownership
tests run under AddressSanitizer. Privileged local-utun tests were not used.

```sh
CARGO_TARGET_DIR=target cargo build --release --locked
# Start/configure the daemon with wg and confirm Network / AES-256-GCM in its log.
iperf3 -c 10.20.0.1 -t 30 -O 1 -J
iperf3 -c 10.20.0.1 -t 30 -O 1 -J -R
iperf3 -c 10.20.0.1 -t 30 -O 1 -J --bidir
netstat -ibnI utun14
```

[Experiment artifacts](benchmarks/macos-native-workers/) include commands,
receiver results, CPU samples, profiles, and the measurement script.
