# macOS send-path investigation

2026-09-27, M2 Pro, AES-256-GCM, MTU 1420, batch capacity 128, utun pending
limit 1024. Windows peer and the 10 GbE path were unchanged. Rates below are
receiver application payload rates, not encrypted wire rates.

## Preallocation

Payload buffers and queue capacity were already preallocated. Receive and send
now also retain their descriptor/iovec/address-family scratch storage per I/O
thread. Receive address storage is initialized once. Active descriptors are
refreshed before each call, including source-address capacity, lengths, flags,
and pointers to the current pooled payloads. Unused array entries no longer
need to be zeroed on every syscall. This does not preallocate XNU mbufs or
remove kernel copies. Regression coverage reuses descriptors across shrinking
and growing batches, truncation, and utun/UDP mode changes.

## Traffic and CPU probes

Each case ran ten measured seconds after two seconds warmup. These are single
sequential diagnostic samples, not a controlled A/B comparison.

| Case | Receiver Gbit/s | UDP loss |
| --- | ---: | ---: |
| Existing build, tunnel TCP, one stream | 2.075 | — |
| Existing build, tunnel TCP, four streams | 1.983 | — |
| Direct LAN TCP, one stream | 9.407 | — |
| Existing build, tunnel UDP, offered 3 Gbit/s | 2.988 | 0.415% |
| Reused descriptors, tunnel TCP, one stream | 2.072 | — |
| Reused descriptors, tunnel UDP, offered 3 Gbit/s | 2.987 | 0.436% |

UDP used 1360-byte application datagrams. Its result demonstrates a working
path above 2 Gbit/s; it does not establish a loss-free ceiling. Four TCP streams
did not lift the TCP plateau. Preallocation did not produce a clear throughput
improvement in these samples.

`ps -M` cumulative thread CPU times bracketed each entire test, including warmup
and process-wait overhead. In the original single-stream TCP case, TX consumed
7.34 seconds system + 1.27 seconds user CPU over 12.09 seconds elapsed: about
71% of one core, with 85% of its CPU time in the kernel. RX consumed about 22%
of a core. With 3 Gbit/s UDP, TX consumed 10.37 + 1.55 CPU seconds over 12.11
elapsed, about 98% of a core; 87% of its CPU time was kernel time. The iperf UDP
sender was also near one core, so it can itself limit higher offered rates.
The CPU percentages reported by iperf describe iperf, not the tunnel daemons.

[Throughput](benchmarks/macos-bottleneck-throughput.csv),
[thread CPU deltas](benchmarks/macos-bottleneck-cpu.csv),
[environment](benchmarks/macos-bottleneck-environment.json).
In these artifacts, `bottleneck` is commit `61a51ad` with `io-metrics`;
`preallocated` adds descriptor reuse; `profile` also enables sampled timing.
Thread roles in the `ps` data are inferred from main/TX/RX creation order.

## Sampled attribution

The optional `io-profile` feature samples one in 64 calls using wall time and
`CLOCK_THREAD_CPUTIME_ID`. Normal builds compile out the timing and TLS state.
`io-profile` implies `io-metrics`; it emits per-thread five-second stage rows.

```sh
CARGO_TARGET_DIR=target cargo build --release --locked --features io-profile
```

For a five-second window entirely inside the 3 Gbit/s UDP run, scaling each
stage's sampled CPU time by `calls / samples` gives these approximate fractions
of one core:

| TX stage | Approximate core use |
| --- | ---: |
| UDP send syscall | 73% |
| utun receive syscall | 15% |
| Encryption batch, including framing and queue bookkeeping | 9% |
| Receive descriptor setup | 1.1% |
| Send descriptor setup | 0.5% |

In a TCP window, the corresponding UDP-send, utun-read, and encryption estimates
were about 47%, 12%, and 6.5% of one core. UDP send calls averaged about 33 µs
CPU time each in that TCP window. Sampled syscall wall time was close to CPU
time; these samples do not show substantial time blocked inside those calls.

Clock probes add overhead, especially to short setup spans. Periodic sampling
can be biased. Pool refill/recycling, routing, polling, activity handoff, and
work on other kernel threads are not separately attributed. Stage estimates
are not exact totals or instruction-level profiles.
[Raw sampled stages](benchmarks/macos-bottleneck-stages.csv).

## What this establishes

The dominant measured Mac TX cost is inside UDP sending, not AES or userspace
allocation. Raw crypto measured seal/open in memory and omitted this kernel
path. The [XNU audit](xnu-performance-audit.md) describes remaining per-packet
allocation/copy and UDP/IP dispatch even with connected batch sends.

This does not prove what limits TCP to roughly 2 Gbit/s: the Mac TX thread is
not CPU-saturated during that TCP test, and UDP has less reverse ACK work.
Distinguishing socket processing, TCP/ACK behavior, and Windows receive/injection
requires endpoint profiling. Kernel stacks are needed to separate allocation,
routing/filtering, and driver cost within the expensive Mac UDP-send syscall.
Increasing userspace preallocation alone does not address that kernel work.

## Follow-up: direct UDP and offload limitations

The 9.407 Gbit/s direct-LAN baseline above used TCP. Direct iperf UDP with
1360-byte application datagrams, ten measured seconds and two seconds warmup,
gave the following single sequential samples on the same Mac-to-Windows path:

| Offered Gbit/s | Sender Gbit/s | Receiver Gbit/s | UDP loss | Sender process CPU | Sender system CPU |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | 3.000 | 2.077 | 30.735% | 83.97% | 77.16% |
| 9 | 4.416 | 2.508 | 43.211% | 99.73% | 93.12% |

CPU percentages are fractions of one core and describe iperf, not interestun.
The 9 Gbit/s offered rate was not achieved. A four-stream attempt failed with
`unable to read from stream socket: Resource temporarily unavailable`; it gives
no usable scaling result. [Commands and iperf summaries](benchmarks/macos-direct-udp.json).

Small-datagram sending therefore has substantial kernel cost even without
utun or encryption. This is consistent with the tunnel's sampled attribution.
It does not locate the direct-UDP packet losses: receiver goodput is a separate
measurement from sender throughput. The earlier tunnel UDP sample delivered
more than these direct UDP samples; the receivers, buffering, and scheduling
paths differ, so that observation is not evidence that encryption improves UDP.

The identified architectural limitation is the absence of UDP segmentation
offload in our current BSD send path. Connected `sendmsg_x` amortizes syscall
entry and setup, but the audited XNU path still allocates/copies each packet
and dispatches UDP/IP processing per datagram. See the
[source-linked audit](xnu-performance-audit.md). Apple's public
[UDP header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/udp.h)
and the installed SDK expose no Linux-style `UDP_SEGMENT` socket option.
This does not establish the absence of all alternative/private Apple paths.

TCP can instead use segmentation offload (TSO) to pass larger chunks toward
the NIC for segmentation. The existing Ethernet interface reports TSO enabled;
we did not trace its use in the baseline transfer. Apple's
[TCP output implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/tcp_output.c)
contains that path. Checksum offload is a separate capability and can also
benefit UDP; describing this as a lack of all UDP offloads would be inaccurate.

Thus missing segmentation offload and retained per-packet kernel processing
explain why TCP's 10 GbE result is not an equivalent performance baseline.
They are a supported bottleneck hypothesis, not a fully isolated root cause
for the exact 4.416 Gbit/s direct-UDP or roughly 2 Gbit/s tunnel-TCP ceilings.
The iperf sender differs from our batch sender. A standalone benchmark of our
connected batch path with prebuilt packets, successful multi-sender tests,
and kernel stacks are still needed to separate stack, driver, and scaling costs.

## Adapter capability comparison

Read-only `ifconfig -m en8`, `ifconfig -m en14`, and `system_profiler
SPEthernetDataType SPThunderboltDataType` identified the newly connected Apple
adapter. Supported and enabled option masks matched on both interfaces:

| Property | OWC dock / Aquantia (`en8`) | Apple Thunderbolt Ethernet (`en14`) |
| --- | --- | --- |
| Controller | Aquantia AQC107 | Apple 57762-A0 |
| Driver | `AppleEthernetAquantiaAqtion` | `AppleBCM5701Ethernet` |
| Maximum Ethernet speed | 10 Gbit/s | 1 Gbit/s |
| Capability/option mask | `0x567` | `0x50b` |
| RX/TX checksum flags | `RXCSUM,TXCSUM` | `RXCSUM,TXCSUM` |
| TCP segmentation flags | `TSO4,TSO6` | Not advertised |
| VLAN flags | `VLAN_MTU` | `VLAN_HWTAGGING` |
| Other flags | `AV,CHANNEL_IO` | `AV,CHANNEL_IO` |
| Link at inspection | Active, 10Gbase-T, full duplex, flow control | Inactive |

Both adapters use Apple drivers. The Apple-branded adapter advertises no extra
UDP acceleration and fewer relevant segmentation capabilities. Its Thunderbolt
bus reports 10 Gbit/s, but its Ethernet port is limited to 1 Gbit/s. It cannot
test the existing 3–4 Gbit/s send ceiling. Flags describe driver-advertised
capabilities, not proof of hardware offload use for a particular packet.

## Alternative transport path

The missing UDP segmentation API does not exhaust the available approaches.
Network.framework can use Apple's userspace transport stack, with a different
packet exchange path from BSD UDP. The opt-in
[Network.framework benchmark](network-framework-benchmark.md) compares raw and
BoringTun-encrypted sends through both APIs without changing the live tunnel.
API selection alone does not prove a particular connection uses that path.
The [build-time daemon experiment](apple-udp-backends.md) also tests the actual
tunnel using Network.framework exclusively for UDP.
