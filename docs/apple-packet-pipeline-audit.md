# Network Extension packet pipeline audit

Measured on 2026-09-28, M2 Pro, macOS 27.0 (26A428), against Windows
`192.168.1.226:51820` / `10.20.0.1`. AES-256-GCM, MTU 1420, 10 GbE.
TCP iperf3 runs inside the UDP tunnel. The selected extension is running on
`utun4`; Network Extension still creates the interface and configures routes.

The selected implementation reads/writes the **existing NE utun descriptor**
directly and keeps **Network.framework for UDP**. It does not attach an
experimental utun or open a mapped utun channel. The direct Skywalk attachment
interlock remains disabled.

## Results

Each row uses 30 measured seconds after one warmup second. Rates are receiver
TCP payload goodput. CPU is the extension's cumulative process CPU time divided
by steady wall time; one core equals 100%, excluding iperf and work charged to
other processes. These are sequential desktop experiments, not randomized
confidence intervals or an absolute performance ceiling.

| Variant | Send Gbit/s | Receive Gbit/s | Send cores | Receive cores |
| --- | ---: | ---: | ---: | ---: |
| Original public packet-flow bridge | 3.878 | 2.732 | 1.782 | 1.436 |
| Public bridge, larger utun queues | 4.063 | 2.744 | 1.929 | 1.446 |
| Direct descriptor, corrected backpressure, original packet boundaries | 4.738 | 2.755 | 1.719 | 1.081 |
| Selected implementation, repeat | 4.816 | 2.747 | 1.732 | 1.070 |

The repeated result is about **24% faster send** and **25% less receive CPU**
than the original bridge. Receive throughput remains around 2.75 Gbit/s.
The selected send/reverse/duplex sequence and repeat recorded zero new peer
drops, zero transmit-queue drops, and zero utun input/output errors. TCP still
reported retransmissions: 836 and 728 for the two selected send runs. Windows
sender retransmissions and Windows daemon CPU were not available in these
measurements.

Simultaneous traffic reached **3.452 Gbit/s send + 1.130 Gbit/s receive**, at
1.737 extension CPU cores. The original bridge measured 2.583 + 1.486 Gbit/s.
Aggregate duplex goodput increased, but the reverse share decreased; this is
not an improvement in every individual direction under competing traffic.
Direct LAN TCP measured 9.372 Gbit/s earlier in this session.

Queue tuning alone increased send peer drops by 998. The first descriptor
candidate sent at 4.684 Gbit/s but inherited ordinary-utun TCP coalescing and
nearly stalled receive. Those rejected observations are preserved in the
experiment artifacts; they are not treated as successful bidirectional results.

## Copies and scheduling in each direction

### Mac to Windows

Original path:

```text
utun control socket → framework receive buffer
  → NSData payload copy → NEPacket objects → Swift control-queue hop
  → temporary NSData/view arrays → Rust pool payload copy → bounded input queue
  → peer TX worker → in-place AES-GCM
  → dispatch_data payload copy → nw_connection_batch / per-datagram sends
```

Selected path:

```text
utun control socket → recvmsg_x directly into Rust pool, with crypto headroom
  → peer TX worker → in-place AES-GCM
  → dispatch_data payload copy → nw_connection_batch / per-datagram sends
```

The change removes **two userspace payload copies before encryption**, packet
object construction, temporary bridging arrays, a queue hop, and the separate
packet-flow input queue. The kernel-to-user copy remains. This does not make
the whole tunnel zero-copy.

The installed NetworkExtension binary requests 64 packets in both public
read methods. Its `readPacketObjects` callback calls the Objective-C selector
`initWithBytes:length:` at unslid address `0x19666C864`; the resolved shared-cache
stub is `0x198003db0`. Apple's [NSData initializer documentation](https://developer.apple.com/documentation/foundation/nsdata/init(bytes:length:))
confirms that this initializer copies bytes. This is exact-build inspection,
not a claim that every macOS release has the same implementation. The direct
reader uses the existing 128-packet batch storage and four-byte family prefix.

The remaining Network.framework TX copy is deliberate: Rust recycles the
accepted packet buffers synchronously, while framework ownership is
asynchronous. Apple's [libdispatch implementation](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/data.c)
copies `DISPATCH_DATA_DESTRUCTOR_DEFAULT` input; a custom destructor introduces
asynchronous destruction work. Earlier [ownership experiments](network-framework-audit.md)
did not justify replacing this contract. We did not repeat those rejected
designs or mutate framework-owned immutable data.

### Windows to Mac

```text
Network.framework grouped receive → retained immutable dispatch_data ring
  → one copy into writable Rust pool → in-place AES-GCM / source validation
  → sendmsg_x of plaintext slices + family headers → existing NE utun
```

The default framework receive SPI still requests 1–256 messages, publishes
one group, and wakes the RX worker once per group. Its ring holds 1024 retained
messages; the Rust worker drains at most 128 at a time. The direct utun writer
removes the `Arc<OutputBatch>` allocation, per-packet Foundation/NEPacket
objects, and their ownership bookkeeping. The original output bridge already
avoided an additional large-payload copy; removing it primarily saves allocation
and reference-counting work. Kernel injection copies remain, including the
mbuf-to-Skywalk-buffer conversion in this utun mode.

### Wakeups and backpressure

- Active Rust work polls with a zero timeout; idle workers arm kqueue and
  recheck the atomic notification mask before blocking. Existing race tests
  exercise publication against sleep. The 250 ms timer is housekeeping, not
  a packet batching delay.
- Network.framework RX requests a minimum of one message. Neither direction
  waits for a full 128-packet batch. The receive low-water mark remains one.
- TX has 1024 framework send credits. A completion waking a previously full
  sender cannot be lost merely because the worker has not armed sleep yet:
  the notification bit remains pending. Completions are per datagram even
  inside [nw_connection_batch](https://developer.apple.com/documentation/network/nw_connection_batch(_:_:)).
- The original send loop could drain a full batch into an already-full
  256-packet plaintext queue. With one peer, it now reserves space for a full
  read before draining utun. Readiness stays latched while paused; encryption
  and UDP credit callbacks allow progress. The shared multi-peer dispatcher
  retains its existing per-peer drop policy so one congested peer does not
  prevent dispatch to the others. `tx_queue_drops` now distinguishes this
  overflow from other peer drops.

No extra packet I/O threads, fixed sleeps, busy-wait delays, artificial
low-water batching thresholds, or global sysctl changes were introduced.

## Actual utun options and tuning

The provider follows the Firezone/WireGuard descriptor-table technique, checking
the utun control ID and **exact interface name**, then duplicating the descriptor
with close-on-exec. It retains Network Extension's ownership of the original.
It verifies ordinary family-prefix framing and preserves existing descriptor
flags when enabling nonblocking I/O. Public packet-flow reads are never started
in descriptor mode. This descriptor access is not a public NEPacketTunnelFlow
API contract; the public frontend remains a build-time option.

Startup option readback showed:

| Setting | Framework supplied | Selected |
| --- | ---: | ---: |
| `SO_RCVBUF` | 524,288 bytes | 4,194,304 bytes |
| `UTUN_OPT_MAX_PENDING_PACKETS` | 64 | 1024 |
| `SO_SNDBUF` | 524,288 bytes | unchanged |
| `SO_RCVLOWAT` / `SO_SNDLOWAT` | 1 / 2048 bytes | unchanged |
| `SO_DONTTRUNC` / utun flags | 0 / 0 | unchanged |
| Netif / flowswitch enabled | 1 / 1 | unchanged |
| User utun channels | 0 | unchanged |
| Slot size | 4096 bytes | unchanged |
| Netif ring / TX flowswitch ring / RX flowswitch ring | 64 / 64 / 128 | unchanged |
| Kernel-pipe TX/RX rings | 0 / 0 | unchanged |

Queue settings are raised only if needed and read back; unsupported or clamped
requests fail startup explicitly. `interestunctl show` exposes before/after
values in `utun_options`. A later [source-only datapath audit](utun-skywalk-datapath.md)
found that the explicit `MAX_PENDING_PACKETS` admission check applies to legacy
`utun_start`, not the Skywalk netif TX socket fallback. The readback therefore
does not establish an effective 1024-packet Skywalk queue. Socket byte capacity
and the separate provider-to-host input-chain limit are different resources.

The following covers every `UTUN_OPT_*` in the audited
[XNU header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.h).
Setter restrictions come from [utun option handling](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L2276).

| Option suffix (`UTUN_OPT_`) | Value | Use / decision |
| --- | ---: | --- |
| `FLAGS` | 1 | Framing/direction flags; creation-time. Require zero. |
| `IFNAME` | 2 | Read exact interface identity. |
| `EXT_IFDATA_STATS` | 3 | External accounting; retain automatic stats. |
| `INC_IFDATA_STATS_IN`, `INC_IFDATA_STATS_OUT` | 4, 5 | Manual accounting, not throughput controls. |
| `SET_DELEGATE_INTERFACE` | 15 | Interface delegation; leave framework policy intact. |
| `MAX_PENDING_PACKETS` | 16 | Set/read back as 1024; explicit admission check is on the legacy path, not netif TX. See follow-up audit. |
| `ENABLE_CHANNEL` | 17 | Creation-time kernel-pipe setup; do not enable. |
| `GET_CHANNEL_UUID` | 18 | Channel identity, not a tuning control. |
| `ENABLE_FLOWSWITCH` | 19 | Advertises netagent provider/listener capability; already enabled. |
| `ENABLE_NETIF` | 20 | Creation-time mode selection; already enabled. |
| `SLOT_SIZE` | 21 | Creation-time packet storage; read 4096. |
| `NETIF_RING_SIZE` | 22 | Creation-time capacity; read 64. |
| `TX_FSW_RING_SIZE`, `RX_FSW_RING_SIZE` | 23, 24 | Creation-time capacities; read 64/128. |
| `KPIPE_TX_RING_SIZE`, `KPIPE_RX_RING_SIZE` | 25, 26 | Creation-time kernel-pipe capacities; unused. |
| `ATTACH_FLOWSWITCH` | 27 | Creation-time attachment; do not change. |
| `CHANNEL_BIND_UUID`, `CHANNEL_BIND_PID` | 28, 29 | Creation-time channel ownership; not throughput knobs. |

The three public flag bits disable output, disable input, or add a process UUID
to each packet header. None removes a payload copy. The descriptor frontend
rejects nonzero flags instead of silently parsing a different header layout.

## Socket and Network.framework options

The audited [public socket options](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/socket.h)
and [private socket options](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/socket_private.h)
contain no general switch that makes this utun boundary zero-copy.

| Options | Assessment |
| --- | --- |
| Receive/send byte buffers | Receive capacity changed as above. A 512 KiB send buffer already exceeds one batch of MTU-1420 packets; no evidence justified changing it. |
| Low-water marks, send/receive timeouts | Raising thresholds can delay sparse traffic; nonblocking workers already use readiness. Leave unchanged. |
| `SO_DONTTRUNC`, `SO_WANTMORE`, `SO_WANTOOBFLAG` | Retention/ancillary receive semantics, not larger batch guarantees. DONTTRUNC selects a different XNU receive path; leave off. |
| Timestamp options, `SO_NREAD`, `SO_NWRITE`, `SO_NUMRCVPKT`, error/type/status queries | Observability or extra metadata; no throughput feature. |
| Address/port reuse and interface binding | Connectivity/path controls. Network.framework already reuses the configured local port; do not rewrite its reservation socket. |
| Traffic/service classes, background flags, pacing | Scheduling or rate limits. Best-effort remains appropriate for this uncongested LAN test. |
| Keepalive, linger, OOB, broadcast, routing and SIGPIPE controls | No identified steady UDP/utun copy or batching benefit. |
| Delegation, NECP, flow diversion, filtering IDs, restrictions, wake policies, defunct/flush controls | Policy/lifecycle/diagnostics; do not use as throughput shortcuts. |

Apple's current [UDP options](https://developer.apple.com/documentation/network/nwprotocoludp/options)
expose checksum preference, not a public `SO_RCVBUF`/`SO_SNDBUF` equivalent.
[IP options](https://developer.apple.com/documentation/network/nwprotocolip/options)
cover address family, receive timestamps, hop limit, fragmentation, and minimum
MTU. None changes datagram ownership. IPv4
[checksum suppression](https://developer.apple.com/documentation/network/nwprotocoludp/options/prefernochecksum)
was already rejected after a prior severe regression and remains off.

Apple recommends choosing another [service class](https://developer.apple.com/documentation/network/nwparameters/serviceclass-swift.property)
only for a concrete traffic requirement or measured benefit. Prior priority
experiments did not help. The [send contract](https://developer.apple.com/documentation/network/nw_connection_send(_:_:_:_:_:))
also distinguishes content processing from remote delivery; completing a send
is not proof that its storage can be recycled independently of retained data.
The existing bounded ownership contract is preserved. Fast-open and idempotent
markers are not steady-state throughput switches for this tunnel.

Read-only sysctls: max socket buffer 8 MiB, max sendmsg_x/recvmsg_x messages 256,
utun pending input 512, netif/TX-flowswitch/RX-flowswitch ring defaults 64/64/128.
No system-wide setting was changed. Network.framework remains on the observed
Ethernet path; its reservation socket is not assumed to carry its channel data.

## The coalescing regression and its correction

The first descriptor experiment accidentally inherited the standalone BSD
adapter's TCP coalescer. The kernel logged:

```text
utun_netif_sync_rx utun4: legacy packet length 13732 > 4096
utun_netif_sync_rx utun4: legacy packet length 4156 > 4096
```

The published [netif receive path](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L722)
queues control-socket input, then drops packets exceeding its packet-pool buffer.
Thus a successful write and zero conventional interface errors did not prove
successful delivery. This exact host logged the oversized-packet rejection.

The corrected `NetworkExtension` descriptor variant preserves packet boundaries
and cannot opt into ordinary-utun coalescing. Receive returned to 2.75 Gbit/s.
A regression fixture injects four adjacent compatible TCP segments whose
aggregate exceeds 4096 bytes and verifies four original datagrams arrive.
No live channel flags or ring sizes were changed to work around this.

## Validation and remaining work

All 47 selected Rust tests and 41 Swift/C ABI assertions passed, as did
all-feature Clippy and the no-default-features build check. The alternate
`--packet-flow` app also built successfully without installation.

Rust checks cover ciphers, replay/authentication, routing, multi-peer traffic,
callback wake races, retained packet-flow storage, and NE descriptor packet
boundaries. Swift/C ABI tests exercise both ciphers and buffer lifetimes. The
public frontend can still be built explicitly with `--packet-flow`; the default
build uses the existing descriptor. Neither has a runtime fallback to another
UDP backend.

One parallel test invocation timed out in the pre-existing Network.framework
fixture during initial packet exchange. Its isolated rerun and subsequent
complete suites passed without changing that fixture. It is recorded rather
than counted as a clean first-pass test run.

The remaining application payload copies are the framework-owned UDP send copy
and the immutable-UDP-to-writable-decryption copy. Removing them needs a measured
ownership or out-of-place crypto design, not casting away const or recycling
buffers at an unsafe completion point. Receive goodput and duplex asymmetry
remain unexplained ceilings on this pair; lower extension CPU alone does not
attribute them to Windows, crypto, or a particular kernel component.

The subsequent [send CPU profile](apple-send-profile.md) captures Instruments
user/kernel call stacks from the same running build. It attributes most CPU
to framework send processing and callbacks, with encryption around 6% of
sampled CPU; its current throughput and attribution limits are recorded there.

[Experiment artifacts](benchmarks/macos-apple-pipeline-audit/) contain raw
throughput/counter/CPU records and build hashes. Local source excerpts,
resolved framework selector, and kernel regression logs are under
`target/apple-path/pipeline-audit-20260928/`. Public XNU revision
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` is not claimed to exactly match the
running `xnu-13432.1.9~1`; option values, framework inspection, kernel logs,
and throughput were checked on the running host.
