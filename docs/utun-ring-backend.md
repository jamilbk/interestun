# Experimental Skywalk utun backend

The mapped-ring backend is implemented behind `apple-utun-ring` and connected
to the existing WireGuard UAPI and peer workers. One explicitly authorized live
attempt on 2026-09-28 attached a kernel interface, then failed to enable its
channels with `EPERM`. No channel was opened or mapped. The attachment gate in
[`utun_ring.rs`](../src/platform/utun_ring.rs) is disabled again because the
interface remained present after the process exited. Startup now returns
`PermissionDenied` before loading channel symbols, creating a journal, or
opening a control socket. There is no runtime override.

The original disabled release build is staged locally at `target/skywalk-staged/interestun`, with
its checksum and validation metadata in `target/skywalk-staged/build.json`.
It was built and inspected, not executed. Enabling attachment later requires a
source change and rebuild; this staged binary cannot attach a Skywalk interface.

The old option sweep remains disabled and is not used by this backend. The
[panic investigation](utun-ring-panic.md) still applies; the implementation does
not establish a fix for the kernel assertion.

## Implementation

- [`native.rs`](../src/platform/utun_ring/native.rs) owns the utun control socket
  and channel. Private `os_channel` APIs manage mapping and opaque slot handles;
  Rust does not duplicate the private ring layout. Slot-property layout is
  checked at compile time. The `nexus_port_t` FFI argument is a 16-bit integer.
- [`engine.rs`](../src/platform/utun_ring/engine.rs) contains the actual receive
  and injection loops. A batch handles at most 128 packets and publishes once
  by advancing to the last completed slot and synchronizing. Empty-ring refresh
  may require an additional sync. A short batch flushes immediately.
- `Utun::receive`, `Utun::flush`, and `Utun::io_fd` route the runtime through
  the selected adapter. The existing per-peer send/receive threads, shared
  outgoing dispatcher, 1024-packet pending queues, Network.framework UDP, and
  cipher selection remain in use. Startup reports the TUN backend separately
  from the UDP backend.

This first implementation serializes channel slot operations with one mutex
per adapter, acquired per batch. Crypto and Network.framework callbacks execute
outside those operations. Multiple peer writers cannot publish the same slot.
The descriptor is borrowed for the existing native kqueue worker loop; the
channel API alone owns and closes its guarded descriptor. Destruction closes
the channel before the control socket.

RX copies IP payloads into the existing preallocated packet pool before
advancing the ring. TX copies authenticated IP payloads into free mapped slots.
No mapped pointer escapes to an asynchronous send or a different peer. This is
not an end-to-end zero-copy implementation. The published utun kernel path also
contains copies; see the [source audit](utun-skywalk-audit.md).

RX validates the four-byte family prefix, IP version/length, MTU, and packet
buffer capacity. Invalid slots are consumed without delivery. Pool exhaustion
leaves unread slots reserved. TX validates its attempted prefix before changing
shared storage and preserves the unsent queue tail under backpressure.
Advance/sync failures stop the channel; an already-published TX prefix is removed
from the queue even if synchronization fails, preventing an ambiguous retry.

The socket backend's TCP coalescer is bypassed for rings: its aggregates can
reach 64 KiB, exceeding the proposed 2048-byte slots. Original packet boundaries
are preserved. This difference must be accounted for in any future performance
comparison.

## Fixed attachment sequence

There is one configuration and one connection attempt per invocation:

| Setting | Requested value |
| --- | ---: |
| Netif enabled | 1 |
| Kernel-pipe channels | 1 |
| Attach flowswitch | 0 |
| Slot bytes | 2048 |
| Netif, kpipe TX, kpipe RX slots | 256 each |
| MTU | CLI value, default 1420 |
| Channel user packet pool | 0 |
| Channel defunct-OK | 1 |

Readable preconnect options are verified; `ATTACH_FLOWSWITCH` is set-only in the
audited source. After connection, setup reads the interface name, sets its MTU,
reads one channel UUID, and opens that channel. It queries actual ring IDs,
capacities, metadata type, and fragment limits. Unexpected geometry causes an
error without falling back to BSD. No routes or addresses are installed by this
setup path; the existing `wg` / interface configuration workflow still applies.

Before each setup operation, a stage marker is flushed with `sync_all` and
Darwin `F_FULLFSYNC` to `/var/tmp/interestun-skywalk-<pid>.log`. The file is created
exclusively with mode 0600; existing files are not overwritten. The journal
includes option values and actual channel attributes, but no keys. Each durable
record is also mirrored to stderr for inspection without reading the root-owned
journal. Destruction
also records channel/control close order. Logging cannot prevent a kernel panic
or guarantee recovery of the last record after every kind of failure.

## Validation performed without attaching

The production batch engine is exercised by 17 memory-backed tests, including:

- 128-packet limits and immediate partial-batch publication in both directions;
- wraparound and immediate kernel buffer reuse after RX advancement;
- a full TX ring, short slot availability, and later reclamation;
- stalled consumers and exhausted packet pools;
- IPv4/IPv6 at MTU 2000, bad families, invalid lengths, and undersized slots;
- concurrent peer injection, defunct channels, and advance/sync failures;
- rejection through the public adapter-open path while attachment is disabled.

The open-path test asserts that the interlock is disabled before calling it;
any future arming must preserve that unit-test interlock. No test in the new
module invokes native attachment, channel creation, or mapping.

40 tests passed in the selected suite (33 library, 2 cipher, 4 dataplane, 1 UAPI).
Dataplane/UAPI tests use fake adapters and ordinary loopback sockets. These
validate the runtime refactor, not live ring readiness or throughput.

Build and non-privileged verification commands:

```sh
cargo build --locked --release --features apple-utun-ring
cargo test --features apple-utun-ring --lib --test dataplane --test uapi --test ciphers
cargo clippy --all-targets --all-features -- -D warnings
```

The default and ring-only (`--no-default-features --features apple-utun-ring`)
configurations also compile. The ring build retains the default Network.framework
UDP backend unless default features are explicitly disabled. This verification
phase ran no ignored real-utun tests, daemon startup, channel attachment, or
throughput tests. The selected 40 tests passed again before the live attempt.

## Authorized live attempt: 2026-09-28 05:25:33 PDT

The user authorized bringing the interface up. The production gate was enabled
temporarily, with attachment still disabled under `cfg(test)`. Exactly one
invocation ran as root, requesting the previously absent `utun64`, MTU 1420,
default Network.framework UDP, and the fixed options above. No peers, addresses,
routes, or traffic tests were configured.

All preconnect options and applicable readbacks succeeded. `connect()` returned
`EPERM`; the daemon (PID 6874) closed its control descriptor and exited with code
1. Kernel logs at the same timestamp establish this sequence:

```text
utun64: attached (recycled)
System Policy: interestun(6874) deny(1) system-privilege 12001
utun_ctl_connect: utun64 failed to enable channels
```

Privilege 12001 is `PRIV_SKYWALK_REGISTER_KERNEL_PIPE`. The published
[`utun_enable_channel`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L1539)
checks it before allocating channels. XNU's
[`priv.h`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/priv.h#L144)
defines its number, and
[`skywalk.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/skywalk/core/skywalk.c#L540)
associates it with `com.apple.private.skywalk.register-kernel-pipe` in debug
diagnostics. This confirms a system-policy denial under sudo, not that Skywalk
utun is unavailable in every authorized process context. It does not prove
which signing/entitlement combination this OS will accept.

The boot time remained unchanged and no panic occurred during this attempt.
However, `ifconfig -l` still listed `utun64` after the daemon exited. Descriptor
close succeeded, but kernel-interface cleanup did not complete. No reuse,
destruction, bring-up ioctl, or second attachment was attempted. This matches
the failure-path lead in the [source audit](utun-skywalk-audit.md); it does not
prove the cause of the previous PF panics.

Local evidence is in `target/skywalk-live-20260928T122515Z/`: `launch.json`,
`daemon.log`, `kernel.log`, and the exact attempted binary preserved without
execute permission as `attempted-interestun.disabled`. Its SHA-256 is
`55002363a7dd277a86ba3d05f82465c6f1e75d0cc0d03eb856421b39d5357b3f`.
The durable root-owned journal is `/var/tmp/interestun-skywalk-6874.log`.
The source gate was disabled again and a rebuilt, attachment-disabled ring
binary replaced `target/release/interestun`. There is no BSD fallback.

Actual channel geometry, mapping ABI, readiness, packet transfer, and throughput
remain unverified. Resolve the privilege and failed-attachment cleanup paths
before another live attempt.

## System extension development state

A read-only check after this attempt found `developerMode = true` in
`/Library/SystemExtensions/db.plist`, while `csrutil status` reported SIP enabled.
`systemextensionsctl developer` refused to query with SIP enabled; the stored
flag was inspected directly, not changed. Firezone and Twingate network system
extensions were both listed as activated and enabled.

A packet tunnel Network Extension is a candidate for a supported process
context. Apple's public APIs expose packet reads/writes through
[`NEPacketTunnelFlow`](https://developer.apple.com/documentation/networkextension/nepackettunnelflow);
this is not proof that our code can obtain mapped `os_channel` rings inside an
extension. Developer mode relaxes installation checks; it does not establish
that the missing Skywalk privilege is granted. See Apple's
[system extension development documentation](https://developer.apple.com/documentation/driverkit/debugging-and-testing-system-extensions).
