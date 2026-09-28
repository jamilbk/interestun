# Offline utun / Skywalk investigation

Audited 2026-09-28. The live probe remains disabled. The original audit consisted of
reading saved crash reports, local binaries, SDK headers, and published source.
No experimental interface or channel was created during that offline phase.
A later authorized attempt is recorded below and in the [backend report](utun-ring-backend.md).

The published XNU revision is `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`.
The installed kernel is `xnu-13432.1.9~1`, macOS 27.0 build 26A428.
Source findings describe the published revision; local binary evidence is
identified separately. These findings do not establish availability or safety
of private APIs on the installed kernel.

## Crash boundary

UUID-matched offline symbolication places both crashes in
`kern_nexus_controller_alloc_net_provider_instance -> ifnet_attach`, followed
by the PF assertion. This is the Skywalk interface-attachment stage, before
userspace channel opening and ring access in the failing iteration. Earlier
sweep iterations and preconnect options could have contributed to the state
that failed; this is not a minimal single-attachment reproducer. See the
[incident report and reproducer](utun-ring-panic.md#offline-follow-up-skywalk-attachment-confirmed).

The kernel-control layer retains its allocated unit across `bind()` and
`connect()`: `ctl_setup_kctl` returns early for an already-bound control, and
both callbacks receive the stored sockaddr. Reusing an input `sc_unit=0`
therefore does not inherently allocate a second unit.
[Source: kern_control.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_control.c#L425).

Normal interface teardown calls the PF detach hook before the driver's free
callback. The utun unit reservation persists until that callback frees its PCB.
This weakens the hypothesis that ordinary rapid close/reopen alone explains
the assertion.
[Source: dlil.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/dlil.c#L5932),
[source: utun_detached](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L3152).

One failure-path lead remains: after successful nexus attachment, an
`utun_enable_channel` failure immediately frees the PCB and clears `unitinfo`;
the adjacent flowswitch failure explicitly preserves the PCB for later detach.
That lifetime discrepancy warrants investigation. In a subsequent single live
attempt, the installed kernel logged `utun64: attached (recycled)`, a denial of
system privilege 12001, and `utun_ctl_connect: utun64 failed to enable channels`.
The control-socket `connect()` returned `EPERM` and the process exited, but
`utun64` remained listed. This establishes an attach-then-channel-failure
sequence on this OS; it does not establish the exact PCB lifetime in the
installed binary or prove that this caused the earlier PF assertion.
[Source: connection failure handling](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L1918).

Apple's test helper uses the same bind/options/connect sequence and retries
`EBUSY` after a short wait. Its comments discuss asynchronous teardown. This
does not demonstrate protection against our PF assertion, and we have not
adopted retries as a workaround.
[Source: test helper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/tests/skywalk/skywalk_test_utils.c#L1066).

## Ring path and performance constraints

| Finding | Consequence for a future implementation |
| --- | --- |
| Kernel pipe RX is local host output; kernel pipe TX injects packets into the host. | The tunnel's UDP send worker consumes channel RX. The UDP receive worker produces channel TX. |
| Both netif-to-kpipe and kpipe-to-netif paths allocate and copy packet data. | Mapping removes the userspace socket transfer mechanism, not every kernel copy. Any speedup needs measurement. |
| The ring frame retains the four-byte address family in network byte order. | Account for that prefix when sizing buffers and exposing IP payloads to crypto. |
| Four channels select WMM service-class queues. | They are not four arbitrary peer queues; shared-utun dispatch is still necessary. |
| The kpipe provider is shared and reference-counted, with attributes chosen when first registered. | Requested per-interface ring settings are not sufficient evidence of actual channel capacity. |

Source: [utun implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c)
(`utun_in_wmm_mode`, `utun_register_kernel_pipe_nexus`,
`utun_netif_sync_rx`, `utun_kpipe_sync_rx`).

The published kernel-pipe provider rejects user packet pools, event rings, and
low-latency channel mode with `ENOTSUP`. The installed SDK additionally exposes
`UTUN_OPT_USER_PACKET_POOL=30`, `UTUN_OPT_RX_FLOW_STEERING_AUTO=31`, and
`UTUN_OPT_LOW_POWER_WAKE=32`; those declarations alone do not establish runtime
behavior or equate these utun options with similarly named channel attributes.
[Source: kernel-pipe connection checks](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/skywalk/nexus/kpipe/nx_kernel_pipe.c#L330).

## Batching, ownership, and readiness contract

The following contract now informs the [staged backend](utun-ring-backend.md).
Its userspace batch engine is tested; live channel behavior remains unverified:

1. Obtain actual RX/TX ring IDs and attributes from the channel. Use the opaque
   slot API rather than reproducing private shared-memory offsets in Rust.
2. Give each ring one userspace owner. A shared utun still needs one dispatcher
   for outgoing packets and serialized publication by incoming peer workers.
   Four WMM queues cannot replace peer dispatch.
3. Fill or consume up to 128 available slots, update lengths, advance once to
   the last completed slot, and sync once for the batch. Flush partial batches
   promptly; do not wait to fill all 128.
4. Never let a borrowed slot buffer outlive ring ownership. In particular,
   publishing RX advancement before an asynchronous Network.framework send has
   released its data would permit reuse of memory still in flight. A bounded
   copy into an owned packet buffer remains the conservative initial design.
5. Reject oversize packets before touching slot storage. Do not alter immutable
   slot properties. Stop using a defunct channel, and let the channel owner
   destroy its guarded descriptor after users have stopped.

Source: [os_channel API contract](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/skywalk/channel/os_channel.h#L330).

The published TX capacity calculation reserves one slot: a 128-slot ring offers
at most 127 slots. A future 128-packet batch experiment should request 256 slots
and verify the actual capacity. This is distinct from the application's 1024
pending-packet queue. `get_next_slot` does not advance ownership; `advance_slot`
changes the head. Sync modes are an enum, TX=0 and RX=1, not combinable flags.
[Source: userspace channel implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/skywalk/os_channel.c#L940).

Channel `kevent` handling can perform synchronization under the channel lock.
It is not just a passive wakeup mechanism. Keep write readiness disabled when
there is no pending injection; enable it for backpressure. Drain available
work before waiting, recheck availability after registration, and treat
`EV_EOF` as a channel failure. Avoid having another thread perform readiness
operations that can publish a ring whose buffer ownership is still changing.
[Source: channel filters and ch_event](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/skywalk/channel/channel.c#L677).

Apple's loopback test has a selected branch that moves one packet and syncs
each outgoing packet. Copying that loop would defeat the intended batching;
the alternative branch demonstrates a single advance/sync after a batch.
[Source: skt_utunloop](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/tests/skywalk/skt_utunloop.c#L260).

## Work that can continue on this Mac

- Audit exact-build binaries and published source without invoking their APIs.
- Extend the implemented memory-only ring adapter harness for further ownership
  and failure scenarios. Its tests validate userspace logic, not kernel behavior
  or throughput.
- Compile future FFI code while keeping channel creation disconnected from the
  attachment gate and the live probe disabled.

Actual attach, mapping, wakeup, and throughput validation requires a disposable
macOS guest or a separate test Mac. A guest can contain a guest-kernel panic but
is not proof against host/hypervisor faults; a separate machine provides the
stronger boundary. Neither VM support for this private path nor a safe live
configuration is established. The next live experiment should be a single,
durably logged case in that environment, with no automatic sweep or retries.
