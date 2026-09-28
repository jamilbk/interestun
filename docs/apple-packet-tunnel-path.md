# Network Extension Skywalk startup investigation

Observed 2026-09-28 at 06:17:40 PDT on macOS 27.0 (26A428), kernel
`xnu-13432.1.9~1`. App version `1790601131`, Firezone team `47R2M6779T`.

This records the initial public packet-flow build. The later
[pipeline audit](apple-packet-pipeline-audit.md) switched to direct I/O on the
existing NE descriptor while retaining Network.framework UDP, and contains
the current build's throughput and option measurements.

## Initial result: clean boot succeeds

After the user rebooted at 06:32:06 PDT, `utun64` was gone. The **unchanged
signed build** started successfully on the first attempt at 06:33:46 PDT,
creating `utun4`. The VPN connected and the Rust engine reported AES-256-GCM,
Network.framework UDP, and `failed: false`.

That startup's datapath had two distinct userspace boundaries:

| Boundary | Observed mechanism |
| --- | --- |
| Host IP packets to/from the packet tunnel provider | Skywalk-backed `utun4`, accessed through its kernel-control socket by `NEPacketTunnelFlow`; batched `recvmsg_x` / `sendmsg_x` |
| Encrypted UDP to/from `en8` | Network.framework channel on the Ethernet flowswitch, with `USER_PACKET_POOL` |

Evidence from this startup:

- `ifconfig -v utun4` reports `CHANNEL_DRV`, `CHANNEL_IO`, and separate
  Skywalk netif (`CD2B885A-2A96-4273-A8FA-65D9750283EE`) and flowswitch
  (`44478273-BDA6-4FF0-9D23-3A446652BFF8`) UUIDs.
- Root `lsof` for provider PID 1817 shows FD 5 as
  `com.apple.net.utun_control`, unit 5 (`utun4`). Its sole `CHAN` descriptor,
  FD 8, belongs to flowswitch `03602A32-3538-4720-B0A8-5905AEE9288E`, port 4.
  `ifconfig -v en8` identifies that UUID as the Ethernet flowswitch.
- Root `skywalkctl channel` confirms that FD 8 uses `USER_PACKET_POOL` and
  `DEFUNCT_OK`. It lists no provider-owned utun channel. The utun netif's
  listed channels are kernel-owned. The presence of `CHANNEL_IO` alone is
  therefore not evidence that the provider maps utun rings.
- Inspection of this exact OS build's NetworkExtension framework shows
  `readPacketObjects` reaching `NEVirtualInterfaceReadMultiplePackets`, whose
  shared-cache call stub resolves to `recvmsg_x`. `writePacketObjects` reaches
  `NEVirtualInterfaceWriteMultipleIPPackets`, whose corresponding call
  resolves to `sendmsg_x`. These symbols were resolved from the loaded
  framework's bound stubs without invoking private networking operations.
- Four ICMP requests routed to `10.20.0.1` through `utun4` produced four
  packet-flow callbacks and four accepted input packets, with zero input
  drops. At that stage there was no peer handshake or reply. After the Windows
  peer was updated, the same extension passed the sustained traffic tests below.

This establishes a working Skywalk-backed adapter, **not a mapped utun-ring
frontend in our provider**. The public packet-flow API still crosses the utun
socket boundary. A future mapped-channel experiment needs to address that
boundary explicitly; it must not infer ownership or ring availability from
interface flags or the outer UDP channel.

The same nonfatal `Signature check failed` message appeared during this
successful startup. It was not the cause of the earlier `EBUSY` failure.
Success with the unchanged build after reboot supports stale kernel state as
the explanation; the exact internal-ID collision remains unproven.

Evidence is in `target/apple-path/reboot-20260928/`, including the user-supplied
root channel/FD listings, interface flags, startup log, packet counters, and
resolved framework syscall symbols. The CLI's `skywalk: "unverified"` field is
still a static placeholder; these findings come from the independent live
diagnostics, not that field.

## End-to-end Windows tests

After Windows received the new Mac peer configuration, the handshake completed
and 30-second TCP tests through the AES-256-GCM UDP tunnel measured
**3.878 Gbit/s Mac → Windows** and **2.732 Gbit/s Windows → Mac**. Simultaneous
traffic measured 2.583 and 1.486 Gbit/s, respectively. There were no new bridge
or peer drops, write failures, or utun errors during these tests; TCP did report
retransmissions. The adapter was left connected after those runs. See the
[Windows test report](apple-packet-tunnel-windows-testing.md) for CPU usage,
methodology, and raw evidence. This validates the public packet-flow bridge,
not direct mapped access to the utun rings.

## First attempt before reboot

One authorized start attempt through the installed Network Extension reached
the kernel's Skywalk utun nexus attachment path. It failed with `EBUSY` (16)
while allocating the network provider instance. The VPN was disconnected; no
new interface appeared and no packet-flow or throughput test ran.

The filtered log shows this sequence:

```text
nesessionmanager: Creating a virtual interface with type 1
kernel: utun_nexus_ifattach alloc_net_provider_instance failed, 16
kernel: utun_ctl_connect - utun_nexus_ifattach failed: 16
nehelper: connect failed on kernel control socket: [16] Resource busy
nesessionmanager: SIOCGIFMTU failed: Device not configured
nesessionmanager: Failed to obtain a virtual interface of type 1, aborting
nesessionmanager: status changed to disconnected, last stop reason Plugin failed
```

Apple's helper made the failing control-socket request. The failure occurred
during framework interface creation, before our Rust engine started. The
extension remained activated and enabled. Boot time remained 04:27:49 PDT;
this attempt did not cause a kernel panic. No attachment retries were made.

The kernel function establishes that Network Extension requested the Skywalk
netif path on this host. It does **not** establish successful userspace channel
opening, ring mapping, packet delivery, or zero-copy behavior. Kernel-pipe and
flowswitch setup occur later in the published utun connection sequence.

## Leading explanation for EBUSY

The earlier direct-utun experiment left `utun64` attached after channel
creation failed and the owning process exited. That same interface was present
before and after this attempt. `skywalkctl interface` also lists it as a netif,
with UUID `5B4B5A0D-DBEA-4D51-983A-20A43BA5B3E3`.

Published XNU provides a concrete possible mechanism:

1. `utun_ctl_setup` assigns an internal unique ID from the remaining PCB list.
   This is separate from the visible `utunN` interface number.
2. `utun_ctl_connect` passes that internal `utunidN` to interface allocation.
   Its channel-failure branch frees the PCB after nexus attachment, without
   the explicit preservation used in the adjacent flowswitch-failure branch.
3. `kern_nexus_controller_alloc_net_provider_instance` first calls
   `ifnet_allocate_extended`, which calls `dlil_if_acquire`.
4. `dlil_if_acquire` returns `EBUSY` when the requested internal unique ID
   matches an interface still marked in use. An orphaned interface could
   therefore block a new utun even when its visible interface number differs.

This fits the observed attach/channel failure followed by a surviving netif
and the later allocation failure. It remains a hypothesis: we have not read
the orphan's internal unique ID or traced the precise returning instruction
in the installed kernel. The published revision is older than this kernel.

Sources at XNU revision `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`:
[utun setup and connection](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L1744),
[nexus instance allocation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/skywalk/nexus/nexus_kern.c#L1054),
[interface allocation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/kpi_interface.c#L317),
[in-use collision checks](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/dlil_ctl.c#L43).

## Recovery performed

The user-initiated reboot and single subsequent Network Extension startup are
recorded above. The disabled direct-utun probe was not run, and the orphan was
not manually destroyed.

The previous Mac test key disappeared with its temporary directory. A new
mode-0600 config is stored outside the repository at
`~/.config/interestun/windows-ne.conf`, using the established Windows endpoint
`192.168.1.226:51820`, Mac address `10.20.0.2/32`, and only the peer host route
`10.20.0.1/32`. Its new Mac public key is:

```text
KLDBAbZi3TXTjwdvxcT83KJoWvlwwqLxBWWekNq+MEo=
```

Windows subsequently received this public key and passed the handshake and
traffic tests above. The missing handshake did not explain the earlier
interface allocation failure.

Local evidence is saved under `target/apple-path/`: `startup.log`,
`result.json`, before/after interface and Skywalk netif listings, and boot-time
records. No private key is included in those diagnostics. Unprivileged
`skywalkctl channel/provider` and process sampling were denied access, so their
empty/error output is not evidence that the system has no channels.

## Firezone signing and lifecycle comparison

Compared directly with `~/Developer/firezone/firezone/main/swift/apple` and
`rust/client-ffi`, and with the Firezone and Interestun system extensions
actually copied into `/Library/SystemExtensions`:

- Both installed extensions have `packet-tunnel-provider` and team
  `47R2M6779T`. Interestun uses Apple Development signing; the installed
  Firezone build uses TestFlight Beta Distribution. Interestun's profile
  explicitly grants its Network Extension entitlement and exact app ID.
- Both containing apps have `com.apple.developer.system-extension.install`.
  Interestun's App Group and Mach service prefix validate. Its signature
  satisfies its designated requirement, and the installed extension binary
  matches the containing app's extension byte-for-byte.
- Firezone enables App Sandbox and client/server networking permissions in its
  extension. Interestun is currently unsandboxed; sandbox network permissions
  are therefore not missing grants. Firezone's keychain groups and custom
  `AppGroupIdentifier` Info.plist entry support its own credential/shared-data
  code, which this CLI prototype does not use.
- Both extension entry points call `NEProvider.startSystemExtensionMode()`
  and `dispatchMain()`. Both subclass and override the provider's `startTunnel`.
- Firezone's app calls `NETunnelProviderSession.startTunnel(options:)`.
  Interestun uses the inherited `startVPNTunnel(options:)`. Disassembly of the
  installed NetworkExtension framework shows the former forwarding directly
  to the superclass selector `startVPNTunnelWithOptions:andReturnError:`.
- Firezone's provider calls `Adapter.start()`, then `connectApple`, then
  `find_tun_fd`. The FD scan uses `getpeername`, `CTLIOCGINFO`, and
  `UTUN_OPT_IFNAME` to locate the already-created, framework-owned interface.
  It does not create or attach a utun. Interestun instead consumes the public
  packet-flow callbacks. That choice applies after interface creation and
  does not repair the observed helper allocation failure.

The extension process also logged `Signature check failed: code failed to
satisfy specified code requirement(s)`. Exact-build framework inspection found
that message in the general `NEVerifyDesignatedRequirement` helper, including
use by a Cisco AnyConnect identity probe and a Developer ID classification
check. Those checks can fail for correctly signed development software; the
message alone does not establish invalid provisioning. The precise caller of
this logged invocation was not captured, so this is not a proven attribution
of that individual message. The recorded abort remains the helper's kernel
`EBUSY` failure.

The signing audit is saved in `target/apple-path/signing-audit.json`.
Exact-build framework disassembly and string tables are saved alongside it.
