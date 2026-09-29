# Bounded RemotePairing ring-delegation investigation

2026-09-29, macOS 27.0 build 26A428. This follows the
[installed entitlement inventory](system-network-entitlements.md).

## Result and stopping point

**nehelper implements delegation to another executable, but this investigation
did not find an entry point that lets Interestun request that delegation.**

The RemotePairing implementation creates and consumes its own utun channel. Its
traced client-facing tunnel-use API returns connection/device information and
an assertion, rather than ownership of a mapped packet channel. That makes it
a concrete reference implementation, not an identified general-purpose ring
broker for our provider.

This conclusion rests on creation arguments, helper authorization, channel
binding, and the inspected request/result types. It does not rest on the name
of the daemon or on assuming all IPsec paths use kernel pipes.

No interfaces were attached, no private constructors or service requests were
invoked, no preferences or security settings were changed, and no live channel
was opened. This is static evidence, not a tested claim that all possible
service requests are denied.

## Creation and ownership chain

1. RemotePairing's `SkywalkChannelVirtualInterface` requests interface type 1,
   netif enabled, and one kernel-pipe channel. Its extended constructor call
   supplies a **null executable UUID** and an options dictionary. In the arm64
   slice, `0x2C57C` stores the null UUID alongside the options object, and the
   call occurs at `0x2C5A8`.
2. The same behavior exists in the arm64e slice: null UUID at `0x338E0`, channel
   count 1 at `0x33904`, constructor call at `0x3390C`. The wrapper forwards the
   arguments to NetworkExtension. It does not substitute the identity of a
   RemotePairing service client.
3. NetworkExtension's constructor requests PID binding when the channel count
   is nonzero and no non-null executable UUID is supplied. It asks nehelper to
   create the kernel-control socket with the pre-connect options.
4. nehelper obtains the **immediate XPC caller's PID**, rather than trusting an
   integer PID supplied in the request. In the saved helper arm64e disassembly,
   `0x10000ECF4` gets the remote connection, `0x10000ED08` gets its PID, and
   `0x10000ED94` sets the binding option. For utun this is option 29.
5. XNU's `utun_enable_channel` binds `NEXUS_PORT_KERNEL_PIPE_CLIENT` to that
   process, or to an executable UUID when one was supplied. Nexus binding
   comparison uses the process unique ID for PID-derived bindings, not merely
   the reusable numeric PID. `nx_port_alloc` rejects a binding mismatch with
   `EACCES` for a non-anonymous provider.
6. RemotePairing obtains the nexus UUID and opens the channel itself using
   `nw_channel_create_with_attributes`: `0x2E3F0` in arm64 and `0x35DE0` in
   arm64e. Its interface class implements local `readPackets` and
   `writePackets` methods over that machinery.

Therefore learning its nexus UUID or obtaining only its utun control descriptor
would not by itself authorize a different process to open a fresh bound channel.
This is not a general claim about whether an already-open channel descriptor
could ever be transferred; no such transfer was established in this service.

## Delegation exists, behind the helper's caller check

nehelper recognizes `interface-bind-channel-exec-uuid`, reads its UUID at
`0x10000EE10`, and applies utun option 28 at `0x10000EE64`. Thus an authorized
creator can prepare a channel for a selected executable instead of itself.

The authorization happens before this option handling:

- `NEHelperSocketFactory` reads
  `com.apple.private.nehelper.privileged` from the remote XPC connection at
  `0x10000D140`, then stores the Boolean at `0x10000D18C`.
- The kernel-control creation branch checks that stored Boolean at
  `0x10000D86C`/`0x10000D870`, before `socket` at `0x10000D884`.
- The separate `com.apple.private.neagent` check can admit a connection without
  granting this privileged kernel-control operation.

Consequently, target-UUID support is not an authorization substitute for the
requesting process. Loading the RemotePairing framework inside Interestun would
leave Interestun as the caller whose entitlement is checked.

## What RemotePairing clients receive

The inspected framework exposes a `ConnectableDevice.createTunnelUsageAssertion`
operation and these request/result representations:

| Representation | Inspected data |
| --- | --- |
| `CreateAssertionCommand` | Optional `RPTunnelUsageAssertionFlags`; encoder/decoder inspected |
| `CreateAssertionResult` | Assertion identifier, fulfilled assertion information, new device state |
| `TunnelUsageAssertion.FulfilledAssertionInfo` | RSD device information and tunnel IPv6 address |
| `StartTunnelResponse` | Transport port, optional service name, protocol options, optional host |
| `TunnelInterfaceParameters` | IPv6 address, netmask, MTU |

These are evidence of a paired-device tunnel-management contract. The assertion
UUID is not shown to be a nexus UUID. Device information also contains an XPC
endpoint; an endpoint is not evidence of a mapped-ring or file-descriptor grant.
None of these inspected representations supplies a channel-binding executable
UUID or an arbitrary packet consumer callback.

The daemon is packaged as `com.apple.CoreDevice.remotepairingd`, a user XPC
service. Its code imports RemotePairing's tunnel manager and start-tunnel
response types. The bounded trace did **not** establish a universal private
entitlement requirement for all of this daemon's clients. In particular, the
result must not be misreported as “ordinary applications cannot communicate
with remotepairingd.” Communicating with it and receiving packet-channel
ownership are separate capabilities.

## Coverage and reproducibility

Inspected the installed RemotePairing framework's arm64 and arm64e creation
paths, its request/result metadata and relevant coders, the daemon's arm64
code/imports and service metadata, the saved NetworkExtension constructor,
nehelper's arm64e authorization/options code, and XNU's saved utun/nexus binding
implementation. Arbitrary indirect calls and every daemon command were not
fully reverse-engineered.

Local artifacts: `target/apple-path/remote-delegation-20260929/`, plus
`target/apple-path/system-entitlements-20260929/remotepairing-disassembly.txt`.
The framework hash and binary entitlement evidence are recorded in the
[inventory](system-network-entitlements.md). Use `xcrun dyld_info -arch arm64`
or `-arch arm64e` with `-disassemble`, `-imports`, and
`-section __TEXT __cstring`. Swift names were decoded with
`xcrun swift-demangle --compact`. All addresses are build/slice-specific;
RemotePairing addresses are preferred image-relative addresses, while the
saved nehelper addresses include its preferred image base.

## Concrete question for Apple

For a normally provisioned third-party macOS packet-tunnel system extension,
is there a supported way for the system to create a utun with nonzero
kernel-pipe channels and bind its client port to the provider executable?

Our observed NE session path requests zero user channels. The installed
RemotePairing implementation demonstrates nonzero utun channel creation, and
nehelper implements target-executable UUID binding, but both direct creation
and direct helper access encounter restricted authorization checks in our
current signing context. Can Apple authorize a suitable entitlement, expose a
brokered provider path, or identify a supported equivalent for batched/mapped
packet I/O?

This question does not claim that rings would eliminate our measured throughput
bottleneck. No further live attachment or guessed-option experiment follows
from this bounded investigation.
