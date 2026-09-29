# NetworkExtension kernel-pipe function audit

Read-only audit on macOS 27.0, build 26A428, 2026-09-29. No networking API
constructors, helper requests, interfaces, or channels were exercised. The
running Interestun tunnel was not changed.

## Result

The installed framework has a concrete private constructor for requesting
mapped utun kernel-pipe channels. This audit did not find an additional public
provider setting or an alternative helper operation that avoids the caller
authorization requirement. This is **not** proof that every Apple consumer or
possible authorization arrangement has been exhausted.

The important improvement over the previous searches is resolving optimized
Objective-C selector stubs. Previously, numeric branch targets hid calls from
name-based searches. This pass indexed the whole saved framework disassembly,
resolved its external direct-branch targets, and inspected the interface and
channel creation paths and their arguments.

## Scope and reproducibility

| Inventory | Count |
| --- | ---: |
| Named code entries, including methods and blocks | 7,350 |
| Unique external direct-branch stub targets | 3,360 |
| Targets resolved to selectors or symbols | 3,360 |
| Entries calling selected interface/channel/helper/socket-option/mapping functions | 46 |
| Installed public NetworkExtension headers searched | 62 |

These are inventory counts, not a claim that every method was manually
reverse-engineered. Detailed inspection concentrated on every constructor family
listed below, socket/channel creation sinks, the provider parameter encoding,
packet-flow read/write paths, and relevant helper policy.

Run `python3 scripts/audit-ne-kpipe.py` from the repository root with the saved
`target/apple-path/networkextension-disassembly.txt` snapshot. The tool refuses
OS builds other than 26A428 and checks the input hash before reading addresses.
It loads NetworkExtension only to inspect this process's shared-cache stub
bytes and symbol metadata. It does not invoke private networking functions.

Outputs in `target/apple-path/ne-full-audit-20260929/`:

- `summary.json`: counts and snapshot identity.
- `stub-symbols.json`: numeric branch target to selector/import mapping.
- `functions.json`: named entries and direct branches.
- `creation-callers.json`: candidate creation and option-setting callers.
- `annotated.txt`: local disassembly with decoded external targets.

Additional read-only evidence includes disassembly of
`/usr/lib/system/libsystem_networkextension.dylib` and the existing nehelper
and nesessionmanager snapshots. Apple disassembly is not committed.

The index does not resolve arbitrary function-pointer calls, infer the runtime
receiver of every Objective-C message, or index callers in every other shared
cache image. Those remain explicit coverage limits.

## Constructor and accessor results

| Family | Observed behavior on this build |
| --- | --- |
| `NEVirtualInterfaceCreateNexusExtendedWithOptions` | Serializes nonzero utun channel count as option 17, plus ring sizing and process/executable binding. Opens through `NEHelperGetKernelControlSocketExtended`. |
| `CreateNexusExtended`, `CreateNexus` | Forward constructor arguments to the same implementation. No separate authorization route. |
| `Create`, `CreateWithOptions` | Explicitly supply zero channel count. The latter still forwards its options object; it is not itself a request for ring channels. |
| `NENexus` extended initializer | Accepts virtual-interface type and channel count separately and forwards the count. Type 1 plus a nonzero count is the private utun-ring construction shape. |
| `NEIPsecNexus` initializers | The Boolean `shouldCreateKernelChannel` is forwarded as channel count; the extended variants accept count and ring sizes. Interface type is 2, IPsec. |
| `NEInternetNexus` Boolean initializer | Supplies zero channel count to its superclass, then conditionally attempts channel creation. Its name is not evidence of successful utun kernel-pipe activation. |
| `CreateFromSocket`, `CreateFromSocketAndName` | Wrap an existing descriptor. No separate ring-enabling call was identified in these wrappers. |
| `CreateUserEthernet` | Separate user-Ethernet controller/descriptor path. It does not request utun channel count. |
| `CreateRedirect`, `CreateRedirectInner`, `CreateRedirectFromName` | Interface type 4; the creation path calls `NEHelperInterfaceCreate`. The helper creates an `rd` interface via ioctl. This is not a second utun constructor. |
| `EnableChannelAndGetNexusInstance` | Tail-calls the UUID getter, rather than setting option 17. |
| `CreateChannel` | Gets an existing nexus instance, then calls `nw_channel_create_with_attributes`. It does not supply the missing channel-enable operation. |

Example anchors in the installed disassembly:

- `NENexus` forwards count in `x6` at `0x196665D0C`; constructor call
  `0x196665D14`.
- `NEIPsecNexus` forwards the Boolean in `x6` at `0x196645058`; later calls
  `NEVirtualInterfaceCreateChannel` at `0x196645074`.
- Basic `CreateWithOptions` zeros `w6` at `0x1966D3C98`.
- Redirect creation calls `NEHelperInterfaceCreate` at `0x1966D3EA8`.

## Newly checked IKEv2 path

`-[NEIKEv2Session addEmptyInterface]` calls the extended constructor at
`0x1966177CC`, with interface type 2 and **channel count zero** loaded at
`0x1966177C4`. This is one additional concrete IPsec creation path; it does not
establish the channel configuration of every operational IKEv2 session.

The previously suspicious call in
`-[NEIKEv2PacketTunnelProvider configureProxyPathIfNeeded]` at `0x196602BC0`
resolves to `endpointWithHostname:port:` on `NWHostEndpoint`. It is endpoint
configuration, not an IPsec nexus constructor. A companion-proxy method name
alone must not be used as evidence of kernel-pipe consumption.

No live IPsec provider was created. The actual production caller of a nonzero
`NEIPsecNexus` configuration remains unproven by this framework-only audit.

## A second helper route exists, but also checks authorization

`NEHelperInterfaceSetOption` in libsystem_networkextension, at `0x186FBC0F4`,
serializes an interface descriptor, option number, and option data, then calls
`NEHelperCopyResponse`. The helper's interface-manager command 4 duplicates
the supplied descriptor and calls `setsockopt` at `0x10000C4CC`.

However, `NEHelperInterfaceManager` checks
`com.apple.private.nehelper.privileged` during connection initialization
(`0x10000C090` through `0x10000C0A4`). Failure takes the branch logging that the
interface-manager connection is denied for lack of that entitlement. Thus this
is not an identified way around the socket-factory check described in
[the earlier audit](utun-framework-kpipe.md).

The extended kernel-control helper itself serializes the request and obtains
the response through `NEHelperCopyResponse` at `0x186FBB3CC`. No direct local
socket-creation fallback was found in that function.

## Options and provider serialization

`NEVirtualInterfaceParameters` encodes/decodes the control socket, name, type,
max-pending packet count, Ethernet address, and MTU. Its encoding calls are at
`0x19667ED18` through `0x19667EDD4`. There is no channel-count, ring-size, nexus
UUID, or private constructor-options field in this inspected representation.

The private constructor's options callback specially handles
`EnableUserPacketPool`, `EnableRxFlowSteeringAuto`, and `EnableLowPowerWake`
as socket options 30, 31, and 32. **Unknown keys are also forwarded**, as
individual one-key XPC dictionaries, at `0x1966DAD20` through `0x1966DAD2C`.
Therefore this must not be described as an options whitelist containing only
three keys. Neither this forwarding behavior nor the private options object
establishes a connection from public `providerConfiguration` to the helper's
channel-creation request.

## Packet-flow and other channel users

Both `NEPacketTunnelFlow.readPackets` and `readPacketObjects` install the same
multiple-IP-packet handler and call `NEVirtualInterfaceReadyToReadMultiple`.
Both write variants call `NEVirtualInterfaceWriteMultipleIPPackets`. The
shared packet I/O uses `recvmsg_x` (`0x1966D6480`) and `sendmsg_x`
(`0x1966D6BE0`). Selecting packet objects does not switch to mapped rings.

Apple's public [packet-flow documentation](https://developer.apple.com/documentation/networkextension/nepackettunnelflow)
describes packet-array read/write operations, with no mapped-channel ownership
API. The installed 62 public headers also have no matches for kernel-pipe,
Skywalk, nexus, mapped, ring-buffer, or channel-count terminology. Header
searches supplement the implementation trace; they are not its sole basis.

The direct `os_channel_create_extended` caller in the framework is the packet
filter interpose-claim block (`0x196680FFC`). `NENexus` also calls
`nw_nexus_create` and `nw_nexus_create_channel_to_new_instance` for flow
machinery. These channel users do not establish an alternate public utun
packet-injection interface. See [the caller audit](utun-framework-callers.md)
for the different public filtering contract.

## What remains open

Subsequent [system-wide entitlement inventory](system-network-entitlements.md)
identified RemotePairing's `SkywalkChannelVirtualInterface` as an external
caller requesting one utun kernel-pipe channel and opening its nexus. This
advances the external-caller lead below; access for Interestun is still unproven.

We have a more complete inventory of the installed NetworkExtension creation
surface, not a newly working attachment. The strongest remaining lead is a
caller **outside** this framework that requests nonzero utun/IPsec channels
and an authorization arrangement that can serve our process. The inventory
and resolved selectors make that external caller search more precise.

The authorization failures already observed remain evidence about our current
signing setup, not proof that Apple cannot authorize another arrangement. No
new live attachment experiment is justified solely by these newly resolved
function names.
