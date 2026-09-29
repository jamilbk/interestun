# Callers of Apple's private virtual-interface and channel machinery

Read-only investigation, 2026-09-29. No interfaces, channels, extensions, or
helper requests were started. This follows the
[framework creation/authorization trace](utun-framework-kpipe.md).

The question is whether an Apple caller leads back to a usable public API for
**custom tunnel IP packets through mapped utun kernel-pipe rings**. A public
API using Skywalk internally is not sufficient: it must expose the required
packet ownership and host injection behavior.

The [Ethernet-provider follow-up](apple-ethernet-path.md) traces its IOKit
creation path and confirms that its provider boundary also uses batched
control-socket I/O.

## Concrete consumers and candidates

| Consumer | Installed-code evidence | Does it expose our required public API? |
| --- | --- | --- |
| `nesessionmanager` / NetworkExtension packet tunnels | Calls `NEVirtualInterfaceCreateNexusExtended`, with channel count zero. | Public custom tunnel API exists, but this inspected path gives us the control socket. |
| `rapportd` | Calls basic `NEVirtualInterfaceCreate`, type 1, at `0x100096770` (arm64e). | Apple daemon uses a private constructor; basic wrapper requests zero channels. No public mapped-utun API established. |
| `identityservicesd` / IDS | Calls basic `NEVirtualInterfaceCreate`; separately creates nexus providers, binds clients, and opens `os_channel` channels. | Private transport machinery. Coexistence of utun and channels does not mean the channels map utun. |
| Private `NEIPsecNexus` | Initializers accept channel count/ring sizes; pass interface type 2 to the superclass and forward nonzero counts when requested. | IPsec-specific internal path. Public IKEv2 configuration does not expose a custom packet-ring consumer. A direct public-to-this-specific-constructor call chain is not established. |
| Private `NEInternetNexus` | Has a `shouldCreateKernelChannel` initializer and calls `NEVirtualInterfaceCreateChannel`. | Not a documented public API. Its inspected superclass call supplies zero channel count, so the name alone does not prove a successful utun-kpipe configuration on this build. |
| `NEFilterPacketProvider` | Its provider context constructs `NEFilterPacketInterpose`; channel creation, FD handling, and paired RX/TX ring handling appear in that implementation. | Public packet filtering, not arbitrary virtual-interface creation and packet injection. |
| vmnet / Virtualization | Public batched packet read/write and VM network attachment APIs. | Possible different Ethernet backend, not access to an NE-created utun's kernel pipes. No performance advantage measured. |

## IDS: distinguish multiple kinds of nexus

The installed IDS daemon imports basic virtual-interface APIs alongside
`os_channel_*` and `os_nexus_*`. In one inspected path it calls
`NEVirtualInterfaceCreate` at `0x10003f24c`, then separately registers a provider
named `IDSClientChannelNexusOS` at `0x10003f2d4`. Client/server binding and
`os_channel_create_extended` follow in separate methods. Other virtual-interface
creation call sites include `0x10006fa08`, `0x100259208`, and `0x1002592c8`.

This is positive evidence that Apple uses both facilities. It is not evidence
that calling an IDS API grants us the utun packet rings. In particular, the
basic NE creation wrapper zeroes the channel-count argument.

## An apparently promising enable function is only a getter

`NEVirtualInterfaceEnableChannelAndGetNexusInstance` at `0x1966d4ac4` is a
single branch to `NEVirtualInterfaceGetNexusInstance` in the saved framework.
That calls `NEVirtualInterfaceCopyNexusInstances`, whose utun branch reads
option 18 (`UTUN_OPT_GET_CHANNEL_UUID`) from the existing control descriptor.
It does not set option 17 in this path.

Therefore this symbol's name is not evidence of a supported post-connect
upgrade from our existing socket to mapped kernel pipes. The source restriction
identified earlier remains consistent with this implementation.

## Public APIs that are related, but have different contracts

[NEFilterPacketProvider](https://developer.apple.com/documentation/networkextension/nefilterpacketprovider)
exposes a callback with a packet buffer and allow/drop/delay verdicts. Its
`allow` operation releases a previously delayed packet. This is not a public
interface for submitting arbitrary decrypted IP packets to the host or taking
ownership of a utun RX/TX ring. Replacing tunnel reads with packet interception
would still leave injection, routing, exclusion of the encrypted transport,
and buffer lifetime to solve; no faster design is established by its existence.

[NEVPNProtocolIKEv2](https://developer.apple.com/documentation/networkextension/nevpnprotocolikev2)
configures Apple's IKEv2/IPsec implementation. That public configuration surface
does not expose a custom WireGuard-compatible codec or packet-ring callback.
The shared framework can contain IPsec, filtering, and packet-tunnel code
without sharing their capabilities through one public interface.

[vmnet](https://developer.apple.com/documentation/vmnet) exposes batched
`vmnet_read` / `vmnet_write` with caller-provided packet buffers and full
Ethernet frames. This is a concrete public alternative to investigate if we
accept an Ethernet virtual-network design, but it is not proof of zero-copy,
Skywalk utun access, or higher throughput. ARP/neighbor handling and host
routing would need design work.

[VZFileHandleNetworkDeviceAttachment](https://developer.apple.com/documentation/virtualization/vzfilehandlenetworkdeviceattachment)
uses an app-managed connected datagram socket for a VM's data-link traffic;
it is not a public utun ring mapping API.

## Search limits and evidence

Saved artifacts are in `target/apple-path/framework-callers-20260929/`.
Individual daemon imports and arm64e disassemblies were read for rapportd,
identityservicesd, and the previously inspected session manager. Cached IDS,
IDSFoundation, NetworkServiceProxy, and vmnet implementations were also
inspected. Addresses are build-specific and all code inspection was static.

A bounded disassembly/name scan covered 1,354 cached images before being
stopped; matches for the selected NE constructor/class names occurred only in
NetworkExtension. Results and the interrupted child exit status are saved in
`cache-callers.json`. This is not a completed whole-cache audit and does not
exclude callers through optimized stubs or Objective-C dispatch.

An all-cache import scan is not a complete cross-reference index: optimized
shared-cache bindings may disappear from the displayed import lists, and
`dyld_info -objc` explicitly cannot print live Objective-C information from
cached dylibs. Symbol/name searches also miss indirect calls, runtime class
lookup, and stripped/optimized references. Negative searches are therefore
not proof that no additional internal caller exists.

The evidence supports continuing to distinguish public behavior from private
implementation. It does not support enabling a guessed provider dictionary
key or retrying the earlier denied attachment. No callable public path to
mapped utun kernel pipes has been established by this investigation.
