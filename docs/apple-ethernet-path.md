# NEEthernetTunnelProvider packet-path audit

Read-only, 2026-09-29. No adapter was created, activated, or reconfigured.
No helper networking requests were sent. This follows the
[framework caller investigation](utun-framework-callers.md).

## Result

The public Ethernet tunnel provider takes a different interface-creation path,
but **still uses a kernel-control socket and the same batched socket I/O
routines as the packet-tunnel provider**. It is not an established route to
mapped packet queues. An Ethernet prototype could compare a different kernel
driver, but the inspected userspace boundary does not justify it as a
copy-removal optimization.

This corrects the earlier promising interpretation of `IOEthernetController`:
a controller object does not itself imply DriverKit packet pools or mapped
Skywalk rings. The legacy IOKit user-Ethernet facility and modern
`IOUserNetworkEthernet` NetworkingDriverKit API are different facilities.

## Installed-code trace

1. `NESMVPNSession` handles virtual interface type 3 by creating an
   `IOEthernetController` (`nesessionmanager`, arm64e, `0x1000263e8`). It sets
   its dispatch queue, registers the BSD-attach callback, and requests link-up.
   These are instructions inspected in the binary; none were invoked.
2. The callback gets the controller's descriptor through
   `IOEthernetControllerGetBSDSocket` at `0x10009bacc`, then wraps it in an
   `NSFileHandle`.
3. The continuation calls `NEVirtualInterfaceCreateUserEthernet` at
   `0x100026da4`. That framework function creates a type-3 interface wrapper
   and stores its descriptor in the same socket field used by packet I/O
   (`0x1966d3cb0` onward).
4. In IOKit, `IOEthernetControllerCreate` uses an IOKit service/user-client
   for creation, then calls `__connect_to_kernel` and stores its descriptor
   at controller offset `0x58` (`0x184dff1d4`).
5. `__connect_to_kernel` creates a PF_SYSTEM/SOCK_DGRAM/SYSPROTO_CONTROL
   socket (`0x184dff2bc`), resolves the control ID, connects, applies a
   controller binding option, and sets socket buffers. The IOKit string
   section includes `com.apple.userspace_ethernet`.
6. `IOEthernetControllerGetBSDSocket` returns that stored descriptor
   (`0x184dffad8`). There is no ring mapping in this getter.

Creation therefore has two mechanisms: IOKit manages the virtual controller;
the kernel-control socket transfers frames. Finding IOKit in the setup path
was insufficient evidence for a mapped data path.

## Both packet directions

`NEVirtualInterfaceReadMultiplePackets` checks interface type 1 to decide
whether to reserve a four-byte utun family prefix. Type 3 skips that prefix,
but still builds message/iovec arrays and calls the same `recvmsg_x` stub at
`0x1966d6480`.

`NEVirtualInterfaceWriteMultipleIPPackets` accepts type 3, builds packet
message/iovec arrays, and calls the same `sendmsg_x` stub at `0x1966d6be0`.
The function's IP-oriented name does not mean Ethernet uses a different
mapped path. The exact-build syscall stub resolution was previously saved in
`target/apple-path/reboot-20260928/framework-io-symbols.json`.

Thus both paths retain syscall/socket transfers. Framework batching remains
possible, and Ethernet frames omit the utun family prefix. These facts do not
establish identical performance: the driver behind the descriptor differs.

## What remains unknown

The Ethernet kernel driver's internal batch callback registration, allocation,
copying, and wakeup behavior were not established by this audit. We must not
copy the utun findings onto that driver simply because both use control sockets.
In particular, we have not shown whether Ethernet implements `ctl_send_list`.
No throughput comparison or live socket-option readback was performed.

The current published IOKitUser file
[`network.subproj/IOUserEthernetController.c`](https://github.com/apple-oss-distributions/IOKitUser/blob/323ead896d04424f87184d8f6ff0cce811aab106/network.subproj/IOUserEthernetController.c)
contains only a license header, not the implementation. The installed
IOUserEthernet kext directory contains metadata but no standalone executable;
extracting and tracing its kernel-collection code would be separate offline
work. Published IONetworkingFamily's inspected tree did not contain that driver.

## Original audit decision

A subsequent explicit request added an experimental [Ethernet backend](apple-ethernet-backend.md).
The following describes the decision at the time of this audit.

No new adapter implementation was added on the strength of this finding. The
conditional plan was to prototype if this path offered a useful packet-boundary
improvement; it does not expose the mapped boundary we were seeking. Merely
switching the provider superclass would also be incorrect: the engine expects
IP packets and its descriptor setup requires utun options. An Ethernet backend
needs frame parsing, local ARP/IPv6 neighbor handling, frame construction on
host injection, and separate descriptor setup.

NetworkingDriverKit remains a separate candidate because it documents buffer
pools and batch submission/completion queues. Software-only device attachment,
entitlement eligibility, and the process boundary to our Rust/Network.framework
engine must be resolved before treating it as a viable replacement. Any extra
IPC/copying could consume its potential gain.

## Evidence

Saved locally under `target/apple-path/ethernet-audit-20260929/`:
IOKit disassembly and strings, published-source tree listings, and the empty
published implementation file. Session-manager/framework disassembly comes
from the earlier saved exact-build audits. No Apple binary/disassembly dump
is committed. Addresses are specific to the inspected build.

[Public Ethernet provider](https://developer.apple.com/documentation/networkextension/neethernettunnelprovider),
[DriverKit packet queues](https://developer.apple.com/documentation/networkingdriverkit/iousernetworkpacketqueue).
