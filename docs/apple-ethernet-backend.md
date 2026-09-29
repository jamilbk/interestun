# Experimental Apple Ethernet backend

Build-time alternative to the existing NE utun descriptor and public IP packet
flow backends. It uses Apple's public
[NEEthernetTunnelProvider](https://developer.apple.com/documentation/networkextension/neethernettunnelprovider)
and [NEEthernetTunnelNetworkSettings](https://developer.apple.com/documentation/networkextension/neethernettunnelnetworksettings).
The containing CLI, signing identities, peer workers, crypto, and Network.framework
outer UDP transport are shared. It is not a mapped-ring implementation; see the
[installed-code audit](apple-ethernet-path.md).

## Build

```sh
python3 scripts/build-apple.py --ethernet --automatic-signing --team-id 47R2M6779T
```

The app is written to `target/apple-ethernet/Interestun.app` by default. Omit the
signing arguments for a non-activatable ad-hoc build. `--ethernet` and
`--packet-flow` are mutually exclusive. Without either flag the existing utun
backend remains selected. Both direct Swift and Xcode automatic-signing builds
compile the Ethernet provider subclass when selected.

The builder only builds/signs; it does not install or activate anything. This
variant intentionally uses the same bundle IDs and VPN configuration as the
other builds. Installing it later replaces the selected provider rather than
running two backends simultaneously. The build manifest records `tun_frontend`;
runtime `show` reports `NEEthernetTunnelProvider packet flow (IPv4)`.

## Packet pipeline

Host → Ethernet packet-flow callback → strip Ethernet header and padding → copy
IP once into the bounded encryption pool → existing peer send worker → encrypted
UDP via Network.framework.

Network.framework → existing peer receive/decrypt worker → prepend Ethernet
header in the decrypted packet's existing headroom → lease batch to Foundation
→ `writePacketObjects` → host stack. The usual transport path does not move the
IP payload when prepending the header. The handshake fallback can produce a
packet without headroom; that case moves the payload within its existing buffer.
Foundation/framework internal copies are not claimed to be eliminated.

The callback bridge retains batches of at most 128 packets, 1024 pending IP
packets, and the existing event wakeups. There is one outstanding framework read;
no Ethernet polling timer, new sleep, or per-packet data-plane thread is added.
ARP is handled locally and never encrypted or sent to Windows. Replies are small
control packets using the bounded pool; data-plane output retains its batch lease
until the last Foundation reference is released.

## Current scope

- IPv4 unicast only. IPv6 tunnel addresses/routes are rejected during CLI and
  provider validation, before applying settings. IPv6 outer UDP endpoints remain
  valid. IPv6 neighbor discovery, VLANs, bridging, broadcast, and multicast are
  not implemented.
- Fixed locally administered host MAC `02:49:54:00:00:01` and synthetic router MAC
  `02:49:54:00:00:02`. This is a routed IP edge for the experiment, not an Ethernet
  bridge between peers.
- Proxy ARP answers requests from configured local IPv4 addresses for targets in
  peer AllowedIPs. It excludes local addresses, unspecified/multicast/broadcast
  targets, and unrelated routes. Host ARP probes are not answered.
- Complete Ethernet frames use `AF_UNSPEC` at the callback ABI; EtherType selects
  IPv4 or ARP. Outgoing IP length validation excludes Ethernet padding. The
  encrypted wire format stays IP, so no Windows framing change is required.
- Ethernet uses public packet-flow I/O. It never calls the utun fd scanner,
  applies utun socket options, opens private channels, or changes the ring gate.
  Framework/internal driver queue capacities have not been tuned or measured.
- MTU remains an IP MTU of 1420 by default. No jumbo frames or extra peer
  connections are involved.

## Validation and remaining work

```sh
cargo test --locked --lib --features apple-packet-tunnel platform::ethernet
cargo test --locked --lib --features apple-packet-tunnel platform::packet_flow
python3 scripts/test-apple.py --ethernet-offline
```

These selected tests validate ARP, malformed/truncated frames, padding, unsupported
protocols, batches, buffer ownership/headroom, Swift settings, IPv6 rejection,
and Foundation frame representation without activating a system extension or
creating an interface. The ordinary `test-apple.py` test suite also performs
loopback UDP exchanges; it is not the offline Ethernet test.

Build and offline tests are not a connectivity or performance result. Live
activation, host routes/ARP behavior, framework frame delivery, Windows tunnel
exchange, and throughput/CPU still require a separately authorized live run.

## First live activation, 2026-09-29

The Firezone-team signed Ethernet extension activated successfully. Starting with
IPv4 settings failed before Rust startup: `setTunnelNetworkSettings` returned
`NEAgentErrorDomain` error 1. At the same timestamp (11:53:22 local), the kernel
logged:

```
(IOUserEthernet) IOUE_UC:: com.apple.networking.ethernet.user-access entitlement missing
```

`nesessionmanager` then logged `Failed to create a ethernet controller` and
`Failed to create a user ethernet interface`. The driver is loaded and its
`IOUserEthernetResource` service is registered, matched, and active, so this is
not an absent-driver finding. Static codesign inspection found the named
entitlement absent from both the installed `nesessionmanager` and our extension.
The earlier static trace places controller creation in `nesessionmanager`;
which task identity the driver's entitlement check uses still needs confirmation.
Adding an entitlement to our extension is therefore not an established fix.

The tunnel was left stopped, with the Ethernet build installed. No handshake or
throughput result exists for this backend. The previous installed app was backed
up locally to `target/apple-ethernet/pre-ethernet-installed.app`.

## Root cause traced in the loaded driver

Follow-up static analysis resolved the task-identity question above. The decoded
local kernelcache contains IOUserEthernet UUID
`7D9B4C3B-9559-3443-9041-82C3D2ED258E`, matching `kmutil showloaded`, and the
installed kernel build string `xnu-13432.1.9~1`.

`IOUserEthernetResourceUserClient::initWithTask(task*, void*, unsigned)` starts
at `0xfffffe000b65931c`. It preserves its incoming task argument (`x1`) in `x20`
at `0xfffffe000b65934c`. After superclass initialization succeeds, it passes that
same task and the string `com.apple.networking.ethernet.user-access` to
`IOTaskHasEntitlement` at `0xfffffe000b659384`. Failure prints the observed
`IOUE_UC` error and returns false. There is no root-UID bypass or alternative
provider entitlement in this method.

The installed IOKit `IOEthernetControllerCreate` opens the matching service with
`IOServiceOpen` at `0x184dff104`, using a task port loaded from its process globals,
not a provider task/audit-token argument. The caller is the already-traced
`nesessionmanager` Ethernet branch at `0x1000263e8`. Our provider's settings reach
that branch correctly. The daemon's signed entitlements lack the required grant.
This places the failing entitlement check in Apple's controller-creation process,
not our Rust engine or packet-flow callback code.

Interpretation: this is evidence of an entitlement failure inside the Apple
controller-creation path on macOS 27.0 build `26A428`. It does not establish that
changing OS builds is the only remedy, or exhaust supported setup alternatives.
Adding a grant to our extension would not change the daemon's task entitlement.
The earlier categorical conclusion that an OS replacement/fix was required was
premature. Startup remains unresolved.
No system daemon/kernel was modified, no extra private entitlement was added,
and no alternate backend was started.

Local diagnostic artifacts are in `target/apple-path/ethernet-startup/`. The
kernelcache was decoded and inspected as data only, never loaded or executed.
The extracted Mach-O's UUID and kernel build identify the exact inspected code;
Apple binaries/disassembly are intentionally not committed.


## Public documentation cross-check

Apple's [TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
explicitly supports Ethernet tunnel providers packaged as macOS system extensions
from macOS 13.0, including direct distribution. The public API is supported;
the private entitlement error is not a documented restriction on its availability.

The [Network Extensions entitlement reference](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
lists `packet-tunnel-provider` and the Developer ID variant
`packet-tunnel-provider-systemextension`; it lists no separate Ethernet-provider
value. The installed development-signed extension has `packet-tunnel-provider`,
and its embedded provisioning profile grants that value and expires 2027-09-28.
The Developer ID suffix is not a missing flag in this development-signed build.

Our provider subclasses `NEEthernetTunnelProvider`, constructs
`NEEthernetTunnelNetworkSettings(tunnelRemoteAddress:ethernetAddress:mtu:)`, and
passes it to `setTunnelNetworkSettings`. Its system-extension provider class is
registered under `com.apple.networkextension.packet-tunnel`. These match the
public API and inherited packet-provider registration. The framework recognizes
the Ethernet settings and reaches its user-Ethernet creation branch.

This review found no missing requirement in those documents. It does not turn a
failed live start into a working implementation or prove all possible remedies
have been ruled out. The precise current result is: documented public setup,
valid provisioned extension, failed controller creation, unresolved remedy.
