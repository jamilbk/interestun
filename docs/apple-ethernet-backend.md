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
