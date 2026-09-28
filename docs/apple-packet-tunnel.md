# macOS packet tunnel system extension

`Interestun.app` contains a CLI executable and a packet tunnel system extension.
The implementation follows Firezone's Apple client structure: a containing app
submits `OSSystemExtensionRequest`, configures `NETunnelProviderManager`, and
starts a provider whose entry point calls `NEProvider.startSystemExtensionMode()`.
There is no GUI, login item, telemetry, or separate Rust daemon to launch.

The IDs are `dev.jamilbk.interestun` and
`dev.jamilbk.interestun.packet-tunnel`. The authorized signing team is Firezone,
`47R2M6779T`. These IDs are independent of the installed Firezone client.
Both bundles use the macOS App Group `47R2M6779T.dev.jamilbk.interestun`;
the extension's `NEMachServiceName` is prefixed with that group. Network
Extension category validation requires this even without shared file storage.

## Build

Xcode and the native Rust toolchain are required. Builds currently target the
host architecture, with deployment target macOS 15. The default experimental
Network.framework UDP receive SPI has only been validated on this macOS 27 host.

```sh
python3 scripts/build-apple.py --automatic-signing --team-id 47R2M6779T
```

This generates a small Xcode project under `target/apple/`, uses Xcode's
signed-in developer account to provision the two IDs, and signs the bundles
with Apple Development. The result is `target/apple/Interestun.app`; checksums
and build information are in `target/apple/build.json`. Building does not
activate an extension or start a tunnel. Previous bundles are retained alongside
the new build. No certificate/private-key material is stored in the repository.

For a local unprovisioned build, omit the signing flags. `--help` and `validate`
work, while activation commands refuse to proceed without provisioning.

The default frontend reads and writes the existing Network Extension utun
descriptor from Rust. Add `--packet-flow` to build the public
`NEPacketTunnelFlow` frontend. This is a build-time choice; both use
Network.framework for outer UDP.

Developer ID builds accept explicit profiles and an identity:

```sh
python3 scripts/build-apple.py \
  --team-id 47R2M6779T \
  --identity 'Developer ID Application: Firezone, Inc. (47R2M6779T)' \
  --app-profile /path/to/interestun-app.provisionprofile \
  --extension-profile /path/to/interestun-extension.provisionprofile
```

Profiles must match these bundle IDs and grant the Network Extension capability.
The host also needs `com.apple.developer.system-extension.install`. Automatic
development signing uses `packet-tunnel-provider`; Developer ID profiles use
`packet-tunnel-provider-systemextension`. This script does not notarize or
distribute the app, change SIP, or change system extension developer mode.

## CLI workflow

Place the app in `/Applications/Interestun.app` before activation. Run its
executable directly; it has no window and must remain inside its containing
bundle. `install` activates only the extension. macOS may require approval in
System Settings. `start` is the separate operation that creates a live tunnel.

```sh
/Applications/Interestun.app/Contents/MacOS/interestunctl install
/Applications/Interestun.app/Contents/MacOS/interestunctl status
/Applications/Interestun.app/Contents/MacOS/interestunctl validate --config /path/to/test.conf
/Applications/Interestun.app/Contents/MacOS/interestunctl start --config /path/to/test.conf
/Applications/Interestun.app/Contents/MacOS/interestunctl show
/Applications/Interestun.app/Contents/MacOS/interestunctl stop
```

The configuration uses WireGuard INI syntax, with `Address` and optional `MTU`
in `[Interface]`. For example, the established Windows test peer is:

```ini
[Interface]
PrivateKey = <the existing Mac private key; do not paste it into logs>
Address = 10.20.0.2/32
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = YTe9120oVSm/zw6s9Xz8xcKD/q8O1x1+YzvTsnPiJgs=
Endpoint = 192.168.1.226:51820
AllowedIPs = 10.20.0.1/32
PersistentKeepalive = 25
```

Keep the real config mode 0600. The CLI reads it and sends credentials as
ephemeral start options; keys are not saved in VPN preferences. Starting from
System Settings without those options fails with an explicit explanation. This
prototype has no unattended reconnect/keychain provisioning yet.

`--address`, `--mtu`, and `--cipher` can override startup settings. AES-256-GCM
is the default custom protocol; use `--cipher chacha20-poly1305` for standard
WireGuard peers. Endpoints must be numeric IP:port. IPv4 and IPv6 are supported.
Each peer needs an endpoint and AllowedIPs; each route family needs a matching
tunnel address. DNS and wg-quick hook fields are rejected. Only the supplied
AllowedIPs are installed as routes; a default route requires explicitly
configuring one.

The standalone daemon still supports the standard `wg` UAPI. The new extension
prototype accepts WireGuard config files but currently exposes control through
`interestunctl` and provider messages, not a `/var/run/wireguard` UAPI socket.
`show` returns public peer information and counters, without private/PSK fields.

## Packet path and ownership

Network Extension creates the adapter and configures addresses/routes. The
default frontend walks the provider's descriptor table, verifies the utun
control ID and exact interface name, and duplicates its existing descriptor.
It does not open another utun, use KVC, or set channel/ring attachment options.
The standalone Skywalk attachment interlock remains disabled. Descriptor
discovery follows Firezone's approach but is not a public NEPacketTunnelFlow
API contract.

- The first peer's send worker reads directly into preallocated Rust buffers
  with `recvmsg_x`, in batches of up to 128, and dispatches packets among peers.
  Each peer still has one send and one receive worker. There are no Foundation
  packet objects, Swift queue hops, or packet-flow input queues in this path.
- The receive worker injects decrypted slices using `sendmsg_x`, preserving
  original packet boundaries. Ordinary-utun TCP coalescing is disabled: the
  observed Skywalk netif rejects packets larger than its 4096-byte buffers.
- Startup raises the utun socket receive buffer to 4 MiB and its pending packet
  limit to 1024, verifies readback, and exposes before/after options in `show`.
  No global sysctls or live ring/channel settings are changed.
- A serial control queue handles lifecycle and 250 ms housekeeping. Rust uses
  kqueue readiness and Network.framework callbacks; no packet batching delay
  or dedicated bridging I/O thread is added.

With `--packet-flow`, one outstanding `readPacketObjects` request supplies
outbound packets. Their Foundation storage is copied synchronously into a
bounded 1024-packet Rust input queue. Decrypted output uses
`writePacketObjects`, with reference-counted leases retaining Rust buffers
across asynchronous Foundation ownership, including shutdown. The output
bridge requests no additional payload copy. A false framework write result
is terminal because the API cannot report an unambiguous consumed prefix.
The two frontends never read the utun concurrently.

`show` includes the selected frontend, peer traffic/drops, transmit-queue drops,
handshake timestamps, and utun option readback. The public frontend additionally
reports callback/batch counts, input drops, and write failures. The legacy
`skywalk: "unverified"` field is a static placeholder; the independent
[path investigation](apple-packet-tunnel-path.md) confirmed a Skywalk-backed
netif and socket boundary. Neither frontend maps utun rings into userspace.

Provider lifecycle errors are visible with:

```sh
log stream --style compact --predicate 'subsystem == "dev.jamilbk.interestun"'
```

## Validation

```sh
cargo test --locked --all-features --lib --test ciphers --test dataplane --test uapi --test packet_flow
cargo clippy --locked --all-targets --all-features -- -D warnings
python3 scripts/test-apple.py
```

The Rust suite tests bounded queues, readiness before/after registration, batch
leases across shutdown, write rejection, and real AES/ChaCha traffic over
loopback Network.framework UDP. The Swift tests cross the actual C ABI and
construct real `NEPacket` objects. They validate configuration/routes, encrypted
traffic in both directions, secret-free status, and buffer lifetime after stop.
On this host, the tested 1420-byte `NEPacket` objects preserved the original
buffer address. This is evidence about the Foundation bridge, not the kernel.
None of these tests activate a provider or create a real interface.

On 2026-09-28, the Apple Development build was separately installed in
`/Applications/Interestun.app` on this macOS 27 host. After user approval,
`systemextensionsctl list` reported `activated enabled` under team `47R2M6779T`.
The CLI's `status` command also confirmed the extension was enabled. No VPN
configuration or live tunnel was started during this initial activation check.
The initial activation
exposed a missing App Group entitlement, which the build script now includes
in both bundles.

A subsequent authorized start reached Skywalk nexus attachment but failed
with `EBUSY` before a tunnel became operational. See the
[live startup investigation](apple-packet-tunnel-path.md) for the logs,
stale-interface hypothesis, and successful startup after a clean boot. That
follow-up confirmed a Skywalk-backed `utun4` whose public packet-flow frontend
still uses batched socket syscalls; the outer UDP connection uses a separate
Ethernet flowswitch channel. Subsequent
[Windows tunnel tests](apple-packet-tunnel-windows-testing.md) measured
3.878 Gbit/s send and 2.732 Gbit/s receive over 30 seconds, with no new bridge
or peer drops or utun errors. Simultaneous traffic also passed.

The subsequent [packet pipeline audit](apple-packet-pipeline-audit.md) replaced
the public bridge with direct I/O on the existing descriptor, tuned the utun
queues, and corrected transmit backpressure. Repeated 30-second results reached
4.816 Gbit/s send and 2.747 Gbit/s receive; receive process CPU fell from 1.436
to 1.070 cores. The selected build is installed and connected. Direct mapped
access to the utun rings remains unvalidated.

Sources: [provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment),
[packet flow](https://developer.apple.com/documentation/networkextension/nepackettunnelflow),
[provider lifecycle](https://developer.apple.com/documentation/networkextension/neprovider),
and the local Firezone reference at `~/Developer/firezone/firezone/main/swift/apple`.
