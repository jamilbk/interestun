# Windows backend

Build with Rust 1.88+ and the MSVC C++ build tools:

```powershell
cargo build --release --locked
.\scripts\install-wintun.ps1
```

The installer downloads Wintun 0.14.1 from [wintun.net](https://www.wintun.net/),
checks the published archive SHA-256 and DLL Authenticode signature, then places
the DLL matching the executable's architecture and its license beside
`target\release\interestun.exe`. It can be rerun and refuses to overwrite a different
DLL. For debug/custom builds, use `-ExecutablePath .\target\debug\interestun.exe`.
No elevation is needed to copy the DLL into a writable build directory; creating
an adapter later requires elevation. The DLL/driver is not bundled in this repository.
Use a trusted directory: the daemon loads native code from this file. It resolves
the explicit DLL path and restricts dependency lookup to its directory and System32.

In an elevated PowerShell terminal:

```powershell
.\target\release\interestun.exe interestun
# An explicit DLL location is also supported:
.\target\release\interestun.exe interestun --wintun-dll C:\VPN\wintun.dll
# Standard WireGuard peers require --cipher chacha20-poly1305.
```

The foreground process creates a temporary adapter, sets the IPv4 and IPv6 MTU,
and opens a Wintun session with 16 MiB per ring (32 MiB total).
`--wintun-ring-mib 4` restores the initial backend's ring capacity for comparison;
the setting accepts powers of two from 1 through 64 MiB per direction.
Ctrl-C/Break joins workers, ends the session,
closes the adapter and removes its named-pipe endpoint. No existing adapter is
adopted. IP addresses, routes, DNS, and firewall policy are caller-managed.

## Configuration

The UAPI is `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\interestun`.
Only SYSTEM and elevated Administrators can access it; remote pipe clients are
rejected. An existing endpoint is never taken over. Requests use the same text
UAPI as macOS: hexadecimal keys, `set=1` or `get=1`, and a terminating blank line.
Configuration changes validate first, then restart workers; failure attempts to
restore the prior configuration.

**Stock Windows `wg.exe` requires the named pipe's owner to be LocalSystem.**
Run the daemon under a LocalSystem host to use `wg set`, `show`, `setconf`, and
`syncconf`. An ordinary elevated Administrator daemon has a different owner, so
stock `wg.exe` rejects it even though the ACL permits Administrator access.
This requirement comes from [wireguard-tools' Windows IPC implementation](https://git.zx2c4.com/wireguard-tools/tree/src/ipc-uapi-windows.h).
Windows service installation/SCM integration is not included.

For an elevated Administrator daemon, the included direct client is usable from
a second elevated PowerShell terminal:

```powershell
# Query the interface (includes private keys once configured).
.\scripts\uapi.ps1 -Interface interestun
# Apply a UAPI request stored in a protected UTF-8 file.
.\scripts\uapi.ps1 -Interface interestun -RequestFile .\peer.uapi
```

Example `peer.uapi` (replace both placeholders with 64 hexadecimal characters):

```text
set=1
private_key=<local-private-key-hex>
listen_port=51820
public_key=<remote-public-key-hex>
endpoint=192.0.2.2:51820
allowed_ip=10.20.0.2/32
persistent_keepalive_interval=25

```

Restrict access to the request file because it contains the private key. Configure
the opposite keys on the remote host, select the same cipher, and replace the
example endpoint with the remote host's reachable address. Then assign the local
address and route, for example:

```powershell
New-NetIPAddress -InterfaceAlias interestun -IPAddress 10.20.0.1 -PrefixLength 32
New-NetRoute -InterfaceAlias interestun -DestinationPrefix 10.20.0.2/32 -NextHop 0.0.0.0
```

## Data path and validation

Windows uses independent transmit and receive workers per peer in
`runtime_windows.rs`, matching the macOS duplex ownership model. The receive
worker owns handshakes, replay protection, timers, and adapter injection; it
transfers a non-cloneable transport sender to the transmit worker, which owns
encryption and its nonce counter. No shared tunnel lock serializes the two directions.
One additional reader waits on Wintun's read event and dispatches packets to
bounded transmit inboxes. Shutdown waits at most 100 ms for an idle reader.
The first peer's receive worker receives both shared UDP listeners through
Mio/IOCP. Windows uses exclusive UDP binds and `send_to` through the shared
listeners; it does not depend on Darwin's `SO_REUSEPORT` flow selection.
UDP receive/send and encryption work use 128-packet fairness budgets. This is
userspace batching, not multiple datagrams in a Windows socket call. Packet and
coalescing storage is reused; Darwin's descriptor arrays and utun pending-queue
socket option have no Wintun equivalent and are not copied to Windows.

Wintun receives copy directly into pooled packet storage and release the ring
packet before returning. Windows UDP also receives directly into pooled storage;
both avoid the original scratch-to-pool copy. Pool exhaustion drains into a discard
buffer so the device/socket continues making progress.

Transport encryption/decryption now reuse that same packet buffer, using the
in-place BoringTun APIs introduced in upstream commit `5ff750c`. Wintun reads
reserve 16 bytes before the IP packet and 16 bytes of tail capacity for the tag.
Decryption exposes the plaintext through a slice offset without copying it.
Handshake messages retain their separate output buffers. UDP readiness is
retained across fairness budgets and cleared only on WouldBlock; timer/inbox
wakeups no longer probe idle UDP listeners. Pending output runs immediately after
a full work budget, using the retry delay only when blocked.

Receive-side TCP coalescing is enabled by default. Each peer merges adjacent,
compatible TCP data segments already queued after authentication and source
validation, before injecting them into Wintun. It adds no aggregation delay.
IPv4 (DF set, no options/fragments) and IPv6 (no extension headers) are supported,
up to 65,535 bytes per injected packet. Original IP/TCP checksums are verified,
and complete checksums are computed for merged packets. Sequence numbers must be
contiguous; ACK/window, IP attributes and TCP options must match. PSH terminates
the aggregate. Control packets, pure ACKs, unsupported TCP options (including
TCP-AO/MD5), and any incompatible packet pass through and form an ordering barrier.
There is no flow reordering, UDP aggregation, or change to encrypted wire packets.
Unlike Firezone's multi-flow coalescer, this version only merges adjacent packets.

`--no-tcp-coalescing` keeps original packet boundaries for A/B testing. Each enabled
worker reserves one reusable 64 KiB staging buffer. Originals and a prepared
aggregate are retained intact through backpressure, then released only after a
successful adapter write. Ring-full errors retry after at most 2 ms (Wintun has
no writable event). Larger rings absorb scheduling gaps but do not increase the
bounded peer-queue limits.
Windows UDP is currently one datagram per call, not Darwin-style batching.
Control clients are serviced every 10 ms, with 32 clients, 1 MiB requests, and
five-second deadlines. There is no control-client thread per connection.

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

These tests run real Windows UDP and named pipes with a simulated adapter. They
cover both ciphers, concurrent duplex traffic across multiple peers, IPv4/IPv6,
routing/source validation, roaming, maximum-MTU packets, oversized datagrams,
backpressure with reverse-direction progress, adapter failure, shutdown, exclusive binding,
and UAPI transactions. They do not establish real driver throughput or validate
the protected pipe ACL under separate Windows accounts.

### Performance comparison

The first two-host baseline reported 9.40 Gbps Mac → Windows and 9.41 Gbps
Windows → Mac over LAN, versus 0.946 and 2.32 Gbps respectively through AES-GCM.
These are user-reported results; stream counts and durations were not recorded.
The optimized build still needs a comparable two-host run.

After integrating `5ff750c`, the Windows crypto-only benchmark (one worker,
100,000 packets per sample, three samples, Rust 1.96.0/MSVC x64) observed median
AES-256-GCM seal/open roundtrip time at 1420 bytes of 432.2 ns with copying and
398.5 ns in place. These short samples are a sanity check, exclude sockets and
adapter I/O, and are not a network throughput claim. Raw data:
[copy](benchmarks/windows-transport-copy.csv) and
[in-place](benchmarks/windows-transport-inplace.csv).
The benchmark command was `cargo bench --locked --bench transport`, with
`PACKETS=100000`, `SAMPLES=3`, `MAX_WORKERS=1`, and `IN_PLACE=0` then `IN_PLACE=1`.

The duplex integration of upstream `2e85c13` retains TCP coalescing, its
comparison flag, and diagnostic counters. It still needs a new two-host
throughput run; the crypto-only figures above predate the worker split.

Build separately while the original executable is running:

```powershell
cargo build --release --locked --target-dir target/duplex
.\scripts\install-wintun.ps1 -ExecutablePath .\target\duplex\release\interestun.exe
```

Stop the original daemon with Ctrl-C in its elevated terminal, launch
`.\target\duplex\release\interestun.exe interestun`, and reapply the saved peer
with `scripts/connect-macos-peer.ps1 -Endpoint <mac-lan-ip> -MacPublicKey <mac-public-key>`.
Do not run both daemons for the same interface simultaneously. Repeat the same
iperf3 commands with the same stream count, duration, and direction. For an
isolated coalescing comparison, restart with `--no-tcp-coalescing` and leave the
ring size unchanged. To also reproduce the original ring size, add
`--wintun-ring-mib 4` (receive-copy improvements remain enabled).

The Windows-only diagnostic request contains no private keys:

```powershell
.\scripts\uapi.ps1 -Interface interestun -Request 'stats=1'
```

It reports `tcp_coalescing` and per-peer `wintun_writes`, `coalesced_segments`
(input segments eliminated by merging), `ring_full_retries`, and `drops`.
Counters are snapshots at most 250 ms old and reset on reconfiguration.
Compare counter deltas around a run: `(writes + coalesced_segments) / writes`
is the average number of original packets per adapter write.

Optional sampled stage profiling is also available on Windows:

```powershell
cargo build --release --locked --features io-profile --target-dir target/profile
.\scripts\install-wintun.ps1 -ExecutablePath .\target\profile\release\interestun.exe
```

Run that binary instead of the normal daemon to log per-thread timing every
five seconds. It samples Wintun reads/writes (including coalescing), UDP I/O,
and encryption using wall time and Windows thread CPU time. CPU-time resolution
can make short samples read as zero; aggregate across a sustained test. Windows
UDP reads are timed per syscall, sends per batch. Normal builds compile out the
profiling calls. This does not implement UDP segmentation offload or receive
coalescing for encrypted UDP datagrams.

`cargo bench --bench injection` measures userspace preparation cost and write
counts using a synthetic 32-packet IPv4 TCP burst, with an empty adapter sink.
It deliberately excludes kernel, UDP and encryption costs and cannot predict
network throughput. The benchmark checks that 320,000 input packets become
10,000 writes with coalescing, versus 320,000 without.

The separate driver smoke test requires an elevated terminal and a trusted DLL:

```powershell
$env:INTERESTUN_WINTUN_DLL = 'C:\VPN\wintun.dll'
cargo test --locked --test wintun_privileged -- --ignored --nocapture
```

It creates temporary adapters, checks both MTUs, exercises receive/wait, and
closes/recreates the adapter. A two-host test with actual routes and traffic is
still required before making performance or interoperability claims.
