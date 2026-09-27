# Build-time macOS UDP backend experiment

The macOS daemon now builds with **Network.framework by default**. It opens no
BSD UDP listener or peer socket in this mode and never falls back to BSD.
Rebuild to compare the implementations in separate runs:

```sh
# Network.framework (default feature apple-network)
CARGO_TARGET_DIR=target cargo build --release --locked
sudo ./target/release/interestun utun

# BSD comparison build; stop the previous daemon before starting this one
CARGO_TARGET_DIR=target cargo build --release --locked --no-default-features
sudo ./target/release/interestun utun
```

There is no runtime `--udp-backend` switch. The startup log reports the compiled
selection. Configuration updates and rollback preserve it. Windows remains on
its existing backend; no Windows rebuild or BoringTun fork change is required.
Configure keys, endpoints, cipher, addresses, and routes normally with `wg` and
the OS tools.

## Scope of this experiment

Network.framework mode requires a configured endpoint for every active peer.
It creates one connected `nw_connection_t` per peer and uses that connection for
handshakes, cookies, transport, and keepalives in both directions. With a nonzero
`ListenPort`, each connection requests that local port. With zero, connections
use system-assigned ports and UAPI continues to report zero; this prototype does
not yet select and publish one shared ephemeral port. For a controlled single
peer test, set an explicit listen port (51820 in the Windows setup).

There is **no wildcard listener** in this experiment, so unknown-endpoint
acceptance and automatic remote endpoint roaming are not supported. Set a new
endpoint through `wg` to reconnect. Configurations with an active private key and
missing peer endpoints are rejected rather than silently using BSD. This is a
benchmark implementation for configured peers, not full Network.framework
WireGuard server support. An `NWListener` would be needed for that extension.

## Ownership and readiness

`platform::udp::PeerSocket` exposes batch send/receive and TX/RX readiness.
The BSD comparison uses the original nonblocking sockets and batch syscalls.
The Apple implementation uses `nw_connection_batch`, asynchronous send
completions, and message receives. BoringTun retains the existing exclusive
TX key/counter and RX handshake/replay ownership.

Each Apple flow has a serial dispatch queue, at most 1024 sends awaiting
content-processed callbacks, and a preallocated 256-packet receive ring. Full
receive rings stop posting reads until Rust drains them. Separate nonblocking
Unix socketpairs notify the TX/RX workers; these are local wakeup descriptors,
not BSD UDP transports. Wakeups are coalesced at empty-to-nonempty RX and
full-to-writable TX transitions. Partial accepted sends retain their tails.

The bridge copies bytes across the asynchronous boundary and never retains
Rust buffer pointers. Cancellation marks the flow closed before Rust releases
its descriptors; callbacks retain their own state and notification writers.
This first implementation adds dispatch scheduling and staging copies. It is
not zero-copy or a performance ceiling. Connection waiting/failure and async
I/O errors fail visibly; they do not select another backend.

## Path selection and measurements

Apple describes Network.framework's userspace TCP/UDP stack and mapped packet
exchange in [WWDC18 session 715](https://developer.apple.com/videos/play/wwdc2018/715/).
This is separate from UDP segmentation offload. Choosing the API does not prove
which underlying path a connection uses. An unprivileged loopback sample of the
standalone stub showed `nw_socket_service_writes -> __sendmsg`, with `lo0` in its
connection description. Ethernet descriptions identify `en8` but do not prove
channel use. BSD `io-metrics`/`io-profile` socket counters do not instrument the
framework's internal I/O and cannot be compared as complete UDP syscall totals.

The Network.framework-only daemon connected to the existing Windows peer on
2026-09-27: M2 Pro, en8 10 GbE, AES-256-GCM, MTU 1420, explicit port 51820.
Each diagnostic sample measured five seconds after one second warmup:

| Traffic | Receiver Gbit/s | UDP loss |
| --- | ---: | ---: |
| Mac to Windows TCP | 0.681 | — |
| Windows to Mac TCP | 0.460 | — |
| Mac to Windows UDP, offered 3 Gbit/s, payload 1360 | 3.000 | 0.0108% |

The immediately preceding BSD daemon delivered 2.022 Gbit/s in a shorter
three-second TCP-send sample after one second warmup. These sequential samples
are not an interleaved A/B study. The first Apple bridge is slower for TCP;
there is no established improvement over the earlier roughly 3 Gbit/s BSD UDP
results. Further profiling must separate dispatch/staging costs, flow behavior,
and the selected transport path. The Apple build was left running for further
experiments. [Raw iperf summaries](benchmarks/macos-network-framework.json).

## Validation

All-feature tests cover configured Apple peers against WireGuard fixtures,
AES/ChaCha, IPv4/IPv6 endpoints and payloads, multi-peer bursts and duplex traffic,
and source-address rejection. The BSD comparison retains its discovery/roaming
regressions. Real-utun tests passed with the Network.framework-only binary for
both ciphers, two peers, both inner IP families, six packet sizes, and bursts:

```sh
CARGO_TARGET_DIR=target cargo build --release --locked
cargo test --locked --all-features --test live_macos -- --ignored --nocapture
```

The [standalone transmit benchmark](network-framework-benchmark.md) remains
available to remove utun from the comparison and isolate raw versus encrypted
sends. Loopback correctness tests do not establish Ethernet throughput.
