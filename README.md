# interestun

A barebones Rust userspace tunnel for macOS, based on Firezone's BoringTun fork.
One main housekeeping/control thread, one I/O thread per configured peer, and one
shared BSD utun. This is an experimental implementation, not a production VPN.

The default transport cipher is **AES-256-GCM**. It uses a distinct authenticated
handshake transcript and requires interestun at both ends. Select
`--cipher chacha20-poly1305` for standard WireGuard interoperability. The normal
`wg` command works with either mode through the WireGuard userspace IPC protocol;
CLI compatibility does not imply protocol compatibility for AES.

## Build and run

Requires macOS, Rust 1.88+, and the standard `wireguard-tools` package for `wg`.
The dependency is pinned to a commit on `jamilbk/boringtun`.

```sh
CARGO_TARGET_DIR=target cargo build --release --locked
sudo ./target/release/interestun utun
# Or, to connect to an ordinary WireGuard peer:
sudo ./target/release/interestun utun --cipher chacha20-poly1305
```

The daemon stays in the foreground and prints its actual interface name. In a
second terminal, substitute that name below:

```sh
umask 077
wg genkey > private.key
wg pubkey < private.key > public.key
sudo wg set utun8 private-key ./private.key listen-port 51820
sudo wg set utun8 peer '<peer-base64-public-key>' \
  endpoint 192.0.2.2:51820 allowed-ips 10.20.0.2/32 persistent-keepalive 25
sudo ifconfig utun8 inet 10.20.0.1 10.20.0.2 up
sudo route -n add -host 10.20.0.2 -interface utun8
sudo wg show utun8
sudo wg show utun8 dump
sudo wg showconf utun8
```

`192.0.2.2` is a placeholder: replace it with the remote host's real endpoint.
Configure the opposite keys/addresses on the remote host and use the same cipher.
`wg setconf` and `wg syncconf` use the same UAPI. Address assignment, routes, DNS,
forwarding, and firewall rules remain explicit OS configuration. There is no
`wg-quick` auto-launch integration or GUI yet. Ctrl-C/SIGTERM shuts down workers,
closes utun, and removes the owned UAPI socket.

UAPI sockets live at `/var/run/wireguard/utunN.sock` with mode `0600`. The containing
directory must be owned by the daemon's user and not writable by other users.
A pre-existing socket is never deleted automatically. `--uapi-dir` is useful for
testing; stock `wg` uses its compile-time `/var/run/wireguard` directory.

## Data path

- Mio uses kqueue on macOS. Each peer worker owns its BoringTun state, deadlines,
  and connected UDP socket. Connected sockets share the interface's listen port
  with IPv4/IPv6 wildcard sockets using Darwin's `SO_REUSEPORT` behavior.
- The first peer worker additionally drains the shared utun and wildcard sockets,
  dispatching to peer workers through bounded queues. The main thread does no
  tunnel packet I/O. No extra acceptor, signal, Tokio, or per-socket threads.
- `sendmsg_x` / `recvmsg_x` batch up to 32 packets on utun and connected UDP. Runtime
  symbol resolution falls back to `sendmsg` / `recvmsg` if those private APIs are
  absent. utun's four-byte big-endian address-family header uses scatter/gather I/O.
- Reusable 2048-byte packet buffers, bounded queues, coalesced worker wakeups, a
  prefix trie, and bounded drain budgets avoid unbounded allocation and keep
  timers responsive under load. MTU is explicitly set, default 1420, range 1280–2000.
- Positive partial sends retain the unsent tail in order. WouldBlock retains the
  batch and enables write readiness. Other batch errors drop the attempted batch
  because Darwin does not report unambiguous progress. Pool/queue exhaustion drops
  packets. There is no steady-state heap allocation per packet.
- Authenticated packets may update an endpoint. Cookies never move endpoints.
  Inbound source addresses must belong to that peer under the same longest-prefix
  route lookup used for outbound traffic.

See [architecture and limitations](docs/architecture.md),
[performance methodology and baseline](docs/performance.md), and
[upstream provenance](docs/upstreams.md).

## Verify

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo bench --bench transport
MAX_WORKERS=12 SAMPLES=5 PACKETS=100000 cargo bench --bench transport > samples.csv
```

Tests exercise real macOS batching/kqueue/UDP with simulated utun endpoints,
multiple peers, IPv4/IPv6, spoofed source rejection, cipher mismatch, replay,
tampering, and UAPI transactions. BoringTun's fork also tests a known AES-GCM
answer and nonce-counter boundaries, plus its upstream protocol/timer suite.
The optional real-`wg` integration test is described in `scripts/test-wg.sh`.

The real-utun integration test launches the release daemon through `sudo -n`,
configures temporary IPv4/IPv6 addresses and host routes, and exchanges UDP echoes
with two unprivileged BoringTun peers. It tests both cipher suites, six payload
sizes, 64-packet bursts, `wg` handshake reporting, and interface cleanup. This has
passed on Apple M2 Pro / Darwin 27.0.0. It is a correctness test, not a throughput
benchmark or independent WireGuard implementation interoperability test.

```sh
CARGO_TARGET_DIR=target cargo build --release --locked
cargo test --locked --test live_macos -- --ignored --nocapture
```

It requires noninteractive sudo for the absolute `target/release/interestun` path,
`/sbin/ifconfig`, `/sbin/route`, `/opt/homebrew/bin/wg`, and `/bin/kill`. The test
uses reserved `198.18.254.1–3` and ULA `fd7a:115c:a1::1–3` addresses, refuses existing
test addresses/routes, and removes its temporary configuration on success/failure.
The daemon uses the normal `/var/run/wireguard` UAPI directory. The test is ignored
in ordinary `cargo test` and CI because it changes host networking.

A smaller root-only adapter smoke test is also available:

```sh
CARGO_TARGET_DIR=target cargo test --test utun_privileged --no-run
# The preceding command prints the executable path. Run it as root:
sudo ./target/debug/deps/utun_privileged-<hash> --ignored --nocapture
```

Windows/WinTUN is not implemented yet. The cryptographic/configuration code is
portable; the current event loop, utun adapter, and UAPI server target macOS.
