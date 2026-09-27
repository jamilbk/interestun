# Network.framework transmit-path experiment

To test the actual tunnel rather than synthetic sends, use the
[build-time daemon backend](apple-udp-backends.md). This standalone example
remains useful for separating utun costs from transport API costs.

Network.framework can use Apple's userspace TCP/UDP stack instead of the BSD
socket transport path. Apple describes moving transport processing into the
application and exchanging packets through mapped memory in
[WWDC18 session 715](https://developer.apple.com/videos/play/wwdc2018/715/).
The same presentation describes batching sends and using content-processed
callbacks for backpressure. This is a different avenue from UDP segmentation
offload: lacking UDP GSO in public XNU does not rule out a faster userspace
transport path. It also does not guarantee which path Network.framework will
choose for this Mac, driver, route, and system policy.

`network_bench` is an opt-in standalone example. It does not open utun, alter
routes, or modify the running tunnel. It compares:

- `bsd`: connected nonblocking UDP using interestun's existing `batch::Sender`
  and packet pool; preserves unsent tails and polls writable on WouldBlock.
- `network`: one UDP `nw_connection_t`, `nw_connection_batch`, one serial
  callback queue, and a bounded window of batches. Each completion is checked;
  outstanding batches are drained before timing ends.
- `raw`, `aes`, or `chacha`: raw same-sized datagrams or in-place encryption
  through the pinned BoringTun fork's exclusive `TransportSender`.

Crypto modes establish a local two-peer handshake with fresh random keys and
verify a transport packet before timing. Key/counter limits remain enforced;
an expired sender is replaced with a fresh local session. The remote counting
sink does **not** participate in that handshake, decrypt, authenticate, or inject
packets. This isolates the transmit workload; it is not a tunnel interoperability
test. These ciphertexts cannot be sent to an existing interestun peer expecting
its configured session.

## Build and check

On macOS (requires Xcode/Command Line Tools):

```sh
CARGO_TARGET_DIR=target cargo build --release --locked --features network-bench --example network_bench
python3 scripts/test-network-bench.py --binary target/release/examples/network_bench
```

The finite smoke test checks both backends and all three modes, small and
MTU-sized datagrams, batch sizes 1/128, windows 1/8, partial final batches,
datagram lengths, raw payload integrity, and unique on-wire sequence/counter
values. Initial encrypted plaintext verification happens in the Rust sender.
Loopback smoke-test timing is not an Ethernet performance result.

The Network.framework bridge is compiled only on macOS with `network-bench`.
The BSD comparison build (`--no-default-features`) does not link Network.framework. On Windows/Linux the
example builds just the portable counting sink:

```powershell
cargo build --release --locked --features network-bench --example network_bench
.\target\release\examples\network_bench.exe receive --bind 0.0.0.0:5202 --idle-ms 30000
```

Allow UDP 5202 in the receiver's firewall if required. Run one sender per sink;
the sink rejects a change of source endpoint. It reports after the configured
idle period, or after `--packets N` for finite tests. Start a fresh sink for
each measurement; `--idle-ms` also bounds its wait for the first packet.

## Two-host comparison

Once the remote sink is listening, run one of these on the Mac, restarting the
sink for each invocation:

```sh
target/release/examples/network_bench send --target 192.168.1.226:5202 --backend bsd --mode raw --seconds 10
target/release/examples/network_bench send --target 192.168.1.226:5202 --backend network --mode raw --seconds 10
target/release/examples/network_bench send --target 192.168.1.226:5202 --backend bsd --mode aes --seconds 10
target/release/examples/network_bench send --target 192.168.1.226:5202 --backend network --mode aes --seconds 10
```

Repeat in alternating order. Sweep `--batch 1/32/128` and Network.framework's
`--window 1/8/32`. Defaults send 1452-byte UDP payloads: 1420 inner bytes plus
32 transport bytes. Raw mode sends the same length. Sender CSV reports UDP
payload throughput, including those 32 bytes; it is neither inner-IP throughput
nor Ethernet wire rate. Sender CPU includes all process threads, so the
asynchronous framework's CPU is included, not just the Rust caller.

## Interpretation and limitations

- A successful send/completion means the stack processed the content, **not**
  that the NIC transmitted it or the receiver got it. Compare packet counts at
  both ends. The sink's rate uses first-to-last arrival span; use receiver bytes
  divided by sender elapsed time for a common-duration goodput calculation.
- The current bridge copies each payload into framework-owned `dispatch_data`
  storage. This makes asynchronous lifetimes and timeout/cancellation safe, but
  adds a copy/allocation that BSD does not have at that layer. It is a first
  implementation, not a zero-copy performance ceiling. The in-flight window
  bounds outstanding content-processed requests; it does not bound every
  internal framework/driver queue.
- BSD has one calling thread; Network.framework uses its own scheduling and
  callback threads. Compare total CPU as well as throughput. The stub does not
  prove compatibility with the production one-TX/one-RX-thread model.
- The portable sink uses one `recv_from` per datagram and can itself saturate.
  A receiver bottleneck must not be mistaken for a Mac transmit limit. It
  counts arrivals, not unique packets; no authenticated delivery/loss claim is
  made. Separate sinks/ports are needed for a multi-sender scaling experiment.
- Setup is excluded, but there is no automatic warmup exclusion or CPU pinning.
  Rekey setup, if needed during a long run, is included. Network.framework's
  initial stub accepts IPv4 targets; BSD also accepts IPv6. Payload size is
  limited by the existing 2048-byte packet pool, so this is not a jumbo-MTU test.
- Selecting `network` does not prove Skywalk channel use. Trace/profile the
  connection on the actual Ethernet route before attributing a result to a
  kernel bypass. The current 10 GbE link cannot establish 25 GbE throughput.

No BoringTun fork changes are required for this experiment.
