# Production Network.framework transport control

`network_bench` exercises the tunnel's actual `platform::network::Socket`,
`network_flow.m`, packet pool, prefix acceptance, and callback-driven readiness.
It opens one UDP Network.framework connection, without utun, routing, or crypto
in default raw mode. It does not change the running tunnel. The earlier separate
Objective-C benchmark stub and runtime BSD selector have been removed.

Defaults match the tunnel: 128-packet application batches, 1024 pending send
credits, and 1452-byte UDP payloads (1420 inner bytes + 32 transport bytes).
Payload storage is preallocated; raw mode changes only the packet header and
sequence, not the whole payload. Send callbacks still run for every datagram;
`nw_connection_batch` does not guarantee one syscall per application batch.

## Build and validate

```sh
CARGO_TARGET_DIR=target cargo build --release --locked --features network-bench --example network_bench
python3 scripts/test-network-bench.py --binary target/release/examples/network_bench --iperf3 /opt/homebrew/bin/iperf3
```

Finite loopback checks cover raw/AES/ChaCha, packet lengths, sequences/nonces,
batch sizes 1/128 and partial final batches. The optional iperf3 check starts a
short-lived local UDP receiver and verifies received bytes and loss reporting.
These are protocol/lifetime checks, not local-utun performance measurements.

## Use the existing Windows iperf3 server

```sh
target/release/examples/network_bench send --target 192.168.1.226:5201 --iperf --seconds 30 --json raw-unlimited.json
target/release/examples/network_bench send --target 192.168.1.226:5201 --iperf --seconds 30 --bitrate 4000000000 --json raw-4G.json
```

`--iperf` implements only forward, single-stream UDP testing. A TCP **control**
connection exchanges parameters and results; every benchmark data packet goes
through the production UDP bridge. The receiver is asked for a 4 MiB socket
buffer to absorb the same 128-packet bursts the tunnel submits. An unsupported
setting fails the test. The protocol is based on ESnet's
[control exchange](https://github.com/esnet/iperf/blob/3.21/src/iperf_api.c),
[client states](https://github.com/esnet/iperf/blob/3.21/src/iperf_client_api.c), and
[UDP headers](https://github.com/esnet/iperf/blob/3.21/src/iperf_udp.c).

JSON preserves the unmodified Windows receiver report and includes sender CPU,
accepted packets, received bytes/packets, missing packets (including a missing
tail), offered rate, and bridge occupancy/backpressure counters. The receiver's
`packets` field is a sequence high-water mark, **not** an arrival count; actual
arrivals are computed from received bytes divided by the fixed datagram size.
No receiver CPU conclusion is valid if that Windows iperf3 build returns zeros.

Unlimited mode has no pacing sleeps. Optional `--bitrate` controls the offered
rate once per application batch; requested rate is not guaranteed achieved rate.
Setup is excluded. After submission, pending completions are drained with a
bounded deadline and a callback-queue fence that checks errors. A 1 ms poll is
used only during this final drain because the production bridge signals full to
nonfull, not idle. The drain is included in elapsed time. Completed sends are
stack acceptance, not proof of on-wire transmission or remote receipt.
In iperf mode, a 100 ms tail-settlement interval follows the active send/CPU
measurement before the TCP test-end message. This avoids mistaking TCP control
overtaking the last UDP packets for sustained loss. Both the sender's active
interval and receiver's longer interval remain explicit in the JSON rates.

## Separate counting sink and optional crypto

A portable sink is available for Windows:

```powershell
cargo build --release --locked --features network-bench --example network_bench
.\target\release\examples\network_bench.exe receive --bind 0.0.0.0:5202 --idle-ms 30000
```

On macOS, target that port **without** `--iperf`. `--mode aes` and `--mode chacha`
optionally add BoringTun encryption, with fresh local sessions and enforced key
limits. They cannot be used with iperf3 because the UDP test header must be
readable by the receiver. The sink does not decrypt or authenticate. It uses
one blocking receive per packet and can itself limit throughput; its CSV counts
arrivals, not uniqueness. Use sender/receiver counts together.

## Interpretation

Compare actual received payload rates, loss, packet size, and CPU, not just
submission throughput. Neither the standalone sink nor iperf3 is automatically a
line-rate receiver. This test can isolate utun/crypto overhead, but cannot alone
attribute loss to macOS, the NIC/link, or Windows. Keep one data flow, unchanged
MTU, and run tests sequentially without compiling or exporting traces during
unprofiled measurements. Profile the actual route before claiming Skywalk use.
