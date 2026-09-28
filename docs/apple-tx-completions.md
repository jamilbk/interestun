# Network.framework send bridge and completion experiments

On 2026-09-28 we instrumented and tested the submission and completion costs
identified by the [send CPU profile](apple-send-profile.md). All Windows tests
used one peer, one Network.framework UDP connection, MTU 1420, AES-256-GCM, and
one inner TCP iperf3 stream. Windows remained `192.168.1.226:51820` / `10.20.0.1`.
No jumbo frames, additional transport connections, or direct Skywalk attachments
were used.

## Selected changes

`in_flow_send` caches the immutable connection outside its packet loop and
creates one shared completion block per submitted batch. Each UDP datagram
still has its own content-processed callback, error handling, and immediate
credit return. The 1024-packet credit limit, owned payload copies, and partial
accepted-prefix contract remain intact. There are no new timers or queue hops.

The simpler implementation was retained after testing batch credit returns and
a connection-wide callback. The measurements do not establish a repeatable
throughput increase or process CPU reduction from these changes. The source-level
reduction in our block creation/property access does not remove the framework's
internal per-datagram request allocation and completion reporting.

## What the new counters establish

`interestunctl show` exposes per-peer `network_tx` counters:

- `accepted`: datagrams copied and submitted to the framework, including control
  traffic. It does not mean remote delivery.
- `partial`: calls that accepted less than the requested prefix.
- `blocked`: calls that returned `EAGAIN` because all 1024 credits were reserved;
  waiting for initial connection readiness is excluded.
- `blocked_ns`: completed intervals from the first credit-full return to the
  next successful submission. This includes worker scheduling/retry latency and
  excludes an unfinished interval. It is not per-packet latency.
- `wakes`: full-to-available credit notifications, excluding state/error wakes.
- `batches` and `occupancy`: accepted batch size and pre-reservation pending
  credit histograms. Bucket 0 is zero; bucket n covers `[2^(n-1), 2^n)`.

Counters are relaxed atomic snapshots, not a transactional queue view. Collection
adds a few updates per submission and a clock read only on a credit stall or its
next successful retry. It adds no per-packet clock calls or periodic logging.

The two instrumented baseline runs averaged **92.5 and 94.9 datagrams per batch**.
They blocked on credits just once each, for **47 and 140 microseconds** over
approximately 31 seconds including warmup. The configured limit of 128 was
therefore being used effectively; credit starvation did not explain this run's
throughput. These application batch counts do not establish packets per kernel
channel sync.

## Experiments

Each throughput test measured 30 seconds after a one-second warmup. CPU is
extension process CPU time divided by wall time over the steady sampling window;
1.0 core is 100% of one core. It excludes iperf and work charged to other processes.
The Mac was an active desktop, and the tests were sequential rather than randomized.

| Variant | Send Gbit/s | Process cores | Mean batch | Credit retry time |
| --- | ---: | ---: | ---: | ---: |
| Instrumented baseline | 3.884 | 1.717 | 92.5 | 0.047 ms |
| Connection cache + shared block per batch | 3.968 | 1.647 | 94.2 | 0.337 ms |
| Also return credits when every callback in a batch completes | 4.034 | 1.651 | 93.5 | 2.976 ms |
| Instrumented baseline repeated | 4.337 | 1.688 | 94.9 | 0.140 ms |
| One callback per connection, publish 32 completion credits at a time | 3.850 | 1.647 | 95.5 | 1.994 ms |
| Connection-wide callback repeated | 3.967 | 1.663 | 95.7 | 0.488 ms |
| Selected shared-block implementation, final build | 4.237 | 1.670 | 94.2 | 0.586 ms |

The faster baseline repeat prevents interpreting the first candidate runs as a
throughput win. Credit stalls remained negligible in every variant. All rows
above had zero new generic peer drops and transmit-queue drops.

Additional tests paced the same single TCP stream at 3 Gbit/s to compare CPU at
a matched rate:

| Variant | Received Gbit/s | Process cores | Mean batch |
| --- | ---: | ---: | ---: |
| Connection-wide callback, groups of 32 credits | 3.000 | 1.176 | 33.5 |
| Instrumented baseline | 3.000 | 1.172 | 35.4 |
| Connection-wide callback with separate cache lines for the local completion counter | 3.000 | 1.212 | 26.2 |

There is no demonstrated CPU benefit here. Pacing also changes the batch-size
distribution, and the distributions varied across these runs. The padded variant
was not retained. The connection-wide block needed an explicit close-time cycle
break, and credit grouping conservatively withheld up to 31 completed credits;
neither complication was justified by the results.

Build manifests, raw iperf JSON, process CPU samples, counter snapshots, and
reversible source patches are in
[the experiment record](benchmarks/macos-apple-tx-completions/). Patch names
identify their parent variant. `original` is the bridge at commit `8b18ea3`;
`baseline` adds the diagnostics; `shared` is the selected submission design.
Discarded variants are preserved as patches rather than runtime choices.

Use the final commit's Rust status bindings with these C bridge patches. To
rebuild the instrumented baseline from the selected bridge, reverse
`baseline-to-shared.patch`. The connection-wide variants also need the archived
`connection-tests.patch`, because those prototypes conservatively retain partial
credit groups after idle and explicitly initialize their persistent callback.

The final selected build also received **2.734 Gbit/s at 1.118 cores** in a
30-second reverse test, with zero new peer/TX-queue drops and no send-credit
stalls. ACK sends averaged 1.01 datagrams per batch. Installed provider SHA-256:
`99b419b79beacb735acd6f73d7e91389576febbb10dade0a60016bc8506a4671`.
This build remains connected on `utun4`.

### Follow-up profile

A separate 30-second send with Instruments attached measured 3.624 Gbit/s at
1.639 process cores, zero new peer/TX-queue drops, and zero credit stalls. The
profile captured 25 seconds; the same analysis script as the earlier report
selects seconds 2–22, all running samples. Its 32042 samples represent 1.602
estimated cores in that shorter window:

| Exclusive category | Sampled CPU |
| --- | ---: |
| Framework asynchronous send service | 49.95% |
| Other framework, dispatch and callback work | 21.24% |
| TX utun reads | 10.89% |
| Our Network.framework send submission | 8.09% |
| Encryption/transport framing | 5.53% |
| Other TX work | 3.19% |
| RX worker | 1.11% |

Framework asynchronous processing still dominates. The lower submission share
relative to the prior 9.7% profile is not an isolated speedup estimate: throughput
and batch sizes differ, and these are sampling percentages. The profile run
averaged 77.1 datagrams per batch versus 94.2 in the selected unprofiled run.
Its single TCP retransmission also differs markedly from the unprofiled run's
773. Do not interpret either run as an absolute throughput ceiling.

The raw compressed sample table and analysis JSON are included in the experiment
record. Reproduce with `python3 scripts/analyze-apple-profile.py
docs/benchmarks/macos-apple-tx-completions/selected-samples.xml.gz --output
target/selected-analysis.json`. The native Instruments trace remains in the
ignored experiment directory.

## Private adaptive-write hook

We inspected the installed macOS 27.0 (26A428) Network.framework in an
unprivileged helper under LLDB; we did not invoke this SPI in the tunnel.
`nw_connection_set_adaptive_write_handler` forwards a 32-bit value and block
to the endpoint flow. Its registration path names the notification
`write_timeout`; the TCP compatibility callback emits an event labeled
`adaptive write timeout`. This is evidence of timeout notification handling,
not evidence of aggregate UDP completions or a writable-credit API. UDP
semantics and a supported ABI remain unverified, so it was not adopted.

Relevant inspection commands: `disassemble -n nw_connection_set_adaptive_write_handler`,
`disassemble -n __nw_connection_set_adaptive_write_handler_block_invoke`,
`disassemble -n 'nw_endpoint_handler_register_adaptive_write_handler(NWConcrete_nw_endpoint_handler*)'`,
and `disassemble -n __tcp_connection_set_adaptive_write_handler_on_nw_connection_block_invoke`.
The full local inspection output remains under
`target/apple-path/tx-completion-20260928/`.

Apple's [batch API](https://developer.apple.com/documentation/network/nw_connection_batch(_:_:))
invokes the submission block synchronously. Its
[send API](https://developer.apple.com/documentation/network/nw_connection_send(_:_:_:_:_:))
defines per-send content processing, not a storage-release/completion fence for
earlier independent datagrams. The idempotent marker omits these application
callbacks and permits replay; releasing an application payload does not by
itself establish that all framework-internal write requests have completed.
This experiment keeps individual completions and bounded credits.

## Validation and reproduction

Native tests exercise copied-payload ownership after input reuse, partial sends,
out-of-order completions, per-message errors, cancellation with outstanding
callbacks, 1001 lone sends, and 100003 sends against a concurrent serial callback
queue. A deliberately stalled callback queue forces the 1024-credit limit; the
producer then resumes through its real notification without a retry timer.
Existing RX ownership and private receive-SPI tests also pass.

Run `sh scripts/test-network-notify.sh`, including `SANITIZER=address` and
`SANITIZER=thread`. Rust all-feature tests, formatting, and all-target/all-feature
Clippy with warnings denied pass. These fixtures create no real utun.

For an already handshaken Windows tunnel:

```sh
python3 scripts/measure-apple-tunnel.py send --output target/tx-send
python3 scripts/measure-apple-tunnel.py receive --output target/tx-receive
python3 scripts/measure-apple-tunnel.py send --bitrate 3G --output target/tx-paced
```

The harness requires a new output directory and records the actual provider PID
and executable hash. Do not compile, run sanitizers, or export Instruments traces
during an unprofiled performance test.
