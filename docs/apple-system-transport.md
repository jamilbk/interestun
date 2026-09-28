# System Trace and production transport control, 2026-09-28

This investigation separates the current macOS/Windows tunnel result from a
claim about an architectural XNU UDP limit. One Windows peer, one outer UDP
connection, MTU 1420, AES256-GCM, and the existing en8 10 GbE path are retained.
No jumbo frames or additional data connections are used.

## System Trace

A 25-second System Trace attached to provider PID 15142 during a 30-second
single-stream TCP send through the UDP tunnel. The running provider was built
from `4fbc148`, version 1790616930, SHA-256
`99b419b79beacb735acd6f73d7e91389576febbb10dade0a60016bc8506a4671`.

The traced test delivered 3.389 Gbps at 1.662 process CPU cores, with 643 TCP
retransmits, 8 peer drops, and no TX queue drops. Profiling changes throughput;
this is not an unprofiled maximum. The 1024-credit window was full for just six
retry episodes totaling 0.810 ms across the full test; mean application batch
was 95.70 packets.

Within trace seconds 2–22, scheduling intervals give:

| Thread group | Running CPU seconds | Average cores |
| --- | ---: | ---: |
| Rust peer TX | 9.378 | 0.469 |
| Rust peer RX | 0.430 | 0.022 |
| Remaining provider threads, principally framework/dispatch | 23.099 | 1.155 |
| Total | 32.907 | 1.645 |

The TX thread was blocked for 9.774 seconds, runnable for 0.079 seconds,
preempted for 0.650 seconds, and interrupted for 0.120 seconds. Most running
time was on cores Instruments labels S Core, not E Core. Neither the TX worker
nor the RX worker was saturated at one CPU core. Dispatch workers migrate and
can service multiple queues; adding their CPU time does not prove that a
particular serial queue was continuously busy.

The same 20-second window contains these actual syscall counts:

- 217,432 `channel_sync` calls from `nw_channel_finalize_output_frame`.
- 41,872 other `channel_sync` calls from input processing, 259,304 total.
- 235,633 `kevent_id` calls from write-completion reporting/event-loop pokes.
- 318,112 `kevent_id` calls and 284,765 `workq_kernreturn` calls overall.
- 71,005 `recvmsg_x` calls on the TX worker, including 7,139 EAGAIN returns;
  the successful reads returned 6,186,803 messages.

This proves significant framework scheduling and channel-sync activity despite
application-level batching. It does not imply one `channel_sync` per packet,
one syscall per application batch, or that all syscall elapsed time is kernel
CPU time. The output-sync stack is the Network.framework userspace UDP path;
the `recvmsg_x` calls are utun reads.

The export has two limitations. In 345,728 syscall rows, modeled CPU/wait time
exceeds the syscall wall interval. Those fields are retained for auditing but
are not used as CPU cost estimates. Also, this Xcode's compound XPath export
appended thread-state rows under the syscall schema. The analyzer explicitly
rejects this unless `--skip-foreign-rows` is supplied; scheduling uses a separate
thread-state export. Known-answer tests cover reference resolution, interval
clipping, and this schema mismatch.

## Transport control

The standalone benchmark now uses exactly the production Network.framework
bridge and readiness code. Its former independent Objective-C stub has been
removed. Raw mode bypasses utun and crypto, reuses packet storage, and sends
1452-byte UDP payloads in application batches of 128 with 1024 send credits.

A minimal iperf3 control client lets that bridge use the existing Windows
iperf3 UDP receiver. No SSH deployment is needed for these measurements. TCP
carries control metadata only. JSON records received bytes and sequence gaps,
not just local send completions. A 4 MiB receive-buffer request eliminated loss
in a low-rate 128-packet burst check (169 of 896 packets missing with the
receiver default, zero missing after the larger buffer request). This is a
short diagnostic, not a receiver capacity benchmark.

The Windows iperf3 build returns zero CPU utilization fields, so they cannot
be used to claim Windows is idle. Received-packet counts come from bytes divided
by datagram size. The server's `packets` field is a highest sequence number;
its `errors` count alone misses a lost tail.

See [benchmark instructions](network-framework-benchmark.md) for setup, timing,
tail settlement, and interpretation of accepted versus received rates.

## Controlled results and rejected refill change

Each row is a sequential, unprofiled 30-second raw UDP send through the
production bridge to Windows. Received rates here use the sender's active
interval so every row shares the same denominator. JSON also preserves the
receiver's longer interval (including the 100 ms tail settlement), which gives
about 0.3% lower rates. The first unrestricted run predates tail settlement;
its 101 missing final packets should not be interpreted as sustained loss.

| Control | Accepted Gbps | Received Gbps | Missing % | Mac CPU cores | Mean send batch |
| --- | ---: | ---: | ---: | ---: | ---: |
| 3 Gbps offered | 3.000 | 3.000 | 0.0000% | 0.865 | 128.00 |
| 4 Gbps offered | 4.000 | 4.000 | 0.0000% | 1.441 | 8.69 |
| 5 Gbps offered | 4.018 | 4.018 | 0.0000% | 1.450 | 8.96 |
| Unlimited, first | 4.094 | 4.094 | 0.0010% | 1.456 | 8.76 |
| Unlimited, repeat | 4.046 | 4.046 | 0.0000% | 1.441 | 9.41 |
| 128-credit refill experiment | 3.680 | 3.680 | 0.0000% | 1.346 | 45.26 |
| Unlimited, final baseline | 4.179 | 3.825 | 8.4879% | 1.435 | 9.40 |

At 3 Gbps, batches stayed at 128 and the send-credit limit was never reached.
The unrestricted producer repeatedly filled the 1024-credit window, leading to
roughly nine-packet accepted prefixes and hundreds of thousands of readiness
waits. This differs materially from the tunnel, where credit stalls were rare
and batches averaged about 96. The raw test is therefore a useful overdrive
control, not a clean measurement of Network.framework's absolute capacity.

As a controlled experiment, the callback wake threshold was changed from one
free credit to 128 free credits. It reduced readiness waits from roughly
350,000–400,000 to 56,193 per 30 seconds and increased mean batches to 45.26.
But received throughput fell to 3.680 Gbps. The change was rejected and reverted;
it is saved as a patch alongside its result, not deployed to the provider.

The final baseline repeat accepted 4.179 Gbps but delivered only 3.825 Gbps.
Windows reported substantial sequence gaps throughout that run (8.49% missing
by byte count), rather than merely a missing tail. Prior runs delivered about
4 Gbps without measured loss. These results do not locate the later drops in
the Mac, NIC/link, or Windows. Windows-side tracing is still needed for that
attribution; no trusted SSH connection was configured during this session.

A fresh unprofiled full-tunnel TCP send then delivered **3.518 Gbps at 1.676 Mac
CPU cores**, with 603 TCP retransmits, zero peer/TX queue drops, a mean send
batch of 96.04, and only 0.730 ms of full-credit retry time across the test.
The provider remained on the validated `4fbc148` implementation throughout.

These results support investigation of Network.framework's per-message work,
completion scheduling, and actual channel batching. They do **not** establish a
5 Gbps XNU-wide UDP ceiling, nor eliminate Windows/driver effects. The simple
refill experiment already demonstrates that fewer wakeups/larger application
batches do not automatically yield higher delivered throughput.

## Standalone sender path and CPU profile

A separate 20-second raw send with 15 seconds of Time Profiler attached confirms
that the standalone bridge also takes the Network.framework channel path. This
profile is saved separately from the unprofiled capacity controls above.
It delivered 4.035 Gbps with zero measured loss; this further demonstrates that
the preceding lossy baseline was not a consistent loss rate for the transport.
Within profile seconds 2–12, there were 14,484 running samples (1.448 estimated
cores). One framework worker alone accounts for 0.956 cores; stacks containing
`nw_endpoint_handler_service_writes` account for 0.909 cores. The Rust main
thread accounts for 0.245 cores. This is evidence of a nearly saturated
framework worker in this run, not of all macOS CPUs or all UDP APIs saturating.

`objc_retain`/`objc_release` together take 21.75% of sampled CPU as leaf frames;
`__channel_sync` takes 20.63%. The latter is a userspace syscall boundary, so it
includes work below that boundary without resolving individual kernel frames.
Inclusive, overlapping costs include write-request pruning (18.95%), completion
reporting (15.67%), and copying write-request metadata (12.98%). These percentages
must not be added together. `dispatch_data_create` accounts for 2.82% inclusive;
that includes allocation/ownership work, not only payload copying. The generic
analyzer's "Other framework" category includes the benchmark main thread; use
its per-thread and named-frame tables for these conclusions.

The immediate Mac-side lead is per-datagram framework request management,
channel synchronization, and completion scheduling. A kernel-wide 5 Gbps ceiling
would be a much broader claim than these measurements support.

## Validation

Production-bridge finite datagram tests passed for raw/AES/ChaCha, packet sizes
20/1420, and batches 1/128. The real local iperf3 protocol check verifies exact
receiver bytes and clean teardown. Native ownership/backpressure tests passed
for both public and private receive paths, including ThreadSanitizer. The 39
Rust library tests, all-target/all-feature Clippy, formatting, and trace-analyzer
known-answer tests passed. No mapped utun attachment was attempted.

## Reproduce the trace

```sh
xcrun xctrace record --template 'System Trace' --attach PID --time-limit 25s --output tunnel-send.trace --no-prompt
python3 scripts/measure-apple-tunnel.py send --output tunnel-send
xcrun xctrace export --input tunnel-send.trace --xpath '/trace-toc/run[@number="1"]/data/table[@schema="syscall"]' --output syscalls.xml
xcrun xctrace export --input tunnel-send.trace --xpath '/trace-toc/run[@number="1"]/data/table[@schema="thread-state"]' --output thread-states.xml
python3 scripts/analyze-apple-system-trace.py syscalls.xml --output syscall-analysis.json
python3 scripts/analyze-apple-system-trace.py thread-states.xml --output thread-state-analysis.json
python3 tests/test_apple_system_trace.py
```

Start the recording and tunnel test concurrently. Export/analyze only after the
measurement. The raw trace and XML remain locally under
`target/apple-path/system-transport-20260928/`; compact results and analyses are
saved under `docs/benchmarks/macos-system-transport/`. The raw recording is about
8 GiB and is intentionally not checked into Git.
