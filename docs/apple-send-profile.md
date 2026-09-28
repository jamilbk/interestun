# macOS Network Extension send CPU profile

Captured 2026-09-28 with Instruments 27.0 Time Profiler, attached to the existing
Interestun system extension during TCP iperf3 sends through the AES-256-GCM UDP
tunnel to Windows. The adapter and process were not restarted or rebuilt.

Most sampled CPU is in Network.framework's asynchronous send processing and
dispatch/callback work. Encryption is about 6% of the process's sampled CPU.
The Rust TX worker averages approximately half a core, so this run does not
show that worker continuously consuming a full core.

## Workload and comparison

Same M2 Pro, macOS 27.0 (26A428), MTU 1420, `utun4`, Network.framework UDP,
Windows `192.168.1.226:51820` / `10.20.0.1`, and installed build `1790604265`.
Provider PID 4872 remained unchanged. Its executable SHA-256 was verified as
`3a6caea0bd78e658ae03984daca635d6004e50db53c700aae1f40d925171ac0c`.

Each iperf test measured 30 seconds after a one-second warmup. Profiles captured
25 seconds within the test; analysis uses seconds 2–22 of each trace. This
excludes startup and tail effects. Sampling was the default 1 ms interval with
waiting-thread and context-switch sampling disabled. All selected samples
reported `Running`. CPU percentages below describe the extension process,
including kernel work charged to its sampled threads, not the entire machine.

| Run | Receiver goodput Gbit/s | Extension process CPU cores | New peer drops | TCP retransmissions |
| --- | ---: | ---: | ---: | ---: |
| User stacks | 4.084 | 1.724 | 0 | 707 |
| Unprofiled control | 3.852 | 1.666 | 7 | 790 |
| User + kernel stacks | 3.938 | 1.695 | 0 | 644 |

Transmit-queue drops and interface input/output errors did not increase in
these runs. The seven generic peer drops during the control run were not
attributed to a specific drop site. The previous
[4.816 Gbit/s result](apple-packet-pipeline-audit.md) was not reproduced in
this session. The control run was also slower, so the difference cannot be
assigned solely to profiling overhead. These are sequential desktop runs,
not an isolated throughput ceiling or a controlled profiler-overhead estimate.

## Where the CPU goes

The user-stack run contains 34,034 selected samples, representing 34.034 CPU
seconds over a 20-second window, or 1.702 estimated cores. The kernel-stack
repeat contains 33,355 samples, or 1.668 cores. Their similar distributions
support the attribution below. Process CPU from `ps` uses a longer window and
is independently reported in the table above.

These categories are mutually exclusive; each sampled stack is counted once:

| Work | User-stack CPU share | Kernel-stack repeat |
| --- | ---: | ---: |
| Network.framework asynchronous send service | 47.8% | 48.9% |
| Other framework, dispatch and callback work | 20.1% | 19.4% |
| TX worker reading utun | 12.2% | 11.9% |
| TX worker submitting Network.framework sends | 9.7% | 9.6% |
| Encryption and transport framing | 5.9% | 6.0% |
| Other TX routing, buffers, clocks and polling | 3.2% | 3.2% |
| RX worker handling returning traffic/control | 1.1% | 1.1% |

Thread totals for the first run are approximately 0.527 TX cores, 0.018 RX
cores, and 1.156 cores spread across dispatch workers. Dispatch work migrates
between worker threads; no individual worker thread's identity establishes
the utilization of a particular serial queue.

The classifier in [the analysis script](../scripts/analyze-apple-profile.py)
uses the named peer threads, utun syscall, `in_flow_send`, crypto frames, and
`nw_endpoint_handler_service_writes` ancestry. The remainder is explicitly
retained as other work. This is attribution from sampled call stacks, not
added timing code in the application.

## Specific expensive paths

The following entries overlap with each other and the category table, so they
must not be added together:

- `__channel_sync` ancestry accounts for 16.3% in the first run and 17.8% in
  the kernel-stack repeat. It appears beneath
  `nw_channel_finalize_output_frame` → IPv4/UDP output finalization →
  `nw_flow_service_writes`. This is actual Skywalk channel submission in the
  outer Network.framework path. Samples establish CPU cost, not syscall count
  or the number of datagrams submitted by each call.
- `nw_write_request_list_prune` accounts for about 12.7% inclusively. Its
  completion-reporting path, `nw_write_request_report`, accounts for about
  11.0%, including dispatch-block creation and scheduling. These two
  measurements overlap substantially.
- `nw_flow_copy_write_request` accounts for approximately 8.9% inclusively.
  Send-request bookkeeping and allocation are visible beyond the packet
  payload copy itself.
- The leaf routines `objc_retain` and `objc_release` alone account for 14.0%
  and 14.1% in the two runs. Other retain/release variants, block operations,
  and allocator functions add additional costs. These occur in both send
  submission and asynchronous framework processing.
- `dispatch_data_create` accounts for about 2.0–2.2% inclusively. This is one
  identified allocation/copy site; eliminating that call's cost would not
  eliminate the remaining framework request/completion machinery.
- `ring_core_0_17_14__aes_gcm_enc_kernel` accounts for about 5.3% of CPU.
  The stack reaches ring's AArch64 AES-GCM implementation, confirming that
  this workload actually executes the optimized assembly path. Encryption
  plus transport framing is about 6% in both profiles.

The kernel-enabled capture exposes `copyout` below `recvmsg_x`, as well as
`copyin` and `memcpy` in kernel stacks. Many internal kernel routines remain
unnamed in the shipping symbol set. The kernel UUID matches the installed
`kernel.release.t6020` (`A68631F1-6B54-30AB-89D0-3CF684C5674D`); missing private
symbols are not assigned speculative function names. Copy routine self weights
are preserved in the analysis JSON and include metadata as well as payloads.

## Implications and limits

The clearest next targets are Network.framework send-request/completion
bookkeeping and channel submission. The implementation already calls
`nw_connection_batch`, but its loop still creates a dispatch-data object and
supplies a completion block for each datagram. The measured stacks show that
the framework also processes per-request reporting and lifetime management.
Batch submission therefore has not removed those costs.

The profile identifies CPU consumers. It does not by itself prove which
serial queue, credit limit, scheduler interaction, or remote behavior sets the
throughput ceiling. A queue/scheduling trace or a controlled implementation
experiment would be needed to establish that causal limit. The 250 ms
housekeeping timer is not prominent in the sampled CPU stacks; this does not
constitute a latency measurement of every packet.

## Candidate experiments after this profile

These are options, not measured improvements:

1. Measure actual accepted batch sizes and time blocked on send credits, then
   simplify our Objective-C submission shim. Cache the connection once per
   batch and separate costs in our bridge from framework-internal object work.
   A maximum batch size of 128 does not establish the actual batch distribution.
2. Isolate completion/reporting costs from payload-ownership changes. The public
   idempotent-send marker omits application callbacks, but our bounded send
   credits currently depend on them. The SDK recommends explicit callbacks for
   backpressure-sensitive content. Do not assume the final datagram's callback
   is a documented completion or storage-release fence for preceding datagrams.
   The SDK export list also contains `nw_connection_set_adaptive_write_handler`;
   its ABI and UDP behavior remain unverified, so this is only a private-SPI
   investigation lead.
3. Test larger tunnel packets on a jumbo-capable LAN. A roughly 3900-byte inner
   MTU would reduce packet count per payload byte compared with 1420, while
   remaining below the observed 4096-byte NE slot limit. This requires larger
   Rust/bridge buffers (currently 2048 bytes), changing the current 2000-byte
   configuration limit, and verifying the Windows and physical path MTUs.
4. Experiment with multiple outer UDP connections for one peer to test
   per-connection serialization. This requires distinct flows and coordinated
   Windows endpoint handling, bounded reordering, and correct nonce/replay
   ownership; creating more inner iperf streams is not the same experiment.
5. Investigate direct access to the Ethernet Skywalk data path below the
   Network.framework message layer. It could remove per-message framework
   machinery, but flow registration, entitlements, and supported ownership are
   unresolved. This is separate from the utun ring frontend. No live direct
   channel attachment was attempted during profiling.

The [earlier ownership audit](network-framework-audit.md) already rejected
shared completion blocks, several no-copy ownership designs, and an
ownership-based idempotent-send variant after no compelling sustained win.
Those should not be presented as untouched optimizations or repeated unchanged.
The new profile makes it possible to isolate which costs a new design removes
and which costs it merely moves into asynchronous reclamation.

Apple documents [batch submission](https://developer.apple.com/documentation/network/nw_connection_batch(_:_:))
and the [send/completion contract](https://developer.apple.com/documentation/network/nw_connection_send(_:_:_:_:_:)).
The local SDK's `Network/connection.h` additionally describes the idempotent
marker's missing callbacks and backpressure limitation. Neither contract
provides a general public batch-completion callback for independent datagrams.

## Reproduction and evidence

The profiling attachment succeeded through Instruments. Plain unprivileged
`sample` was denied access to the root-owned extension. No entitlement,
privilege policy, SIP setting, or running application code was changed.

```sh
# Run iperf through the tunnel in another terminal while recording.
iperf3 -c 10.20.0.1 -t 30 -O 1 -J --connect-timeout 3000
# Replace 4872 with the current provider PID.
xcrun xctrace record --template 'Time Profiler' --attach 4872 \
  --time-limit 25s --output send.trace --no-prompt
xcrun xctrace export --input send.trace \
  --xpath '/trace-toc/run[@number="1"]/data/table[@schema="time-profile"]' \
  --output samples.xml
python3 scripts/analyze-apple-profile.py samples.xml --output analysis.json
```

For kernel call stacks, the second recording adds `--recording-options` with
the saved `kernel/recording-options.json`. Both remain at the default sampling
frequency and exclude waiting threads. Reproduce analysis of the saved export:

```sh
python3 scripts/analyze-apple-profile.py \
  docs/benchmarks/macos-apple-send-profile/kernel/samples.xml.gz \
  --output /tmp/interestun-send-profile-analysis.json
```

[Saved artifacts](benchmarks/macos-apple-send-profile/) include compressed XML
samples, table schemas, both analyses, raw iperf/counter/CPU records, exact
binary/dSYM identity, and hashes. The native `.trace` bundles remain under
`target/apple-path/send-profile-20260928/` for opening in Instruments. The
selected build remained connected and healthy after capture.
