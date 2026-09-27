# macOS send-path investigation

2026-09-27, M2 Pro, AES-256-GCM, MTU 1420, batch capacity 128, utun pending
limit 1024. Windows peer and the 10 GbE path were unchanged. Rates below are
receiver application payload rates, not encrypted wire rates.

## Preallocation

Payload buffers and queue capacity were already preallocated. Receive and send
now also retain their descriptor/iovec/address-family scratch storage per I/O
thread. Receive address storage is initialized once. Active descriptors are
refreshed before each call, including source-address capacity, lengths, flags,
and pointers to the current pooled payloads. Unused array entries no longer
need to be zeroed on every syscall. This does not preallocate XNU mbufs or
remove kernel copies. Regression coverage reuses descriptors across shrinking
and growing batches, truncation, and utun/UDP mode changes.

## Traffic and CPU probes

Each case ran ten measured seconds after two seconds warmup. These are single
sequential diagnostic samples, not a controlled A/B comparison.

| Case | Receiver Gbit/s | UDP loss |
| --- | ---: | ---: |
| Existing build, tunnel TCP, one stream | 2.075 | — |
| Existing build, tunnel TCP, four streams | 1.983 | — |
| Direct LAN TCP, one stream | 9.407 | — |
| Existing build, tunnel UDP, offered 3 Gbit/s | 2.988 | 0.415% |
| Reused descriptors, tunnel TCP, one stream | 2.072 | — |
| Reused descriptors, tunnel UDP, offered 3 Gbit/s | 2.987 | 0.436% |

UDP used 1360-byte application datagrams. Its result demonstrates a working
path above 2 Gbit/s; it does not establish a loss-free ceiling. Four TCP streams
did not lift the TCP plateau. Preallocation did not produce a clear throughput
improvement in these samples.

`ps -M` cumulative thread CPU times bracketed each entire test, including warmup
and process-wait overhead. In the original single-stream TCP case, TX consumed
7.34 seconds system + 1.27 seconds user CPU over 12.09 seconds elapsed: about
71% of one core, with 85% of its CPU time in the kernel. RX consumed about 22%
of a core. With 3 Gbit/s UDP, TX consumed 10.37 + 1.55 CPU seconds over 12.11
elapsed, about 98% of a core; 87% of its CPU time was kernel time. The iperf UDP
sender was also near one core, so it can itself limit higher offered rates.
The CPU percentages reported by iperf describe iperf, not the tunnel daemons.

[Throughput](benchmarks/macos-bottleneck-throughput.csv),
[thread CPU deltas](benchmarks/macos-bottleneck-cpu.csv),
[environment](benchmarks/macos-bottleneck-environment.json).
In these artifacts, `bottleneck` is commit `61a51ad` with `io-metrics`;
`preallocated` adds descriptor reuse; `profile` also enables sampled timing.
Thread roles in the `ps` data are inferred from main/TX/RX creation order.

## Sampled attribution

The optional `io-profile` feature samples one in 64 calls using wall time and
`CLOCK_THREAD_CPUTIME_ID`. Normal builds compile out the timing and TLS state.
`io-profile` implies `io-metrics`; it emits per-thread five-second stage rows.

```sh
CARGO_TARGET_DIR=target cargo build --release --locked --features io-profile
```

For a five-second window entirely inside the 3 Gbit/s UDP run, scaling each
stage's sampled CPU time by `calls / samples` gives these approximate fractions
of one core:

| TX stage | Approximate core use |
| --- | ---: |
| UDP send syscall | 73% |
| utun receive syscall | 15% |
| Encryption batch, including framing and queue bookkeeping | 9% |
| Receive descriptor setup | 1.1% |
| Send descriptor setup | 0.5% |

In a TCP window, the corresponding UDP-send, utun-read, and encryption estimates
were about 47%, 12%, and 6.5% of one core. UDP send calls averaged about 33 µs
CPU time each in that TCP window. Sampled syscall wall time was close to CPU
time; these samples do not show substantial time blocked inside those calls.

Clock probes add overhead, especially to short setup spans. Periodic sampling
can be biased. Pool refill/recycling, routing, polling, activity handoff, and
work on other kernel threads are not separately attributed. Stage estimates
are not exact totals or instruction-level profiles.
[Raw sampled stages](benchmarks/macos-bottleneck-stages.csv).

## What this establishes

The dominant measured Mac TX cost is inside UDP sending, not AES or userspace
allocation. Raw crypto measured seal/open in memory and omitted this kernel
path. The [XNU audit](xnu-performance-audit.md) describes remaining per-packet
allocation/copy and UDP/IP dispatch even with connected batch sends.

This does not prove what limits TCP to roughly 2 Gbit/s: the Mac TX thread is
not CPU-saturated during that TCP test, and UDP has less reverse ACK work.
Distinguishing socket processing, TCP/ACK behavior, and Windows receive/injection
requires endpoint profiling. Kernel stacks are needed to separate allocation,
routing/filtering, and driver cost within the expensive Mac UDP-send syscall.
Increasing userspace preallocation alone does not address that kernel work.
