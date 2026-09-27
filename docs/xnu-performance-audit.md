# macOS XNU dataplane audit

Audited public XNU revision `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` on 2026-09-27. The test
machine runs Darwin 27 / `xnu-13432.1.9~1`, Apple M2 Pro. This public
snapshot is not established to match the running kernel exactly. Socket-option
readback and observed batch counters validate the pending-limit change locally;
other source findings identify experiments, not measured bottleneck attribution.

## Findings

| Area | Source finding | Consequence for interestun |
| --- | --- | --- |
| utun output flow control | The pending-packet default is one; output pauses at the limit and resumes as reads drain the control socket. [utun initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L1833), [flow control](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L2807) | Set and read back 128. Implemented; this enables useful batches without changing the peer-thread model. |
| utun byte capacity | utun registers 512 KiB send and receive buffers. [control registration](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L1648) | Generic kernel-control buffer defaults do not apply. 128 MTU-1420 packets occupy about 182 KiB before mbuf overhead. Measure occupancy/drops before increasing byte limits. |
| Connected UDP | Connected datagram sockets select the list-send path. Each message still gets a kernel packet allocation and a payload copy. [send conversion](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_syscalls.c#L1713), [path selection](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_syscalls.c#L1895) | Keep connected peer sockets and in-place userspace crypto. Batching does not remove the kernel copy. |
| UDP protocol processing | UDP registers a per-packet send callback; socket list-send falls back to invoking that callback for each message. [IPv4 callbacks](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/udp_usrreq.c#L232), [IPv6 callbacks](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet6/udp6_usrreq.c#L194), [list dispatch](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_socket.c#L2736) | Larger batches amortize syscall/setup work, but UDP/IP processing remains per datagram. |
| utun injection | utun registers a single-packet callback. Kernel-control list-send invokes it once per message, unlocking/relocking the socket each time. [registration](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L1648), [callback loop](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_control.c#L869) | A larger injection batch cannot eliminate this callback/lock work through the BSD API. |
| Receive path | Default receive uses `soreceive_m_list`; enabling `SO_DONTTRUNC` selects an alternative that calls protocol receive per slot. [receive selection](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_syscalls.c#L2700), [alternative receive](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_syscalls.c#L2581) | Do not enable this flag as a batching optimization. Preserve current truncation checks. |
| Channel backend | utun exposes a channel path with a Skywalk kernel-pipe privilege check. [channel setup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c#L1539) | Investigate as a separate backend prototype only after verifying access on deployment targets. It is not a drop-in socket tuning option. |

Read-only runtime checks: `kern.ipc.maxsendmsgx=256`,
`kern.ipc.maxrecvmsgx=256`, `kern.ipc.sendmsg_x_mode=0`,
`kern.ipc.do_recvmsg_x_donttrunc=0`, and `kern.ipc.maxsockbuf=8388608`.
No global sysctls were changed. Current userspace batch capacity remains 32;
128 is the utun pending-packet limit, not the syscall batch size.

## Measured effect of pending limit 128

One TCP stream between macOS and Windows over AES-256-GCM, MTU 1420, on the
existing 10 GbE LAN. Three alternating samples per direction; each sample has
one second warmup and five measured seconds. The daemon includes `io-metrics`.

| Direction | Samples, Gbit/s | Median, Gbit/s |
| --- | --- | ---: |
| Mac → Windows | 2.006, 2.014, 2.027 | 2.014 |
| Windows → Mac | 2.534, 2.565, 2.557 | 2.557 |

The preceding pending-limit-one diagnostic run measured 1.13 Gbit/s send and
2.30 Gbit/s receive, with a different duration (10 seconds plus two seconds
warmup). These are sequential desktop observations, not an interleaved A/B test.
They support a substantial send improvement, not a precise causal percentage.

A send-heavy five-second counter interval completed 881,966 UDP messages in
66,938 send calls: **13.18 messages/call**, versus about **1.09** previously.
Utun received 881,964 packets in 186,387 calls, including 58,671 WouldBlock
returns: **6.91 packets/successful call**, versus one previously. Counter
windows are not synchronized with iperf measurement windows; UDP aggregates
connected and wildcard sockets. These counters do not measure delivery or loss.

Raw throughput samples: [CSV](benchmarks/macos-utun-pending128.csv).
Correctness validation: real-utun IPv4/IPv6 tests with both cipher suites,
all-target/all-feature clippy, and release build. Every utun open now verifies
that the kernel accepted the requested limit.

## Next experiments, in order

1. Sweep syscall batch capacity 32/64/128 with pending limit fixed at 128.
   Interleave repeated runs in both directions; measure CPU, actual batch fill,
   retransmits, and latency under load. Keep fairness budgets in packets so a
   larger batch does not silently multiply work per peer scheduling round.
   Include multiple peers and sparse handshake/keepalive traffic.
2. Attribute remaining userspace overhead: descriptor preparation and buffer
   pool synchronization. Test reusable per-worker descriptor storage and local
   recycling only if profiles show material cost. Preserve existing in-place
   buffer ownership and bounded queues.
3. Read back utun byte buffers and inspect backpressure before tuning capacity.
   Keep receive low-water thresholds low: delaying readiness to fill batches
   needs an explicit latency bound for sparse traffic.
4. Investigate channel availability and ownership semantics before committing
   to a new backend. Source support alone does not establish usable privileges,
   zero-copy operation, or a throughput benefit on this machine.
