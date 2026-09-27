# Architecture and scope

The library is the Rust data-plane/service boundary a future native or Rust GUI
can control. The binary is a minimal foreground service. It follows Firezone's
separation of platform I/O from the cryptographic state machine, without pulling
in its authentication, portal, Tauri UI, or per-direction TUN threads.

| Execution context | Ownership |
| --- | --- |
| Main thread | UAPI clients, configuration, rate-limiter maintenance, worker lifecycle, shutdown |
| Peer worker | One BoringTun, one connected UDP socket after endpoint discovery, timers, queues, encryption/decryption, UDP and utun writes |
| First peer worker, additional work | Shared utun reads, wildcard IPv4/IPv6 UDP reads, outbound prefix routing, first-handshake dispatch |

Workers are created only when a private key is configured. The first worker is
chosen from the stable public-key ordering for each configuration generation.
A single utun has no peer-specific receive queues, so all outbound traffic passes
through this reader. This is an explicit scaling ceiling; adding peer workers
scales crypto and connected UDP receive processing, not shared utun ingress.

Connected UDP sockets use the same local port as the wildcard listeners. Darwin's
exact flow match directs established peer traffic to its worker; new endpoints
and roaming arrive at wildcard listeners. Receiver indices map directly to worker
IDs. Initial handshakes are rate-checked before anonymous static-key decryption.
The target tunnel verifies the packet again; initial wildcard handshakes therefore
consume two rate-limit checks. Public keys are authenticated before an endpoint
is changed. Cipher selection is fixed per interface, with no negotiation.

Queue capacities are 256 packets per inbox / pending-plaintext / output direction.
The shared packet pool allocates 864 buffers per worker, capped at 16384 buffers
(32 MiB of payload storage), with a minimum of 128. RX scratch slots borrow from
that pool. There is a maximum of 4096 configured peers, but practical thread and
memory limits are lower. Queue/pool pressure intentionally drops packets. A
worker processes at most four batches per direction before servicing timers and
other directions, and continues without sleeping when a drain budget was used.
Readiness from kqueue is retained until a syscall returns WouldBlock, including
across fairness-budget boundaries. Idle descriptors are not probed on unrelated
wakeups. Buffer-pool exhaustion retains readiness because no syscall occurred.
Readiness interests enable writable events only while output is pending; after
WouldBlock, writes wait for a writable event. Endpoint replacement resets the
connected socket's readiness state.
Receive buffers deliberately exceed the maximum supported datagram size. Full
buffers are rejected even without MSG_TRUNC: Darwin's legacy recvmsg_x path can
lose that flag during per-message copyout. This was reproduced by the oversized
UDP test on Darwin 27 and checked against XNU's `bsd/kern/uipc_syscalls.c`.

Control clients have five-second deadlines, a 1 MiB request limit, and a 32-client
limit. The main thread uses poll for control sockets only. Signal handlers store
to an atomic; there is no signal handling thread. Secrets are returned only over
the permission-restricted UAPI, as required by `wg showconf`.

## Current limitations

The execution table and Darwin I/O details above describe macOS. Windows uses
the same peer crypto/routing logic, one additional Wintun reader, shared exclusive
UDP listeners, and named-pipe control. See [Windows backend](windows.md) for the
threading, backpressure, control ownership, and validation differences.

- `wg set`, `setconf`, and `syncconf` validate a complete proposed configuration,
  then stop/join/rebuild all workers. This briefly interrupts traffic and resets
  sessions/counters. Resource-setup failures attempt to restart the old config;
  if restoration also fails the daemon exits. Incremental, session-preserving
  reconfiguration is future work.
- UAPI statistics are snapshots updated at most every 250 ms. Drop counters are
  internal diagnostics, not yet a stable metrics interface.
- Each peer requires a distinct configured UDP endpoint tuple. Multiple peers
  sharing exactly the same remote IP/port are not supported by this initial
  connected-socket ownership design. Standard peers with unknown endpoints and
  authenticated endpoint roaming are supported.
- No PMTU discovery, route/DNS management, privilege separation, daemonization,
  launchd/Windows service packaging, Network Extension integration, or GUI yet.
- utun and UDP batching uses private Darwin symbols, with symbol-absence fallback.
  The real utun path passed IPv4/IPv6 UDP echo and burst testing with two peers
  and both ciphers on Darwin 27.0.0. Other supported macOS releases, Network
  Extension entitlements, and broader end-to-end performance still need validation.
- AES is an experimental protocol extension using ring's AES-256-GCM transport.
  Handshake encryption remains ChaCha20-Poly1305, cookies use XChaCha20, and the
  suite-specific initial transcript separates keys/protocols. No custom AES
  implementation or assembly has been introduced. It needs independent protocol
  review before production use.

## Next performance experiments

The first two-host TCP measurements are recorded in [performance](performance.md).
Measure loss and CPU per packet, sweep
batch sizes and peer counts, then profile the dispatcher, packet-pool contention,
queue wakeups, encryption, kernel socket locks, and utun injection independently.
Connected flow sockets and utun writes still contend on kernel resources.
A per-worker recycle cache could reduce shared-pool atomics; reconfiguration could
hand ownership between peer workers without rekeying. Neither improvement should
be claimed until benchmarked under the same packet/byte accounting.
