# Architecture and scope

The library is the Rust data-plane/service boundary a future native or Rust GUI
can control. The binary is a minimal foreground service. It follows Firezone's
separation of platform I/O from the cryptographic state machine, without pulling
in its authentication, portal, or Tauri UI.

| Execution context | Ownership |
| --- | --- |
| Main thread | UAPI clients, configuration, rate-limiter maintenance, worker lifecycle, shutdown |
| Peer send thread | Exclusive transmit key/counter, encryption, connected UDP batch writes, outbound queues |
| Peer receive thread | BoringTun handshake/session lifecycle, receive keys/replay, timers, UDP reads, decryption, utun injection |
| Peer 0 send thread, additional work | Shared utun reads and outbound prefix dispatch |
| Peer 0 receive thread, additional work | Wildcard IPv4/IPv6 UDP reads and first-handshake dispatch |

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
The shared packet pool allocates 1664 buffers per peer, capped at 16384 buffers
(32 MiB of payload storage), with a minimum of 384. RX scratch slots borrow from
that pool. There is a maximum of 4096 configured peers, but practical thread and
memory limits are lower. Queue/pool pressure intentionally drops packets. A
direction worker reads/encrypts/flushes in 128-packet batches, retaining readiness
between batches. Send and receive no longer alternate on one worker. Bounded
queues, flushing between batches, and control checks still prevent unbounded
work and starvation of handshakes or shutdown. A congested peer cannot stop the
shared utun reader from dispatching packets to other peers.
The utun pending-packet limit is set to 1024 and verified with getsockopt at
startup. Darwin's default of one pending packet prevents effective receive
batching under load; this limit allows eight batches of 128.
Readiness from kqueue is retained until a syscall returns WouldBlock, including
across fairness-budget boundaries. Idle descriptors are not probed on unrelated
wakeups. Buffer-pool exhaustion retains readiness because no syscall occurred.
After WouldBlock, writable interest is enabled and writes wait for a writable
event. Endpoint replacement resets the
connected socket's readiness state.
Receive buffers deliberately exceed the maximum supported datagram size. Full
buffers are rejected even without MSG_TRUNC: Darwin's legacy recvmsg_x path can
lose that flag during per-message copyout. This was reproduced by the oversized
UDP test on Darwin 27 and checked against XNU's `bsd/kern/uipc_syscalls.c`.

Transport data uses one packet allocation through receive, encryption/decryption,
and batched output. macOS utun receives at offset 16, leaving transport-header
space; the 16-byte tag fits after the maximum 2000-byte IP packet in the existing
2048-byte buffer. Descriptor, iovec, address-family, and source-address scratch
storage is allocated once per I/O context and reused across batches. Active
metadata is reset before each call. UDP receives at offset zero; authenticated decryption exposes
the plaintext at offset 16 without moving it. Packet ownership transfers between
workers unchanged. Handshake output still needs a separate buffer. Wintun's
reader copies directly from the ring into the pooled packet at offset 16, leaving
space for the header and authentication tag; UDP receives directly into the same
pool at offset zero. Windows retains socket readiness until WouldBlock and keeps
processing after a fairness budget is exhausted. Buffer recycling remains shared/atomic.

The fork exports a non-cloneable `TransportSender`: key and nonce ownership move
out of the receive/control tunnel after session promotion. The initial handshake
confirmation is encrypted before that handoff, so the moved counter continues
at the next nonce. Regular timer keepalives are forwarded to the send owner.
Session destruction revokes detached handles atomically; handles also enforce
lifetime and message limits without depending on the receive thread's timer
schedule. Idle send owners check validity at least every 250 ms and drop invalid
handles. A packet already being encrypted can finish during revocation.

Unauthenticated cookie replies are sent directly by receive workers on wildcard
sockets; authenticated control output is handed to the send worker.

Cipher operations do not acquire a shared tunnel mutex. Send activity is merged
once per batch under a short metadata mutex and consumed by the receive owner
before timer updates (at most 250 ms while idle). First/last send timestamps
bound the no-response timer conservatively within a batch; delayed reports do
not regress receive timestamps. Session/socket changes use a separate control
mailbox; key ownership changes cannot be dropped because a packet inbox is full.

With multiple peers, only shared-utun batch writes use an interface mutex.
Concurrent nonblocking `sendmsg_x` calls on one socket reproduced silent loss
in the duplex test; XNU's send-lock/error-count path explains the observation.
Single-peer injection avoids this mutex. See the [XNU audit](xnu-performance-audit.md).
Windows uses the same split ownership in `runtime_windows.rs`, with one additional
Wintun reader. Its receive workers coalesce compatible authenticated TCP packets
before adapter injection; Wintun's thread-safe ring API needs no XNU write mutex.

Control clients have five-second deadlines, a 1 MiB request limit, and a 32-client
limit. The main thread uses poll for control sockets only. Signal handlers store
to an atomic; there is no signal handling thread. Secrets are returned only over
the permission-restricted UAPI, as required by `wg showconf`.

## Current limitations

The execution table's Darwin I/O details above describe macOS. Windows also has
independent send/receive workers, but uses one additional Wintun reader, shared
exclusive UDP listeners, and named-pipe control. See [Windows backend](windows.md) for the
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

The macOS experiment selects the [UDP backend at build time](apple-udp-backends.md).
Network.framework is now the default and uses no BSD UDP listeners. It retains
BoringTun's TX/RX ownership, with bounded callback staging and notification
descriptors. It currently requires configured peer endpoints; the discovery and
roaming behavior described above applies to the BSD comparison build.

The first two-host TCP measurements are recorded in [performance](performance.md).
Measure loss and CPU per packet, sweep
batch sizes and peer counts, then profile the dispatcher, packet-pool contention,
queue wakeups, encryption, kernel socket locks, and utun injection independently.
Connected flow sockets and utun writes still contend on kernel resources.
A per-worker recycle cache could reduce shared-pool atomics; reconfiguration could
hand ownership between peer workers without rekeying. Neither improvement should
be claimed until benchmarked under the same packet/byte accounting.
