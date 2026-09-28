# Network.framework callback and ownership audit

On 2026-09-27, replacing individual receive requests with grouped framework reads
and removing the receive-ring mutex reduced daemon receive CPU by about 30% at
similar tunnel throughput. The no-copy send experiments did not improve sustained
throughput enough to retain. The selected implementation still copies outgoing
payloads into owned dispatch data and incoming immutable payloads into writable
Rust packet storage.

This is an audit of the relevant public SDK APIs, exported private entry points,
Apple's open-source libdispatch, and the installed Network.framework implementation.
Network.framework itself is not open source. We did not audit its entire source
or establish a universal macOS throughput ceiling.

## Selected implementation

The default experimental feature `apple-network-multiple` enables
`nw_connection_receive_multiple`. This is **private Apple SPI**, not declared by
the public Network headers. The ABI and behavior below were checked against
macOS 27.0 build 26A428 on Apple M2 Pro using the SDK export list, LLDB inspection
of the loaded Apple implementation, and an unprivileged UDP correctness fixture:

```c
void receive_multiple(nw_connection_t connection,
                      uint32_t minimum_messages,
                      uint32_t maximum_messages,
                      nw_connection_receive_completion_t completion);
```

The installed implementation collects a group of messages for one internal read,
then invokes the application block inline for each message in the group. Its
boolean argument is **last in group**, not the public API's message-completeness
flag. Thus there are still per-datagram block invocations, but no separate
application receive request, group publication, or worker signal for each one.
The installed implementation caps the maximum at 256. We request a minimum of
one and maximum of 256, reduced to available ring capacity. No timer or minimum
full-batch requirement delays a lone handshake or transport packet.

Each flow keeps one outstanding group request. The callback queue reserves space
in the 1024-slot ring, retains immutable datagram references, and publishes the
completed group with one release store and one worker signal. A single Rust
consumer acquires the published cursor, transfers up to 128 references to local
storage, releases the slots, and copies into cached writable packet buffers.
The consumer's once-per-call guard enforces the SPSC contract even through the
safe `Sync` socket API. Producer/consumer cursors are separated by at least an
Apple M2 cache line. Connection and callback queue properties are immutable after
setup and no longer use atomic Objective-C property accessors.

A full ring stops receive posting. Draining it requests a refill. Reservation is
cleared before publication so a consumer acquiring the new group can observe
that it may need to request another read. Cancellation releases both published
messages and any retained messages in an unfinished group. Existing send credits,
partial-send handling, async error reporting, AES authentication, replay checks,
and worker readiness semantics remain in place. Utun batches remain 128;
pending packet limits remain 1024, with a separate 4 MiB utun byte buffer.

The startup log identifies the receive mode. Missing SPI fails with `ENOTSUP`;
there is no silent switch to a different UDP backend. Symbol availability alone
does **not** establish ABI compatibility with another macOS release. Before using
this private mode on another OS build, run the host ABI fixture and tunnel tests.
For the public API implementation, rebuild:

```sh
cargo build --release --locked --no-default-features --features apple-network,apple-coalesce
```

Both choices use Network.framework. Only an explicit build without
`apple-network` selects the older BSD backend. Private SPI is unsuitable for
software requiring a supported Apple API contract or App Store distribution.

## What the other APIs actually provide

| Candidate | Finding and decision |
| --- | --- |
| `nw_connection_batch` | Already used for TX. Groups submissions; it does not promise one completion or one kernel call. Public RX still completes each receive request separately. |
| `nw_connection_receive_message` | Public, one completion per request. Kept as a build-time alternative, now using the SPSC ring. |
| `dispatch_data_create(...DEFAULT)` | Copies the payload. Safe when Rust recycles its packet immediately after the bridge returns. |
| Custom dispatch-data destructor | Can retain Rust buffers without copying, but custom destruction is dispatched asynchronously. Returning pooled ownership added queue work in the tested designs. |
| `DISPATCH_DATA_DESTRUCTOR_FREE` | Avoids the custom destructor dispatch; requires ownership of a compatible allocation. Direct per-packet allocation transfer reduced send throughput in this experiment. |
| Idempotent send completion marker | Removes application content-processed callbacks but permits replay and loses those per-message errors. Ownership-based credit accounting was still required; no compelling throughput gain. Rejected. |
| Private `nw_connection_write_multiple` | The installed implementation wraps `nw_connection_batch`, individual sends, and dispatch-group enter/leave/completion bookkeeping. It does not eliminate the underlying per-message completion work. Not adopted. |
| Private connection read-buffer entry points | Inspection of the installed callback path still found dispatch-data copy-out machinery. No supported guarantee of writable, zero-copy datagrams. Not adopted. |
| `NWProtocolFramer` / no-copy operations | Useful protocol composition primitives, but parser storage has callback-scoped ownership. A local prototype received one input invocation per UDP datagram; it did not establish a batch or ownership advantage. |
| IPv4 `preferNoChecksum` | Public option, but the [earlier sweep](native-worker-performance.md) nearly stalled tunnel data with it. The failure location remains unresolved. Normal checksums stay enabled; no retest was needed for this receive-only change. |
| Dispatch/worker QoS | Higher priorities were already screened in the earlier sweep without a throughput improvement worth keeping. |
| Private buffering/path-selection flags | Exported names such as `reduce_buffering` and `no_fullstack_fallback` are not supported performance guarantees. Not enabled without validating their behavior and selected path. |
| Connection groups / Ethernet channels | Multicast or multiplexed flows and raw L2 access solve different problems; they are not a drop-in connected UDP optimization for this tunnel. |

The public receive data contract is immutable. Casting away const and decrypting
inside its storage would violate that contract. A future out-of-place AEAD API
could combine movement with decryption into owned output, but that requires a
separate measured BoringTun/ring change. This work makes no crypto changes.
Likewise, kernel zero-copy is not implied by removing an application `memcpy`.

Public API references: Apple's [batch](https://developer.apple.com/documentation/network/nw_connection_batch(_:_:)),
[message receive](https://developer.apple.com/documentation/network/nw_connection_receive_message(_:_:)),
[send](https://developer.apple.com/documentation/network/nw_connection_send(_:_:_:_:_:)),
[IPv4 checksum preference](https://developer.apple.com/documentation/network/nwprotocoludp/options/prefernochecksum),
and [framer](https://developer.apple.com/documentation/network/framer-protocol-options)
documentation. Ownership and destruction behavior were also checked in
[Apple's libdispatch data implementation](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/data.c).
Private SPI findings above come from this host's installed implementation, not
those public documents.

## Measurements

All performance measurements used TCP iperf3 **inside the AES-256-GCM UDP tunnel**
to the existing Windows peer: Mac 192.168.1.211 / 10.20.0.2, Windows
192.168.1.226:51820 / 10.20.0.1, en8 10 GbE, MTU 1420. No local-utun throughput
results are used. One stream unless labeled otherwise. Measurements use
`-O 1`, with either 10 or 30 measured seconds. Daemon CPU is sampled from process
CPU time; 1.0 core means 100% of one core, not the whole system. It excludes the
iperf processes and work charged elsewhere. Commands and CPU samples are in
[the experiment record](benchmarks/network-framework-audit/experiments.json).

An interleaved 30-second candidate/baseline comparison gave:

| Binary | Mac send Gbit/s | Send cores | Mac receive Gbit/s | Receive cores |
| --- | ---: | ---: | ---: | ---: |
| Original `630e9dc` repeated | 4.303 | 1.750 | 2.726 | 1.570 |
| Grouped receive, 256 repeated | 4.317 | 1.745 | 2.736 | 1.109 |

That is about 29% less daemon CPU at essentially the same receive throughput.
The initial original-binary sample received 2.479 Gbit/s at 1.491 cores, while
later originals reached 2.726. Comparing only the initial original with the later
candidate would overstate the throughput improvement. These are short sequential
LAN experiments, not a randomized confidence-interval study.

One candidate 30-second send measured 2.913 Gbit/s: its first eight measured
seconds ran at only 26–84 Mbit/s, followed by approximately 4 Gbit/s. The cause
was not established; it is retained in the data rather than discarded. A repeat
of the same binary sent 4.317 Gbit/s. Duplex results also varied, and do not
establish a stable bidirectional improvement.

The final release (with feature isolation and cancellation/refill fixes) was then
measured for 30 seconds per case:

| Traffic | Send Gbit/s | Receive Gbit/s | Daemon cores |
| --- | ---: | ---: | ---: |
| Single-stream send | 4.364 | — | 1.753 |
| Single-stream receive | — | 2.713 | 1.064 |
| Four-stream send | 3.784 | — | 1.792 |
| Four-stream receive | — | 2.326 | 0.921 |
| Simultaneous bidirectional | 3.177 | 1.210 | 1.696 |

The extra streams did not improve throughput. This binary was left running on
the configured Windows tunnel. These results support keeping the CPU reduction,
not claiming a new absolute throughput maximum.

### Exploratory variants

Each row below is one 10-second send/receive pair unless marked 30 seconds.
These are screening results, not isolated attribution or proof that every
ownership-transfer design is slower. Several variants inherit earlier changes.

| Variant | Send Gbit/s | Receive Gbit/s | Receive cores | Decision |
| --- | ---: | ---: | ---: | --- |
| Shared send completion block / batch credit return | 3.683 | 2.470 | 1.534 | Rejected |
| Stage public receive callbacks, publish together | 4.151 | 2.407 | 1.731 | Rejected extra queue work |
| Pooled owned TX batches + staged RX | 3.520 | 2.452 | 1.711 | Rejected |
| SPSC with public receive requests | 4.320 | 2.461 | 1.441 | Kept SPSC |
| Private grouped RX, maximum 128 | 4.174 | 2.516 | 1.050 | Kept batching |
| Grouped RX + owned/idempotent TX | 4.055 | 2.713 | 1.192 | Rejected TX changes |
| Grouped RX + `FREE` buffer transfer | 3.818 | 2.681 | 1.073 | Rejected TX changes |
| Grouped RX + immutable nonatomic properties | 3.940 | 2.729 | 1.110 | Kept property change; no isolated throughput claim |
| Grouped RX, maximum 256 | 4.335 | 2.702 | 1.103 | Selected for longer tests |
| One shared payload allocation per TX batch, 30s | 4.331 | 2.745 | 1.091 | Similar throughput; higher RSS, rejected |

The pooled TX implementation preallocated 64 batch owners, each with space for
128 packets; it avoided a new Rust box per packet. Custom dispatch-data
destructors held batch ownership until every payload had been released. The
idempotent experiment retained normal control-message completions while omitting
transport-message completions. The `FREE` experiment instead allocated compatible
packet storage and transferred each accepted prefix, including subranges, to
libdispatch. The final parent-allocation experiment copied each batch into one
allocation and sent retained subranges, with ordinary completions. None justified
replacing the existing TX ownership contract.

## Path evidence and remaining limits

`netstat -anv -p udp` showed a connected kernel UDP socket for the actual daemon,
192.168.1.211:51820 → 192.168.1.226:51820, with traffic counters. This establishes
socket ownership and connectivity; it does not prove where every framework
payload travels or exclude a userspace channel accompanied by a reservation
socket. Root process sampling was unavailable under the current noninteractive
sudo configuration. We did not turn that limitation into a claim about offloads
or a hard platform throughput limit.

The remaining send-side costs include individual framework messages/completions
and owned dispatch-data allocation. Receive still performs a copy into writable
packet storage, decryption, TCP coalescing, and utun injection. Further work needs
attribution across those stages before changing crypto or adding another buffer
ownership layer. Lower receive CPU alone does not identify why single-stream TCP
throughput remains around 2.7 Gbit/s in these runs.

## Validation

- Rust formatting and all-target/all-feature Clippy with warnings denied.
- Rust tests with all features, public Network.framework plus coalescing, and
  no default features. Fake-adapter integration tests cover both ciphers,
  IPv4/IPv6, multiple peers, bursts, duplex traffic, and source rejection.
- Native ring ownership, partial drains, wraparound, 100,000 concurrent packets,
  group publication/wake count, full-ring refill, invalid packet sizes, and
  cancellation during an unpublished group.
- Real private-SPI host fixture: exact datagram boundaries, requested group cap,
  lone-message delivery, and cancellation completion.
- Native tests run normally and with AddressSanitizer and ThreadSanitizer.
- Standalone framework transmit correctness fixture (raw/AES/ChaCha, batch 1/128)
  and the real upstream `wg` UAPI compatibility script.
- Real Windows tunnel iperf checks with the selected release binary. Privileged
  local-utun fixture tests were intentionally not run as part of this audit.

Reproduce the native checks with:

```sh
sh scripts/test-network-notify.sh
SANITIZER=address sh scripts/test-network-notify.sh
SANITIZER=thread sh scripts/test-network-notify.sh
```

The host ABI fixture exits 77 if the private symbol is absent; the script prints
that skip explicitly. A present but incompatible implementation must fail its
assertions, not silently run the public or BSD implementation.
