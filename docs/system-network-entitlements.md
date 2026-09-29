# Installed network entitlement holders

Read-only inventory on macOS 27.0 (26A428), 2026-09-29. No inspected executable
was started, no helper requests were sent, and no tunnel or channel was opened.

## Kernel-pipe holders

Seven distinct signed executable identities claim
`com.apple.private.skywalk.register-kernel-pipe`. Every one also claims
`com.apple.private.nehelper.privileged`, and every inspected copy passed
`codesign --verify -R='anchor apple'`.

| Executable | Location | User-pipe registration too? |
| --- | --- | --- |
| `nehelper` | `/usr/libexec/nehelper` | No |
| `rapportd` | `/usr/libexec/rapportd` | Yes |
| `sharingd` | `/usr/libexec/sharingd` | Yes |
| `identityservicesd` | `/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd` | Yes |
| `chronod` | `/System/Library/PrivateFrameworks/ChronoCore.framework/Support/chronod` | Yes |
| `replicatord` | `/System/Library/PrivateFrameworks/ReplicatorCore.framework/Support/replicatord` | Yes |
| `remotepairingd` | `/Library/Apple/System/Library/PrivateFrameworks/RemotePairing.framework/Versions/A/XPCServices/remotepairingd.xpc/Contents/MacOS/remotepairingd` | Yes |

There are eight matching filesystem paths because the scan also found the
system template copy of `remotepairingd`. These are entitlement/signature
findings, not proof that each process currently has an open kernel-pipe channel.

## Positive consumer: RemotePairing

Follow-up: [bounded delegation and channel-ownership trace](remote-pairing-ring-delegation.md).

Following the new `remotepairingd` match revealed a concrete consumer of the
utun kernel-pipe constructor in its RemotePairing framework. This closes an
important gap in the earlier searches: an external Apple caller requesting
nonzero **utun** channels is now established by static code inspection.

Framework:
`/Library/Apple/System/Library/PrivateFrameworks/RemotePairing.framework/Versions/A/RemotePairing`

SHA-256: `ab66f3ccd45c54d7ae81d715fe712b5b97ddc0835cb8b18e74a91775f74796dd`.

Its Swift implementation includes `SkywalkChannelVirtualInterface`, with
packet read/write methods and an initializer accepting queue, address, netmask,
MTU, max-pending packets, and physical-interface name.

The arm64 disassembly shows:

1. The interface creation helper at `0x2C4A8` calls
   `__RemotePairing_NEVirtualInterfaceCreateNexusExtendedWithOptions` at
   `0x2C5A8`, supplying **type 1 (utun), netif enabled, channel count 1**.
   The count is loaded into `w6` at `0x2C5A0`.
2. The wrapper resolves `NEVirtualInterfaceCreateNexusExtendedWithOptions`
   through `dlopen`/`dlsym` and forwards the count. Its fallback to
   `NEVirtualInterfaceCreateNexus` also preserves the count.
3. Another helper retrieves the interface's nexus instances at `0x2E344`,
   extracts the first UUID, and calls `nw_channel_create_with_attributes`
   at `0x2E3F0`.
4. Strings include `tunnelUseSkywalk` and
   `RemotePairing/SkywalkVirtualInterfaceNetworkProtocol.swift`.

Addresses are framework-relative preferred addresses from `dyld_info`, not
live process addresses. This is positive static implementation evidence, not
a demonstration that this Mac currently selects the path. A preference-looking
string is not evidence of a supported setting for our Network Extension.

RemotePairing/CoreDevice is consequently a stronger next investigation than
guessing provider dictionary keys: it contains the actual construction and
consumption code, running in an entitled service. Whether that service can
create a suitable channel for Interestun, or only its own paired-device
tunnels, remains unestablished. No service request or private initializer was
invoked to test that question.

## Other grants

No scanned executable claimed `com.apple.private.skywalk.register-net-if`.
This is a bounded negative result for readable installed files, not proof
that kernel netif creation or another authorization arrangement is unavailable.

Xcode's `DTServiceHub` claims **register-flow-switch**, **register-user-pipe**,
and **observe-all**, but not register-net-if or register-kernel-pipe. Its path:

`/Applications/Xcode.app/Contents/SharedFrameworks/DVTInstrumentsFoundation.framework/Versions/A/Resources/DTServiceHub`

It passed the Apple-anchor check. This identifies another authorized Skywalk
participant, not an established generic tunnel-creation service.

The helper entitlement occurs on 24 paths representing 23 signing identities.
Besides the seven kernel-pipe holders, they are:

- `threadradiod`, `mediaremoted`, `CommCenter`, and iPhone Mirroring.
- `ContinuityCaptureAgent`, `networkserviceproxy`, `srp-mdns-proxy`, and `wifip2pd`.
- `assessmentagent`, `remotecompositorclientd`, `nesessionmanager`, and `UserEventAgent`.
- `symptomsd`, `mDNSResponder`, `racoon`, and `CoreDeviceService`.

All matched helper holders passed the Apple-anchor signature check. The helper
grant is not itself a kernel-pipe grant; it is relevant because of nehelper's
caller checks documented in [the function audit](ne-kpipe-function-audit.md).

For the separate Ethernet investigation,
`com.apple.networking.ethernet.user-access` occurs on `InternetSharing`,
`bluetoothd`, and, unexpectedly, `mpsgraphtool`. All passed the Apple-anchor
check. This does not show that any brokers the failed public Ethernet-provider
creation path.

Observation entitlements are kept separate from registration grants. Access
to statistics is not evidence of permission to create our rings.

## Why the entitlement inventory does not itself grant us access

Apple distinguishes unrestricted macOS entitlements from restricted ones that
must be authorized by a provisioning profile; see
[TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles).
Our local [signing probes](utun-kpipe-access.md) were rejected when we added
the kernel-pipe entitlement. The helper separately inspects its caller's
private entitlement. Root privileges and an ordinary Network Extension grant
did not satisfy those checks in our tests and traces.

The inventory identifies Apple-authorized software, but its grants do not
transfer to Interestun merely because we load the same framework or connect
to its service. Service authorization and channel ownership still need tracing.

## Coverage and reproduction

The scan considered **1,921,015 unique regular files**, identified **22,737
Mach-O candidates**, and inspected signatures for all candidates. It found
87 binaries matching the selected network entitlement terms; 30 had Skywalk,
privileged-helper, or Ethernet-user-access keys recorded in the committed
[filtered inventory](experiments/system-network-entitlements-20260929.json).
The inventory includes paths, entitlement values, signing identifiers,
Apple-anchor verification, and SHA-256 hashes.

Roots covered system libraries/apps, `/usr`, `/bin`, `/sbin`, `/Library`,
`/Applications`, `/opt`, the current user's Applications directory, and the
resolved OS/App/ExclaveOS/Rosetta Cryptex roots. A supplementary scan of
`/System/Developer` found no regular-file candidates; `/Developer` and
`/AppleInternal` were absent. Inode deduplication avoids repeated scans.

Limits:

- 141 permission-denied paths and 9 operation-not-permitted paths remained,
  including protected application data and a few unreadable executables such
  as `sudo`, CUPS backends, and authentication helpers.
- 3,718 paths were unavailable, largely framework/symlink targets absent as
  standalone files. Shared-cache-only libraries are not independently launched
  processes and do not confer their own process entitlement on a caller.
- Arbitrary source checkouts, personal caches, other users' home directories,
  unmounted volumes, and opaque assets were not recursively inspected.
- `codesign` chose its default architecture. This is not an inventory of every
  architecture slice, and signature verification is not a live privilege test.
- No claim is made about inaccessible code.

Reproduce with `python3 scripts/inventory-network-entitlements.py`. It only
reads files and invokes `codesign` to inspect or verify signatures. Raw
results, access errors, candidate paths, and RemotePairing disassembly are
under ignored `target/apple-path/system-entitlements-20260929/`.
