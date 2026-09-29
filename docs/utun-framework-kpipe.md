# NetworkExtension kernel-pipe creation: installed-framework audit

Audited 2026-09-29, read-only. No private networking API, XPC request, interface
creation, channel opening, or configuration change was performed. This extends
[the XNU datapath audit](utun-skywalk-datapath.md) with installed Apple binary
evidence, rather than assuming the public API describes all implementation paths.

## Finding

**A private framework path exists for requesting utun kernel-pipe channels.**
However, the inspected normal packet-tunnel session creation path explicitly
passes zero channels. The privileged helper can configure and bind channels,
but it checks a private caller entitlement before creating kernel-control
sockets. Calling the private framework function from our extension therefore
is not established as a usable route around our earlier privilege denial.

No provider configuration switch enabling this path was found. This is a
bounded finding about the inspected path and OS build, not proof that every
Apple-internal path or future release lacks such a switch.

## Private creation API and request shape

The saved NetworkExtension disassembly contains:

- `NEVirtualInterfaceCreateNexusExtendedWithOptions` at `0x1966d2f7c`.
- `NENexus` initializer accepting `channelCount`, `netifRingSize`,
  `kernelPipeTxRingSize`, `kernelPipeRxRingSize`, and `execUUID`.
- `NEVirtualInterfaceCreateChannel` and channel UUID retrieval functions.

Tracing the named NENexus initializer to the C function establishes that `w6`
is the channel-count argument. In the utun branch, a nonzero channel count
causes serialization of option **17**, `UTUN_OPT_ENABLE_CHANNEL`, with the
count as a four-byte value (`0x1966d347c` through `0x1966d34cc`). It also builds
channel binding information, using executable UUID when supplied or a
request to bind the requesting process's PID otherwise.

The serialized keys include `interface-option`, `interface-option-data`,
`interface-bind-channel-pid`, `interface-bind-channel-exec-uuid`, and
`interface-type`. These are helper protocol details, not demonstrated keys
for `NETunnelProviderProtocol.providerConfiguration`.

The generic private options handler also recognizes `EnableUserPacketPool`,
`EnableRxFlowSteeringAuto`, and `EnableLowPowerWake`, producing socket options
30, 31, and 32. These do not set option 17 in that handler. Their existence
does not demonstrate a public route to mapped channels or that putting those
names in our provider dictionary has an effect.

## The normal packet-tunnel path hardcodes zero

Static Objective-C metadata identifies the session manager method at
`0x10002605c` as:

`-[NESMVPNSession plugin:didRequestVirtualInterfaceWithParameters:completionHandler:]`

For the utun/IPsec creation branch it calls
`NEVirtualInterfaceCreateNexusExtended` at `0x100026538`. Its arguments include:

| Argument | Observed value |
| --- | --- |
| Interface type | Requested type, held in `x24` |
| Netif enable (`w4`) | 1 |
| Channel count (`w6`) | **0**, loaded immediately before the call |
| Slot size (`w7`) | 4096 |
| Netif/kpipe ring overrides | Zero |
| Executable UUID | Null |

The C wrapper forwards these arguments to the WithOptions implementation and
adds a null options argument. There is no provider-dictionary lookup feeding
the channel-count argument at this call site. The session manager then enables
the flowswitch and sets utun max-pending to 64. This matches our saved
observations of an enabled netif/flowswitch with zero user channels and a
4096-byte slot setting.

The installed public SDK's `NEPacketTunnelNetworkSettings` exposes no channel
count or ring-size setting. `NETunnelProviderProtocol.h` describes
`providerConfiguration` as vendor-specific data passed to the provider. It
is not documented as the private interface-creation options dictionary.

## The helper has the entitlement, but checks its caller

Read-only `codesign` inspection confirms `/usr/libexec/nehelper` has:

`com.apple.private.skywalk.register-kernel-pipe = true`

Its `NEHelperSocketFactory` initializer reads the caller's
`com.apple.private.nehelper.privileged` entitlement and stores the Boolean at
object offset 8 (`0x10000d134` through `0x10000d18c`, arm64e slice). A second
`com.apple.private.neagent` entitlement can admit a socket-factory connection,
but does not set that privileged Boolean.

The kernel-control request branch checks that Boolean at `0x10000d868` before
calling `socket`. The failure branch logs rejection of an unprivileged
kernel-control request. Thus admission to some helper services is not enough;
the kernel-control operation has its own check. Public Network Extension
entitlement possession is not the test in this branch.

For an accepted request, the helper applies the option array before `connect`
(`0x10000dffc` / `0x10000e00c`). Its option callback issues `setsockopt` using
the requested option number. For channel PID binding it obtains the remote
XPC connection's PID and applies utun option 29; UUID binding uses option 28.
This solves the helper-creates/provider-owns binding problem for callers
that are allowed to use this path.

`nesessionmanager` has `com.apple.private.nehelper.privileged`, explaining how
Apple's session process can use this facility. It still requests zero channels
in the inspected provider interface creation method.

## Consequence for Interestun

A normal provider setting has not been identified that changes the hardcoded
channel count. Calling the low-level private function directly would have to
satisfy the helper's caller policy; an ordinary NE entitlement is not evidence
that this succeeds. Adding a private entitlement to a local signature is not
proof that macOS grants it.

The remaining viable investigation is a separately identified Apple-authorized
creation path or supported entitlement/API arrangement. A development OS/test
machine could investigate different policy contexts, but that is distinct
from a deployable framework setting on this Mac. The staged ring backend
remains disabled. Repeating the previously denied direct attachment would not
test any new solution and previously left an orphan interface.

## Reproduction and evidence

Local evidence is in `target/apple-path/framework-kpipe-20260929/`:
`nehelper-disassembly.txt`, `nesessionmanager-disassembly.txt`,
`nesessionmanager-objc.txt`, `session-stubs.txt`, and
`nehelper-entitlements.plist`. Framework evidence is in the saved
`target/apple-path/networkextension-disassembly.txt` and companion strings.
No full Apple disassembly is committed to the repository.

Helper addresses above use the arm64e slice. Reproduce with
`xcrun llvm-objdump --macho --arch=arm64e --disassemble --no-show-raw-insn`,
`--objc-meta-data`, and `--section=__TEXT,__objc_stubs`. Inspect signatures with
`codesign -d --entitlements :-`; none of these commands starts the binary.

SHA-256 of installed executables inspected:

- nehelper: `f8cbbcf2995db706d11bfca83b02658eab39307489b6612c731fe5cc6ed704c9`
- nesessionmanager: `7cf25060e0a692245749f50d27a064d40fd0cc5090eea881596d3918d2ae996c`

Framework evidence was saved on macOS 27.0 (26A428). Absolute addresses and
private request formats are build-specific and are not a stable API contract.
