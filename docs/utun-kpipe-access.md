# Getting access to mapped utun kernel-pipe rings

Investigation on macOS 27.0 build 26A428, 2026-09-29. The working BSD utun4 tunnel
was left running. No utun attachment, channel opening, privileged helper request,
or system security configuration change occurred in this investigation.

## Concrete creation contract

The source implementation has two separate requirements:

1. The creator must pass `priv_check_cred(...,
   PRIV_SKYWALK_REGISTER_KERNEL_PIPE, 0)` (privilege 12001).
2. The resulting nexus client port must be bound to the process opening its
   channel, by PID or executable UUID. Passing a control fd to a different
   process alone is insufficient if the port remains bound to the creator.

The helper/worker arrangement is therefore implementable in principle: an
**authorized** creator configures netif and channel count before connect, binds
the future consumer, creates the utun, and transfers its control descriptor and
channel UUID to the worker. The creator/worker must preserve control-fd lifetime,
open the bound channel, and close the channel before the final control-fd close.
This is an architectural route, not a newly demonstrated working attachment.

The existing staged ring implementation covers the direct-creator case. It stays
gated off. Kernel-side attachment occurs before the privilege check in the
published source, which is why another denied connect is not a safe preflight.
The earlier attempt left an orphan interface.

## New test: can we locally sign the required entitlement?

Built a tiny [signature probe](../scripts/kpipe-entitlement-probe.c) that only
reads its own entitlement and code-signing metadata. It never opens a socket.
Tested otherwise identical binaries with and without this one added key:

`com.apple.private.skywalk.register-kernel-pipe = true`

| Signing context | Without private entitlement | With private entitlement |
|---|---|---|
| Ad-hoc | Runs, key absent | Killed before main, AMFI error -424 |
| Apple Development, existing Firezone-team app profile | Runs, key absent | Killed before main, AMFI error -413 |

AMFI describes the ad-hoc rejection as restricted entitlements in ad-hoc code.
For the development-signed variant, `taskgated-helper` explicitly identifies:

```
Unsatisfied entitlements: com.apple.private.skywalk.register-kernel-pipe
```

AMFI reports `No matching profile found`, with that same key as the unsatisfied
entitlement. Both development probes use copies of the existing host's bundle
identity, entitlement set, and embedded profile, in local test-only bundles.
Neither was installed or registered with LaunchServices. Installed apps were not
modified. The binary without the extra key runs; adding the key causes rejection.

This directly tests the current local signing/profile combination. It does not
prove Apple cannot authorize a different profile. Also, `SecTaskEntitlementsValidated`
returned false in both running baseline probes; it is recorded as raw diagnostic
metadata, not used as a standalone verdict on macOS execution authorization.
No kernel privilege success or ring mapping is claimed from signature readback.

## Apple uses explicit grants too

Apple's own [Skywalk test entitlements][test-entitlements] include the exact
kernel-pipe grant. The [test build rules][makefile] assign that file to
`skywalk_tests`. This is evidence of the intended test signing requirements, not
proof that a locally compiled test receives the grant on a stock Mac.

A bounded signature inspection found the grant on installed `nehelper`,
`rapportd`, and `identityservicesd`. These are potential *authorized creators*,
not documented interfaces for arbitrary third-party ring creation.

`nehelper` is the most concrete existing mechanism: its socket factory can
configure preconnect options and bind the client PID/UUID. However, its caller
must pass the separately traced `com.apple.private.nehelper.privileged` check.
The normal Network Extension session process is admitted but hardcodes channel
count zero. See the [helper audit](utun-framework-kpipe.md). Changing app versus
system-extension packaging does not itself supply either private grant.

## Why root and the debug sysctl aren't established solutions

[XNU privilege evaluation][priv] consults mandatory access-control policy before
its root-UID shortcut. This explains how a root caller can still be denied, as
our prior live attempt was.

The `kern.skywalk.priv_check` sysctl is compiled only in DEVELOPMENT/DEBUG XNU;
it is absent on this Mac. More importantly, its override is inside
`sk_priv_chk` in [skywalk.c][skywalk], while [utun_enable_channel][utun] calls
`priv_check_cred` directly. Merely enabling that debug sysctl is therefore not
an established way past utun's creation check even on a development kernel.
No sysctl or boot policy was changed.

## Next experiments that would test something new

- Obtain an Apple-authorized provisioning/signing arrangement for a small creator
  helper with the kernel-pipe grant. No public entitlement request category or
  promise of approval has been identified; this would need Apple clarification.
  First rerun the signature-only probe, then validate actual privilege separately
  from a full tunnel benchmark.
- Identify an Apple-supported helper entry point that both accepts our caller and
  requests nonzero utun channels. The currently traced NE path does not do this;
  finding such a path requires positive call-chain evidence, not guessing a
  providerConfiguration dictionary key.
- Use a separate research machine/VM with a deliberately configured development
  environment to establish ring functionality and performance. This would be a
  different deployment target, and its policy changes are not authorized or
  performed here. Any source-level preflight should exercise the exact privilege
  check before attaching an interface and fix the failure unwind first.

No successful ring attachment or deployable third-party access path has yet been
established. The next blocker is a valid creator authorization context, not the
ring-buffer layout or packet-pipeline implementation.

## Evidence

Local artifacts: `target/apple-path/kpipe-access-20260929/`: probe sources,
signing plists, process exit/readback results, creator-entitlement inventory,
pinned XNU sources, and static sandbox/kernel inspection. No provisioning
profiles, signing material, Apple binaries, or binary disassemblies are committed.

[test-entitlements]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/tests/skywalk_test.entitlements
[makefile]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/tests/Makefile
[priv]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_priv.c
[skywalk]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/skywalk/core/skywalk.c
[utun]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/if_utun.c
