# utun option sweep kernel panics

The experimental `--probe-utun-rings` option sweep triggered two host kernel
panics. It is disabled, including when `apple-utun-ring` is explicitly enabled.
The CLI returns an error before opening a socket or loading Skywalk symbols.
The experiment source is archived in
[`experiments/utun_ring_probe.rs.disabled`](experiments/utun_ring_probe.rs.disabled)
and is not part of the build. Do not run it on this host.

## Evidence

Both reports identify `interestun` as the panicked process and contain the same
assertion, kernel stack offsets, and executable UUID:

```text
assertion failed: kif->pfik_ifp == NULL || kif->pfik_ifp == ifp
xnu/bsd/net/pf_if.c, line: 253 @uipc_socket.c:8321
```

| Panic time (local, UTC−07:00) | PID | Process uptime | Report filename |
| --- | ---: | ---: | --- |
| 2026-09-27 20:36:35 | 41189 | 1.428 s | panic-full-2026-09-28-042535.0002.panic |
| 2026-09-28 04:27:33 | 3231 | 0.818 s | panic-full-2026-09-28-042813.0002.panic |

Times above come from the panic's `Epoch Time / Calendar` field. Report creation
times differ. Original reports remain in
`/Library/Logs/DiagnosticReports/Retired/`; full reports are not copied here
because they contain unrelated system and process information.

Environment: macOS 27.0 build 26A428, Darwin 27.0.0,
`xnu-13432.1.9~1/RELEASE_ARM64_T6020`.

Offline symbolication matched these UUIDs:

- Panicking executable: `98A25964-ED52-389B-9964-724B54178AE6`.
  The matching binary was in `/Users/jamil/.cache/cargo/target/release/interestun`,
  rather than the workspace's older `target/release/interestun`.
- Shared cache: `EA2C265E-297C-39C2-8646-7D8A2DFF648A`.
- Kernel: `A68631F1-6B54-30AB-89D0-3CF684C5674D`.

The user stack's shared-cache offset `0x84d370` resolves to
`libsystem_kernel.dylib::__connect + 8` in the matching loaded cache.
The executable return offset `0x6a424` resolves to `main.rs:47`;
disassembly shows the preceding instruction calls `utun_ring::probe`.
Together these identify the probe's utun control-socket `connect()` as the
triggering operation. This was interface setup, before tunnel throughput testing.

The exact binary is preserved without execute permission under
`/Users/jamil/.cache/interestun/utun-panic-2026-09-28/interestun-98a25964.quarantined`.
Its SHA-256 is
`855a5da2acf79804a1323d1e595fd7d1767f45958799ba24c50316924355d5f8`.

## Interpretation and limits

The assertion means PF's interface entry already points to a different `ifnet`
object. Apple's published
[`pf_if.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf_if.c#L221)
looks up that entry by interface name when attaching an interface. That source
predates the running kernel and does not contain this assertion, so its line
numbers and implementation cannot establish the exact failure in this build.

The sweep rapidly creates and closes dynamically numbered interfaces. Reuse of
an interface name before teardown finishes is one plausible explanation. A
problem within Skywalk interface attachment is another. Neither is established:
the saved reports do not reveal the active option case, and the sweep did not
persist a marker before each syscall. We have not demonstrated that adding a
delay, changing unit allocation, or changing one option fixes the problem.

At the time of these crashes, the mapped-ring data path was not implemented;
this was an option and channel
availability probe. No further probe, interface creation, daemon restart, or
traffic test was performed during the crash investigation. Further work should
start with offline source analysis and a separate test environment.

## Offline follow-up: Skywalk attachment confirmed

Mapping the panic's executable segment base to the matching Mach-O's
`__TEXT_EXEC` exposes two named frames in both crashes:

```text
kern_nexus_controller_alloc_net_provider_instance + 404
    -> ifnet_attach + 4580
    -> PF assertion
```

This narrows the failing setup path to Skywalk network-interface attachment.
For the failing iteration, it occurs before userspace channel creation or
mapped-ring access. Earlier iterations may already have opened and closed
interfaces and channels. The stack establishes the failure location, not that
a single attachment from clean state is sufficient to reproduce it. Preconnect
options and state left by earlier cases remain possible contributors.
The exact option case remains unknown. Generic kernel-slide subtraction is
insufficient for this kernel collection's segment layout; it can produce
misleading nearest-symbol names even with a matching UUID.

[`scripts/symbolicate-utun-panic.py`](../scripts/symbolicate-utun-panic.py)
reproduces the analysis using saved files and `atos`; it never executes the
target executable or opens a tunnel. It verifies UUIDs before symbolication.
[Minimized results for both reports](utun-ring-panic-symbols.json) contain the
relevant stacks without the original report's unrelated process information.
Validated both reports and rejection of the newer, mismatched executable.

Example (read-only, no `sudo`):

```sh
python3 scripts/symbolicate-utun-panic.py \
  --kernel /System/Library/Kernels/kernel.release.t6020 \
  /Library/Logs/DiagnosticReports/Retired/panic-full-2026-09-28-042813.0002.panic
```

Narrow unified-log queries around both panic times returned no matching utun
or PF messages, so they did not establish the failing option case.

The published normal teardown sequence reserves the unit until `utun_detached`
frees the PCB, after PF detach. This weakens the simple timing-race explanation;
an arbitrary sleep is not a demonstrated fix. See the
[offline Skywalk audit](utun-skywalk-audit.md) for the source trace and next work.

The subsequent [ring backend](utun-ring-backend.md) replaces the option sweep
with a fixed setup sequence and a tested userspace batch engine. One authorized
attempt on 2026-09-28 at 05:25:33 PDT attached `utun64`, then failed with a logged
system-policy denial of kernel-pipe privilege 12001. It did not panic, but the
interface remained listed after process exit. No channel was opened. The gate
was disabled again without another attachment attempt. This provides evidence
for the previously suspected failure path, not proof of the PF panic's cause.
