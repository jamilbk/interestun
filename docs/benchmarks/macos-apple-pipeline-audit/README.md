# Network Extension pipeline experiment records

See the [audit report](../../apple-packet-pipeline-audit.md) for conclusions,
Apple/XNU sources, copy accounting, and limitations. Measurements were taken on
2026-09-28 against the Windows tunnel peer, using one TCP stream per direction
inside the AES-256-GCM UDP tunnel.

| Directory | Candidate | Disposition |
| --- | --- | --- |
| `queue-only` | Public packet-flow bridge; 4 MiB receive buffer and 1024 pending packets | Comparison; new send peer drops |
| `direct-utun` | Existing NE descriptor; inherited ordinary-utun coalescer | Rejected: oversized injections dropped by the Skywalk netif |
| `direct-backpressure` | Existing NE descriptor; packet boundaries preserved; TX backpressure | Selected; initial send, receive, duplex runs plus receive smoke test |
| `direct-repeat` | Same selected build | Repeat 30-second send and receive runs |

The original public-bridge baseline is in
[macos-apple-packet-tunnel](../macos-apple-packet-tunnel/).

Each directory contains the exact `measure.py` used for its runs, raw iperf3
JSON, provider counters before/after, interface counters, CPU samples, and the
signed build's binary hashes. `*-summary.json` includes the command, timestamps,
process ID, counter deltas, goodput, and process CPU calculation. Missing metrics
on older builds are not evidence of zero drops; inspect their before/after files
and the report. Running these scripts would generate new measurements and
overwrite their adjacent result files, so copy the script to a new directory
for subsequent experiments.

`selected-installation.json` records the final connected build and verifies
that the installed system extension and containing app match the measured
build hashes. `selected-final-status.json` and the selected interface files
record final health and utun option readback. The `skywalk` status placeholder
is not the source of the netif/channel conclusions.

`packet-object-copy.json` records resolution of the public packet-flow
implementation's copying NSData initializer on this exact OS build.
`coalescing-kernel-excerpt.log` preserves the first twelve oversized-packet
rejections from the rejected descriptor candidate. The selected implementation
does not coalesce packets across this boundary.

App bundles, private keys, configuration secrets, and full downloaded Apple
sources are not included.
