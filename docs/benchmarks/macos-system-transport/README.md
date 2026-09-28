# macOS System Trace and transport controls

See [analysis and interpretation](../../apple-system-transport.md).

- `tunnel-send/`: 30-second TCP-through-UDP send with System Trace attached.
- `tunnel-final/`: fresh unprofiled 30-second tunnel send.
- `raw-*.json`: standalone production-bridge sends, including unmodified Windows
  iperf3 receiver reports, CPU, acceptance, received counts, and backpressure.
- `*-manifest.json`: tested commands, binary hashes where recorded, and tracing
  configuration. The refill experiment was rejected and reverted.
- `windows-*-check.*`: low-rate burst/protocol checks before/after requesting a
  4 MiB receiver buffer. `local-iperf.json` is a correctness check only.
- `syscall-analysis.json`, `thread-state-analysis.json`: trace seconds 2–22.
  Modeled syscall CPU/wait fields contain inconsistencies; use the separately
  exported thread states for scheduling. The syscall export required skipping
  foreign thread-state rows, which is counted explicitly in diagnostics.
- `raw-profiled-samples.xml.gz` and its analysis: standalone sender Time Profiler
  samples, analyzed over seconds 2–12. Inclusive percentages overlap.

Full System Trace and its large XML exports remain locally in
`target/apple-path/system-transport-20260928/`. Compact raw results are committed;
the multi-gigabyte recording is not. All tests used one UDP data connection and
1452-byte raw UDP payloads. No jumbo frames or direct mapped-utun attachment.
