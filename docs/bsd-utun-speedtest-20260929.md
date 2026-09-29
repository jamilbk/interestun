# BSD utun speed test — 2026-09-29

Rebuilt the standalone daemon from d0bc19e using default Cargo features, with
BSD control-socket utun creation and Network.framework outer UDP. All Interestun
Network Extension sessions were stopped before this test. Interface utun4;
Mac 10.20.0.2, Windows 10.20.0.1; outer peer 192.168.1.226:51820 over en8.
AES-256-GCM, MTU 1420, syscall batch 128, pending packets 1024, utun receive
buffer 4 MiB. A peer handshake succeeded before testing.

One TCP connection through the encrypted UDP tunnel; sequential 30-second tests,
omitting the initial second (`iperf3 -c 10.20.0.1 -t 30 -O 1 -J`, then `-R`).
Rates below use receiver-reported goodput. CPU uses the daemon's process CPU-time
delta divided by elapsed wall time from approximately one-second ps samples;
100% means one CPU core. It excludes iperf and system-wide work outside the
process, and the sample window does not exactly match iperf's omitted interval.

| Direction | Goodput | Mac tunnel daemon CPU |
|---|---:|---:|
| Mac → Windows | 3.60 Gbps | 1.61 cores (161%) |
| Windows → Mac | 4.71 Gbps | 1.51 cores (151%) |

Forward test reported 3 TCP retransmits. Reverse test did not report a retransmit
count. No packet loss or throughput ceiling is inferred from that absence.
This is one run in each direction, not an isolated comparison to previous NE
results. The BSD tunnel was left running and connected.

Local raw JSON, CPU samples, stderr, and daemon log:
`target/benchmarks/bsd-utun-20260929/`.
