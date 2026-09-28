# Network Extension tunnel tests against Windows

The installed packet tunnel extension passed real TCP traffic through its
AES-256-GCM UDP tunnel on 2026-09-28. Both directions and simultaneous traffic
worked. The extension was left connected on `utun4` after testing.

These measurements are the original public packet-flow baseline. The later
[pipeline audit](apple-packet-pipeline-audit.md) records the selected direct
descriptor frontend, queue tuning, repeated results, and current installed build.

## Configuration and method

Mac: M2 Pro, macOS 27.0 (26A428), app version `1790601131`, provider PID 1817.
The installed extension's SHA-256 matches the signed build. Windows endpoint:
`192.168.1.226:51820`. Mac endpoint: `192.168.1.211:51820`, over 10 GbE `en8`.
Tunnel addresses: Mac `10.20.0.2/32`, Windows `10.20.0.1/32`; MTU 1420.

The inner packet path uses `NEPacketTunnelFlow`; the outer UDP path uses
Network.framework. The [live path investigation](apple-packet-tunnel-path.md)
established the Skywalk-backed utun and Ethernet flowswitch channel. These tests
use that same extension and do not open a mapped utun channel.

Windows initially still needed the new Mac peer configuration. UDP handshake
attempts were visible in both directions, but neither side completed a handshake.
After the Windows update, the Mac reported a handshake and authenticated traffic.
A five-second TCP smoke test then delivered 3.879 Gbit/s from Mac to Windows.
Five preceding tunnel pings received no reply; the ICMP cause was not diagnosed.

Each sustained test measured 30 seconds after a one-second warmup, with one TCP
stream per direction. Rates below are receiver TCP payload goodput. Encrypted
outer traffic remains UDP. Process CPU comes from cumulative `ps` CPU time
sampled every half second, using samples from seconds 2 through 30. One core is
100%; this measures the whole extension process, excluding iperf and CPU charged
to other processes. Windows daemon CPU and revision were not independently
measured. These are single sequential runs, not a controlled comparison with
the earlier standalone daemon or an absolute performance ceiling.

## Results

| Test | Mac → Windows Gbit/s | Windows → Mac Gbit/s | Extension CPU cores |
| --- | ---: | ---: | ---: |
| Send | 3.878 | — | 1.78 |
| Receive | — | 2.732 | 1.44 |
| Simultaneous | 2.583 | 1.486 | 1.90 total |

A separate ten-second direct LAN TCP test reached **9.372 Gbit/s**, with zero
reported retransmissions. It confirms the server and physical link can carry
more traffic than this tunnel configuration.

Across all three sustained tunnel runs:

- No new packet-flow input drops, output write failures, or peer drops.
- Utun input/output error counters remained zero; the provider stayed healthy.
- TCP retransmissions were 841 for the send run and 690 for the Mac sender
  during simultaneous traffic. Windows sender retransmissions were not present
  in the returned JSON. Zero local drop counters therefore do not establish
  loss-free delivery.
- The largest observed packet-flow read callback contained 64 packets. During
  the send run, input callbacks averaged 51.3 packets. During the receive run,
  output batches averaged 28.7 packets. The Rust batch limit remains 128 and
  its pending input queue remains 1024.
- Peak extension RSS was 27.8 MiB across the three runs.

For context, the earlier [standalone native-worker measurements](native-worker-performance.md)
reported roughly 4.3 Gbit/s send and 2.5 Gbit/s receive for the selected build.
The new packet-flow bridge is operational, but this first measurement does not
demonstrate a general performance gain from moving into a Network Extension.

## Reproduction and evidence

With the extension connected and Windows running `iperf3 -s`:

```sh
/Applications/Interestun.app/Contents/MacOS/interestunctl show
iperf3 -c 10.20.0.1 -t 30 -O 1 -J --connect-timeout 3000
iperf3 -c 10.20.0.1 -t 30 -O 1 -J --connect-timeout 3000 -R
iperf3 -c 10.20.0.1 -t 30 -O 1 -J --connect-timeout 3000 --bidir
```

[Benchmark artifacts](benchmarks/macos-apple-packet-tunnel/) contain raw iperf
JSON, before/after provider and interface counters, process CPU samples, build
metadata, and the measurement script. Additional local diagnostics are in
`target/apple-path/windows-tests-20260928/`. No private keys are included.
