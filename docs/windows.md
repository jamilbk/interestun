# Windows backend

Build with Rust 1.88+ and the MSVC C++ build tools:

```powershell
cargo build --release --locked
.\scripts\install-wintun.ps1
```

The installer downloads Wintun 0.14.1 from [wintun.net](https://www.wintun.net/),
checks the published archive SHA-256 and DLL Authenticode signature, then places
the DLL matching the executable's architecture and its license beside
`target\release\interestun.exe`. It can be rerun and refuses to overwrite a different
DLL. For debug/custom builds, use `-ExecutablePath .\target\debug\interestun.exe`.
No elevation is needed to copy the DLL into a writable build directory; creating
an adapter later requires elevation. The DLL/driver is not bundled in this repository.
Use a trusted directory: the daemon loads native code from this file. It resolves
the explicit DLL path and restricts dependency lookup to its directory and System32.

In an elevated PowerShell terminal:

```powershell
.\target\release\interestun.exe interestun
# An explicit DLL location is also supported:
.\target\release\interestun.exe interestun --wintun-dll C:\VPN\wintun.dll
# Standard WireGuard peers require --cipher chacha20-poly1305.
```

The foreground process creates a temporary adapter, sets the IPv4 and IPv6 MTU,
and opens a 4 MiB Wintun session. Ctrl-C/Break joins workers, ends the session,
closes the adapter and removes its named-pipe endpoint. No existing adapter is
adopted. IP addresses, routes, DNS, and firewall policy are caller-managed.

## Configuration

The UAPI is `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\interestun`.
Only SYSTEM and elevated Administrators can access it; remote pipe clients are
rejected. An existing endpoint is never taken over. Requests use the same text
UAPI as macOS: hexadecimal keys, `set=1` or `get=1`, and a terminating blank line.
Configuration changes validate first, then restart workers; failure attempts to
restore the prior configuration.

**Stock Windows `wg.exe` requires the named pipe's owner to be LocalSystem.**
Run the daemon under a LocalSystem host to use `wg set`, `show`, `setconf`, and
`syncconf`. An ordinary elevated Administrator daemon has a different owner, so
stock `wg.exe` rejects it even though the ACL permits Administrator access.
This requirement comes from [wireguard-tools' Windows IPC implementation](https://git.zx2c4.com/wireguard-tools/tree/src/ipc-uapi-windows.h).
Windows service installation/SCM integration is not included.

For an elevated Administrator daemon, the included direct client is usable from
a second elevated PowerShell terminal:

```powershell
# Query the interface (includes private keys once configured).
.\scripts\uapi.ps1 -Interface interestun
# Apply a UAPI request stored in a protected UTF-8 file.
.\scripts\uapi.ps1 -Interface interestun -RequestFile .\peer.uapi
```

Example `peer.uapi` (replace both placeholders with 64 hexadecimal characters):

```text
set=1
private_key=<local-private-key-hex>
listen_port=51820
public_key=<remote-public-key-hex>
endpoint=192.0.2.2:51820
allowed_ip=10.20.0.2/32
persistent_keepalive_interval=25

```

Restrict access to the request file because it contains the private key. Configure
the opposite keys on the remote host, select the same cipher, and replace the
example endpoint with the remote host's reachable address. Then assign the local
address and route, for example:

```powershell
New-NetIPAddress -InterfaceAlias interestun -IPAddress 10.20.0.1 -PrefixLength 32
New-NetRoute -InterfaceAlias interestun -DestinationPrefix 10.20.0.2/32 -NextHop 0.0.0.0
```

## Data path and validation

Windows shares the existing BoringTun peer workers, routing, authentication,
bounded queues, and packet pool. One additional reader waits on Wintun's read
event and dispatches packets to those workers. Shutdown waits at most 100 ms for
an idle reader. The first peer worker receives both shared UDP listeners through
Mio/IOCP. Windows uses exclusive UDP binds and `send_to` through the shared
listeners; it does not depend on Darwin's `SO_REUSEPORT` flow selection.

Wintun buffers are copied and released before returning from receive. Concurrent
injection writes allocate/copy/commit directly to Wintun. Ring-full errors retain
queued packets and retry after at most 2 ms (Wintun has no writable event).
Windows UDP is currently one datagram per call, not Darwin-style batching.
Control clients are serviced every 10 ms, with 32 clients, 1 MiB requests, and
five-second deadlines. There is no control-client thread per connection.

```powershell
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

These tests run real Windows UDP and named pipes with a simulated adapter. They
cover both ciphers, multiple peers, IPv4/IPv6, routing/source validation, roaming,
oversized datagrams, backpressure, adapter failure, shutdown, exclusive binding,
and UAPI transactions. They do not establish real driver throughput or validate
the protected pipe ACL under separate Windows accounts.

The separate driver smoke test requires an elevated terminal and a trusted DLL:

```powershell
$env:INTERESTUN_WINTUN_DLL = 'C:\VPN\wintun.dll'
cargo test --locked --test wintun_privileged -- --ignored --nocapture
```

It creates temporary adapters, checks both MTUs, exercises receive/wait, and
closes/recreates the adapter. A two-host test with actual routes and traffic is
still required before making performance or interoperability claims.
