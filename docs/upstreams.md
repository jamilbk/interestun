# Upstream references

- Firezone BoringTun base: `d76a1cb23af9f2b0020d5f6a1de7d95c1989fc4f`,
  https://github.com/firezone/boringtun/tree/d76a1cb23af9f2b0020d5f6a1de7d95c1989fc4f
- Cipher extension commit: `d60ac5643f8241e12fa6d35aa8e353079e96e703`.
  Branch:
  https://github.com/jamilbk/boringtun/tree/interestun-cipher-suites
- In-place transport API commit: `74e450f6072b04d5dc198473eb9859ac04899f7f`
  (current dependency pin; same cipher transcript and wire format).
- Firezone reference checkout: `f533bded5ea40d3d24ac3498f5df8421546dffbc`,
  https://github.com/firezone/firezone/tree/f533bded5ea40d3d24ac3498f5df8421546dffbc
  - `rust/libs/connlib/tun/src/apple/{sys,bulk}.rs`: Darwin batch ABI,
    dynamic symbol lookup, utun scatter/gather framing, and partial-send handling.
  - `rust/libs/connlib/socket-factory/src/pool/apple.rs`: wildcard sockets plus
    connected flow sockets sharing a port.
  - `rust/gui-client`: Rust service/client separation; no UI copied into this project.
- BoringTun `src/device/tun_darwin.rs`: BSD utun creation and interface naming.
- WireGuard tools / UAPI: https://git.zx2c4.com/wireguard-tools/
- Wintun 0.14 API: https://git.zx2c4.com/wintun/about/?h=0.14.1
  (dynamically loaded; signed DLL/driver supplied separately).
- Windows named-pipe protocol/owner check:
  https://git.zx2c4.com/wireguard-tools/tree/src/ipc-uapi-windows.h
- Apple XNU ABI: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/socket_private.h

Interestun's I/O implementation is newly written against these APIs. Firezone's
reference code is Apache-2.0; BoringTun is BSD-3-Clause. The fork retains its
upstream license and copyright notices. ring supplies the existing hardware-aware
AEAD implementations; the extension selects algorithms rather than implementing
cryptographic primitives.
