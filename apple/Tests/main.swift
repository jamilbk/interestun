// Exercises Foundation packet ownership and the real C ABI over loopback UDP.
// Does not instantiate a provider, activate an extension, or create a utun.
import Darwin
import Foundation
import NetworkExtension

var assertions = 0
func check(_ condition: Bool, _ message: String) {
    precondition(condition, message); assertions += 1
}
func rejects(_ action: () throws -> Void) {
    do { try action(); preconditionFailure("Expected rejection") } catch { assertions += 1 }
}

let privateKeys = [41, 42].map { String(repeating: String(format: "%02x", $0), count: 32) }
let publicKeys = ["17d7e2acd30bf5e19d861ae80988d17fae8f662f5d80b0053f6cc73cdab1d264",
                  "07aaff3e9fc167275544f4c3a6a17cd837f2ec6e78cd8a57b1e3dfb3cc035a76"]
let ini = """
[Interface]
PrivateKey = \(Data(repeating: 41, count: 32).base64EncodedString())
Address = 10.20.0.2/32, fd20::2/128
MTU = 1420
[Peer]
AllowedIPs = 10.20.0.1/32, fd20::1/128
Endpoint = 127.0.0.1:51820
PublicKey = \(Data(repeating: 42, count: 32).base64EncodedString())
PersistentKeepalive = 25
"""

let config = try TunnelConfiguration.parse(ini)
check(config.uapi.contains("public_key="), "Public key reordered into UAPI")
check(config.addresses.count == 2 && config.routes.count == 2, "Dual-stack parsed")
let settings = try config.networkSettings()
check(settings.tunnelRemoteAddress == "127.0.0.1", "Uses the actual peer endpoint")
let v6Endpoint = try TunnelConfiguration.parse(ini.replacingOccurrences(of: "127.0.0.1:51820", with: "[::1]:51820"))
check(try v6Endpoint.remoteAddress() == "::1", "IPv6 endpoint strips port and brackets")
check(settings.ipv4Settings?.includedRoutes?.first?.destinationAddress == "10.20.0.1", "IPv4 route")
check(settings.ipv6Settings?.includedRoutes?.first?.destinationAddress == "fd20::1", "IPv6 route")
check(try CIDR("192.168.42.19/24").network == "192.168.42.0", "Network mask normalization")
check(try CIDR("fd20:1::42/64").network == "fd20:1::", "IPv6 network mask")
check(try CIDR("0.0.0.0/0").mask == "0.0.0.0", "Default route mask")
rejects { _ = try TunnelConfiguration.parse(ini.replacingOccurrences(of: "127.0.0.1:51820", with: "example.com:51820")) }
rejects { _ = try TunnelConfiguration.parse(ini, mtuOverride: 9000) }
rejects { _ = try TunnelConfiguration.parse(ini, addressOverride: "10.20.0.2/32") }
rejects { _ = try TunnelConfiguration.parse(ini + "\nDNS = 1.1.1.1") }
rejects { _ = try CIDR("10.20.0.1/33") }
rejects { _ = try TunnelConfiguration.parse(ini.replacingOccurrences(of: "[Interface]", with: "[Peer]")) }
rejects { _ = try TunnelConfiguration.parse(ini.replacingOccurrences(of: "PublicKey =", with: "UnknownKey =")) }
rejects { try TunnelConfiguration(uapi: config.uapi, addresses: config.addresses, routes: ["0.0.0.0/0"], mtu: 1420, cipher: 0).validate() }
let roundtrip = try JSONDecoder().decode(TunnelConfiguration.self, from: JSONEncoder().encode(config))
try roundtrip.validate()
check(roundtrip.uapi == config.uapi, "Start-options encoding")

final class Capture: @unchecked Sendable {
    let condition = NSCondition()
    var packets = [NEPacket]()
    var pointerPreserved = false
    func accept(_ packets: [NEPacket], pointer: UnsafePointer<UInt8>) {
        condition.lock(); defer { condition.unlock() }
        if let first = packets.first { pointerPreserved = (first.data as NSData).bytes == UnsafeRawPointer(pointer) }
        self.packets.append(contentsOf: packets)
        condition.signal()
    }
    func next() throws -> NEPacket {
        condition.lock(); defer { condition.unlock() }
        let deadline = Date().addingTimeInterval(8)
        while packets.isEmpty {
            guard condition.wait(until: deadline) else { throw TunnelError("Loopback packet timed out") }
        }
        return packets.removeFirst()
    }
}
let captureWrite: InterestunWrite = { context, views, count, lease in
    guard let context, let views, let lease, let first = views.pointee.bytes,
          let packets = leasedPacketObjects(views, count: count, lease: lease) else { return false }
    Unmanaged<Capture>.fromOpaque(context).takeUnretainedValue().accept(packets, pointer: first)
    return true
}
let captureRelease: InterestunRelease = { context in
    if let context { Unmanaged<Capture>.fromOpaque(context).release() }
}

func port() throws -> UInt16 {
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    guard fd >= 0 else { throw TunnelError("UDP socket failed") }
    defer { close(fd) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    } }
    guard bound == 0 else { throw TunnelError("UDP bind failed") }
    var size = socklen_t(MemoryLayout<sockaddr_in>.size)
    let named = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) } }
    guard named == 0 else { throw TunnelError("UDP getsockname failed") }
    return UInt16(bigEndian: address.sin_port)
}
func ip(source: UInt8, destination: UInt8) -> Data {
    var bytes = [UInt8](repeating: 0, count: 1420)
    bytes[0] = 0x45; bytes[2] = 5; bytes[3] = 140
    bytes[12] = 10; bytes[13] = 20; bytes[15] = source
    bytes[16] = 10; bytes[17] = 20; bytes[19] = destination
    for i in 20..<bytes.count { bytes[i] = UInt8(i % 251) }
    return Data(bytes)
}
func feed(_ engine: OpaquePointer, _ data: Data) -> Int {
    data.withUnsafeBytes { bytes in
        var view = InterestunPacketView(bytes: bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), len: bytes.count, family: UInt32(AF_INET))
        return interestun_ne_receive(engine, &view, 1)
    }
}
func exchange(cipher: UInt32) throws {
    let ports = [try port(), try port()]
    let captures = [Capture(), Capture()]
    var engines = [OpaquePointer]()
    defer { engines.forEach(interestun_ne_stop) }
    for i in 0..<2 {
        let uapi = "set=1\nprivate_key=\(privateKeys[i])\nlisten_port=\(ports[i])\npublic_key=\(publicKeys[1-i])\nendpoint=127.0.0.1:\(ports[1-i])\nallowed_ip=10.20.0.\(2-i)/32\n\n"
        let context = Unmanaged.passRetained(captures[i]).toOpaque()
        var error: UnsafeMutablePointer<CChar>?
        guard let engine = interestun_ne_start(uapi, cipher, 1420, "test-flow", context, captureWrite, captureRelease, &error) else { throw takeRustError(error) }
        engines.append(engine)
    }
    let outgoing = ip(source: 1, destination: 2)
    check(feed(engines[0], outgoing) == 1, "FFI input accepted")
    let retained = try captures[1].next()
    check(retained.data == outgoing, "Authenticated output arrives through Foundation batch")
    let incoming = ip(source: 2, destination: 1)
    check(feed(engines[1], incoming) == 1, "Reverse FFI input accepted")
    check(try captures[0].next().data == incoming, "Reverse authenticated output")
    for engine in engines {
        check(interestun_ne_tick(engine), "Workers alive")
        guard let text = interestun_ne_status(engine) else { throw TunnelError("No status") }
        let status = String(cString: text)
        interestun_ne_string_free(text)
        check(!status.contains("private_key") && !status.contains("preshared_key"), "No secrets in status")
        check(status.contains("NEPacketTunnelFlow") && status.contains("unverified"), "Backend reported without claiming Skywalk")
    }
    engines.forEach(interestun_ne_stop); engines.removeAll()
    check(retained.data == outgoing, "Foundation data survives Rust session teardown")
    print("cipher=\(cipher): NEPacket preserves 1420-byte buffer address: \(captures[1].pointerPreserved)")
}
try exchange(cipher: 0)
try exchange(cipher: 1)

// Invalid configuration must still release the context ownership transferred to Rust.
var capture: Capture? = Capture()
weak var released = capture
let context = Unmanaged.passRetained(capture!).toOpaque()
capture = nil
var error: UnsafeMutablePointer<CChar>?
let rejected = interestun_ne_start("set=1\n\n", 0, 1420, "test-flow", context, captureWrite, captureRelease, &error)
check(rejected == nil && released == nil, "Failed start releases callback context")
interestun_ne_string_free(error)
print("Passed \(assertions) Swift/C ABI assertions; no system extension or utun was opened.")
