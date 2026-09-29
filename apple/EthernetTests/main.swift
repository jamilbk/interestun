// Offline settings validation only: no provider, socket, interface, or session.
import Foundation
import NetworkExtension

let ini = """
[Interface]
PrivateKey = \(Data(repeating: 41, count: 32).base64EncodedString())
Address = 10.20.0.2/32
MTU = 1420
[Peer]
AllowedIPs = 10.20.0.1/32
Endpoint = 192.168.1.226:51820
PublicKey = \(Data(repeating: 42, count: 32).base64EncodedString())
"""
let configuration = try TunnelConfiguration.parse(ini)
let settings = try configuration.networkSettings()
guard let ethernet = settings as? NEEthernetTunnelNetworkSettings else {
    fatalError("Ethernet build must create Ethernet settings")
}
precondition(ethernet.ethernetAddress == "02:49:54:00:00:01")
precondition(ethernet.mtu?.intValue == 1420)
precondition(ethernet.ipv4Settings?.addresses == ["10.20.0.2"])
precondition(ethernet.ipv4Settings?.includedRoutes?.first?.destinationAddress == "10.20.0.1")
precondition(ethernet.ipv6Settings == nil)
let dualStack = ini.replacingOccurrences(of: "10.20.0.2/32", with: "10.20.0.2/32, fd20::2/128")
    .replacingOccurrences(of: "10.20.0.1/32", with: "10.20.0.1/32, fd20::1/128")
do {
    _ = try TunnelConfiguration.parse(dualStack)
    fatalError("Ethernet must reject unsupported IPv6 configuration")
} catch let error as TunnelError {
    precondition(error.message.contains("IPv4 only"))
}
// AF_UNSPEC is the Ethernet callback tag; payload remains an entire frame.
let frame = Data(repeating: 0, count: 60)
let packet = NEPacket(data: frame, protocolFamily: 0)
precondition(packet.data == frame && packet.protocolFamily == 0)
print("Ethernet settings and packet representation passed; no interface or socket opened.")
