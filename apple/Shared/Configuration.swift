import Darwin
import Foundation
import NetworkExtension

struct TunnelError: Error, LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

struct CIDR {
    let address: String
    let network: String
    let prefix: Int
    let family: Int32
    let mask: String

    init(_ value: String) throws {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]) else { throw TunnelError("Expected an IP address/prefix") }
        let address = String(parts[0])
        let family = address.contains(":") ? AF_INET6 : AF_INET
        let size = family == AF_INET ? 4 : 16
        guard (0...size * 8).contains(prefix) else { throw TunnelError("Invalid IP prefix length") }
        var bytes = [UInt8](repeating: 0, count: size)
        guard address.withCString({ inet_pton(family, $0, &bytes) }) == 1 else { throw TunnelError("Expected a numeric IP address") }
        let masks = (0..<size).map { i -> UInt8 in
            let bits = max(0, min(8, prefix - i * 8))
            return bits == 0 ? 0 : UInt8(0xff << (8 - bits) & 0xff)
        }
        for i in bytes.indices { bytes[i] &= masks[i] }
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(family, &bytes, &text, socklen_t(text.count)) != nil else { throw TunnelError("Cannot format IP network") }
        self.address = address
        self.network = String(cString: text)
        self.prefix = prefix
        self.family = family
        self.mask = masks.map(String.init).joined(separator: ".")
    }
}

/// Sent only in start options, never saved into VPN preferences or logs.
struct TunnelConfiguration: Codable {
    let uapi: String
    let addresses: [String]
    let routes: [String]
    let mtu: UInt32
    let cipher: UInt32

    static func parse(_ text: String, addressOverride: String? = nil, mtuOverride: UInt32? = nil,
                      cipher: UInt32 = 0) throws -> TunnelConfiguration {
        guard text.utf8.count <= 1024 * 1024 else { throw TunnelError("Configuration exceeds 1 MiB") }
        var uapi = "set=1\n"
        var addresses: [String] = []
        var routes: [String] = []
        var mtu: UInt32 = 1420
        var section = ""
        var interfaceSeen = false
        var peerKeySeen = false
        var peerKey = ""
        var peerBody = ""
        var interfaceKeys = Set<String>()
        var peerKeys = Set<String>()
        func list(_ value: String) -> [String] { value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } }
        func key(_ value: String) throws -> String {
            guard let bytes = Data(base64Encoded: value), bytes.count == 32 else { throw TunnelError("WireGuard keys must encode exactly 32 bytes") }
            return bytes.map { String(format: "%02x", $0) }.joined()
        }
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.components(separatedBy: "#")[0].trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line == "[Interface]" {
                guard !interfaceSeen, section.isEmpty else { throw TunnelError("Exactly one leading [Interface] section is required") }
                interfaceSeen = true; section = "interface"; continue
            }
            if line == "[Peer]" {
                guard interfaceSeen, section != "peer" || peerKeySeen else { throw TunnelError("Missing Interface or peer PublicKey") }
                if section == "peer" { uapi += "public_key=\(peerKey)\n" + peerBody }
                section = "peer"; peerKeySeen = false; peerKey = ""; peerBody = ""; peerKeys.removeAll(); continue
            }
            let fields = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard fields.count == 2 else { throw TunnelError("Expected a WireGuard key=value line") }
            let name = fields[0].trimmingCharacters(in: .whitespaces)
            let value = fields[1].trimmingCharacters(in: .whitespaces)
            if section == "interface" {
                guard interfaceKeys.insert(name).inserted else { throw TunnelError("Duplicate Interface field: \(name)") }
                switch name {
                case "PrivateKey": uapi += "private_key=\(try key(value))\n"
                case "ListenPort":
                    guard let port = UInt16(value) else { throw TunnelError("Invalid ListenPort") }
                    uapi += "listen_port=\(port)\n"
                case "Address": addresses = list(value)
                case "MTU":
                    guard let parsed = UInt32(value) else { throw TunnelError("Invalid MTU") }
                    mtu = parsed
                default: throw TunnelError("Unsupported Interface field: \(name)")
                }
            } else if section == "peer" {
                guard peerKeys.insert(name).inserted else { throw TunnelError("Duplicate Peer field: \(name)") }
                switch name {
                case "PublicKey": peerKey = try key(value); peerKeySeen = true
                case "PresharedKey": peerBody += "preshared_key=\(try key(value))\n"
                case "Endpoint": peerBody += "endpoint=\(value)\n"
                case "AllowedIPs":
                    for route in list(value) { routes.append(route); peerBody += "allowed_ip=\(route)\n" }
                case "PersistentKeepalive":
                    guard let seconds = UInt16(value) else { throw TunnelError("Invalid PersistentKeepalive") }
                    peerBody += "persistent_keepalive_interval=\(seconds)\n"
                default: throw TunnelError("Unsupported Peer field: \(name)")
                }
            } else { throw TunnelError("Expected [Interface] before configuration fields") }
        }
        guard section == "peer", peerKeySeen else { throw TunnelError("At least one complete Peer section is required") }
        uapi += "public_key=\(peerKey)\n" + peerBody
        if let addressOverride { addresses = list(addressOverride) }
        let configuration = TunnelConfiguration(uapi: uapi + "\n", addresses: addresses,
            routes: Array(Set(routes)).sorted(), mtu: mtuOverride ?? mtu, cipher: cipher)
        try configuration.validate()
        return configuration
    }

    func validate() throws {
        guard (1280...2000).contains(mtu), cipher <= 1 else { throw TunnelError("Invalid MTU or cipher") }
        guard !addresses.isEmpty, !routes.isEmpty else { throw TunnelError("Address and AllowedIPs are required") }
        #if INTERESTUN_ETHERNET
        guard try (addresses + routes).allSatisfy({ try CIDR($0).family == AF_INET }) else {
            throw TunnelError("The experimental Ethernet backend currently supports IPv4 only")
        }
        #endif
        let families = Set(try addresses.map { try CIDR($0).family })
        for route in routes where !families.contains(try CIDR(route).family) {
            throw TunnelError("Each route family needs a tunnel address of that family")
        }
        var error: UnsafeMutablePointer<CChar>?
        guard interestun_ne_validate(uapi, cipher, &error) else { throw takeRustError(error) }
        let configuredRoutes = try Set(uapi.split(separator: "\n").filter { $0.hasPrefix("allowed_ip=") }.map {
            let route = try CIDR(String($0.dropFirst(11)))
            return "\(route.network)/\(route.prefix)"
        })
        let routedNetworks = try Set(routes.map {
            let route = try CIDR($0)
            return "\(route.network)/\(route.prefix)"
        })
        guard configuredRoutes == routedNetworks else { throw TunnelError("Routes must match peer AllowedIPs") }
    }

    func networkSettings() throws -> NEPacketTunnelNetworkSettings {
        #if INTERESTUN_ETHERNET
        let settings = NEEthernetTunnelNetworkSettings(tunnelRemoteAddress: try remoteAddress(),
            ethernetAddress: "02:49:54:00:00:01", mtu: Int(mtu))
        #else
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: try remoteAddress())
        #endif
        settings.mtu = NSNumber(value: mtu)
        let addresses = try addresses.map(CIDR.init)
        let routes = try routes.map(CIDR.init)
        let v4 = addresses.filter { $0.family == AF_INET }
        let v6 = addresses.filter { $0.family == AF_INET6 }
        if !v4.isEmpty {
            let ip = NEIPv4Settings(addresses: v4.map(\.address), subnetMasks: v4.map(\.mask))
            ip.includedRoutes = routes.filter { $0.family == AF_INET }.map { NEIPv4Route(destinationAddress: $0.network, subnetMask: $0.mask) }
            settings.ipv4Settings = ip
        }
        if !v6.isEmpty {
            let ip = NEIPv6Settings(addresses: v6.map(\.address), networkPrefixLengths: v6.map { NSNumber(value: $0.prefix) })
            ip.includedRoutes = routes.filter { $0.family == AF_INET6 }.map { NEIPv6Route(destinationAddress: $0.network, networkPrefixLength: NSNumber(value: $0.prefix)) }
            settings.ipv6Settings = ip
        }
        return settings
    }

    func remoteAddress() throws -> String {
        // Rust validation has already required numeric SocketAddr endpoints.
        guard let line = uapi.split(separator: "\n").first(where: { $0.hasPrefix("endpoint=") }),
              let colon = line.lastIndex(of: ":") else { throw TunnelError("Missing peer endpoint") }
        return String(line[line.index(line.startIndex, offsetBy: 9)..<colon])
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    }
}

func takeRustError(_ text: UnsafeMutablePointer<CChar>?) -> TunnelError {
    guard let text else { return TunnelError("Rust engine failed without an error message") }
    defer { interestun_ne_string_free(text) }
    return TunnelError(String(cString: text))
}
