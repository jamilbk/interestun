import Darwin
import Foundation
import NetworkExtension
import SystemExtensions

let usage = """
Usage: interestunctl <command> [options]

  validate --config FILE [--address IP/PREFIX] [--mtu N] [--cipher aes256-gcm|chacha20-poly1305]
  install           Activate the bundled system extension; does not start a tunnel
  status            Show installed extension and VPN state
  start --config FILE [--address IP/PREFIX] [--mtu N] [--cipher aes256-gcm|chacha20-poly1305]
  show              Show running tunnel counters and public peer information as JSON
  stop              Stop this app's VPN configuration

FILE uses WireGuard [Interface]/[Peer] syntax, plus Address and MTU.
Endpoint must be a numeric IP:port. Keys stay out of saved VPN preferences.
Run this executable from Interestun.app/Contents/MacOS/interestunctl.
"""

func requireProvisioning() throws {
    guard Bundle.main.object(forInfoDictionaryKey: "InterestunSignedForActivation") as? Bool == true else {
        throw TunnelError("This is an unprovisioned build. Rebuild with scripts/build-apple.py and matching app/extension provisioning profiles before activation.")
    }
}

func extensionID() throws -> String {
    guard let id = Bundle.main.object(forInfoDictionaryKey: "InterestunExtensionIdentifier") as? String else {
        throw TunnelError("Run the CLI from its containing Interestun.app bundle")
    }
    return id
}

/// All delegate callbacks and submission use the main queue; CLI dispatchMain
/// keeps XPC and approval callbacks responsive without creating any windows.
final class ExtensionRequest: NSObject, OSSystemExtensionRequestDelegate {
    private var continuation: CheckedContinuation<String, Error>?
    private var timeout: DispatchWorkItem?

    func perform(install: Bool) async throws -> String {
        let id = try extensionID()
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let request = install
                ? OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: id, queue: .main)
                : OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: id, queue: .main)
            request.delegate = self
            let timeout = DispatchWorkItem { [weak self] in self?.finish(.failure(TunnelError("System extension request timed out; check System Settings for pending approval"))) }
            self.timeout = timeout
            DispatchQueue.main.asyncAfter(deadline: .now() + 60, execute: timeout)
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }
    private func finish(_ result: Result<String, Error>) {
        timeout?.cancel(); timeout = nil
        let continuation = self.continuation; self.continuation = nil
        continuation?.resume(with: result)
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed: finish(.success("System extension activated. No tunnel has been started."))
        case .willCompleteAfterReboot: finish(.success("System extension activation requires a restart. No tunnel has been started."))
        @unknown default: finish(.failure(TunnelError("Unknown activation result")))
        }
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let error = error as NSError
        finish(.failure(TunnelError("\(error.localizedDescription) (\(error.domain) \(error.code)); inspect sysextd/nesessionmanager logs for validation details")))
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        FileHandle.standardError.write(Data("Approve Interestun in System Settings > General > Login Items & Extensions > Network Extensions.\n".utf8))
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension new: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        finish(.success(properties.isEmpty ? "System extension: not installed" : properties.map {
            "System extension: \($0.bundleIdentifier) version=\($0.bundleVersion) enabled=\($0.isEnabled)"
        }.joined(separator: "\n")))
    }
}

func managers() async throws -> [NETunnelProviderManager] {
    try await withCheckedThrowingContinuation { continuation in
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error { continuation.resume(throwing: error) }
            else { continuation.resume(returning: managers ?? []) }
        }
    }
}
func manager(create: Bool = false) async throws -> NETunnelProviderManager {
    let id = try extensionID()
    let matches = try await managers().filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == id }
    guard matches.count <= 1 else { throw TunnelError("Multiple Interestun VPN configurations exist; resolve duplicates before continuing") }
    if let manager = matches.first { return manager }
    guard create else { throw TunnelError("No Interestun VPN configuration. Use start --config FILE first.") }
    return NETunnelProviderManager()
}
func state(_ value: NEVPNStatus) -> String {
    switch value {
    case .invalid: return "invalid"
    case .disconnected: return "disconnected"
    case .connecting: return "connecting"
    case .connected: return "connected"
    case .reasserting: return "reasserting"
    case .disconnecting: return "disconnecting"
    @unknown default: return "unknown"
    }
}
func waitFor(_ manager: NETunnelProviderManager, connected: Bool) async throws {
    let deadline = Date().addingTimeInterval(45)
    var observedStart = false
    while Date() < deadline {
        let status = manager.connection.status
        if connected && status == .connected { return }
        if !connected && (status == .disconnected || status == .invalid) { return }
        if status == .connecting || status == .reasserting { observedStart = true }
        // startVPNTunnel can return before the asynchronous status update.
        if connected && observedStart && (status == .disconnected || status == .invalid) { throw TunnelError("Tunnel start failed; inspect the Interestun packet-tunnel log") }
        try await Task.sleep(nanoseconds: 100_000_000)
    }
    throw TunnelError("Timed out waiting for VPN state; current state: \(state(manager.connection.status))")
}

private final class ProviderReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    init(_ continuation: CheckedContinuation<Data, Error>) { self.continuation = continuation }
    func finish(_ result: Result<Data, Error>) {
        lock.lock()
        let continuation = self.continuation; self.continuation = nil
        lock.unlock()
        continuation?.resume(with: result)
    }
}

func configuration(_ arguments: [String]) throws -> TunnelConfiguration {
    var options = [String: String]()
    var index = 0
    while index < arguments.count {
        let name = arguments[index]
        guard ["--config", "--address", "--mtu", "--cipher"].contains(name), index + 1 < arguments.count,
              options[name] == nil else { throw TunnelError("Invalid, missing, or repeated option: \(name)") }
        options[name] = arguments[index + 1]; index += 2
    }
    guard let path = options["--config"] else { throw TunnelError("--config FILE is required") }
    let attributes = try FileManager.default.attributesOfItem(atPath: path)
    guard let permissions = attributes[.posixPermissions] as? NSNumber, permissions.uint16Value & 0o077 == 0 else {
        throw TunnelError("Configuration contains private keys; restrict it with chmod 600 before reading")
    }
    guard (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 1024 * 1024 else { throw TunnelError("Configuration exceeds 1 MiB") }
    let cipher: UInt32
    switch options["--cipher"] ?? "aes256-gcm" {
    case "aes256-gcm": cipher = 0
    case "chacha20-poly1305": cipher = 1
    default: throw TunnelError("Unknown cipher")
    }
    let mtu = options["--mtu"].flatMap(UInt32.init)
    if options["--mtu"] != nil && mtu == nil { throw TunnelError("Invalid MTU") }
    return try TunnelConfiguration.parse(String(contentsOfFile: path, encoding: .utf8),
        addressOverride: options["--address"], mtuOverride: mtu, cipher: cipher)
}

func run() async throws {
    let args = Array(CommandLine.arguments.dropFirst())
    guard let command = args.first, !["help", "--help", "-h"].contains(command) else { print(usage); return }
    let rest = Array(args.dropFirst())
    if command == "validate" {
        let config = try configuration(rest)
        print("Valid configuration: \(config.addresses.count) address(es), \(config.routes.count) route(s), MTU \(config.mtu), cipher \(config.cipher == 0 ? "aes256-gcm" : "chacha20-poly1305"). No tunnel opened.")
        return
    }
    guard ["install", "status", "start", "show", "stop"].contains(command) else { throw TunnelError("Unknown command: \(command)") }
    if command != "start", !rest.isEmpty { throw TunnelError("Unexpected options for \(command)") }
    try requireProvisioning()
    switch command {
    case "install":
        let request = ExtensionRequest()
        print(try await request.perform(install: true))
    case "status":
        let request = ExtensionRequest()
        print(try await request.perform(install: false))
        let id = try extensionID()
        for manager in try await managers() where (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == id {
            print("VPN: \(state(manager.connection.status))")
        }
    case "start":
        let config = try configuration(rest)
        let manager = try await manager(create: true)
        guard [.invalid, .disconnected].contains(manager.connection.status) else { throw TunnelError("Interestun is already active; stop it before changing configuration") }
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = try extensionID()
        proto.serverAddress = try config.remoteAddress()
        proto.disconnectOnSleep = false
        // Deliberately no private key, UAPI string, or configuration in preferences.
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Interestun"
        manager.isEnabled = true
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
        try manager.connection.startVPNTunnel(options: ["configuration": try JSONEncoder().encode(config) as NSData])
        try await waitFor(manager, connected: true)
        print("Interestun connected. Use show for packet counters and peer handshakes.")
    case "stop":
        let manager = try await manager()
        manager.connection.stopVPNTunnel()
        try await waitFor(manager, connected: false)
        print("Interestun stopped.")
    case "show":
        let manager = try await manager()
        guard manager.connection.status == .connected,
              let session = manager.connection as? NETunnelProviderSession else { throw TunnelError("Interestun is not connected") }
        let response: Data = try await withCheckedThrowingContinuation { continuation in
            let reply = ProviderReply(continuation)
            DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
                reply.finish(.failure(TunnelError("Provider status request timed out")))
            }
            do {
                try session.sendProviderMessage(Data("status".utf8)) { data in
                    if let data { reply.finish(.success(data)) }
                    else { reply.finish(.failure(TunnelError("Provider did not return status"))) }
                }
            } catch { reply.finish(.failure(error)) }
        }
        let object = try JSONSerialization.jsonObject(with: response)
        let pretty = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        print(String(decoding: pretty, as: UTF8.self))
    default: break
    }
}

Task { @MainActor in
    do { try await run(); exit(0) }
    catch {
        FileHandle.standardError.write(Data("interestunctl: \(error.localizedDescription)\n".utf8))
        exit(1)
    }
}
dispatchMain()
