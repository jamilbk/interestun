import Foundation
import Network
import NetworkExtension
import os

private let logger = Logger(subsystem: "dev.jamilbk.interestun", category: "packet-tunnel")

/// NEPacketTunnelFlow is documented as thread-safe. Never captures the provider.
final class PacketWriter: @unchecked Sendable {
    let flow: NEPacketTunnelFlow
    init(_ flow: NEPacketTunnelFlow) { self.flow = flow }
}

func leasedPacketObjects(_ views: UnsafePointer<InterestunPacketView>, count: Int,
                         lease: UnsafeRawPointer) -> [NEPacket]? {
    guard count > 0, count <= 128 else { return nil }
    var packets = [NEPacket]()
    packets.reserveCapacity(count)
    for view in UnsafeBufferPointer(start: views, count: count) {
        guard let bytes = view.bytes else { return nil }
        interestun_ne_batch_retain(lease)
        let data = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: bytes), count: view.len,
                        deallocator: .custom { _, _ in interestun_ne_batch_release(lease) })
        packets.append(NEPacket(data: data, protocolFamily: sa_family_t(view.family)))
    }
    return packets
}

let writePacketBatch: InterestunWrite = { context, views, count, lease in
    guard let context, let views, let lease else { return false }
    return autoreleasepool {
        let writer = Unmanaged<PacketWriter>.fromOpaque(context).takeUnretainedValue()
        guard let packets = leasedPacketObjects(views, count: count, lease: lease) else { return false }
        return writer.flow.writePacketObjects(packets)
    }
}

let releasePacketWriter: InterestunRelease = { context in
    if let context { Unmanaged<PacketWriter>.fromOpaque(context).release() }
}

#if INTERESTUN_ETHERNET
typealias InterestunProviderBase = NEEthernetTunnelProvider
#else
typealias InterestunProviderBase = NEPacketTunnelProvider
#endif

final class PacketTunnelProvider: InterestunProviderBase, @unchecked Sendable {
    // Serializes lifecycle, input callbacks, housekeeping, and status. The Rust
    // peer threads write through the independent thread-safe PacketWriter.
    private let control = DispatchQueue(label: "dev.jamilbk.interestun.control", qos: .userInitiated)
    private var engine: OpaquePointer?
    private var timer: DispatchSourceTimer?
    private var generation: UInt64 = 0
    private var readCallbacks: UInt64 = 0
    private var largestReadBatch = 0
    private var utunOptions: [String: Any] = [:]

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping @Sendable (Error?) -> Void) {
        control.async {
            guard self.engine == nil, let data = options?["configuration"] as? Data else {
                completionHandler(TunnelError("Start using the Interestun CLI with --config; credentials are not saved in VPN preferences"))
                return
            }
            do {
                guard data.count <= 2 * 1024 * 1024 else { throw TunnelError("Start configuration is too large") }
                let configuration = try JSONDecoder().decode(TunnelConfiguration.self, from: data)
                try configuration.validate()
                let settings = try configuration.networkSettings()
                self.generation &+= 1
                let generation = self.generation
                self.setTunnelNetworkSettings(settings) { error in
                    self.control.async {
                        guard self.generation == generation else {
                            completionHandler(TunnelError("Tunnel start cancelled")); return
                        }
                        if let error {
                            logger.error("Network settings failed: \(error.localizedDescription, privacy: .public)")
                            completionHandler(error); return
                        }
                        let name = self.virtualInterface?.name ?? "packet-flow"
                        #if !INTERESTUN_ETHERNET
                        var optionError: UnsafeMutablePointer<CChar>?
                        guard let optionJSON = interestun_ne_utun_options(name, 4 * 1024 * 1024, 1024, &optionError) else {
                            completionHandler(takeRustError(optionError)); return
                        }
                        defer { interestun_ne_string_free(optionJSON) }
                        self.utunOptions = (try? JSONSerialization.jsonObject(with: Data(String(cString: optionJSON).utf8))) as? [String: Any] ?? [:]
                        #endif
                        var error: UnsafeMutablePointer<CChar>?
                        #if INTERESTUN_PACKET_FLOW || INTERESTUN_ETHERNET
                        let writer = Unmanaged.passRetained(PacketWriter(self.packetFlow)).toOpaque()
                        #if INTERESTUN_ETHERNET
                        let localAddresses = configuration.addresses.map { String($0.split(separator: "/")[0]) }.joined(separator: ",")
                        self.engine = interestun_ne_start_flow(configuration.uapi, configuration.cipher,
                            configuration.mtu, name, localAddresses, writer, writePacketBatch, releasePacketWriter, &error)
                        #else
                        self.engine = interestun_ne_start(configuration.uapi, configuration.cipher,
                            configuration.mtu, name, writer, writePacketBatch, releasePacketWriter, &error)
                        #endif
                        #else
                        self.engine = interestun_ne_start_utun(configuration.uapi, configuration.cipher, name, &error)
                        #endif
                        guard self.engine != nil else {
                            let failure = takeRustError(error)
                            logger.error("Rust startup failed: \(failure.message, privacy: .public)")
                            completionHandler(failure); return
                        }
                        self.readCallbacks = 0; self.largestReadBatch = 0
                        self.startHousekeeping()
                        #if INTERESTUN_PACKET_FLOW || INTERESTUN_ETHERNET
                        self.readNext(generation: generation)
                        #if INTERESTUN_ETHERNET
                        logger.notice("Tunnel ready on \(name, privacy: .public); NEEthernetTunnelProvider IPv4 packet flow; mapped rings unverified")
                        #else
                        logger.notice("Tunnel ready on \(name, privacy: .public); public NEPacketTunnelFlow; Skywalk path unverified")
                        #endif
                        #else
                        logger.notice("Tunnel ready on \(name, privacy: .public); existing NE utun descriptor; Network.framework UDP")
                        #endif
                        completionHandler(nil)
                    }
                }
            } catch { completionHandler(error) }
        }
    }

    private func readNext(generation: UInt64) {
        guard engine != nil, self.generation == generation else { return }
        packetFlow.readPacketObjects { [weak self] packets in
            guard let self else { return }
            // At most one outstanding read. This hop also avoids recursion if
            // the framework delivers a ready batch synchronously.
            self.control.async {
                guard let engine = self.engine, self.generation == generation else { return }
                self.readCallbacks &+= 1
                self.largestReadBatch = max(self.largestReadBatch, packets.count)
                for start in stride(from: 0, to: packets.count, by: 128) {
                    // NSData references pin stable byte addresses for this one
                    // synchronous copy into Rust's preallocated encryption pool.
                    let chunk = packets[start..<min(start + 128, packets.count)]
                    let buffers = chunk.map { $0.data as NSData }
                    var views = zip(buffers, chunk).map { data, packet in
                        InterestunPacketView(bytes: data.bytes.assumingMemoryBound(to: UInt8.self),
                            len: data.length, family: UInt32(packet.protocolFamily))
                    }
                    withExtendedLifetime(buffers) {
                        _ = views.withUnsafeMutableBufferPointer { interestun_ne_receive(engine, $0.baseAddress, $0.count) }
                    }
                }
                self.readNext(generation: generation)
            }
        }
    }

    private func startHousekeeping() {
        let timer = DispatchSource.makeTimerSource(queue: control)
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250), leeway: .milliseconds(10))
        timer.setEventHandler { [weak self] in
            guard let self, let engine = self.engine else { return }
            if !interestun_ne_tick(engine) {
                logger.error("Rust peer worker failed; stopping tunnel")
                self.stopEngine()
                self.cancelTunnelWithError(TunnelError("Rust peer worker stopped; see tunnel logs"))
            }
        }
        self.timer = timer
        timer.resume()
    }

    private func stopEngine() {
        generation &+= 1
        timer?.cancel(); timer = nil
        if let engine { self.engine = nil; interestun_ne_stop(engine) }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void) {
        control.async { self.stopEngine(); completionHandler() }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        control.async {
            guard messageData == Data("status".utf8), let engine = self.engine,
                  let text = interestun_ne_status(engine) else { completionHandler?(nil); return }
            defer { interestun_ne_string_free(text) }
            do {
                let data = Data(String(cString: text).utf8)
                var status = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
                #if INTERESTUN_PACKET_FLOW || INTERESTUN_ETHERNET
                status["read_callbacks"] = self.readCallbacks
                status["largest_read_callback"] = self.largestReadBatch
                #endif
                #if !INTERESTUN_ETHERNET
                status["utun_options"] = self.utunOptions
                #endif
                completionHandler?(try JSONSerialization.data(withJSONObject: status, options: [.sortedKeys]))
            } catch { completionHandler?(nil) }
        }
    }
}
