import SwiftUI
import Foundation
@preconcurrency import NetworkExtension

@MainActor
final class IOSForwardingMaster: ObservableObject {
    @Published private(set) var enabled: Bool?
    @Published private(set) var busy = false
    @Published private(set) var detail = "Connect a Router VPN node to read its forwarding master."
    private var sessionID: String?
    private var verifiedNodeID: String?
    private var generation = UUID()
    private var requestID: UUID?
    private var requestTask: Task<Void, Never>?

    // A confirmation belongs to the state shown when the dialog was opened,
    // never whichever server happens to be selected when Confirm is tapped.
    struct Intent: Sendable {
        fileprivate let generation: UUID
        fileprivate let nodeID: String
        fileprivate let sessionID: String
        let enabled: Bool
    }

    func intent(model: RouterVPNModel, enabled: Bool) -> Intent? {
        guard !busy, model.connected, !model.tunnelTransitioning,
              let node = model.unifiedSelectedProfile, node.normalizedNodeKind == "router-vpn",
              node.id == verifiedNodeID, let sessionID, self.enabled != nil else { return nil }
        return Intent(generation: generation, nodeID: node.id, sessionID: sessionID, enabled: enabled)
    }

    func invalidate() {
        generation = UUID(); sessionID = nil; verifiedNodeID = nil; enabled = nil
        requestID = nil; busy = false
        let previous = requestTask; requestTask = nil; previous?.cancel()
        detail = "Forwarding state is unknown until the active tunnel verifies it."
    }

    func request(model: RouterVPNModel, intent: Intent? = nil) async {
        guard !Task.isCancelled, !busy else { return }
        guard model.connected, !model.tunnelTransitioning,
              let node = model.unifiedSelectedProfile, node.normalizedNodeKind == "router-vpn" else {
            invalidate(); detail = "Connect a Router VPN node, not an external-only exit, to manage its forwarding master."; return
        }
        if let intent {
            guard intent.generation == generation, intent.nodeID == node.id,
                  intent.nodeID == verifiedNodeID, intent.sessionID == sessionID else {
                detail = "The connection changed after confirmation was opened. Refresh and confirm again."; return
            }
        }
        let epoch = generation, id = UUID(), nodeID = node.id, nodeName = node.name
        requestID = id; busy = true
        let task = Task { [weak self] in
            guard let self else { return }
            await execute(model: model, nodeID: nodeID, nodeName: nodeName, epoch: epoch, id: id, intent: intent)
        }
        requestTask = task
        await withTaskCancellationHandler {
            await task.value
        } onCancel: { task.cancel() }
        // Old completion must not clear a newer operation's busy state or task.
        if requestID == id {
            requestID = nil; requestTask = nil; busy = false
        }
    }

    private func execute(model: RouterVPNModel, nodeID: String, nodeName: String,
                         epoch: UUID, id: UUID, intent: Intent?) async {
        let requested = intent?.enabled, expectedSession = intent?.sessionID
        do {
            try Task.checkCancellation()
            guard requestID == id, epoch == generation else { return }
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" && $0.connection.status == .connected
            }
            // Loading preferences suspends. Recheck the captured node and ticket
            // BEFORE sending a mutation, including when a view has disappeared.
            try Task.checkCancellation()
            guard requestID == id, epoch == generation,
                  model.connected, !model.tunnelTransitioning,
                  model.unifiedSelectedProfile?.id == nodeID else { return }
            guard managers.count == 1, let manager = managers.first,
                  let session = manager.connection as? NETunnelProviderSession,
                  let connectedAt = session.connectedDate,
                  let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  let data = proto.providerConfiguration?["bundle"] as? Data,
                  ["wireguard", "libbox"].contains(proto.providerConfiguration?["engine"] as? String ?? "wireguard"),
                  let active = try? JSONDecoder().decode(ClientBundle.self, from: data),
                  active.selectedRouterID == nodeID,
                  active.routerProfiles.contains(where: { $0.id == nodeID && $0.normalizedNodeKind == "router-vpn" }) else {
                throw Self.issue("No single proved Router VPN tunnel owns this selected node.")
            }
            var message: [String: Any] = ["version": 1, "action": requested == nil ? "get" : "set", "node_id": nodeID]
            if let requested { message["enabled"] = requested; message["session_id"] = expectedSession }
            let bytes = try JSONSerialization.data(withJSONObject: message)
            let response = try await Self.send(bytes, session: session)
            try Task.checkCancellation()
            guard requestID == id, epoch == generation else { return }
            guard response.count <= 4096 else { throw Self.issue("Invalid forwarding reply size.") }
            struct Reply: Decodable {
                let version: Int; let ok: Bool; let enabled: Bool?
                let node_id: String?; let session_id: String?; let error: String?
            }
            let reply = try JSONDecoder().decode(Reply.self, from: response)
            guard reply.version == 1, reply.ok else { throw Self.issue(reply.error ?? "Tunnel could not verify forwarding state.") }
            guard epoch == generation, model.connected, !model.tunnelTransitioning,
                  model.unifiedSelectedProfile?.id == nodeID, session.status == .connected,
                  session.connectedDate == connectedAt,
                  (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["bundle"] as? Data == data,
                  reply.node_id == nodeID, let lease = reply.session_id, UUID(uuidString: lease) != nil,
                  requested == nil || lease == expectedSession, let verified = reply.enabled,
                  requested == nil || verified == requested else {
                throw Self.issue("Tunnel changed before confirmation. Server state is unknown; refresh before retrying.")
            }
            sessionID = lease; verifiedNodeID = nodeID; enabled = verified
            detail = "Verified through the active tunnel to \(nodeName.isEmpty ? nodeID : nodeName)."
        } catch {
            guard requestID == id, epoch == generation else { return }
            sessionID = nil; verifiedNodeID = nil; enabled = nil; detail = error.localizedDescription
        }
    }

    private static func send(_ bytes: Data, session: NETunnelProviderSession) async throws -> Data {
        let waiter = ReplyWaiter()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                waiter.install(continuation)
                guard !Task.isCancelled, session.status == .connected else {
                    waiter.finish(.failure(CancellationError())); return
                }
                do {
                    try session.sendProviderMessage(bytes) { data in
                        if let data { waiter.finish(.success(data)) }
                        else { waiter.finish(.failure(Self.issue("The tunnel did not return forwarding state."))) }
                    }
                } catch { waiter.finish(.failure(error)) }
                DispatchQueue.global().asyncAfter(deadline: .now() + 22) {
                    waiter.finish(.failure(Self.issue("Forwarding confirmation timed out. Refresh to learn the server's actual state.")))
                }
            }
        } onCancel: { waiter.finish(.failure(CancellationError())) }
    }

    nonisolated private static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.Forwarding", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    private final class ReplyWaiter: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Data, Error>?
        private var result: Result<Data, Error>?
        func install(_ continuation: CheckedContinuation<Data, Error>) {
            lock.lock()
            if let result { lock.unlock(); continuation.resume(with: result); return }
            self.continuation = continuation; lock.unlock()
        }
        func finish(_ result: Result<Data, Error>) {
            lock.lock()
            guard self.result == nil else { lock.unlock(); return }
            self.result = result; let continuation = self.continuation; self.continuation = nil; lock.unlock()
            continuation?.resume(with: result)
        }
    }
}

struct IOSForwardingMasterButton: View {
    @EnvironmentObject var model: RouterVPNModel
    @StateObject private var master = IOSForwardingMaster()
    @State private var showing = false
    @State private var connectionRevision = UUID()
    var body: some View {
        Button { showing = true } label: {
            VStack(spacing: 2) {
                Image(systemName: "arrow.triangle.branch")
                Text(master.enabled.map { $0 ? "ON" : "OFF" } ?? "?").font(.caption2)
            }
        }
        .buttonStyle(.bordered)
        .accessibilityLabel("Server forwarding master")
        .accessibilityValue(master.enabled.map { $0 ? "On" : "Off" } ?? "Unknown")
        .sheet(isPresented: $showing) { IOSForwardingMasterPanel(master: master).environmentObject(model) }
        .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in
            master.invalidate(); connectionRevision = UUID()
        }
        .task(id: "\(model.connected)-\(model.tunnelTransitioning)-\(model.unifiedSelectedProfile?.id ?? "")-\(connectionRevision)") {
            master.invalidate()
            guard model.connected, !model.tunnelTransitioning else { return }
            await master.request(model: model)
        }
        .onDisappear { master.invalidate() }
    }
}

struct IOSForwardingMasterPanel: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var master: IOSForwardingMaster
    @State private var proposed: IOSForwardingMaster.Intent?
    @State private var confirm = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Live server state") {
                    LabeledContent("Forwarding master", value: master.enabled.map { $0 ? "On" : "Off" } ?? "Unknown")
                    if master.busy { ProgressView("Verifying through the tunnel…") }
                    Text(master.detail).font(.caption).foregroundStyle(.secondary)
                    Button("Refresh state") { Task { await master.request(model: model) } }
                        .disabled(master.busy || !model.connected || model.tunnelTransitioning)
                    if let enabled = master.enabled {
                        Button(enabled ? "Turn master off" : "Turn master on") {
                            proposed = master.intent(model: model, enabled: !enabled)
                            confirm = proposed != nil
                        }
                            .disabled(master.busy || !model.connected || model.tunnelTransitioning)
                    }
                }
                Section("Scope") {
                    Text("This changes the Router VPN server's master for its existing forwarding rules, including other peers. It does not create rules, open phone ports, enable Protected DMZ, or expose management services.")
                    Text("Only the running VPN extension contacts the private agent. A state change appears here only after the server confirms it and an independent readback agrees.").font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Forwarding master")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .confirmationDialog("Change this server's forwarding master?", isPresented: $confirm, titleVisibility: .visible) {
                if let proposed {
                    Button(proposed.enabled ? "Enable existing forwarding" : "Disable existing forwarding") {
                        Task { await master.request(model: model, intent: proposed) }
                    }
                }
                Button("Cancel", role: .cancel) { }
            }
            .task {
                while !Task.isCancelled {
                    await master.request(model: model)
                    do { try await Task.sleep(for: .seconds(5)) } catch { return }
                }
            }
            .onDisappear {
                proposed = nil; confirm = false
                if master.busy { master.invalidate() }
            }
        }
    }
}
