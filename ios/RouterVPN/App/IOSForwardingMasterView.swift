import SwiftUI
import Foundation
@preconcurrency import NetworkExtension

@MainActor
final class IOSForwardingMaster: ObservableObject {
    @Published private(set) var enabled: Bool?
    @Published private(set) var busy = false
    @Published private(set) var detail = "Connect a Router VPN node to read its forwarding master."
    private var sessionID: String?
    private var generation = UUID()

    func invalidate() {
        generation = UUID(); sessionID = nil; enabled = nil
        detail = "Forwarding state is unknown until the active tunnel verifies it."
    }

    func request(model: RouterVPNModel, enabled requested: Bool? = nil) async {
        guard !busy else { return }
        guard model.connected, !model.tunnelTransitioning,
              let node = model.unifiedSelectedProfile, node.normalizedNodeKind == "router-vpn" else {
            invalidate(); detail = "Connect a Router VPN node, not an external-only exit, to manage its forwarding master."; return
        }
        let epoch = generation, expectedSession = sessionID
        if requested != nil && expectedSession == nil {
            detail = "Refresh the live server state before changing it."; return
        }
        busy = true
        defer { busy = false }
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" && $0.connection.status == .connected
            }
            guard managers.count == 1, let manager = managers.first,
                  let session = manager.connection as? NETunnelProviderSession,
                  let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  let data = proto.providerConfiguration?["bundle"] as? Data,
                  ["wireguard", "libbox"].contains(proto.providerConfiguration?["engine"] as? String ?? "wireguard"),
                  let active = try? JSONDecoder().decode(ClientBundle.self, from: data),
                  active.selectedRouterID == node.id,
                  active.routerProfiles.contains(where: { $0.id == node.id && $0.normalizedNodeKind == "router-vpn" }),
                  epoch == generation, model.connected, !model.tunnelTransitioning else {
                throw Self.issue("No single proved Router VPN tunnel owns this selected node.")
            }
            var message: [String: Any] = ["version": 1, "action": requested == nil ? "get" : "set", "node_id": node.id]
            if let requested { message["enabled"] = requested; message["session_id"] = expectedSession }
            let bytes = try JSONSerialization.data(withJSONObject: message)
            let response = try await Self.send(bytes, session: session)
            try Task.checkCancellation()
            guard response.count <= 4096 else { throw Self.issue("Invalid forwarding reply size.") }
            struct Reply: Decodable {
                let version: Int; let ok: Bool; let enabled: Bool?
                let node_id: String?; let session_id: String?; let error: String?
            }
            let reply = try JSONDecoder().decode(Reply.self, from: response)
            guard reply.version == 1, reply.ok else { throw Self.issue(reply.error ?? "Tunnel could not verify forwarding state.") }
            guard epoch == generation, model.connected, !model.tunnelTransitioning,
                  model.unifiedSelectedProfile?.id == node.id, session.status == .connected,
                  (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["bundle"] as? Data == data,
                  reply.node_id == node.id, let lease = reply.session_id, UUID(uuidString: lease) != nil,
                  requested == nil || lease == expectedSession, let verified = reply.enabled,
                  requested == nil || verified == requested else {
                throw Self.issue("Tunnel changed before confirmation. Server state is unknown; refresh before retrying.")
            }
            sessionID = lease; enabled = verified
            detail = "Verified through the active tunnel to \(node.name.isEmpty ? node.id : node.name)."
        } catch {
            guard epoch == generation else { return }
            sessionID = nil; enabled = nil; detail = error.localizedDescription
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
        .task(id: "\(model.connected)-\(model.tunnelTransitioning)") {
            master.invalidate()
            guard model.connected, !model.tunnelTransitioning else { return }
            await master.request(model: model)
        }
    }
}

struct IOSForwardingMasterPanel: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var master: IOSForwardingMaster
    @State private var proposed: Bool?
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
                        Button(enabled ? "Turn master off" : "Turn master on") { proposed = !enabled; confirm = true }
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
                    Button(proposed ? "Enable existing forwarding" : "Disable existing forwarding") {
                        Task { await master.request(model: model, enabled: proposed) }
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
        }
    }
}
