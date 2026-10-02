import Foundation
import SwiftUI
@preconcurrency import NetworkExtension

@MainActor final class IOSMTUClient: ObservableObject {
    @Published private(set) var running = false
    @Published private(set) var text = "No fresh MTU measurement for this session."
    private var generation = UUID()
    private var task: Task<Void, Never>?
    private var binding: IOSMTUControl.Binding?
    private var ownedRequest = ""

    func refresh(model: RouterVPNModel) async {
        guard !running else { return }
        let round = generation
        do {
            let captured = try await IOSMTUControl.capture(model)
            let request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            let data = try await IOSMTUControl.message(captured, model: model, operation: "mtu-status", request: request)
            let status = try JSONDecoder().decode(IOSMTUStatus.self, from: data)
            guard generation == round, !running else { return }
            text = status.summary
        } catch { if generation == round, !running { text = error.localizedDescription } }
    }
    func start(model: RouterVPNModel) {
        guard !running, !IOSMTUMeasurementGate.held else { return }
        let round = UUID(); generation = round
        let request = round.uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        running = true; text = "Capturing the current native TUN and private node…"
        task = Task { @MainActor [weak self, weak model] in
            guard let self, let model else { return }
            defer { if generation == round { running = false; task = nil; ownedRequest = ""; binding = nil } }
            do {
                let captured = try await IOSMTUControl.capture(model)
                try Task.checkCancellation()
                guard generation == round, !IOSMTUMeasurementGate.held else { throw CancellationError() }
                binding = captured; ownedRequest = request
                var operation = "mtu-start"
                let deadline = ProcessInfo.processInfo.systemUptime + 55
                while ProcessInfo.processInfo.systemUptime < deadline {
                    try Task.checkCancellation()
                    guard generation == round, !IOSMTUMeasurementGate.held else { throw CancellationError() }
                    let data = try await IOSMTUControl.message(captured, model: model, operation: operation, request: request)
                    let status = try JSONDecoder().decode(IOSMTUStatus.self, from: data)
                    guard generation == round, status.session_id == captured.session,
                          status.request_id == request else { throw CancellationError() }
                    text = status.summary
                    if status.complete == true || status.running == false { return }
                    operation = "mtu-status"
                    try await Task.sleep(for: .milliseconds(250))
                }
                throw IOSMTUControl.failure("MTU Retest timed out; cancellation requested.")
            } catch {
                if generation == round { cancelRequest(); text = "MTU result discarded: \(error.localizedDescription)" }
            }
        }
    }
    private func cancelRequest() {
        guard let binding, !ownedRequest.isEmpty, binding.connection.status == .connected,
              binding.connection.connectedDate == binding.connectedDate,
              let data = try? JSONSerialization.data(withJSONObject:
                ["operation": "mtu-cancel", "request_id": ownedRequest, "session_id": binding.session]) else { return }
        try? binding.connection.sendProviderMessage(data) { _ in }
    }
    func cancel() {
        cancelRequest(); generation = UUID(); task?.cancel(); task = nil
        ownedRequest = ""; binding = nil; running = false
        text = "No new measurement adopted; refreshing current native status."
    }
}

struct IOSMTUCard: View {
    @EnvironmentObject private var model: RouterVPNModel
    @StateObject private var probe = IOSMTUClient()
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Live MTU / Retest").font(.headline)
            Text(probe.text).font(.caption.monospacedDigit()).textSelection(.enabled)
            Button(probe.running ? "Cancel MTU Retest" : "Retest current native MTU") {
                if probe.running { probe.cancel() } else { probe.start(model: model) }
            }.disabled(!model.connected || (!probe.running && (IOSMTUMeasurementGate.held || !model.activeEngine.contains("libbox"))))
            Text("Measures authenticated private packets plus upload and download. Saved values and restored settings are never shown as fresh measurements. Manual and Jumbo policies do not enter Auto-MTU.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .task {
            while !Task.isCancelled {
                await probe.refresh(model: model)
                try? await Task.sleep(for: .seconds(1))
            }
        }
        .onChange(of: model.activeSessionIdentity) { _ in probe.cancel() }
        .onDisappear { probe.cancel() }
    }
}
