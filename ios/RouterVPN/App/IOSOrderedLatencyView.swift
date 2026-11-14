import SwiftUI

struct IOSOrderedLatencyCard: View {
    @EnvironmentObject private var model: RouterVPNModel
    @ObservedObject var probe: IOSOrderedLatency
    let otherTestRunning: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("50 responses per captured node", systemImage: "waveform.path.ecg").font(.headline)
            Text("Test the cumulative route through one node of the connected SOCKS path. Private HTTP timing includes connection establishment; the custom middle uses HTTPS timing after TLS. Saved history is not live readiness, ICMP ping, or a link speed.")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(Array(probe.ids.enumerated()), id: \.element) { position, id in
                VStack(alignment: .leading, spacing: 6) {
                    Text("Node \(position + 1) • \(id)").font(.subheadline)
                    if let history = probe.history[id] { Text(history).font(.caption.monospacedDigit()).textSelection(.enabled) }
                    Button("Retest node \(position + 1) — 50 responses") { probe.start(model, position: position) }
                        .disabled(probe.running || otherTestRunning || !IOSOrderedLatency.supported(model))
                }
            }
            if probe.running { Button("Cancel benchmark") { probe.cancel() } }
            Text(probe.text).font(.caption).textSelection(.enabled)
        }
        .padding(16).background(.background, in: RoundedRectangle(cornerRadius: 18))
        .onAppear { probe.load(model) }
        .onChange(of: model.activeSessionIdentity) { _ in probe.cancel(); probe.load(model) }
        .onChange(of: model.connected) { _ in probe.cancel(); probe.load(model) }
        .onChange(of: otherTestRunning) { value in if value { probe.cancel() } }
        .onDisappear { probe.cancel() }
    }
}
