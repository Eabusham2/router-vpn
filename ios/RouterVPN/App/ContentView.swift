import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var importing = false
    var body: some View {
        NavigationStack {
            Form {
                Section("Connection") {
                    Toggle("AUTO", isOn: $model.auto)
                    Picker("Mode", selection: $model.selectedMode) {
                        ForEach(model.modes) { Text($0.name).tag($0.id) }
                    }.disabled(model.auto)
                    Toggle("DAITA", isOn: $model.daita)
                    Toggle("Jumbo TUN", isOn: $model.jumbo)
                    Button(model.connected ? "Disconnect" : "Connect") {
                        if model.connected { model.disconnect() } else { Task { await model.connect() } }
                    }
                }
                Section("SOCKS5 after VPN") { Text(model.socksSummary).textSelection(.enabled) }
                Section("Port forwarding — WG/AWG") {
                    Picker("Protocol", selection: $model.forwardProtocol) {
                        Text("Both").tag("both"); Text("TCP").tag("tcp"); Text("UDP").tag("udp")
                    }
                    TextField("External start", text: $model.forwardFrom).keyboardType(.numberPad)
                    TextField("External end", text: $model.forwardTo).keyboardType(.numberPad)
                    TextField("Target port (0 preserves range)", text: $model.forwardTarget).keyboardType(.numberPad)
                    HStack {
                        Button("Apply") { Task { await model.applyForward(dmz: false) } }
                        Button("Protected DMZ") { Task { await model.applyForward(dmz: true) } }
                        Button("Clear") { Task { await model.clearForward() } }
                    }
                }
                Section("Bundle") {
                    Button("Import router-vpn-bundle.json") { importing = true }
                    Text(model.message)
                }
                Section("Modes") {
                    ForEach(model.modes) { m in
                        VStack(alignment: .leading) {
                            Text(m.name).bold(); Text(m.protection).font(.caption)
                            Text("+\(m.pingMinMs, specifier: "%.1f")–\(m.pingMaxMs, specifier: "%.1f") ms • +\(m.trafficMinPct, specifier: "%.0f")–\(m.trafficMaxPct, specifier: "%.0f")% traffic")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("Router VPN")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
                guard case .success(let url) = result, url.startAccessingSecurityScopedResource() else { return }
                defer { url.stopAccessingSecurityScopedResource() }
                do { try model.importBundle(Data(contentsOf: url)) } catch { model.message = error.localizedDescription }
            }
        }
    }
}
