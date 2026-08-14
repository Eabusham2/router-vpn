import SwiftUI
import UniformTypeIdentifiers

struct RouterVPNNodeManagerSheet: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var editing: RouterProfile?
    @State private var importing = false
    @State private var pairHost = "192.168.50.133"
    @State private var pairCode = ""

    var body: some View {
        NavigationStack {
            List {
                Section("Add / link node data") {
                    TextField("AI Board LAN IP / hostname", text: $pairHost)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("6-digit one-time pairing code", text: $pairCode)
                        .keyboardType(.numberPad)
                    HStack {
                        Button("Pair from home LAN") {
                            let host = pairHost
                            let code = pairCode
                            pairCode = ""
                            Task { await model.linkFromLAN(host: host, code: code) }
                        }
                        .buttonStyle(.borderedProminent)
                        Button("Import node bundle") { importing = true }
                            .buttonStyle(.bordered)
                    }
                    Text("Pairing/importing adds a node bundle to the per-node store; it does not reinstall Router VPN or overwrite another home's raw WG/Libbox assets.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                if model.allNodeProfiles.isEmpty {
                    Section {
                        ContentUnavailableView(
                            "No linked nodes",
                            systemImage: "point.3.connected.trianglepath.dotted",
                            description: Text("Pair a Router VPN home node or import a validated node bundle above.")
                        )
                    }
                } else {
                    Section("Linked nodes") {
                        ForEach(model.allNodeProfiles) { profile in
                            nodeRow(profile)
                                .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                    Button(role: .destructive) {
                                        model.removeNode(profile.id)
                                    } label: {
                                        Label("Remove", systemImage: "trash")
                                    }
                                }
                        }
                    }
                }

                Section("Status") {
                    Text(model.message)
                        .font(.caption)
                        .textSelection(.enabled)
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Linked Nodes")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Done") { dismiss() }
                }
            }
            .sheet(item: $editing) { profile in
                RouterVPNNodeMetadataEditor(profile: profile)
                    .environmentObject(model)
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
                guard case .success(let url) = result, url.startAccessingSecurityScopedResource() else {
                    if case .failure(let error) = result { model.message = "Import failed: \(error.localizedDescription)" }
                    return
                }
                defer { url.stopAccessingSecurityScopedResource() }
                do {
                    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
                    guard data.count <= 32 * 1024 * 1024 else { throw URLError(.dataLengthExceedsMaximum) }
                    try model.linkNodeBundle(data)
                } catch {
                    model.message = "Import failed: \(error.localizedDescription)"
                }
            }
        }
    }

    @ViewBuilder
    private func nodeRow(_ profile: RouterProfile) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(profile.name.isEmpty ? profile.id : profile.name).font(.headline)
                        if profile.id == model.bundle?.selectedRouterID {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(.blue)
                        }
                    }
                    Text(profile.normalizedNodeKind == "external" ? "External • \(profile.external?.protocolName ?? "unknown")" : "Router VPN")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Edit") { editing = profile }
                    .buttonStyle(.borderless)
            }

            Text(model.nodeRuntimeSummary(profile))
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(profile.endpoint.isEmpty ? "No endpoint" : profile.endpoint)
                .font(.caption2.monospaced())
                .textSelection(.enabled)

            if let location = profile.location, !location.isEmpty {
                Text(location).font(.caption2).foregroundStyle(.secondary)
            }
            if let median = profile.latencyMedianMs {
                Text(String(format: "Latency median %.1f ms", median))
                    .font(.caption2).foregroundStyle(.secondary)
            }
            if profile.normalizedNodeKind == "external", let expected = profile.external?.expectedPublicIP, !expected.isEmpty {
                Text("Expected public exit: \(expected)")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }

            HStack {
                Button(profile.id == model.bundle?.selectedRouterID ? "Selected" : "Select") {
                    model.selectNode(profile.id)
                }
                .buttonStyle(.bordered)
                .disabled(profile.id == model.bundle?.selectedRouterID)

                if profile.normalizedNodeKind == "external" {
                    Button("Connect external") {
                        model.selectNode(profile.id)
                        Task { await model.connectSelectedExternal() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!["wireguard", "socks5", "shadowsocks", "hysteria2"].contains(profile.external?.protocolName.lowercased() ?? ""))
                }
            }
        }
        .padding(.vertical, 4)
    }
}

private struct RouterVPNNodeMetadataEditor: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    let profile: RouterProfile
    @State private var name: String
    @State private var location: String
    @State private var latitude: String
    @State private var longitude: String

    init(profile: RouterProfile) {
        self.profile = profile
        _name = State(initialValue: profile.name)
        _location = State(initialValue: profile.location ?? "")
        _latitude = State(initialValue: profile.latitude.map { String(format: "%.8f", $0) } ?? "")
        _longitude = State(initialValue: profile.longitude.map { String(format: "%.8f", $0) } ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Local display metadata") {
                    TextField("Name", text: $name)
                    TextField("Location label", text: $location)
                    TextField("Latitude", text: $latitude)
                        .keyboardType(.numbersAndPunctuation)
                    TextField("Longitude", text: $longitude)
                        .keyboardType(.numbersAndPunctuation)
                    Text("Coordinates are optional. Router VPN never invents or geocodes missing node locations.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Runtime identity") {
                    LabeledContent("Kind", value: profile.normalizedNodeKind)
                    LabeledContent("Endpoint", value: profile.endpoint)
                    if profile.normalizedNodeKind == "external" {
                        LabeledContent("Protocol", value: profile.external?.protocolName ?? "unknown")
                        LabeledContent("Expected exit", value: profile.external?.expectedPublicIP ?? "missing")
                    }
                    Text("Protocol credentials, private keys and expected-exit identity are not edited in this metadata sheet. Re-import a validated profile to change security-critical fields.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Edit Node")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        model.updateNodeMetadata(id: profile.id, name: name, location: location, latitudeText: latitude, longitudeText: longitude)
                        dismiss()
                    }
                }
            }
        }
    }
}
