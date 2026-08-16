import SwiftUI

private struct RouterVPNOnboardingStep: Identifiable {
    let id: Int
    let title: String
    let body: String
}

struct RouterVPNProductOnboardingView: View {
    @Environment(\.dismiss) private var dismiss
    @AppStorage("RouterVPNProductOnboardingDoneV2") private var done = false
    @AppStorage("RouterVPNProductOnboardingStepV2") private var storedStep = 0

    private let steps: [RouterVPNOnboardingStep] = [
        .init(id: 0, title: "Welcome to Router VPN", body: "This is the daily native iPhone/iPad VPN app. Setup Center deploys and administers the home node; app onboarding is separate from Setup Center onboarding. Install Router VPN once, then link one or many Router VPN or validated external nodes without reinstalling."),
        .init(id: 1, title: "Install and sign the Apple app truthfully", body: "The current GitHub CI artifact is an unsigned IPA/source-built app. It is not installable on an ordinary device until it is signed with a valid Apple identity and provisioning profile, or distributed through a properly signed TestFlight/App Store/sideload workflow. A green source build never counts as signed-device proof."),
        .init(id: 2, title: "Add or link a node", body: "Use LAN pairing with a short-lived one-time code from the authenticated private Setup Center, or import router-vpn-bundle.json / validated external node data. iOS may request Local Network permission for LAN pairing. Linked Nodes lets you select, remember, remove and relink nodes; private node data stays separate from the generic app."),
        .init(id: 3, title: "VPN permission, Network Extension and privacy", body: "The first full-device connection asks iOS/iPadOS for VPN permission for the PacketTunnel Network Extension. Approve it only for the signed Router VPN build you intended to install. WireGuardKit and supported Libbox paths are real source-wired engines; unsupported AWG/desktop-equivalent graphs stay unavailable. Never send WG/AWG private keys, PSKs, node secrets, admin tokens, SSH passwords or provider API secrets to external support or AI providers."),
        .init(id: 4, title: "Node, logical mode and base", body: "Choose the selected node and a logical mode whose iOS readiness is green. Where an iOS runtime/base is genuinely supported, Router VPN reports it; it never invents desktop parity. AUTO/SMART/CUSTOM semantics remain health-based: AUTO stops at the first proven healthy eligible path, SMART restores last-good state after a failed simplification, and CUSTOM keeps requested compatible layers."),
        .init(id: 5, title: "DNS and real query RTT", body: "DNS choices include Home AdGuard, Fastest measured, Custom UDP/TCP, DoT, DoH, DoH3 and Rescue with common IPv4/IPv6 resolvers. Retest measures actual A/AAAA DNS query RTT from the selected home node, not ICMP ping. iPhone system DoH is not Router VPN DNS proof; the active PacketTunnel/session must prove the selected resolver path."),
        .init(id: 6, title: "LAN access and kill-switch truth", body: "LAN access is explicit shared state. LAN Off must block ordinary private-LAN reachability while preserving the minimum safe control/recovery path. iOS protection uses the PacketTunnel route/network settings it can actually enforce; unsupported desktop-style firewall behavior must remain visibly unavailable. Emergency stop/intentional Disconnect is different from protected reconnect/failure."),
        .init(id: 7, title: "MTU, Auto MTU and Jumbo TUN", body: "MTU state is shared with the node profile: default/manual/auto/effective. Treat measured Auto MTU as network/path specific and do not guess that MTU caused a cellular slowdown without controlled proof. Jumbo TUN is only for compatible TUN/proxy paths and cannot override real path MTU."),
        .init(id: 8, title: "Multihop and external exits", body: "A real multihop is entry → exit → Internet and must prove the actual exit. Full desktop-equivalent iOS Router VPN multihop remains unavailable where the current iOS dataplane does not implement it. External/hop combinations are offered only when the selected Apple runtime can genuinely enforce them; unsupported graphs fail closed."),
        .init(id: 9, title: "Forwarding where applicable", body: "Incoming forwarding is only valid through a routable Router VPN tunnel path and the authenticated home-node forwarding API. Proxy-only paths cannot fake arbitrary DNAT. Protected DMZ and reserved management/private ports remain server-owned policy and must be validated off-LAN."),
        .init(id: 10, title: "First connect and proof", body: "After signing/installing and granting VPN permission, start with a genuinely supported baseline such as WireGuard Raw. Watch real connection phase/runtime/fallback. Connected requires selected-node path proof. Then verify the public VPN exit IP, Router VPN DNS proof and IPv4/IPv6 behavior on Wi-Fi and cellular; generic Internet access alone is not success."),
        .init(id: 11, title: "Diagnostics, recovery and physical-device proof", body: "Use the app state/recovery views for actual runtime, path proof and DNS proof. Normal Disconnect must cleanly stop the PacketTunnel. Network changes, background/reassert behavior, Wi-Fi↔cellular handoff, leak tests, sleep/background recovery and local-network pairing still require a real signed-device matrix before release."),
        .init(id: 12, title: "Full guide and rerun", body: "Setup Center Full Guide remains the server/router administration source of truth. Use Setup Guide in the native app to run this onboarding again. Final Apple release proof requires signed installation, real device launch, Network Extension start, VPN permission, path/DNS/public-exit proof and the visual/orientation matrix; an unsigned IPA is not that proof.")
    ]

    private var stepIndex: Int { max(0, min(storedStep, steps.count - 1)) }
    private var step: RouterVPNOnboardingStep { steps[stepIndex] }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    ProgressView(value: Double(stepIndex + 1), total: Double(steps.count))
                    Text("Step \(stepIndex + 1) of \(steps.count) • app onboarding is separate from Setup Center onboarding")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(step.title)
                        .font(.largeTitle.bold())
                        .fixedSize(horizontal: false, vertical: true)
                    Text(step.body)
                        .font(.body)
                        .lineSpacing(5)
                        .fixedSize(horizontal: false, vertical: true)
                    if stepIndex == 1 {
                        Label("Current CI output: unsigned IPA — signing/provisioning is still required for a physical device.", systemImage: "signature")
                            .font(.callout.bold())
                            .padding()
                            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 14))
                    }
                }
                .frame(maxWidth: 760, alignment: .leading)
                .padding(22)
            }
            .navigationTitle("Router VPN Setup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close & resume later") { dismiss() }
                }
            }
            .safeAreaInset(edge: .bottom) {
                HStack(spacing: 12) {
                    Button("Back") {
                        storedStep = max(0, stepIndex - 1)
                    }
                    .disabled(stepIndex == 0)
                    Spacer()
                    Button(stepIndex == steps.count - 1 ? "Finish" : "Next") {
                        if stepIndex == steps.count - 1 {
                            done = true
                            storedStep = 0
                            dismiss()
                        } else {
                            storedStep = stepIndex + 1
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(.horizontal, 22)
                .padding(.vertical, 12)
                .background(.regularMaterial)
            }
        }
    }
}

// Shipping Apple onboarding contract markers:
// unsigned IPA / TestFlight / App Store / sideload / provisioning / VPN permission /
// Network Extension / Local Network permission / router-vpn-bundle.json / pairing /
// AUTO / WireGuard / DNS / LAN Off / MTU/Jumbo / kill-switch / Multihop / forwarding /
// Disconnect / private identity/path proof / public VPN exit / Diagnostics /
// Setup Center Full Guide / Setup Guide.
