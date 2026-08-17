import MapKit
import SwiftUI

struct ProductRootView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var showingMap = false
    @State private var showingNodes = false
    @State private var showingModeDetails = false
    @State private var showingDNS = false
    @State private var showingOnboarding = false
    @State private var showingStrategies = false
    @State private var startupApplied = false

    init() {
        // ContentView still contains an older deployment-oriented tutorial for
        // explicit legacy/manual use. Suppress only its automatic first-run
        // presentation so the complete Apple-specific product onboarding below
        // is the one authoritative first-run/resume flow.
        UserDefaults.standard.set(true, forKey: "routerVPNOnboardingDoneV4")
        UserDefaults.standard.set(0, forKey: "routerVPNOnboardingStepV4")
    }

    var body: some View {
        ContentView()
            .safeAreaInset(edge: .top) {
                ScrollView(.vertical) {
                    IOSHomeSummaryView()
                        .environmentObject(model)
                        .padding(.horizontal, 10)
                        .padding(.top, 6)
                }
                .frame(maxHeight: 250)
                .background(.regularMaterial)
            }
            .overlay(alignment: .bottomTrailing) {
                VStack(alignment: .trailing, spacing: 8) {
                    Button { showingStrategies = true } label: {
                        Label("AUTO / SMART / CUSTOM", systemImage: "wand.and.stars")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Runs only iOS-runnable WireGuardKit or Libbox strategies; unsupported engine graphs stay unavailable")

                    Button {
                        UserDefaults.standard.set(0, forKey: "RouterVPNProductOnboardingStepV2")
                        showingOnboarding = true
                    } label: {
                        Label("Setup Guide", systemImage: "questionmark.circle.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Runs the persistent Router VPN app onboarding again, separate from Setup Center onboarding")

                    Button { showingNodes = true } label: {
                        Label("Linked Nodes", systemImage: "point.3.connected.trianglepath.dotted")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Selects, edits or removes Router VPN and external nodes, including nodes without coordinates")

                    Button { showingMap = true } label: {
                        Label("Nodes & Map", systemImage: "map.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Shows only real coordinates stored in imported Router VPN or external node profiles")

                    Button { showingModeDetails = true } label: {
                        Label("Mode Details", systemImage: "chart.bar.doc.horizontal")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Shows layers, estimated added latency, traffic overhead, speed loss, runtime readiness and exact reason for every logical mode")

                    Button { showingDNS = true } label: {
                        Label("DNS Settings", systemImage: "network")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Selects Home, Fastest, Custom, DoT, DoH, DoH3 or Rescue DNS and shows real home-node DNS query RTT results")
                }
                .padding(.trailing, 14)
                .padding(.bottom, 58)
            }
            .sheet(isPresented: $showingMap) { RouterVPNNodeMapSheet().environmentObject(model) }
            .sheet(isPresented: $showingNodes) { RouterVPNNodeManagerSheet().environmentObject(model) }
            .sheet(isPresented: $showingModeDetails) { RouterVPNModeMetricsSheet().environmentObject(model) }
            .sheet(isPresented: $showingDNS) { RouterVPNDNSSettingsSheet().environmentObject(model) }
            .sheet(isPresented: $showingOnboarding) { RouterVPNProductOnboardingView() }
            .sheet(isPresented: $showingStrategies) { IOSStrategySheet().environmentObject(model) }
            .onAppear {
                if !UserDefaults.standard.bool(forKey: "RouterVPNProductOnboardingDoneV2") { showingOnboarding = true }
            }
            .onChange(of: model.activeRawProfile) { _, value in
                if model.connected && !value.isEmpty { model.recordIOSLastRuntime() }
            }
            .task {
                guard !startupApplied else { return }
                startupApplied = true
                await model.applyIOSStartupPolicyIfNeeded()
            }
    }
}

private let routerVPNMapContract = "Map( latitude longitude No real node coordinates Linked Nodes"
private let routerVPNProductParityContract = "Home / Connect state actual public VPN exit Emergency Disconnect Setup Guide RouterVPNProductOnboardingDoneV2 AUTO SMART CUSTOM Mode Details DNS Settings Added latency traffic speed loss readiness exact reason Home Fastest Custom DoT DoH DoH3 Rescue"
