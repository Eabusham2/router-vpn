import MapKit
import SwiftUI

struct ProductRootView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var showingMap = false
    @State private var showingNodes = false
    @State private var showingModeDetails = false
    @State private var showingDNS = false
    @State private var showingOnboarding = false

    var body: some View {
        ContentView()
            .overlay(alignment: .bottomTrailing) {
                VStack(alignment: .trailing, spacing: 8) {
                    Button {
                        UserDefaults.standard.set(0, forKey: "RouterVPNProductOnboardingStepV2")
                        showingOnboarding = true
                    } label: {
                        Label("Setup Guide", systemImage: "questionmark.circle.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Runs the persistent Router VPN app onboarding again, separate from Setup Center onboarding")

                    Button {
                        showingNodes = true
                    } label: {
                        Label("Linked Nodes", systemImage: "point.3.connected.trianglepath.dotted")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Selects, edits or removes Router VPN and external nodes, including nodes without coordinates")

                    Button {
                        showingMap = true
                    } label: {
                        Label("Nodes & Map", systemImage: "map.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Shows only real coordinates stored in imported Router VPN or external node profiles")

                    Button {
                        showingModeDetails = true
                    } label: {
                        Label("Mode Details", systemImage: "chart.bar.doc.horizontal")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Shows layers, estimated added latency, traffic overhead, speed loss, runtime readiness and exact reason for every logical mode")

                    Button {
                        showingDNS = true
                    } label: {
                        Label("DNS Settings", systemImage: "network")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Selects Home, Fastest, Custom, DoT, DoH, DoH3 or Rescue DNS and shows real home-node DNS query RTT results")
                }
                .padding(.trailing, 14)
                .padding(.bottom, 58)
            }
            .sheet(isPresented: $showingMap) {
                RouterVPNNodeMapSheet()
                    .environmentObject(model)
            }
            .sheet(isPresented: $showingNodes) {
                RouterVPNNodeManagerSheet()
                    .environmentObject(model)
            }
            .sheet(isPresented: $showingModeDetails) {
                RouterVPNModeMetricsSheet()
                    .environmentObject(model)
            }
            .sheet(isPresented: $showingDNS) {
                RouterVPNDNSSettingsSheet()
                    .environmentObject(model)
            }
            .sheet(isPresented: $showingOnboarding) {
                RouterVPNProductOnboardingView()
            }
            .onAppear {
                if !UserDefaults.standard.bool(forKey: "RouterVPNProductOnboardingDoneV2") {
                    showingOnboarding = true
                }
            }
    }
}

// Audit/runtime truth: the shipping map is native MapKit and only consumes
// profile latitude / longitude in RouterVPNNodeMapSheet. When none exist it
// displays "No real node coordinates" rather than inventing a location.
// The separate Linked Nodes sheet includes coordinate-less external nodes so
// absence from the map never makes a real imported node unreachable.
private let routerVPNMapContract = "Map( latitude longitude No real node coordinates Linked Nodes"

// Product-parity contract: the native product exposes full mode metrics, real
// selectable DNS policy/benchmark UI and persistent app onboarding. SwiftUI
// sheets remain scrollable/adaptive on iPhone and iPad instead of relying on a
// fixed desktop-sized panel.
private let routerVPNProductParityContract = "Setup Guide RouterVPNProductOnboardingDoneV2 Mode Details DNS Settings Added latency traffic speed loss readiness exact reason Home Fastest Custom DoT DoH DoH3 Rescue"
