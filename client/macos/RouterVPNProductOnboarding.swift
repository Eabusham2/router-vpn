import AppKit
import Foundation

final class RouterVPNProductOnboarding: NSObject {
    static let shared = RouterVPNProductOnboarding()

    private struct Step {
        let title: String
        let body: String
    }

    private let doneKey = "RouterVPNProductOnboardingDoneV2"
    private let stepKey = "RouterVPNProductOnboardingStepV2"
    private let mapFirstHintKey = "RouterVPNProductOnboardingMapFirstHintV1"

    private let steps: [Step] = [
        .init(title: "Welcome to Router VPN", body: "This is the daily native macOS VPN app. Setup Center deploys and administers the home node; app onboarding is separate from Setup Center onboarding. Install Router VPN once, then link one or many Router VPN or validated external nodes without reinstalling."),
        .init(title: "Add or link a node", body: "Use Pair with a short-lived one-time code created in the authenticated private Setup Center, or Import router-vpn-bundle.json / validated external JSON. Nodes & Map lets you select, remember, remove and relink nodes. Pairing is private-LAN only; node bundles are private data and do not belong inside the generic app package."),
        .init(title: "macOS permissions and privacy", body: "Full-device TUN, routes, DNS, firewall/kill-switch helpers and system Network Extension style operations may require macOS network or administrator approval. Only approve the Router VPN package you verified. Never send WG/AWG private keys, PSKs, node secrets, Setup Center/admin tokens, SSH passwords or provider API secrets to external support or AI providers."),
        .init(title: "Node, logical mode and WG/AWG base", body: "Choose the selected node, logical mode and compatible base: Auto, WireGuard or AmneziaWG. AUTO stops at the first proven healthy eligible path. SMART AUTO connects first, tests simplification and restores the last-good path if reduction fails. CUSTOM keeps requested compatible layers. Unavailable paths stay unavailable with an exact reason."),
        .init(title: "DNS and real query RTT", body: "DNS choices include Home AdGuard, Fastest measured, Custom UDP/TCP, DoT, DoH, DoH3 and Rescue with common IPv4/IPv6 resolvers. Retest measures actual A/AAAA DNS query RTT from the selected home node, not ICMP ping. Saving a resolver is not active proof; reconnect/session proof must show the selected DNS path."),
        .init(title: "LAN access and strict kill switch", body: "LAN access is explicit shared state. LAN Off must block ordinary private-LAN reachability while preserving the minimum safe control/recovery path. Strict kill switch is different from Emergency stop and an intentional Disconnect: it must block prohibited IPv4/IPv6/DNS traffic during protected failure/reconnect and release correctly on a deliberate disconnect."),
        .init(title: "MTU, Auto MTU and Jumbo TUN", body: "Advanced MTU state is shared with the node profile: default/manual/auto/effective MTU. Retest only a single connected Router VPN path with Auto MTU and treat the result as network/path specific. Jumbo TUN is advanced and is only valid on compatible TUN/proxy paths; it does not override real path MTU."),
        .init(title: "Multihop and external exits", body: "A real multihop is entry → exit → Internet; entry and exit must differ and Router VPN must prove the actual exit. External WireGuard/OpenVPN/SOCKS5/Shadowsocks/Hysteria2 paths are offered only where the macOS dataplane really supports them. Unsupported graphs fail closed rather than being labeled Connected."),
        .init(title: "Forwarding where applicable", body: "Incoming forwarding is managed through the authenticated private Setup Center/router-agent and is only advertised for routable tunnel modes. Proxy-only paths cannot fake arbitrary DNAT. Protected DMZ must preserve Router VPN listeners and sensitive management/private ports."),
        .init(title: "First connect and proof", body: "Start with WireGuard Raw as the baseline when available, then try AUTO or another ready logical mode. Watch real phase/runtime/base/fallback events. Connected requires selected-node private path proof. Then verify the real public VPN exit IP, DNS proof and IPv4/IPv6 behavior; generic Internet reachability alone is not success."),
        .init(title: "Diagnostics, recovery and clean exit", body: "Diagnostics and Help expose typed session progress, actual runtime/base/fallback, path proof and DNS proof. Emergency stop is for a stuck runtime; normal Disconnect is the deliberate clean path. Network-change, sleep/wake and leak behavior still require physical release testing and must never be inferred from a green-looking control."),
        .init(title: "Full guide and rerun", body: "Setup Center Full Guide remains the home server/router administration source of truth. Use Help → Run onboarding to reopen these steps at any time. The final release also requires off-LAN, leak, DNS/IP, reconnect, visual/DPI and signed Apple-device proof; source readiness is not a substitute for those tests.")
    ]

    /// Latest map-first contract: first launch never blocks Connect/Multihop/
    /// Settings/Mode/DNS with a modal wizard. The full guide remains explicit
    /// from Help and can still be rerun at any time.
    func presentIfNeeded(parent: NSWindow?) {
        let defaults = UserDefaults.standard
        guard !defaults.bool(forKey: doneKey), !defaults.bool(forKey: mapFirstHintKey) else { return }
        defaults.set(true, forKey: mapFirstHintKey)
        // No NSAlert here. Shipping UI is already visible and usable; Help owns
        // the explicit full onboarding entry point.
        _ = parent
    }

    func present(force: Bool, parent: NSWindow?) {
        let defaults = UserDefaults.standard
        let wasDone = defaults.bool(forKey: doneKey)
        var index = force ? 0 : max(0, min(defaults.integer(forKey: stepKey), steps.count - 1))

        while true {
            let step = steps[index]
            let alert = NSAlert()
            alert.alertStyle = .informational
            alert.messageText = step.title
            alert.informativeText = "Step \(index + 1) of \(steps.count) • app onboarding is separate from Setup Center onboarding\n\n\(step.body)"
            let next = alert.addButton(withTitle: index == steps.count - 1 ? "Finish" : "Next")
            next.keyEquivalent = "\r"
            let back = alert.addButton(withTitle: "Back")
            back.isEnabled = index > 0
            alert.addButton(withTitle: "Close & resume later")
            if let parent { alert.window.level = parent.level }

            switch alert.runModal() {
            case .alertFirstButtonReturn:
                if index == steps.count - 1 {
                    defaults.set(true, forKey: doneKey)
                    defaults.set(0, forKey: stepKey)
                    return
                }
                index += 1
                defaults.set(index, forKey: stepKey)
                defaults.set(wasDone, forKey: doneKey)
            case .alertSecondButtonReturn:
                index = max(0, index - 1)
                defaults.set(index, forKey: stepKey)
                defaults.set(wasDone, forKey: doneKey)
            default:
                defaults.set(index, forKey: stepKey)
                defaults.set(wasDone, forKey: doneKey)
                return
            }
        }
    }
}

extension ProductWindowController {
    @objc func runProductOnboarding() {
        RouterVPNProductOnboarding.shared.present(force: true, parent: window)
    }
}

// Shipping onboarding contract markers:
// map first • first launch does not block controls • Help → Run onboarding •
// Add or link a node • pairing • router-vpn-bundle.json • AUTO • WireGuard •
// AmneziaWG • DNS • LAN Off • MTU/Jumbo • kill-switch • Multihop • forwarding •
// permissions • Disconnect • private identity/path proof • Public exit •
// Diagnostics • Emergency stop • Setup Center Full Guide • Run onboarding.
