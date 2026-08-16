static const char *const titles[] = {
    "Welcome to Router VPN",
    "Add or link a node",
    "Linux permissions and privacy",
    "Choose node, logical mode and base",
    "DNS and real query RTT",
    "LAN access and strict kill switch",
    "MTU, Auto MTU and Jumbo TUN",
    "Multihop and external exits",
    "Forwarding where applicable",
    "First connection and proof",
    "Diagnostics, recovery and clean disconnect",
    "Full Guide and rerun"
};
static const char *const bodies[] = {
    "This is the daily native Linux Router VPN app. Setup Center deploys/administers the home server; app onboarding is separate from Setup Center onboarding. Install the generic app once, then link one or many Router VPN or validated external nodes without reinstalling.",
    "Pair a home node using a short-lived one-time code created in the authenticated private Setup Center, or import router-vpn-bundle.json / validated external JSON. Nodes & Map lets you select, remember, remove and relink nodes. Pairing is private-LAN only; private node data stays separate from the generic application package.",
    "Full-device TUN, routes, DNS and strict firewall helpers require the Linux permissions/capabilities configured by the package. Do not replace the native app with a browser or unrelated shell. Never send WG/AWG private keys, PSKs, node secrets, Setup Center/admin tokens, SSH passwords or provider API secrets to external support or AI providers.",
    "Choose the selected node and a logical mode. WireGuard and AmneziaWG are compatible base choices where the runtime supports them. AUTO stops at the first proven healthy eligible path. SMART AUTO connects first, then tests simplification and restores last-good state after a failed reduction. CUSTOM keeps requested compatible layers. Unsupported graphs remain unavailable with the exact reason.",
    "DNS choices include Home AdGuard, Fastest measured, Custom UDP/TCP, DoT, DoH, DoH3 and Rescue with common IPv4/IPv6 resolvers. Retest measures real A/AAAA DNS query RTT from the selected home node, not ICMP ping. Saving a resolver is not active proof; reconnect/session proof must show the selected DNS path.",
    "LAN access is explicit shared state. LAN Off must block ordinary private-LAN reachability while preserving minimum safe control/recovery traffic. Strict kill switch is different from Emergency stop and an intentional Disconnect: protected failure/reconnect must block prohibited IPv4/IPv6/DNS traffic, while deliberate disconnect must release correctly.",
    "Advanced MTU state is shared with the node profile: default/manual/auto/effective MTU. Retest Auto MTU only for one connected Router VPN path and treat the result as network/path specific. Jumbo TUN is advanced and only valid on compatible TUN/proxy paths; it never overrides real Internet path MTU or proves a past slowdown cause.",
    "A real multihop is entry -> exit -> Internet; entry and exit must differ and Router VPN must prove the actual exit. External WireGuard/OpenVPN/SOCKS5/Shadowsocks/Hysteria2 paths are used only where the Linux dataplane really supports them. Incompatible hop/protocol graphs fail closed instead of being labeled Connected.",
    "Incoming forwarding is administered by the authenticated private Setup Center/router-agent and is only advertised for routable tunnel modes. Proxy-only paths cannot fake arbitrary DNAT. Protected DMZ must reserve Router VPN listeners and sensitive management/private services. Validate forwarding from off-LAN before calling it working.",
    "Start with WireGuard Raw as the baseline when available, then use AUTO or another ready logical mode. Watch truthful phase/runtime/base/fallback events. Connected requires selected-node private path proof. Then verify the real public VPN exit IP, selected DNS proof and IPv4/IPv6 behavior; generic Internet access by itself is not success.",
    "Diagnostics shows session phase, actual runtime/base/fallback, selected-path proof, DNS proof and typed events. Emergency stop is for a stuck runtime; normal Disconnect is the deliberate clean path. Sleep/wake, network change, leak behavior and Portable-style clean resource release remain physical/runtime release gates rather than UI assumptions.",
    "Setup Center Full Guide remains the home server/router administration source of truth. Help -> Run Tutorial reopens this app onboarding at any time. Final release proof still includes off-LAN, leak/DNS/IP, reconnect and visual/DPI testing; source readiness is not a substitute."
};

/* Shipping onboarding contract markers:
 * pairing router-vpn-bundle.json AUTO WireGuard AmneziaWG DNS LAN Off MTU/Jumbo
 * kill-switch Multihop forwarding permissions Disconnect private identity/path proof
 * Public exit Diagnostics Emergency stop Setup Center Full Guide Run Tutorial
 */
