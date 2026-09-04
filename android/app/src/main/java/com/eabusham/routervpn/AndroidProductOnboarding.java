package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.widget.Toast;

/** Persistent native app onboarding. First launch never blocks the map-first controls. */
final class AndroidProductOnboarding {
    private static final String PREFS = "routervpn_product_onboarding_v2";
    private static final String DONE = "done";
    private static final String STEP = "step";
    private static final String HINTED = "map_first_hint_shown";

    private static final class OnboardingStep {
        final String title;
        final String body;
        OnboardingStep(String title, String body) { this.title = title; this.body = body; }
    }

    private static final OnboardingStep[] STEPS = new OnboardingStep[] {
            new OnboardingStep("Welcome to Router VPN", "This is the daily native Android VPN app. Setup Center deploys and administers the home node; app onboarding is separate from Setup Center onboarding. Install Router VPN once, then link one or many Router VPN or validated external nodes without reinstalling."),
            new OnboardingStep("Add or link a node", "Pair a home node with a short-lived one-time code created in the authenticated private Setup Center, or import router-vpn-bundle.json / validated external JSON in Connect. Nodes / Map lets you select, remember, remove and relink nodes. Pairing is LAN-only; private node data is separate from the generic APK."),
            new OnboardingStep("Android VPN permission and privacy", "The first full-device connection uses Android VpnService and asks for system VPN permission. Direct external exits that require strict lockdown also need Always-on VPN plus Block connections without VPN when the app tells you so. Never send WG/AWG private keys, PSKs, node secrets, Setup Center/admin tokens, SSH passwords or provider API secrets to external support or AI providers."),
            new OnboardingStep("Choose node, logical mode and base", "Select a Router VPN node and logical mode. Where compatible, the base can be WireGuard or AmneziaWG. AUTO stops at the first proven healthy eligible runtime. SMART AUTO connects first, tests simplification and restores the last-good path if reduction fails. CUSTOM keeps requested compatible layers. Android uses only real WG/AWG/libbox/Xray runtimes it can enforce; unsupported graphs remain unavailable with the exact reason."),
            new OnboardingStep("DNS and real query RTT", "DNS choices include Home AdGuard, Fastest measured, Custom UDP/TCP, DoT, DoH, DoH3 and Rescue with common IPv4/IPv6 resolvers. Retest measures actual A/AAAA DNS query RTT from the selected home node, not ICMP ping. Saving a resolver is not active proof; the tunnel/session must prove the selected DNS path."),
            new OnboardingStep("LAN access and strict kill switch", "LAN access is explicit shared state. LAN Off must block ordinary private-LAN reachability while preserving the minimum safe control/recovery path. Strict kill switch is different from Emergency stop and normal Disconnect. During protected failure/reconnect, prohibited IPv4/IPv6/DNS traffic must stay blocked; deliberate disconnect must release correctly."),
            new OnboardingStep("MTU, Auto MTU and Jumbo TUN", "Advanced MTU state is shared with the node profile: default/manual/auto/effective MTU. Retest is path/network specific and must not be used to invent a cause for an earlier cellular slowdown. Jumbo TUN is only for compatible TUN/proxy paths and never overrides the real path MTU."),
            new OnboardingStep("Multihop and external exits", "A real multihop is entry → exit → Internet; entry and exit must differ and Router VPN must prove the actual exit. Android supports only its real compatible subset. External WireGuard/OpenVPN/SOCKS5/Shadowsocks/Hysteria2 paths are available only when the Android dataplane can enforce them. Unsupported combinations fail closed."),
            new OnboardingStep("Forwarding where applicable", "Incoming forwarding is owned by the authenticated private Setup Center/router-agent and is only advertised for routable tunnel modes. Proxy-only/external paths cannot fake arbitrary DNAT. Protected DMZ must preserve Router VPN listeners and sensitive management/private ports."),
            new OnboardingStep("First connect and proof", "Start with WireGuard Raw as the baseline when available, then try AUTO or another ready logical mode. Approve Android VPN permission, watch real attempt/fallback progress, and require selected-node path proof before Connected. Then verify the real public VPN exit IP, selected DNS proof and IPv4/IPv6 behavior; generic Internet access alone is not success."),
            new OnboardingStep("Diagnostics, recovery and clean disconnect", "Use the app timeline/diagnostics for actual runtime/base/fallback, selected-path proof and DNS proof. Emergency stop is for a stuck protected runtime; normal Disconnect is the deliberate clean path. Network changes, app restarts, sleep/doze and leak behavior still require physical release testing rather than UI assumptions."),
            new OnboardingStep("Full guide and rerun", "Setup Center Full Guide remains the home server/router administration source of truth. Open Help → Run onboarding again whenever you need these steps. Final release proof still includes off-LAN, leak/DNS/IP, reconnect, visual/orientation and physical-device tests; source readiness is not a substitute.")
    };

    /**
     * First-run entry point used by the map-first ProductActivity.
     *
     * Older builds opened the full AlertDialog automatically here, which covered
     * Connect/Multihop/Settings/Mode/DNS before the user could use the app. The
     * newest product contract starts on the map and keeps onboarding opt-in.
     */
    static void showIfNeeded(Activity activity) {
        SharedPreferences prefs = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        if (prefs.getBoolean(DONE, false) || prefs.getBoolean(HINTED, false)) return;
        prefs.edit().putBoolean(HINTED, true).apply();
        Toast.makeText(activity, "Router VPN opens on the map. Full setup guide is available from Help whenever you want it.", Toast.LENGTH_LONG).show();
    }

    static void show(Activity activity, boolean force) {
        SharedPreferences prefs = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        boolean keepDone = prefs.getBoolean(DONE, false);
        int index = force ? 0 : clamp(prefs.getInt(STEP, 0));
        showStep(activity, prefs, index, keepDone);
    }

    private static void showStep(Activity activity, SharedPreferences prefs, int index, boolean keepDone) {
        int step = clamp(index);
        OnboardingStep item = STEPS[step];
        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setTitle(item.title)
                .setMessage("Step " + (step + 1) + " of " + STEPS.length + " • app onboarding is separate from Setup Center onboarding\n\n" + item.body)
                .setPositiveButton(step == STEPS.length - 1 ? "Finish" : "Next", (d, which) -> {
                    if (step == STEPS.length - 1) {
                        prefs.edit().putBoolean(DONE, true).putInt(STEP, 0).apply();
                    } else {
                        int next = step + 1;
                        prefs.edit().putBoolean(DONE, keepDone).putInt(STEP, next).apply();
                        showStep(activity, prefs, next, keepDone);
                    }
                })
                .setNeutralButton("Back", (d, which) -> {
                    int previous = Math.max(0, step - 1);
                    prefs.edit().putBoolean(DONE, keepDone).putInt(STEP, previous).apply();
                    showStep(activity, prefs, previous, keepDone);
                })
                .setNegativeButton("Close & resume later", (d, which) ->
                        prefs.edit().putBoolean(DONE, keepDone).putInt(STEP, step).apply())
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setEnabled(step > 0));
        dialog.show();
    }

    private static int clamp(int step) { return Math.max(0, Math.min(step, STEPS.length - 1)); }

    private AndroidProductOnboarding() {}

    // Shipping onboarding contract markers:
    // map first / non-blocking first-run hint / Help → Run onboarding again /
    // router-vpn-bundle.json / pairing / AUTO / WireGuard / AmneziaWG / DNS /
    // LAN Off / MTU/Jumbo / kill-switch / Multihop / forwarding / permissions /
    // Disconnect / private identity/path proof / Public exit / Diagnostics /
    // Emergency stop / Setup Center Full Guide / Run onboarding again.
}
