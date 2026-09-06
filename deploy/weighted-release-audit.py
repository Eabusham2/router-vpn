#!/usr/bin/env python3
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]


def body(rel: str) -> str:
    p = ROOT / rel
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""


def all_markers(rel: str, *markers: str) -> bool:
    text = body(rel)
    return bool(text) and all(marker in text for marker in markers)


def none_markers(rel: str, *markers: str) -> bool:
    text = body(rel)
    return bool(text) and all(marker not in text for marker in markers)


def exists(rel: str) -> bool:
    return (ROOT / rel).is_file()


def no_self_mutating_workflows() -> bool:
    root = ROOT / ".github" / "workflows"
    if not root.is_dir():
        return False
    for path in root.glob("*.yml"):
        if "git push origin HEAD:main" in path.read_text(encoding="utf-8", errors="replace"):
            return False
    return True


@dataclass(frozen=True)
class Gate:
    name: str
    weight: float
    check: Callable[[], bool]
    kind: str = "source"
    note: str = ""


GATES = [
    Gate("core selected-node connection truth", 5.0, lambda: all_markers("cmd/client/main.go", "validateSelectedNodeProof(p, body)", "selected-router path proof failed")),
    Gate("router agent exact private identity proof", 4.0, lambda: all_markers("cmd/router-agent/main.go", "NodeID", "router-vpn-private-agent-v1") and all_markers("server/scripts/ensure-node-proof.py", "router-vpn-node-proof-v1\\n")),
    Gate("logical modes and fail-closed ALL/MAX runtime", 4.0, lambda: all_markers("modes/run-all.sh", "max-tls", "max-quic") and all_markers("modes/run-max.sh", "MAX")),
    Gate("DNS MTU throughput LAN forwarding management", 4.0, lambda: exists("modes/dns-policy.py") and exists("modes/mtu-policy.py") and all_markers("modes/mtu-throughput-tuner.py", "prove_node(profile)", "enforce_kill_switch()", "candidate_mtus(ceiling)", "pick_winner(results)", '"effective_mtu_source"] = "auto-throughput"', "set_interface_mtu(alias, family, original)") and all_markers("client/Optimize-RouterVPN-MTU.ps1", "Prove-Node $profile", "Ensure-KillSwitch $profile $alias", "Set-NetIPInterface", "durable_adoption=$false", "durable_owner='Router VPN Go controller /api/mtu/retest'", "if($Action-eq'apply')", "if($Action-eq'restore')") and all_markers("cmd/router-agent/main.go", "validateForward", "formatDNAT")),
    Gate("typed session rollback diagnostics", 3.0, lambda: all_markers("cmd/client/session_state.go", "connectionSession", "RollbackState", "DNSProof") and all_markers("cmd/client/extras.go", "/api/session", "/api/session/events")),
    Gate("profile-id traversal hardening", 3.0, lambda: exists("modes/profile-id.sh") and exists("modes/profile_id.py") and exists("modes/test_profile_id_safety.py")),
    Gate("archive extraction hardening", 3.0, lambda: all_markers("server/scripts/build-download-on-demand.py", "safe_extract_zip", "safe_extract_tar", "MAX_UNPACKED") and all_markers("server/scripts/download-broker.py", "MAX_COMPRESSION_RATIO", "cleanup_stale_temp")),
    Gate("atomic private bundle staging", 3.0, lambda: all_markers("cmd/client/bundle_staging.go", ".bundle-staging", "os.MkdirTemp", "os.Rename", "0o600") and all_markers("cmd/client/main.go", "newStagedBundle(", ".writeProfiles(", ".commit(")),
    Gate("immutable node identity on edits/import", 3.0, lambda: all_markers("cmd/client/main.go", "NodeProofID") and any(x in body("cmd/client/main.go") for x in ("linked router node proof identity cannot be changed", "incoming != identity"))),
    Gate("generic package secret separation", 4.0, lambda: all_markers("deploy/check-generic-package-secrets.py", "generic package contains private bundle", "package does not ship LICENSE") and all_markers("server/scripts/build-download-on-demand.py", "copy_generic_runtime", "write_blank_routers", "assert_generic_tree", "same-image prebuilt components", "same-SHA native GitHub artifact is required", "controller-only substitute")),
    Gate("same-SHA GitHub-first package policy", 4.0, lambda: all_markers("server/scripts/download-broker.py", "ROUTER_VPN_GITHUB_SHA", "artifact") and none_markers("server/portainer-current.yaml", "build:") and no_self_mutating_workflows()),
    Gate("Windows native WPF app + Portable lifecycle", 8.0, lambda: all_markers("client/RouterVPN-Windows-App.ps1", "PresentationFramework", "ShowDialog()", "/api/connect-logical") and all_markers("cmd/portable-launcher/main.go", "RouterVPN-Windows-App.ps1", "nativeCmd.Wait()") and none_markers("cmd/portable-launcher/main.go", "msedge.exe", "chrome.exe", "--app=") and all_markers("cmd/client/multihop_native_routes.go", 'runtime.GOOS == "windows"', "nativeWindowsMultihopCommand", "nativeMultihopConnect") and all_markers("client/native-multihop-windows.ps1", "Remove-PrivateRuntime", "Kill 'prepare'", "Kill 'release'")),
    Gate("Android raw WG/AWG native runtime", 3.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "GoBackend", "State.UP", "AndroidNativeProfilePolicy.patchWireGuardLikeConfig", "AndroidPathProbe.prove(privateBundle, 8000)", "recoverAfterNetworkChange", "network-transition recovery failed closed") and all_markers("android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java", "org.amnezia.awg.backend.GoBackend", "State.UP", "AndroidNativeProfilePolicy.patchWireGuardLikeConfig", "AndroidPathProbe.prove(privateBundle, 8000)", "recoverAfterNetworkChange", "network-transition recovery failed closed")),
    Gate("Android embedded libbox/Xray AUTO/SMART/CUSTOM/ALL", 3.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java", "AndroidPathProbe.prove", "SMART AUTO", "void all(File bundle,Callback cb)", "protectionRank", "ALL failed closed because no Android-native branch passed selected-node path proof", "Composite desktop MAX chains remain separate and are never faked on Android") and all_markers("android/app/src/main/java/com/eabusham/routervpn/NativeXrayController.java", "isCompositeProfile", "cannot be represented truthfully by native Xray alone") and exists("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java") and exists("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java") and all_markers("android/build-sing-box-libbox.sh", "LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998", "exactly one gomobile go.Seq runtime class") and none_markers("android/app/build.gradle", "libs/libxray.aar", "prepareXrayLibXray")),
    Gate("Android strict lockdown and transitions", 2.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java", "isAlwaysOn()", "isLockdownEnabled()", "resetNetwork", "updateDefaultInterface") and all_markers("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java", "isAlwaysOn()", "isLockdownEnabled()", "routerXrayRegisterDialerController", "routerXraySetDNS", "routerXrayResetDNS", "restartAfterNetworkChange", "AndroidPathProbe.prove(activeBundle")),
    Gate("Android real narrow multihop + multi-node store", 2.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java", "MAX_NODES = 24", "stableNodeIdentity") and all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java", '"shadowsocks".equals(exitMode)', '"hysteria2".equals(exitMode)', 'proxy.put("detour", "entry-wg")') and all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopRuntime.java", "AndroidPathProbe.prove(prepared.exitBundle", "Exit-node private path proof failed", "if (started) singBox.stop()")),
    Gate("iOS real pinned WireGuard PacketTunnel", 5.0, lambda: all_markers("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift", "WireGuardAdapter(with: self)", "RouterVPNWireGuardConfig.parse", "completionHandler(nil)")),
    Gate("iOS exact node proof, Libbox and strict unsupported fail-closed", 3.0, lambda: all_markers("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift", 'body["node_id"] as? String == expectedNodeID', "strict Apple kill switch requested", "includeAllNetworks", "enforceRoutes", 'case "libbox":', 'case "external-libbox":', "RouterVPNLibboxEngine", "proveExternalExit") and all_markers("ios/RouterVPN/App/IOSRuntimeSelection.swift", 'case libbox = "libbox"', "sing-box.json", "Xray-only, AmneziaWG-only, ALL/MAX and multihop combinations remain unavailable instead of faking Connected.") and all_markers("ios/RouterVPN/App/RouterVPNModelExternal.swift", "external-libbox", "External OpenVPN — unavailable on iOS until a pinned native Apple OpenVPN dataplane exists", "exact public-exit proof")),
    Gate("macOS native AppKit packages", 6.0, lambda: all_markers("client/macos/RouterVPNMacProduct.swift", "NSWindow(", "NSTabViewController", "--self-test") and all_markers("client/macos/build-native-app.sh", 'SRC="$ROOT/client/macos/RouterVPNMacProduct.swift"', '"$ADAPTIVE_SRC" "$HARDENED_UNIFIED_SRC"') and all_markers("deploy/package-macos-native.sh", "RouterVPN.app", "RouterVPN-darwin-amd64", "RouterVPN-darwin-arm64") and none_markers("client/macos/RouterVPNMacProduct.swift", "WKWebView", "import WebKit") and all_markers("cmd/client/multihop_native_darwin.go", 'filepath.Join(root, "modes", "native-multihop-darwin.sh")', "prepareNativeMultihop") and all_markers("modes/native-multihop-darwin.sh", "cleanup-private-runtime.py", "kill-switch-platform.py", "HOMEVPN_POLICY_PROFILE_ID") and all_markers("modes/darwin_kill_switch.py", 'PF_ANCHOR = "com.apple/router-vpn"', "block drop out quick all", "refusing protected connect", 'run_pf(["-X", token]')),
    Gate("Linux native GTK amd64+ARM packages", 6.0, lambda: all_markers("client/linux/routervpn-gtk.c", "gtk_window_new", "gtk_notebook_new", "--self-test") and all_markers(".github/workflows/linux-native-app.yml", "ubuntu-24.04", "ubuntu-24.04-arm") and none_markers("client/linux/routervpn-gtk.c", "WebKit", "WebView")),
    Gate("Setup Center persistent Full Guide lifecycle", 2.0, lambda: all_markers("server/scripts/setup_center_guide.py", "routervpn.setup-guide.v1", "if(!state.completed)setTimeout(show,250)", "Restart guide", "state.completed=true")),
    Gate("zero-knowledge method hierarchy and HOW onboarding", 1.0, lambda: all_markers("server/scripts/setup_center_guide.py", "1 — Simple / native method", "2 — Router VPN app", "3 — Universal third-party", "4 — Manual / custom", "Deploy the home node from zero", "Manual Connect still requires health proof and rollback on failure")),
    Gate("device download and no-server method UX", 1.0, lambda: all_markers("server/scripts/setup_center_ux_patch.py", "Download for this device", "text.includes('no servers found')", "'socks5'", "'overtls'", "'shadowsocks'")),
    Gate("real authenticated multi-provider server-side AI Help", 1.5, lambda: all_markers("server/scripts/ai_help_provider.py", "https://api.openai.com/v1/responses", "https://api.x.ai/v1/responses", "https://generativelanguage.googleapis.com/v1beta/models", "https://api.anthropic.com/v1/messages", "https://api.deepseek.com/chat/completions", "https://api.moonshot.ai/v1/chat/completions", '"claude": "anthropic"', '"grok": "xai"', '"kimi": "moonshot"', '"aiboard": "local"', "plain HTTP local AI is limited to loopback/private addresses", '"store": False', "MAX_CONCURRENT = 2") and all_markers("server/scripts/setup-center-ai-server.py", "/api/ai-help", "self._require_auth()", "credentials:'same-origin'") and none_markers("server/scripts/setup-center-ai-server.py", "sk-", "Authorization: Bearer")),
    Gate("private provider-neutral AI configuration lifecycle", 0.5, lambda: all_markers("server/scripts/configure-ai-help.sh", "stty -echo", "umask 077", "chmod 600", "ai-provider", "ai-model", "ai-api.key", "ai-base-url", "gemini", "anthropic", "deepseek", "xai", "moonshot", "local")),
    Gate("one-SHA authoritative native release workflow", 3.0, lambda: all_markers(".github/workflows/release-candidate.yml", "workflow_call:", "RouterVPN-release-candidate-${{ github.sha }}", "windows-native-smoke", "iOS/iPadOS real WireGuard + Libbox PacketTunnel") and all_markers(".github/workflows/build-all.yml", "uses: ./.github/workflows/release-candidate.yml")),
    Gate("short-lived CI package artifacts", 1.0, lambda: all("retention-days: 1" in body(rel) for rel in (".github/workflows/release-candidate.yml", ".github/workflows/client-apps-ci.yml", ".github/workflows/macos-native-app.yml", ".github/workflows/linux-native-app.yml"))),
    Gate("physical Windows Android iOS reconnect/leak/permission matrix", 4.0, lambda: exists("evidence/release/native-device-matrix.json"), "manual", "must be exact-SHA physical-device evidence"),
    Gate("external off-LAN simple-method interoperability", 3.0, lambda: exists("evidence/release/offlan-methods.json"), "manual", "must cover each exposed simple method"),
    Gate("native visual QA", 1.5, lambda: exists("evidence/release/visual-qa.json"), "manual", "real-device screenshots/checklist"),
    Gate("Apple signing/notarization release proof", 0.5, lambda: exists("evidence/release/apple-signing.json"), "manual", "unsigned CI does not earn this"),
    Gate("production exact-SHA deploy + live smoke", 2.0, lambda: exists("evidence/release/production-smoke.json"), "manual", "must be post-deploy live proof"),
    Gate("ASUS forwarding post-release revalidation", 1.0, lambda: exists("evidence/release/asus-forwarding.json"), "manual", "must be live router evidence"),
]


def main() -> int:
    total = sum(g.weight for g in GATES)
    if abs(total - 100.0) > 0.001:
        raise SystemExit(f"audit weights sum to {total}, expected 100")
    earned = source_earned = source_total = 0.0
    rows = []
    for gate in GATES:
        try:
            ok = bool(gate.check())
        except Exception:
            ok = False
        if ok:
            earned += gate.weight
        if gate.kind == "source":
            source_total += gate.weight
            if ok:
                source_earned += gate.weight
        rows.append({"name": gate.name, "weight": gate.weight, "kind": gate.kind, "pass": ok, "note": gate.note})
    result = {
        "score_percent": round(earned, 2),
        "source_score_percent": round((source_earned / source_total * 100.0) if source_total else 0.0, 2),
        "source_weight": source_total,
        "manual_live_weight": round(100.0 - source_total, 2),
        "gates": rows,
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
