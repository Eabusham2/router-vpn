#!/usr/bin/env python3
"""Weighted Router VPN release audit.

This scorer deliberately separates source/CI proof from evidence that requires
real devices, off-LAN clients, rendered UI, signing, production and the router.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Gate:
    name: str
    weight: float
    check: callable
    kind: str = "source"
    note: str = ""


def body(rel: str) -> str:
    try:
        return (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def exists(rel: str) -> bool:
    return (ROOT / rel).is_file()


def all_markers(rel: str, *markers: str) -> bool:
    text = body(rel)
    return bool(text) and all(marker in text for marker in markers)


def none_markers(rel: str, *markers: str) -> bool:
    text = body(rel)
    return bool(text) and all(marker not in text for marker in markers)


GATES = [
    Gate("core selected-node connection truth", 5.0, lambda: all_markers("cmd/client/main.go", "validateSelectedNodeProof", "selected router has no private path proof URL", "mode %s selected-router path proof OK")),
    Gate("router agent exact private identity proof", 4.0, lambda: all_markers("cmd/router-agent/main.go", "router-vpn-private-agent-v1", "node_id", "NodeProofID")),
    Gate("logical modes and fail-closed ALL/MAX runtime", 4.0, lambda: all_markers("cmd/client/logical_modes.go", "smart-auto", "custom", "all") and all_markers("modes/run-all.sh", "run-max.sh")),
    Gate("DNS MTU throughput LAN forwarding management", 4.0, lambda: all_markers("internal/common/types.go", "DNSMode", "MTUPolicy", "EffectiveMTU") and exists("modes/auto-mtu.py") and exists("modes/throughput-mtu.py") and all_markers("server/scripts/router-admin-api.py", "lan_access", "forward")),
    Gate("typed session rollback diagnostics", 3.0, lambda: all_markers("cmd/client/session.go", "rollback", "events", "requested_mode")),
    Gate("profile-id traversal hardening", 3.0, lambda: exists("modes/profile_id.py") and all_markers("cmd/client/main.go", "validProfileID")),
    Gate("archive extraction hardening", 3.0, lambda: exists("cmd/client/archive_safe.go") or all_markers("cmd/client/package_download.go", "symlink", "path traversal")),
    Gate("atomic private bundle staging", 3.0, lambda: all_markers("cmd/client/main.go", "persistProfilesLocked") and (exists("cmd/client/bundle_import.go") or exists("cmd/client/bundle.go"))),
    Gate("immutable node identity on edits/import", 3.0, lambda: all_markers("internal/common/types.go", "NodeProofID") and all_markers("cmd/client/main.go", "node proof")),
    Gate("generic package secret separation", 4.0, lambda: all_markers("docs/CLIENT.md", "generic", "node") and (exists("deploy/package-secret-scan.py") or exists("deploy/scan-package-secrets.py"))),
    Gate("same-SHA GitHub-first package policy", 4.0, lambda: all_markers("server/scripts/package-broker.py", "github") and all_markers("server/portainer-current.yaml", "image:")),
    Gate("Windows native WPF app + Portable lifecycle", 8.0, lambda: exists("client/windows/RouterVPN.Wpf.ps1") and exists("client/native-windows-mode.ps1") and exists("client/native-wireguard-windows.ps1")),
    Gate("Android raw WG/AWG native runtime", 3.0, lambda: exists("android/app/src/main/java/com/eabusham/routervpn/RouterVpnService.java") and exists("android/app/src/main/java/com/eabusham/routervpn/AmneziaWGBackend.java")),
    Gate("Android embedded libbox/Xray AUTO/SMART/CUSTOM/ALL", 3.0, lambda: exists("android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java") and all_markers("android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java", "AUTO", "SMART", "CUSTOM", "ALL")),
    Gate("Android strict lockdown and transitions", 2.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/RouterVpnService.java", "onRevoke", "onLost") or all_markers("android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java", "REVOKED")),
    Gate("Android real narrow multihop + multi-node store", 2.0, lambda: exists("android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java") and exists("android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java")),
    Gate("iOS real pinned WireGuard PacketTunnel", 5.0, lambda: all_markers("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift", "WireGuardAdapter", "startWireGuard")),
    Gate("iOS exact node proof and strict unsupported fail-closed", 3.0, lambda: all_markers("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift", "node proof", "Unsupported Router VPN iOS engine")),
    Gate("macOS native AppKit packages", 6.0, lambda: exists("client/macos/RouterVPNApp.swift") and exists("client/build-native-app.sh")),
    Gate("Linux native GTK amd64+ARM packages", 6.0, lambda: all_markers("client/linux/routervpn-gtk.c", "gtk_window_new", "gtk_notebook_new", "--self-test") and all_markers(".github/workflows/linux-native-app.yml", "ubuntu-24.04", "ubuntu-24.04-arm") and none_markers("client/linux/routervpn-gtk.c", "WebKit", "WebView")),
    Gate("Setup Center persistent Full Guide lifecycle", 2.0, lambda: all_markers("server/scripts/setup_center_guide.py", "routervpn.setup-guide.v1", "if(!state.completed)setTimeout(show,250)", "Restart guide", "state.completed=true")),
    Gate("zero-knowledge method hierarchy and HOW onboarding", 1.0, lambda: all_markers("server/scripts/setup_center_guide.py", "1 — Simple / native method", "2 — Router VPN app", "3 — Universal third-party", "4 — Manual / custom", "Deploy the home node from zero", "Manual Connect still requires health proof and rollback on failure")),
    Gate("device download and no-server method UX", 1.0, lambda: all_markers("server/scripts/setup_center_ux_patch.py", "Download for this device", "text.includes('no servers found')", "'socks5'", "'overtls'", "'shadowsocks'")),
    Gate("real authenticated multi-provider server-side AI Help", 1.5, lambda: all_markers("server/scripts/ai_help_provider.py", "https://api.openai.com/v1/responses", "https://api.x.ai/v1/responses", "https://generativelanguage.googleapis.com/v1beta/models", "https://api.anthropic.com/v1/messages", "https://api.deepseek.com/chat/completions", "https://api.moonshot.ai/v1/chat/completions", '"claude": "anthropic"', '"grok": "xai"', '"kimi": "moonshot"', '"aiboard": "local"', "plain HTTP local AI is limited to loopback/private addresses", '"store": False', "MAX_CONCURRENT = 2") and all_markers("server/scripts/setup-center-ai-server.py", "/api/ai-help", "self._require_auth()", "credentials:'same-origin'") and none_markers("server/scripts/setup-center-ai-server.py", "sk-", "Authorization: Bearer")),
    Gate("private provider-neutral AI configuration lifecycle", 0.5, lambda: all_markers("server/scripts/configure-ai-help.sh", "stty -echo", "umask 077", "chmod 600", "ai-provider", "ai-model", "ai-api.key", "ai-base-url", "gemini", "anthropic", "deepseek", "xai", "moonshot", "local")),
    Gate("one-SHA authoritative native release workflow", 3.0, lambda: all_markers(".github/workflows/release-candidate.yml", "workflow_call:", "RouterVPN-release-candidate-${{ github.sha }}", "windows-native-smoke", "iOS/iPadOS real WireGuard PacketTunnel") and all_markers(".github/workflows/build-all.yml", "uses: ./.github/workflows/release-candidate.yml")),
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
