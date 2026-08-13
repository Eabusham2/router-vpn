#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
win = (ROOT / "client/RouterVPN-Windows-App.ps1").read_text(encoding="utf-8")
mac = (ROOT / "client/macos/RouterVPNMacApp.swift").read_text(encoding="utf-8")
linux = (ROOT / "client/linux/routervpn-gtk.c").read_text(encoding="utf-8")

concepts = [
    "Add Router", "pairing", "router-vpn-bundle.json", "AUTO", "WireGuard",
    "AmneziaWG", "DNS", "LAN Off", "MTU/Jumbo", "kill-switch", "Multihop",
    "forwarding", "permissions", "Disconnect", "private identity/path proof",
    "Public", "Diagnostics", "Emergency stop", "Setup Center Full Guide", "Rerun",
]
for name, source in (("Windows", win), ("macOS", mac), ("Linux", linux)):
    lower = source.lower()
    for concept in concepts:
        assert concept.lower() in lower, f"{name} tutorial missing {concept}"
    assert "separate from Setup Center onboarding" in source
    assert "Run Tutorial" in source

for marker in (
    "Show-RouterVPNTutorial", "windows-onboarding-v1.json", ".routervpn-state",
    "Close and resume later", "Save-RouterVPNOnboardingState 0 $true",
):
    assert marker in win, f"Windows onboarding missing {marker}"

for marker in (
    "RouterVPNNativeOnboardingDoneV1", "RouterVPNNativeOnboardingStepV1",
    "showTutorial(force:", "Close & resume later", "UserDefaults.standard.set(true",
):
    assert marker in mac, f"macOS onboarding missing {marker}"

for marker in (
    "show_tutorial(App *app, gboolean force)", "linux-onboarding-v1.ini",
    "gtk_assistant_new", "tutorial_save(state->state_path, TRUE, 0)",
    "show_tutorial(&app, FALSE)",
):
    assert marker in linux, f"Linux onboarding missing {marker}"

print("Native desktop onboarding contract: PASS")
