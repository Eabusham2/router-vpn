#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REL = "ios/RouterVPN/App/IOSUnifiedProductView.swift"
PATH = ROOT / REL


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, check=check)


def commit(paths: list[str], message: str) -> None:
    run("git", "add", "-A", "--", *paths)
    status = run("git", "diff", "--cached", "--quiet", check=False)
    if status.returncode == 0:
        return
    if status.returncode != 1:
        raise SystemExit(f"git diff failed: {status.returncode}")
    run("git", "commit", "-m", message)


def replace_once_or_verify(text: str, old: str, new: str, label: str) -> str:
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 1 and new_count == 0:
        return text.replace(old, new, 1)
    if old_count == 0 and new_count == 1:
        return text
    raise SystemExit(f"{label} drift: old={old_count} new={new_count}")


def compose_real_location_control() -> None:
    text = PATH.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        "                        .buttonStyle(.borderedProminent)\n                        .disabled(model.profileMutationBlocked)\n                        Spacer()",
        "                        .buttonStyle(.borderedProminent)\n                        .disabled(model.profileMutationBlocked)\n                        IOSUserLocationControl()\n                        Spacer()",
        "iOS user-location control composition",
    )
    PATH.write_text(text, encoding="utf-8")
    commit([REL], "Compose real iOS user location into map-first UI [skip ci]")


def compose_connection_profiles() -> None:
    text = PATH.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        "    @State private var showingPerformance = false\n    @State private var requireEncrypted = false",
        "    @State private var showingPerformance = false\n    @State private var showingProfiles = false\n    @State private var requireEncrypted = false",
        "iOS profile sheet state",
    )
    text = replace_once_or_verify(
        text,
        "                Section(\"Platform truth\") {",
        "                Section(\"Connection Profiles\") {\n                    Button(\"Add / Load / Update / Delete…\") { showingProfiles = true }\n                        .disabled(model.profileMutationBlocked)\n                    Text(\"Profiles save the selected node and supported non-secret Mode/CUSTOM, DNS, kill-switch, IPv6, LAN, base/fallback, AUTO-requirement, MTU and startup choices. Private keys, tokens and external credentials remain only in the linked node store.\")\n                        .font(.caption).foregroundStyle(.secondary)\n                }\n                Section(\"Platform truth\") {",
        "iOS Connection Profiles settings entry",
    )
    text = replace_once_or_verify(
        text,
        "            .sheet(isPresented: $showingPerformance) { IOSUnifiedPerformanceView(telemetry: telemetry).environmentObject(model) }",
        "            .sheet(isPresented: $showingPerformance) { IOSUnifiedPerformanceView(telemetry: telemetry).environmentObject(model) }\n            .sheet(isPresented: $showingProfiles) { IOSConnectionProfilesView().environmentObject(model) }",
        "iOS Connection Profiles sheet",
    )
    text = replace_once_or_verify(
        text,
        "schema-v4 profile-shared requirements\"",
        "schema-v4 profile-shared requirements Connection Profiles Add Load Update Delete real opt-in user location\"",
        "iOS unified UX contract marker",
    )
    PATH.write_text(text, encoding="utf-8")
    commit([REL], "Expose iOS whole-connection profile CRUD [skip ci]")


def cleanup_transport_automation() -> None:
    paths = [
        ".github/workflows/one-shot-ios-node-selection-fix.yml",
        ".github/scripts/apply-ordered-source-corrections.py",
        ".github/scripts/apply-ios-unified-composition.py",
    ]
    for rel in paths:
        path = ROOT / rel
        if path.exists():
            path.unlink()
    commit(paths, "Remove completed iOS source transport automation [skip ci]")


def main() -> int:
    compose_real_location_control()
    compose_connection_profiles()
    run("git", "diff", "--check")
    cleanup_transport_automation()
    print("iOS unified source composition committed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
