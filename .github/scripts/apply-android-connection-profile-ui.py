#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REL = "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java"
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


def patch_ui() -> None:
    text = PATH.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        '''        LinearLayout settingsRow=controlRow("Settings");Button settings=smallButton("Open settings");settings.setOnClickListener(v->showSettings());settingsRow.addView(settings);performanceButton=smallButton("Performance");performanceButton.setOnClickListener(v->showPerformance());settingsRow.addView(performanceButton);Button mtu=smallButton("MTU");mtu.setOnClickListener(v->showMtuHelp());settingsRow.addView(mtu);sheet.addView(settingsRow,margins(0,dp(7),0,0));''',
        '''        LinearLayout settingsRow=controlRow("Settings");Button settings=smallButton("Open settings");settings.setOnClickListener(v->showSettings());settingsRow.addView(settings);Button connectionProfiles=smallButton("Connections");connectionProfiles.setContentDescription("Add, load, update or delete a whole non-secret connection profile");connectionProfiles.setOnClickListener(v->showConnectionProfiles());settingsRow.addView(connectionProfiles);performanceButton=smallButton("Performance");performanceButton.setOnClickListener(v->showPerformance());settingsRow.addView(performanceButton);Button mtu=smallButton("MTU");mtu.setOnClickListener(v->showMtuHelp());settingsRow.addView(mtu);sheet.addView(settingsRow,margins(0,dp(7),0,0));''',
        "Android Connection Profiles settings control",
    )
    text = replace_once_or_verify(
        text,
        'Button profiles=smallButton("Profiles");profiles.setOnClickListener(v->showProfileManager());',
        'Button profiles=smallButton("Router nodes");profiles.setContentDescription("Manage linked Router VPN node records");profiles.setOnClickListener(v->showProfileManager());',
        "Android Router-profile label",
    )
    text = replace_once_or_verify(
        text,
        '''    private void showProfileManager(){''',
        '''    private void showConnectionProfiles(){
        AndroidConnectionProfilesDialog.show(this,nodeStore,exitStore,this::refreshAll);
    }

    private void showProfileManager(){''',
        "Android whole-profile launcher",
    )
    PATH.write_text(text, encoding="utf-8")
    commit([REL], "Expose Android whole-connection profile CRUD [skip ci]")


def cleanup() -> None:
    paths = [
        ".github/workflows/one-shot-android-connection-profile-ui.yml",
        ".github/scripts/apply-android-connection-profile-ui.py",
    ]
    for rel in paths:
        path = ROOT / rel
        if path.exists():
            path.unlink()
    commit(paths, "Remove completed Android profile UI automation [skip ci]")


def main() -> int:
    patch_ui()
    run("git", "diff", "--check")
    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
