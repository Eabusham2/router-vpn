#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REL = "ios/RouterVPN/App/IOSConnectionProfilesView.swift"
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


def patch_store() -> None:
    text = PATH.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        'private let iosConnectionProfilesKey = "routervpn.connection-profiles.v1"\n',
        'private let iosConnectionProfilesKey = "routervpn.connection-profiles.v1"\nprivate let iosConnectionProfilesFile = "connection-profiles.json"\nprivate let iosConnectionProfilesMaximumBytes = 512 * 1024\n',
        "iOS private profile constants",
    )

    old_all = re.compile(
        r"    static func all\(\) -> \[IOSConnectionProfileRecord\] \{.*?\n    \}\n\n"
        r"(?=    static func snapshot)",
        re.DOTALL,
    )
    new_all = '''    private(set) static var lastStoreError = ""

    static func all() -> [IOSConnectionProfileRecord] {
        do {
            let values = try loadAll()
            lastStoreError = ""
            return values
        } catch {
            lastStoreError = error.localizedDescription
            return []
        }
    }

    private static func loadAll() throws -> [IOSConnectionProfileRecord] {
        if let data = try IOSPrivateJSONStore.read(
            iosConnectionProfilesFile,
            maximumBytes: iosConnectionProfilesMaximumBytes
        ) {
            let values = try JSONDecoder().decode([IOSConnectionProfileRecord].self, from: data)
            guard values.count <= 64 else { throw issue("Connection profile limit exceeded.") }
            return values.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        }

        guard let legacy = UserDefaults.standard.data(forKey: iosConnectionProfilesKey) else { return [] }
        guard !legacy.isEmpty, legacy.count <= iosConnectionProfilesMaximumBytes else {
            throw issue("Legacy connection profile store has an invalid size.")
        }
        let values = try JSONDecoder().decode([IOSConnectionProfileRecord].self, from: legacy)
        guard values.count <= 64 else { throw issue("Legacy connection profile limit exceeded.") }
        try persist(values)
        UserDefaults.standard.removeObject(forKey: iosConnectionProfilesKey)
        return values.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

'''
    old_count = len(old_all.findall(text))
    new_count = text.count('private(set) static var lastStoreError = ""')
    if old_count == 1 and new_count == 0:
        text = old_all.sub(new_all, text, count=1)
    elif old_count == 0 and new_count == 1:
        pass
    else:
        raise SystemExit(f"iOS profile load-store drift: old={old_count} new={new_count}")

    old_persist = '''    private static func persist(_ values: [IOSConnectionProfileRecord]) throws {
        let data = try JSONEncoder().encode(values)
        guard data.count <= 512 * 1024 else { throw issue("Connection profile store is too large.") }
        UserDefaults.standard.set(data, forKey: iosConnectionProfilesKey)
    }
'''
    new_persist = '''    private static func persist(_ values: [IOSConnectionProfileRecord]) throws {
        guard values.count <= 64 else { throw issue("Connection profile limit exceeded.") }
        let data = try JSONEncoder().encode(values)
        try IOSPrivateJSONStore.write(
            data,
            filename: iosConnectionProfilesFile,
            maximumBytes: iosConnectionProfilesMaximumBytes
        )
    }
'''
    text = replace_once_or_verify(text, old_persist, new_persist, "iOS private profile persistence")

    old_refresh = '    private func refresh() { profiles = IOSConnectionProfileStore.all(); if let selectedID, !profiles.contains(where: { $0.id == selectedID }) { self.selectedID = nil } }'
    new_refresh = '''    private func refresh() {
        profiles = IOSConnectionProfileStore.all()
        if !IOSConnectionProfileStore.lastStoreError.isEmpty {
            status = "Connection profile store failed closed: \\(IOSConnectionProfileStore.lastStoreError)"
        }
        if let selectedID, !profiles.contains(where: { $0.id == selectedID }) {
            self.selectedID = nil
        }
    }'''
    text = replace_once_or_verify(text, old_refresh, new_refresh, "iOS profile store error surface")

    PATH.write_text(text, encoding="utf-8")
    commit([REL], "Migrate iOS profiles to private atomic storage [skip ci]")


def cleanup() -> None:
    paths = [
        ".github/workflows/one-shot-ios-private-profiles.yml",
        ".github/scripts/apply-ios-private-profiles.py",
    ]
    for rel in paths:
        path = ROOT / rel
        if path.exists():
            path.unlink()
    commit(paths, "Remove completed iOS profile migration automation [skip ci]")


def main() -> int:
    patch_store()
    run("git", "diff", "--check")
    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
