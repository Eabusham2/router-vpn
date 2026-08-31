#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(args), flush=True)
    return subprocess.run(args, cwd=ROOT, check=check, text=True)


def commit(paths: list[str], message: str) -> None:
    run("git", "add", "-A", "--", *paths)
    changed = run("git", "diff", "--cached", "--quiet", check=False)
    if changed.returncode == 0:
        print(f"no change: {message}", flush=True)
        return
    if changed.returncode != 1:
        raise SystemExit(f"git diff --cached failed with {changed.returncode}")
    run("git", "commit", "-m", message)


def replace_once_or_verify(text: str, old: str, new: str, label: str) -> str:
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 1 and new_count == 0:
        return text.replace(old, new, 1)
    if old_count == 0 and new_count == 1:
        return text
    raise SystemExit(f"{label} drift: old={old_count} new={new_count}")


def patch_ios_selection() -> None:
    print("STAGE patch_ios_selection", flush=True)
    rel = "ios/RouterVPN/App/IOSUnifiedProductView.swift"
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        'Button { Task { await connectFastest() } } label: { Label(telemetry.isTestingFastest ? "Testing…" : "Test & connect fastest", systemImage: "bolt.fill") }',
        'Button { Task { await selectFastest() } } label: { Label(telemetry.isTestingFastest ? "Testing…" : "Test & select fastest", systemImage: "bolt.fill") }',
        "iOS Fastest button",
    )
    text = replace_once_or_verify(
        text,
        'Button { connectSpecific(profile) } label: {',
        'Button { selectSpecific(profile) } label: {',
        "iOS node button",
    )

    new_functions = '''    private func selectSpecific(_ profile: RouterProfile) {
        guard !model.profileMutationBlocked else { return }
        model.selectNode(profile.id)
        model.message = "Selected \\(profile.name.isEmpty ? profile.id : profile.name). Press Connect when ready."
    }
    private func selectFastest() async {
        guard !model.profileMutationBlocked else { return }
        let results = await telemetry.measureAll(routerProfiles, samples: 4)
        guard !model.profileMutationBlocked else {
            model.message = "VPN state changed while Fastest was measuring; the result was not selected."
            return
        }
        guard let winner = results.first else { model.message = telemetry.lastError; return }
        model.selectNode(winner.id)
        model.message = "Selected fastest live node: \\(winner.name) • \\(winner.shortLabel). Press Connect when ready with \\(selectedModeTitle)."
    }
'''
    old_functions = re.compile(
        r"    private func connectSpecific\(_ profile: RouterProfile\) \{.*?"
        r"(?=    private func connectOrDisconnect\(\))",
        re.DOTALL,
    )
    old_count = len(old_functions.findall(text))
    new_count = text.count("    private func selectSpecific(_ profile: RouterProfile) {")
    if old_count == 1 and new_count == 0:
        text = old_functions.sub(new_functions, text, count=1)
    elif old_count == 0 and new_count == 1:
        pass
    else:
        raise SystemExit(f"iOS selector-function drift: old={old_count} new={new_count}")

    if "private func connectSpecific" in text or "private func connectFastest" in text:
        raise SystemExit("old iOS auto-connect selectors remain")
    if text.count("private func selectFastest() async") != 1:
        raise SystemExit("iOS selectFastest count is not one")
    selection = text.split("private func selectSpecific", 1)[1].split("private func connectOrDisconnect", 1)[0]
    if "connectOrDisconnect()" in selection:
        raise SystemExit("iOS node selection still triggers Connect")
    if "Test & connect fastest" in text:
        raise SystemExit("old iOS Fastest label remains")
    path.write_text(text, encoding="utf-8")
    commit([rel], "Separate iOS node selection from Connect [skip ci]")


def patch_map_audit_roots() -> None:
    print("STAGE patch_map_audit_roots", flush=True)
    rel = "deploy/recovered-map-first-ui-contract-audit.py"
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    for old, new in {
        '("client/android",),': '("android",),',
        '("client/ios", "client/iOS"),': '("ios/RouterVPN",),',
    }.items():
        text = replace_once_or_verify(text, old, new, "map-first mobile root")
    path.write_text(text, encoding="utf-8")
    commit([rel], "Point map-first audit at native mobile sources [skip ci]")


def patch_map_audit_test() -> None:
    print("STAGE patch_map_audit_test", flush=True)
    rel = "deploy/recovered-map-first-ui-contract-audit-test.py"
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    if "import sys\n" not in text:
        text = text.replace("import importlib.util\n", "import importlib.util\nimport sys\n", 1)
    registration = "sys.modules[SPEC.name] = AUDIT\nSPEC.loader.exec_module(AUDIT)"
    if registration not in text:
        old = "AUDIT = importlib.util.module_from_spec(SPEC)\nSPEC.loader.exec_module(AUDIT)"
        if old not in text:
            raise SystemExit("map-first test module-loading anchor missing")
        text = text.replace(
            old,
            "AUDIT = importlib.util.module_from_spec(SPEC)\nsys.modules[SPEC.name] = AUDIT\nSPEC.loader.exec_module(AUDIT)",
            1,
        )
    method = '''
    def test_mobile_platform_roots_reference_native_projects(self) -> None:
        platforms = {platform.name: platform for platform in AUDIT.PLATFORMS}
        self.assertEqual(("android",), platforms["Android"].roots)
        self.assertEqual(("ios/RouterVPN",), platforms["iOS/iPadOS"].roots)
'''
    anchor = '\n\nif __name__ == "__main__":\n'
    if "test_mobile_platform_roots_reference_native_projects" not in text:
        if anchor not in text:
            raise SystemExit("map-first test insertion anchor missing")
        text = text.replace(anchor, "\n" + method + anchor, 1)
    path.write_text(text, encoding="utf-8")
    commit([rel], "Test native mobile shipping roots [skip ci]")


def wire_map_audit_into_release_gate() -> None:
    print("STAGE wire_map_audit_into_release_gate", flush=True)
    rel = "deploy/recovered-corrections-audit.py"
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    if "import subprocess\n" not in text:
        text = text.replace("import json\n", "import json\nimport subprocess\nimport sys\n", 1)
    block = '''for audit in (
    'deploy/recovered-map-first-ui-contract-audit.py',
    'deploy/recovered-map-first-ui-contract-audit-test.py',
):
    subprocess.run([sys.executable, str(ROOT/audit)], cwd=ROOT, check=True)
'''
    anchor = "print('Recovered chat-history corrections C1-C7: PASS')"
    if block not in text:
        if anchor not in text:
            raise SystemExit("recovered-corrections audit insertion anchor missing")
        text = text.replace(anchor, block + anchor, 1)
    path.write_text(text, encoding="utf-8")
    commit([rel], "Gate recovered map-first native shipping [skip ci]")


def validate_targeted_contracts() -> None:
    print("STAGE validate_targeted_contracts", flush=True)
    run(sys.executable, "ios/RouterVPN/test_runtime_selection_contract.py")
    run(sys.executable, "deploy/recovered-map-first-ui-contract-audit-test.py")
    run(sys.executable, "deploy/recovered-map-first-ui-contract-audit.py")
    run(sys.executable, "deploy/recovered-corrections-audit.py")
    run("git", "diff", "--check")


def remove_one_shot_files() -> None:
    print("STAGE remove_one_shot_files", flush=True)
    paths = [
        ".github/workflows/one-shot-ios-node-selection-fix.yml",
        ".github/scripts/apply-ordered-source-corrections.py",
    ]
    for rel in paths:
        path = ROOT / rel
        if path.exists():
            path.unlink()
    commit(paths, "Remove completed source-correction automation [skip ci]")


def main() -> int:
    patch_ios_selection()
    patch_map_audit_roots()
    patch_map_audit_test()
    wire_map_audit_into_release_gate()
    validate_targeted_contracts()
    remove_one_shot_files()
    print("ordered source corrections validated and committed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
