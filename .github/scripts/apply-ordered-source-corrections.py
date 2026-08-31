#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
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

    selection = text.split("private func selectSpecific", 1)[1].split("private func connectOrDisconnect", 1)[0]
    if "connectOrDisconnect()" in selection:
        raise SystemExit("iOS node selection still triggers Connect")
    path.write_text(text, encoding="utf-8")
    commit([rel], "Separate iOS node selection from Connect [skip ci]")


def patch_ios_location_map() -> None:
    rel = "ios/RouterVPN/App/IOSUnifiedProductView.swift"
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")

    replacements = (
        (
            "    var latencyByID: [String: Double]\n\n    func makeCoordinator()",
            "    var latencyByID: [String: Double]\n    var userCoordinate: CLLocationCoordinate2D?\n\n    func makeCoordinator()",
            "iOS map user coordinate input",
        ),
        (
            "            coordinatesByID[profile.id] = annotation.coordinate\n        }\n        if let entryID, let exitID",
            "            coordinatesByID[profile.id] = annotation.coordinate\n        }\n        if let userCoordinate {\n            let user = IOSUnifiedMapAnnotation(profileID: \"__user__\", role: \"user\")\n            user.coordinate = userCoordinate\n            user.title = \"YOU\"\n            user.subtitle = \"Real device location\"\n            map.addAnnotation(user)\n        }\n        if let entryID, let exitID",
            "iOS real user annotation",
        ),
        (
            "            switch node.role {\n            case \"entry\": view.markerTintColor = .systemBlue",
            "            switch node.role {\n            case \"user\": view.markerTintColor = .systemGreen; view.glyphText = \"YOU\"; view.displayPriority = .required\n            case \"entry\": view.markerTintColor = .systemBlue",
            "iOS user marker style",
        ),
        (
            "            guard let node = view.annotation as? IOSUnifiedMapAnnotation, node.role != \"packet\" else { return }",
            "            guard let node = view.annotation as? IOSUnifiedMapAnnotation, node.role != \"packet\", node.role != \"user\" else { return }",
            "iOS user marker selection guard",
        ),
        (
            "    @StateObject private var telemetry = IOSUnifiedTelemetry()\n    @AppStorage",
            "    @StateObject private var telemetry = IOSUnifiedTelemetry()\n    @StateObject private var deviceLocation = IOSDeviceLocation()\n    @AppStorage",
            "iOS location state owner",
        ),
        (
            "                IOSUnifiedMap(latencyByID: telemetry.latencyByID).environmentObject(model).ignoresSafeArea()",
            "                IOSUnifiedMap(latencyByID: telemetry.latencyByID, userCoordinate: deviceLocation.coordinate).environmentObject(model).ignoresSafeArea()",
            "iOS map location binding",
        ),
        (
            "                        .buttonStyle(.borderedProminent)\n                        .disabled(model.profileMutationBlocked)\n                        Spacer()",
            "                        .buttonStyle(.borderedProminent)\n                        .disabled(model.profileMutationBlocked)\n                        Button { deviceLocation.requestCurrentLocation() } label: {\n                            Image(systemName: deviceLocation.coordinate == nil ? \"location\" : \"location.fill\")\n                        }\n                        .buttonStyle(.bordered)\n                        .disabled(deviceLocation.isRequesting)\n                        .accessibilityLabel(\"Show my real location\")\n                        .contextMenu {\n                            Button(\"Hide my location\") { deviceLocation.clear() }\n                        }\n                        Spacer()",
            "iOS location button",
        ),
        (
            "        .onChange(of: model.activeRawProfile) { value in if model.connected && !value.isEmpty { model.recordIOSLastRuntime() } }\n        .task",
            "        .onChange(of: model.activeRawProfile) { value in if model.connected && !value.isEmpty { model.recordIOSLastRuntime() } }\n        .onChange(of: deviceLocation.statusText) { value in model.message = value }\n        .task",
            "iOS location status feedback",
        ),
    )
    for old, new, label in replacements:
        text = replace_once_or_verify(text, old, new, label)

    path.write_text(text, encoding="utf-8")
    commit([rel], "Wire real opt-in location into iOS map [skip ci]")


def patch_mobile_audit_roots() -> None:
    paths = [
        "deploy/recovered-map-first-ui-contract-audit.py",
        "deploy/recovered-native-ui-contract-audit.py",
    ]
    for rel in paths:
        path = ROOT / rel
        text = path.read_text(encoding="utf-8")
        for old, new in {
            '("client/android",),': '("android",),',
            '("client/ios", "client/iOS"),': '("ios/RouterVPN",),',
        }.items():
            if old in text or new in text:
                text = replace_once_or_verify(text, old, new, f"{rel} mobile root")
        path.write_text(text, encoding="utf-8")
        commit([rel], f"Point {Path(rel).stem} at native mobile sources [skip ci]")


def wire_map_audit_into_release_gate() -> None:
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


def remove_one_shot_files() -> None:
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
    patch_ios_location_map()
    patch_mobile_audit_roots()
    wire_map_audit_into_release_gate()
    run("git", "diff", "--check")
    remove_one_shot_files()
    print("ordered implementation pass committed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
