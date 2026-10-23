#!/usr/bin/env python3
"""Check the shipping provenance phases, then optionally exercise real Xcode ordering.

The native fixture uses both actual stamp phase definitions and the unchanged
stamper. Only app/extension source bodies and native-engine dependencies are
replaced: the generated plists, embedding, build scheduler and PlistBuddy are real.
Run --native after XcodeGen is installed, before preparing the large frameworks.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import tempfile
import textwrap

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "ios/RouterVPN/project.yml"
STAMPER = ROOT / "ios/RouterVPN/stamp-provenance.sh"
GENERATED_PLIST = "$(TARGET_BUILD_DIR)/$(INFOPLIST_PATH)"
FAMILIES = {"RouterVPN": "ios-app", "RouterVPNPacketTunnel": "ios-packet-tunnel"}
SHA_ONE = "1234567890abcdef1234567890abcdef12345678"
SHA_TWO = "abcdef1234567890abcdef1234567890abcdef12"
CHECKS = 0


def check(condition: bool, message: str) -> None:
    global CHECKS
    if not condition:
        raise AssertionError(message)
    CHECKS += 1


def target_section(source: str, target: str) -> str:
    match = re.search(r"(?ms)^  " + re.escape(target) + r":\n(.*?)(?=^  \S|\Z)", source)
    if not match:
        raise AssertionError(f"Missing shipping target: {target}")
    return match.group(1)


def stamp_phase(source: str, target: str) -> dict:
    section = target_section(source, target)
    post = re.search(r"(?ms)^    postBuildScripts:\n(.*?)(?=^    \S|\Z)", section)
    if not post:
        raise AssertionError(f"Missing post-build provenance phase: {target}")
    matches = list(re.finditer(
        r"(?ms)^      - name: Stamp exact source provenance\n(.*?)(?=^      - |\Z)",
        post.group(1)))
    if len(matches) != 1:
        raise AssertionError(f"Expected one provenance phase: {target}")
    body = matches[0].group(1)
    if not re.search(r"(?m)^        basedOnDependencyAnalysis: false$", body):
        raise AssertionError(f"Provenance must run for each source SHA: {target}")
    inputs = re.search(r"(?m)^        inputFiles:\n((?:          - .+\n)+)", body)
    paths = [json.loads(line.strip()[2:]) for line in inputs.group(1).splitlines()] if inputs else []
    if paths != [GENERATED_PLIST]:
        raise AssertionError(f"Missing exact generated-plist dependency: {target}")
    if re.search(r"(?m)^        output(?:Files|FileLists):", body):
        raise AssertionError(f"The stamp must not claim another plist producer: {target}")
    script = re.search(r"(?ms)^        script: \|\n(.*)\Z", body)
    if not script:
        raise AssertionError(f"Missing shipping stamp command: {target}")
    script_body = textwrap.dedent(script.group(1))
    expected = f'ROUTER_VPN_ARTIFACT_FAMILY={FAMILIES[target]} bash "$SRCROOT/stamp-provenance.sh"'
    if expected not in script_body:
        raise AssertionError(f"Wrong target provenance family: {target}")
    return {"name": "Stamp exact source provenance", "basedOnDependencyAnalysis": False,
            "inputFiles": paths, "script": script_body}


def expect_dependency_failure(source: str, target: str) -> None:
    try:
        stamp_phase(source, target)
    except AssertionError as exc:
        check("generated-plist dependency" in str(exc), str(exc))
    else:
        raise AssertionError(f"Missing dependency negative control was accepted: {target}")


def portable_checks(source: str, work: Path) -> dict:
    phases = {target: stamp_phase(source, target) for target in FAMILIES}
    for target, phase in phases.items():
        check(phase["inputFiles"] == [GENERATED_PLIST], f"Exact generated plist input: {target}")
        check(not phase["basedOnDependencyAnalysis"], f"Always stamp current SHA: {target}")
        section = target_section(source, target)
        for key, value in (("RouterVPNSourceSHA", "$(ROUTER_VPN_SOURCE_SHA)"),
                           ("RouterVPNSourceRepository", "Eabusham2/router-vpn"),
                           ("RouterVPNArtifactFamily", FAMILIES[target])):
            check(f'INFOPLIST_KEY_{key}: "{value}"' in section, f"Generated key: {target}/{key}")
        # Removing either target's edge reproduces the exact scheduling defect.
        omitted = section.replace('        inputFiles:\n          - "' + GENERATED_PLIST + '"\n', "", 1)
        expect_dependency_failure(source.replace(section, omitted, 1), target)
        wrong = section.replace(GENERATED_PLIST, "$(SRCROOT)/Info.plist", 1)
        expect_dependency_failure(source.replace(section, wrong, 1), target)
    check("GENERATE_INFOPLIST_FILE: YES" in source, "Shipping targets must generate their plists")
    for workflow, job in (("client-apps-ci.yml", "ios-native"),
                          ("release-candidate.yml", "ios"),
                          ("ios-native-compile-smoke.yml", "ios-native-compile")):
        shipping = target_section((ROOT / ".github/workflows" / workflow).read_text(), job)
        install = shipping.index("brew install xcodegen")
        native = shipping.index("python3 deploy/test_ios_provenance_order.py --native")
        frameworks = shipping.index("./prepare-libbox.sh")
        check(install < native < frameworks, "Native ordering gate must precede framework work: " + workflow)

    env = dict(os.environ, ROUTER_VPN_SOURCE_SHA=SHA_ONE,
               ROUTER_VPN_SOURCE_REPOSITORY="Eabusham2/router-vpn",
               ROUTER_VPN_ARTIFACT_FAMILY="ios-app", TARGET_BUILD_DIR=str(work),
               INFOPLIST_PATH="RouterVPN.app/Info.plist")
    cases = [({"ROUTER_VPN_SOURCE_SHA": value}, "exact 40-character SHA")
             for value in ("", "main", "a" * 39, "a" * 41, "A" * 40)]
    cases += [({"ROUTER_VPN_SOURCE_REPOSITORY": "../invalid/repo"}, "repository is invalid"),
              ({"ROUTER_VPN_ARTIFACT_FAMILY": ""}, "artifact family is invalid"),
              ({}, "Generated target Info.plist is missing")]
    for overrides, expected in cases:
        # These failures occur before PlistBuddy, so the unchanged script is
        # executable on Linux as well. No plist-tool or filesystem double.
        result = subprocess.run(["bash", str(STAMPER)], env=env | overrides,
                                capture_output=True, text=True, timeout=10)
        check(result.returncode != 0 and expected in result.stderr, expected)
        check(not (work / env["INFOPLIST_PATH"]).exists(), "Failure must not synthesize a plist")
    return phases


def fixture_spec(phases: dict) -> dict:
    # Preserve real generated-plist and embedded-extension scheduling. The two
    # tiny source bodies intentionally exclude unrelated native engine builds.
    common = {"PRODUCT_NAME": "$(TARGET_NAME)", "MARKETING_VERSION": "0.8.0",
              "CURRENT_PROJECT_VERSION": "8", "GENERATE_INFOPLIST_FILE": "YES",
              "IPHONEOS_DEPLOYMENT_TARGET": "17.0", "SWIFT_VERSION": "6.0",
              "INFOPLIST_KEY_RouterVPNSourceSHA": "$(ROUTER_VPN_SOURCE_SHA)",
              "INFOPLIST_KEY_RouterVPNSourceRepository": "Eabusham2/router-vpn"}
    app_settings = common | {"PRODUCT_BUNDLE_IDENTIFIER": "com.eabusham.routervpn.provenancefixture",
                             "INFOPLIST_KEY_RouterVPNArtifactFamily": "ios-app",
                             "INFOPLIST_KEY_UILaunchScreen_Generation": "YES"}
    extension_settings = common | {
        "PRODUCT_BUNDLE_IDENTIFIER": "com.eabusham.routervpn.provenancefixture.PacketTunnel",
        "INFOPLIST_KEY_RouterVPNArtifactFamily": "ios-packet-tunnel", "SKIP_INSTALL": "YES",
        "INFOPLIST_KEY_NSExtension_NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel",
        "INFOPLIST_KEY_NSExtension_NSExtensionPrincipalClass": "$(PRODUCT_MODULE_NAME).PacketTunnelProvider"}
    return {"name": "RouterVPNProvenance", "targets": {
        "RouterVPN": {"type": "application", "platform": "iOS", "sources": ["App"],
                      "settings": {"base": app_settings},
                      "postBuildScripts": [copy.deepcopy(phases["RouterVPN"])],
                      "dependencies": [{"target": "RouterVPNPacketTunnel", "embed": True, "codeSign": False}]},
        "RouterVPNPacketTunnel": {"type": "app-extension", "platform": "iOS", "sources": ["PacketTunnel"],
                                  "settings": {"base": extension_settings},
                                  "postBuildScripts": [copy.deepcopy(phases["RouterVPNPacketTunnel"])]}}}


def run_native(phases: dict, work: Path) -> None:
    check(platform.system() == "Darwin", "--native requires the real Apple build system")
    xcodegen = shutil.which("xcodegen")
    xcodebuild = shutil.which("xcodebuild")
    check(bool(xcodegen and xcodebuild), "Install XcodeGen and Xcode before --native")
    for directory in ("App", "PacketTunnel"):
        (work / directory).mkdir()
    (work / "App/App.swift").write_text(
        "import UIKit\n@main final class FixtureDelegate: UIResponder, UIApplicationDelegate {\n"
        "    var window: UIWindow?\n}\n")
    (work / "PacketTunnel/PacketTunnelProvider.swift").write_text(
        "import NetworkExtension\nfinal class PacketTunnelProvider: NEPacketTunnelProvider {}\n")
    shutil.copyfile(STAMPER, work / "stamp-provenance.sh")
    (work / "project.json").write_text(json.dumps(fixture_spec(phases), indent=2))
    generated = subprocess.run([xcodegen, "generate", "--spec", str(work / "project.json")],
                               cwd=work, capture_output=True, text=True, timeout=30)
    check(generated.returncode == 0, "XcodeGen failed: " + generated.stdout + generated.stderr)
    project = work / "RouterVPNProvenance.xcodeproj"
    # XcodeGen must preserve the actual target input lists in its real PBX file.
    pbx = subprocess.run(["plutil", "-convert", "json", "-o", "-", str(project / "project.pbxproj")],
                         capture_output=True, text=True, timeout=10)
    check(pbx.returncode == 0, "Unable to inspect generated PBX: " + pbx.stderr)
    objects = json.loads(pbx.stdout)["objects"]
    for target, family in FAMILIES.items():
        native = next(value for value in objects.values()
                      if value.get("isa") == "PBXNativeTarget" and value.get("name") == target)
        stamps = [objects[item] for item in native["buildPhases"]
                  if objects[item].get("name") == "Stamp exact source provenance"]
        check(len(stamps) == 1, "One generated PBX stamp per target: " + target)
        check(stamps[0].get("inputPaths") == [GENERATED_PLIST], "PBX input edge: " + target)
        check(not stamps[0].get("outputPaths"), "PBX must not duplicate plist producer: " + target)
        check(str(stamps[0].get("alwaysOutOfDate")) == "1", "PBX stamp must run each build: " + target)
        check(f"ROUTER_VPN_ARTIFACT_FAMILY={family}" in stamps[0]["shellScript"], "PBX family: " + target)

    derived = work / "DerivedData"
    products = derived / "Build/Products/Release-iphoneos"
    app = products / "RouterVPN.app"
    built = {"RouterVPN": app / "Info.plist",
             "RouterVPNPacketTunnel": products / "RouterVPNPacketTunnel.appex/Info.plist"}
    embedded = app / "PlugIns/RouterVPNPacketTunnel.appex/Info.plist"
    command = [xcodebuild, "-project", str(project), "-scheme", "RouterVPN",
               "-configuration", "Release", "-sdk", "iphoneos", "-destination", "generic/platform=iOS",
               "-derivedDataPath", str(derived), "-parallelizeTargets", "-jobs", "4",
               "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO", "DEVELOPMENT_TEAM="]

    def build(sha: str, label: str, success: bool) -> str:
        result = subprocess.run(command + ["ROUTER_VPN_SOURCE_SHA=" + sha, "build"], cwd=work,
                                capture_output=True, text=True, timeout=150)
        log = result.stdout + result.stderr
        (work / (label + ".log")).write_text(log)
        check((result.returncode == 0) == success, label + " unexpected Xcode result:\n" + log[-24000:])
        return log

    def verify(sha: str, log: str) -> None:
        for target, path in built.items():
            plist = plistlib.loads(path.read_bytes())
            check(plist.get("RouterVPNSourceSHA") == sha, "Exact built SHA: " + target)
            check(plist.get("RouterVPNSourceRepository") == "Eabusham2/router-vpn", "Exact repository: " + target)
            check(plist.get("RouterVPNArtifactFamily") == FAMILIES[target], "Exact family: " + target)
            processing = [index for index, line in enumerate(log.splitlines())
                          if line.startswith("ProcessInfoPlistFile ") and str(path) in line]
            stamping = [index for index, line in enumerate(log.splitlines())
                        if line.startswith("PhaseScriptExecution Stamp\\ exact\\ source\\ provenance ")
                        and f"(in target '{target}' " in line]
            check(len(processing) == 1 and len(stamping) == 1 and processing[0] < stamping[0],
                  "Generated plist must precede its stamp: " + target)
        package = plistlib.loads(embedded.read_bytes())
        check(package.get("RouterVPNSourceSHA") == sha, "Embedded extension must carry the current SHA")
        check(package.get("RouterVPNArtifactFamily") == "ios-packet-tunnel", "Embedded extension family")

    first = build(SHA_ONE, "clean", True)
    verify(SHA_ONE, first)
    # Force the producers to run again while preserving the real incremental
    # build graph; a stale pre-existing plist cannot mask the ordering defect.
    for path in (*built.values(), embedded):
        path.unlink()
    second = build(SHA_TWO, "incremental", True)
    verify(SHA_TWO, second)
    failed = build("not-an-exact-sha", "invalid-sha", False)
    check("source provenance requires an exact 40-character SHA" in failed,
          "Malformed source identity must fail the actual Xcode build")
    print("iOS provenance real Xcode: clean + incremental app/embedded-extension ordering and invalid-SHA rejection PASS")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true", help="Build with actual Xcode and XcodeGen; never silently skip")
    args = parser.parse_args()
    source = PROJECT.read_text()
    with tempfile.TemporaryDirectory(prefix="routervpn-ios-provenance-") as directory:
        work = Path(directory).resolve()
        phases = portable_checks(source, work)
        if args.native:
            run_native(phases, work)
        else:
            print("iOS provenance native scheduler: not run in portable mode; mandatory --native gate runs after XcodeGen installation")
    print(f"iOS provenance generated-plist dependency + fail-closed stamper: PASS ({CHECKS} checks; four dependency negative controls)")


if __name__ == "__main__":
    main()
