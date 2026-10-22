#!/usr/bin/env python3
"""Authoritative Tor censorship-circumvention and shipping contract."""
from __future__ import annotations

from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing Tor source: {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing Tor marker {marker!r}")


def forbid(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden Tor marker {marker!r}")


def need_android_tor_editor_controls(path: str) -> None:
    try:
        tree = ast.parse(read(path))
        controls = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "controls" for target in node.targets))
        rows = ast.literal_eval(controls.value)
        expected = {"rewritten-policy", "ipv6-default", "lan-default", "dns-precedence", "hidden-mode-list"}
        if not expected.issubset({row[0] for row in rows}):
            raise ValueError("an actual Tor editor mutation control is missing")
        guard = "rejected.returncode == 0 or failure not in rejected.stderr"
        if not any(isinstance(node, ast.If) and ast.unparse(node.test) == guard
                   and any(isinstance(child, ast.Raise) for child in node.body) for node in ast.walk(tree)):
            raise ValueError("mutated shipping editor must fail its specific executable assertion")
    except (SyntaxError, ValueError, TypeError, IndexError, StopIteration) as error:
        errors.append(f"{path}: Tor editor negative controls are incomplete: {error}")


# Canonical external profile model: PT family is explicit, dynamic Tor exit is
# never replaced with a user-supplied fixed public IP, and imported data cannot
# supply executable paths or torrc directives. ClientTransportPlugin generation
# belongs to the trusted runtime layer below, never to untrusted profile parsing.
need(
    "internal/common/types.go",
    "ExternalTorBridgeConfig",
    'Transport string `json:"transport,omitempty"`',
    'TorBridge *ExternalTorBridgeConfig `json:"tor_bridge,omitempty"`',
)
need(
    "internal/common/tor_bridge.go",
    'return "obfs4", nil',
    'return "meek_lite", nil',
    'return "snowflake", nil',
    'return "webtunnel", nil',
    'return "custom", nil',
    "TorBridgeTransport",
    "mixed Tor pluggable transports require transport=custom",
)
need(
    "internal/common/profile_schema.go",
    'case "tor":',
    'case "tor_bridge", "tor-bridge":',
    'ext.Protocol = "tor-bridge"',
    "Tor bridge has a dynamic circuit exit",
    "normalizeExternalTorBridge",
)
need(
    "internal/common/tor_plain_test.go",
    "TestPlainTor",
)
need(
    "internal/common/tor_bridge_test.go",
    "TestTorBridgeSupportsCircumventionTransportFamilies",
    "TestTorBridgeCustomAndAutoAllowRecognizedMixedPTSets",
    "modern meek no fingerprint",
    "TestTorBridgeRejectsCustomTransportInjection",
)

# Desktop runtime: trusted Tor/PT helpers, private torrc, exact transport set,
# bootstrap=100%, full-device TUN, owned children, and dynamic Tor exit proof.
# Windows x64/ARM64 retain native VPN engines/drivers. ARM64 uses the pinned
# x64 Tor/PT userspace helpers only after an OS compatibility and execution check.
need(
    "cmd/client/tor_bridge_runtime.go",
    'safeExecutable("lyrebird")',
    'safeExecutable("obfs4proxy")',
    "torBridgeTransportBinary",
    "torBridgeRuntimeCapabilityForRoot",
    'case "windows":',
    'windowsTorHostCompatibility()',
    'windowsTorRuntimeExecutable(root, "tor.exe")',
    'windowsTorRuntimeExecutable(root, "lyrebird.exe")',
    'windowsTorRuntimeExecutable(root, "sing-box.exe")',
    "native-tor-bridge-windows.ps1",
    'safeExecutable("powershell.exe")',
    '"-Action", "up"',
    '"-TunnelAlias", "router-vpn-tor"',
    "ClientTransportPlugin ",
    "strings.Join(transports, \",\")",
    "strictLiteralObfs4",
    "multiple or dynamic/CDN/WebRTC bootstrap egress",
    "selectedTorBridgeDNS",
    "HOMEVPN_TOR_PLUGIN_TRANSPORTS=",
    "HOMEVPN_TOR_PT_BINARY=",
)
need(
    "cmd/client/tor_bridge_windows_runtime.go",
    "torWindowsRuntimeWalkLimit",
    "safePinnedRuntimeExecutable",
    "findUniquePinnedRuntimeExecutable",
    "windowsTorRuntimeExecutable",
    'filepath.Join(windowsRoot, "tor-expert")',
    "must contain exactly one",
    "windowsTorHostCompatibility",
)
need(
    "cmd/client/tor_windows_compatibility_windows.go",
    "GetMachineTypeAttributes", "query.Call(0x8664", "attributes&1 != 0",
)
need(
    "client/test-windows-tor-compatibility.ps1",
    "ExpectedArchitecture", "Invoke-RouterVPNTorHelperVersion",
    "0x8664", "Install-PinnedTorExpertBundle", "No Tor network",
)
need(
    "client/Setup-Windows-Runtime.ps1",
    "TorExpertVersion = '15.0.24'",
    "TorExpertWindowsX64Sha256",
    "Install-PinnedTorExpertBundle",
    "tor.exe",
    "lyrebird.exe",
    "TorHelpersAvailable = $true",
    "GetMachineTypeAttributes",
    "Invoke-RouterVPNTorHelperVersion",
)
# Release pins remain reproducible after dist.torproject.org removes an older
# release. Installer and actual Windows execution tests use the same official
# archived bytes; neither a moving version nor an unchecked mirror is allowed.
for path in ("client/Setup-Windows-Runtime.ps1", "client/test-windows-tor-compatibility.ps1"):
    need(path, "https://archive.torproject.org/tor-package-archive/torbrowser/$TorExpertVersion/tor-expert-bundle-windows-x86_64-$TorExpertVersion.tar.gz")
    forbid(path, "https://dist.torproject.org/torbrowser/", "/latest/")
need("client/Setup-Windows-Runtime.ps1",
     "e9dc6ccc93cd6afa507193f4de284d6424233ff5102155cd2c94b259e8a22b65",
     "Get-FileHash -Algorithm SHA256", "if ($actual -ne $Sha256.ToLowerInvariant())")

need(
    "client/install-macos.sh",
    "refs/tags/lyrebird-0.8.1",
    "LYREBIRD_COMMIT_PREFIX=0b10edbb61e0",
    'rev-parse HEAD | cut -c1-12',
    "go mod verify",
    'LYREBIRD_TARGET="$ROOT/bin/lyrebird"',
    'LYREBIRD_SOURCE="$ROOT/bin/lyrebird.source"',
    "Router VPN-owned Lyrebird 0.8.1",
    "source-identity check failed",
)
need(
    "client/install-macos-current.sh",
    "/opt/router-vpn-client/bin:/usr/local/bin:/opt/homebrew/bin",
)
need(
    "client/install-linux.sh",
    "refs/tags/lyrebird-0.8.1",
    "LYREBIRD_COMMIT_PREFIX=0b10edbb61e0",
    'rev-parse HEAD | cut -c1-12',
    "go mod verify",
    'LYREBIRD_TARGET="$ROOT/bin/lyrebird"',
    'LYREBIRD_SOURCE="$ROOT/bin/lyrebird.source"',
    "Router VPN-owned Lyrebird 0.8.1",
    'Environment=PATH=$ROOT/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    "source-identity check failed",
)
need(
    "client/native-tor-bridge-windows.ps1",
    "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
    "AssignProcessToJobObject",
    "windows-kill-switch.ps1",
    "Bootstrapped 100%",
    "Tor SOCKS listener is unavailable after bootstrap",
    "Tor PT binary changed after capability proof",
    "Tor circumvention process exited; tearing down full-device path",
)
need(
    "cmd/client/tor_bridge_windows_runtime_test.go",
    "TestPinnedWindowsTorRuntimeResolverRequiresOneRegularExecutable",
    "TestPinnedWindowsTorRuntimeResolverRejectsSymlink",
    "TestWindowsTorControllerUsesPinnedNativeLifecycle",
)
need(
    "modes/native-tor-bridge.sh",
    "Bootstrapped 100%",
    "Tor process start is not connectivity",
    "HOMEVPN_TOR_PT_BINARY",
    "HOMEVPN_TOR_PLUGIN_TRANSPORTS",
    "Tor PT binary changed after capability proof",
    "legacy obfs4proxy cannot provide Snowflake or WebTunnel",
    "record \"$ROOT\" \"$PID_MODE\" \"$tor_pid\"",
    "record \"$ROOT\" \"$PID_MODE\" \"$sing_pid\"",
    "Tor circumvention process exited; tearing down full-device path",
)
need(
    "cmd/client/tor_bridge_proof.go",
    "IsTor",
    "publicTorExit",
    "check.torproject.org",
)
need(
    "cmd/client/tor_bridge_routes.go",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "/api/tor-bridge/connect",
    "tor_transport",
    "tor-project-is-tor-passed",
    "a.stopOwnedConnectionRuntime(cmd)",
    "a.persistProfilesLocked()",
)
need(
    "cmd/client/tor_bridge_dns.go",
    'case "tcp", "tls", "https"',
    "cannot use UDP/Fastest-UDP",
    "cannot use DoH3/QUIC",
)
need(
    "cmd/client/tor_bridge_dns_test.go",
    "TestTorBridgeDNSAllowsTCPCompatibleTransports",
    "TestTorBridgeDNSRejectsDatagramTransports",
)

# Capability and native profile-builder APIs are the one UI-facing source of
# truth. The shipping /api/tor-bridge/import boundary owns all Tor profile
# construction and delegates only final transactional persistence to the shared
# private external-profile store. A second unregistered Tor builder is forbidden.
need(
    "cmd/client/tor_bridge_capabilities.go",
    "obfs4",
    "meek_lite",
    "snowflake",
    "webtunnel",
    "custom",
    "active probing",
    "WebRTC",
    "HTTPS/domain-fronting",
    "strict_kill_switch",
    "upstream_hop",
    "torBridgeRuntimeCapabilityForRoot",
    'runtime.GOOS == "windows"',
    'windowsTorRuntimeExecutable(root, "lyrebird.exe")',
)
need(
    "cmd/client/tor_bridge_import.go",
    "torBridgeImportRequest",
    "/api/external-profile/import",
    "common.NormalizeRouterProfile",
    'profile.DNSMode, profile.DNSProtocol, profile.DNSPort = "home", "udp", 53',
    "strictLiteralObfs4",
    "dynamic bootstrap egress can be scoped safely",
    "standardExitFromExternalProfile(profile)",
    "externalRuntimePolicy(profile)",
    "updateExistingTorBridgeProfile",
    "preserveTorBridgeEditSettings",
    "profile id belongs to a non-Tor node; refusing replacement",
    "Public exit, durable latency/DNS benchmarks, and effective-MTU measurement",
)
need(
    "cmd/client/tor_bridge_import_test.go",
    "TestTorBridgeImportExistingIDUpdatesInPlace",
    "TestTorBridgeImportUpdatePreservesUnrelatedSettingsAndClearsPathMeasurements",
    "TestTorBridgeImportExistingNonTorIDRefusesReplacement",
    "TestTorBridgeImportUpdatePersistenceFailureRollsBackExistingNode",
)
if (ROOT / "cmd/client/tor_bridge_profile.go").exists():
    errors.append("cmd/client/tor_bridge_profile.go: duplicate/unregistered Tor profile builder must remain removed")

# Product semantics: PT is circumvention; the proved Tor circuit is the
# encrypted final path. Tor-as-upstream-hop remains unavailable.
need(
    "client/unified-control-center-v2.json",
    '"id": "tor-bridge"',
    '"final_transport": true',
    '"upstream_hop": false',
    '"meek_lite"',
    '"snowflake"',
    '"webtunnel"',
    '"custom"',
    '"tor-ntor-v3-circuit"',
    '"tor_dynamic_pt_strict_kill_switch_requires_process_scoped_egress": true',
)
need("client/routervpn_unified_control_center.py", '"tor-bridge"', "proven ntor-v3 circuit")
need("client/RouterVPN-Windows-UnifiedControlCenter.ps1", "Tor pluggable transport + proven ntor-v3 circuit")
need("client/macos/UnifiedControlCenterPolicy.swift", "Tor pluggable transport + proven ntor-v3 circuit")

# Native desktop forms must actually ship, not merely exist as orphan sources.
need(
    "client/macos/RouterVPNMenuBar.m",
    "Tor Bridges…",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "obfs4",
    "meek",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
    "short-lived volunteer WebRTC proxies",
    "profile data cannot inject ClientTransportPlugin commands",
)
need(
    "client/RouterVPN-Windows-TorBridge.ps1",
    "UnifiedTorButton",
    "Tor bridges…",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
)
need(
    "client/RouterVPN-Windows-App.ps1",
    "RouterVPN-Windows-TorBridge.ps1",
    "Add-RouterVPNTorBridgeWindowsShell -ProductSource",
)
need(
    "client/linux/routervpn-tor-bridge-v13.inc",
    "LinuxTorBridgeV13",
    "/api/tor-bridge/capabilities",
    "/api/tor-bridge/import",
    "obfs4",
    "meek / meek_lite",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
    "It never accepts executable paths or raw torrc directives.",
    "Update currently selected Tor node",
    "active_router_id(state->app)",
    'json_builder_set_member_name(builder, "id")',
    "Existing private bridge lines are never read back into this form",
)
need(
    "client/linux/routervpn-unified-shell-v8.inc",
    '#include "routervpn-tor-bridge-v13.inc"',
    "linux_unified_tor_v13",
    "Tor bridges…",
)
need(
    "client/linux/build-native-app.sh",
    "routervpn-unified-shell-v8.inc",
    "gcc -O2 -Wall -Wextra -Werror",
)

# Setup Center must explain the same real censorship-evasion family without
# publishing private bridge lines or pretending dynamic PT bootstrap is covered
# by the endpoint-only strict kill switch.
need(
    "server/scripts/setup_center_guide.py",
    "Tor censorship bridges in the Router VPN app",
    "obfs4",
    "meek / meek_lite",
    "Snowflake",
    "WebTunnel",
    "Auto / Custom",
    "short-lived volunteer WebRTC proxies",
    "dynamic CDN/WebRTC/bootstrap egress",
    "Tor's proved circuit remains the encrypted final path",
    "does not substitute homemade XOR/custom cryptography",
)

# Mobile clients own the full PT family, native lifecycle and dynamic exit
# proof. The original entry profile and selected DNS remain captured throughout
# preparation, VPN permission handoff, startup and cancellation.
need(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java",
    "AndroidTorProfile.isTor(e.protocol)", "AndroidTorProfile.validate(e)",
    'o.put("tor_policy",e.torPolicy)', 'o.put("tor_bridge",new JSONObject()',
)
need("android/app/src/main/java/com/eabusham/routervpn/AndroidTorProfile.java",
     "Libbox.routerCompileTorProfile", "Libbox.routerCompileProxyEntry",
     "capturedExit.equals(AndroidStandardExitStore.snapshot(selected))",
     '"Tor requires one owned runtime and one VPN interface."')
need("android/app/src/main/java/com/eabusham/routervpn/AndroidTorSession.java",
     "Libbox.routerTorCreateProofWithPredecessor", "captured.run()",
     "Libbox.routerStrategyDNSProof(server)", "captured.healthy()",
     "captured.cancel()", "network.equals(owner.network())")
need("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java",
     "Libbox.routerTorSetStateDirectory", "getNoBackupFilesDir()",
     "torPhysicalNetwork = torPhysical", "capturedTor.prove()",
     "Libbox.routerStrategyCloseService(commandServer)",
     "if (torOwner || externalOwner || capturedMAX != null)",
     "Native captured-path teardown remains unconfirmed; runtime ownership is retained.")
need("android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java",
     "showTorForm", "chooseNativeEntryMode(nodes.get(w),exit)",
     "NativeSingBoxController.nativeMultihopEntry(id)", "pendingEntryDigest", "pendingExitDigest",
     "A captured node changed while Android permission was open. Select the path again.")
# Tor and ordinary external exits share the captured owner/entry selector. Keep
# their executable cancellation, native-drain and permission negative coverage
# required instead of requiring the former Tor-only method names.
need("android/test_android_tor_session.py", "DNS completion owner check", "checked native close",
     "captured physical network binding", "Tor MTU Home generation ownership",
     "result.returncode!=0 and 'AssertionError' in result.stderr")
need("android/test_android_external_session.py", "checked native drain",
     "Home invalidation before native drain")
need("android/test_android_tor_form.py", "changed or denied permission started a stale capture",
     '"hidden-mode-list"', "entry.torPolicy=AndroidTorProfile.editedPolicy(saved,initialEditor,edited);")
need_android_tor_editor_controls("android/test_android_tor_form.py")
need("android/test_android_runtime_contract.py", '"test_android_tor_profile.py"',
     '"test_android_tor_form.py"', '"test_android_tor_session.py"',
     '"test_android_external_session.py"',
     '"test_android_start_layer_relay_lifecycle.py"')
need("deploy/test_android_tor_pinned.py", "with_naive_outbound", "TestRouterTorAndroidGeneratedGraphs",
     "all 348 captured graphs and 348 missing-engine controls")
forbid(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java",
    "Tor obfs4 bridge is unavailable on Android",
)
need(
    "ios/RouterVPN/App/RouterVPNModelExternal.swift",
    '"tor", "tor-bridge"',
    "capturedEntry = try externalTorEntryData(source: bundle)",
    'let entryBundleKey = tor ? "tor_entry_bundle" : "external_entry_bundle"',
    'proto.providerConfiguration?[entryBundleKey] = capturedEntry',
    'saved.providerConfiguration?[entryBundleKey] as? Data == capturedEntry',
    'saved.providerConfiguration?[tor ? "external_entry_bundle" : "tor_entry_bundle"] == nil',
    "current circuit exit verified",
)
need("ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift",
     'LibboxRouterCompileTorProfileWithPredecessor(String(decoding: source, as: UTF8.self), sessionID, predecessor, proofProfile ?? "", &failure)',
     "torPredecessorProfile: proofProfile",
     "torProfileJSON: String(decoding: source, as: UTF8.self)",
     'tor["session_id"] as? String == sessionID', 'tor["detour"] as? String == predecessorTag')
need("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift",
     'provider["tor_entry_bundle"]', "RouterVPNExternalExitBuilder.build(profile: selectedProfile, predecessorFiles: entryFiles, predecessorProfile: entryProfile,",
     "restoredExecution: restoredMultihopExecution)", "(runtime.policy?.executionRequested != nil) == (multihopExecutionSource != nil)",
     "engine.proveTor(sessionID: sessionID, profile: profile, predecessorProfile: runtime.torPredecessorProfile",
     "guard let profile = runtime.torProfileJSON", "engine.activateTorMTU()", "self.currentPathProofGuard() === externalPathGuard")
need("ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift",
     "LibboxRouterTorSetStateDirectory", "LibboxRouterTorCreateProofWithPredecessor", "TorProofDelivery",
     "LibboxRouterStrategyDNSProof(server", "request.healthy()", "request.cancel()",
     "Self.torRetirement.retain(server: owned", "torDelivery?.cancel()")
need("deploy/test_ios_tor_profile.py", "mobiletor.CompileProfile", "LibboxRouterCompileProxyEntry", "graphs==348", "profile_policy_combinations")
need("deploy/test_ios_libbox_delivery.py", "Tor requires its selected native DNS before Connected", "Tor stop cancels captured request immediately")
forbid(
    "ios/RouterVPN/App/RouterVPNModelExternal.swift",
    "Tor obfs4 bridge — unavailable",
    "Tor obfs4 bridges are unavailable",
)

# Homemade cipher ideas are explicitly superseded. The outer PT can disguise
# traffic, but confidentiality is provided by vetted Tor/tunnel cryptography.
for rel in (
    "client/unified-control-center-v2.json",
    "client/routervpn_unified_control_center.py",
    "client/RouterVPN-Windows-UnifiedControlCenter.ps1",
    "client/macos/UnifiedControlCenterPolicy.swift",
):
    forbid(rel, "xor cipher", "homemade cipher", "custom packet cipher")

if errors:
    print("TOR CIRCUMVENTION SHIPPING AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("TOR CIRCUMVENTION SHIPPING AUDIT: PASS")
