#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    p = ROOT / path
    try:
        return p.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{path}: unreadable: {exc}")
        return ""


def require(path: str, *markers: str) -> str:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing settings marker {marker!r}")
    return body


def require_combined(label: str, paths: tuple[str, ...], *markers: str) -> str:
    bodies = [(path, read(path)) for path in paths]
    combined = "\n".join(body for _, body in bodies)
    for marker in markers:
        if marker not in combined:
            errors.append(f"{label}: missing composed settings marker {marker!r} across {', '.join(paths)}")
    return combined


def ios_ordered_profile_issues(sources: dict[str, str]) -> list[str]:
    """Audit scoped shipping source; executed Swift tests remain separate gates."""
    problems = []
    scopes = (
        ("profiles", "schema", None, None, ("iosConnectionProfilesSchemaVersion = 8", "var multihopNodes: [IOSMultihopNodeSelection]?", "var chainPolicies: [IOSConnectionEntryCapture]?")),
        ("models", "ordered selection", "struct IOSMultihopNodeSelection:", "struct RouterProfile:", (
            "static let maximumNodes = 8",
            '[entryID, entryMode, exitID, exitMode].allSatisfy({ $0 == nil || $0 == "" })',
            "seen.insert(node.id).inserted", "nodes.last?.id != controlID")),
        ("models", "bounded imported position", "static func supportsImportedMiddle(", "static func transportName(", (
            'guard (3...maximumNodes).contains(count), position == count - 2 else { return false }',
            'if ["socks5", "http-connect", "https-connect", "openvpn"].contains(mode) { return true }',
            'return mode == "shadowsocks"')),
        ("private_local", "sealed Local original", "private init(plan: LibboxRouterNodeChain,", "var members: [Member]", (
            'let identitySources = root["identity_sources"] as? [String], identitySources.count == nodes.count,',
            '(2...IOSMultihopNodeSelection.maximumNodes).contains(nodes.count) || (selectionExecution == "local" || multipleExecution) && IOSMultihopNodeSelection.extendedLocalSource(root["schema"] as? Int, execution: "local", count: nodes.count, identities: identitySources, allowPairedStreams: selectionExecution == "local") && Int(plan.extendedLocalNodeCount()) == nodes.count,',
            '!multipleExecution || schema == 6 && ["server", "auto"].contains(selectionExecution),')),
        ("private_selected", "sealed selected original", "let returned = try Self.object(localSource,", "func requireCurrent()", (
            'let original = try Self.object(local.launchInput, limit: IOSNodeChainCapture.maximumInputBytes)',
            'schema != 6 || (3...IOSMultihopNodeSelection.maximumNodes).contains(nodes.count) || nodes.count > IOSMultihopNodeSelection.maximumNodes && Int(plan.extendedOriginalNodeCount()) == nodes.count,',
            'nodes == original["nodes"] as? [String], identities == original["identity_sources"] as? [String] else {')),
        ("profiles", "all-member snapshot", "static func snapshot(", "static func add(", (
            "let members = try model.iosNodeChainBundles(for: source)",
            "guard let nodes = selected.multihopNodes, nodes.count == members.count else",
            "record.chainPolicies = try members.enumerated().map { position, member in",
            "member.routerProfiles.filter({ $0.id == nodes[position].id }).count == 1",
            "let profile = member.routerProfiles.first(where: { $0.id == nodes[position].id })",
            "return IOSConnectionEntryCapture(nodeID: profile.id, nodeKind: profile.normalizedNodeKind,",
            "nodeProofID: profile.nodeProofID, externalProtocol: profile.external?.protocolName, externalPublicIP: profile.external?.expectedPublicIP,",
            "preferences: try capturePreferences(profile))")),
        ("profiles", "stored order", "private static func validateStoredProfiles(", "private static func validatePreferences(", (
            'record.nodeKind == "router-vpn", record.entryPolicy == nil',
            "var captures = record.chainPolicies, captures.count == nodes.count", "for position in captures.indices",
            "capture.nodeID == nodes[position].id", "proofs.insert(proof).inserted",
            "position == nodes.count - 1, capture.preferences != record.preferences", "else if record.chainPolicies != nil")),
        ("profiles", "original member Load", "private static func applySavedChain(", "private static func applying(", (
            "nodes.count == captures.count", "for (position, capture) in captures.enumerated()",
            "nodes[position].id == capture.nodeID", "profile.nodeProofID == capture.nodeProofID",
            "data == original, capture.preferences == saved.preferences",
            "try model.restoreConnectionProfile(replacements, selectedID: saved.nodeID)")),
        ("store", "atomic private restore", "func restoreConnectionProfile(", "private func profileRestoreError(", (
            "(1...IOSMultihopNodeSelection.maximumNodes).contains(replacements.count)",
            "$0.value == replacement.original", "replacement.updated.profiles == original.profiles",
            "profile.nodeProofID == prior.nodeProofID", "profile.external == prior.external", "profile.apiToken == prior.apiToken",
            "try validate(selected.bundle, prepared)", "guard records == originalRecords", "try commitRecords(next)")),
        ("capture", "original selected sources", "func iosNodeChainBundles(", "static let ordinaryExternalHopProtocols", (
            "controlID: control.id", "for (position, node) in nodes.enumerated()", "proofs.insert(proof).inserted",
            "IOSMultihopNodeSelection.supportsImportedMiddle(node.mode, position: position, count: nodes.count)", "IOSImportedShadowsocksSource.eligible(profile)",
            "let files = source.profiles[node.mode], !files.isEmpty", "source.selectedRouterID = profile.id", "result.append(source)")),
    )
    for owner, label, begin, end, markers in scopes:
        body = sources[owner]
        if begin is not None:
            try:
                body = body.split(begin, 1)[1].split(end, 1)[0]
            except IndexError:
                problems.append(f"iOS ordered profile {label}: shipping owner missing")
                continue
        if label in ("all-member snapshot", "sealed Local original", "sealed selected original"):
            # An inactive copy of the old map in a comment cannot establish
            # complete, ordered capture of the original member at each slot.
            body = re.sub(r"//[^\n]*|/\*.*?\*/", "", body, flags=re.S)
        for marker in markers:
            if marker not in body:
                problems.append(f"iOS ordered profile {label}: missing {marker!r}")
    # Compare the actual predicate bodies, not a bag of tokens that could also
    # occur in comments or an unrelated branch. This is a source contract; the
    # separate Swift/compiler gates execute the complete private admission.
    selection = sources["models"].split("struct IOSMultihopNodeSelection:", 1)[-1].split("struct RouterProfile:", 1)[0]
    selection = re.sub(r"//[^\n]*|/\*.*?\*/", "", selection, flags=re.S)
    compact = lambda value: re.sub(r"\s+", "", value)
    predicates = (
        ("paired prefix modes", r'static let nativePrefixModes\s*=\s*(\[[^\n]+\])',
         '["wg", "awg2-fast", "awg2-strong"]'),
        ("paired prefix predicate", r'static func supportsNativePrefix\([^\n]+\) -> Bool\s*\{([^{}]*)\}',
         'nativePrefixModes.contains(mode)'),
        ("CONNECT execution shape", r'static func supportsCONNECTExecution\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'guard (3...maximumNodes).contains(nodes.count), nodes.last?.mode == "shadowsocks" else { return false } return nodes.dropLast(2).allSatisfy({ supportsNativePrefix($0.mode) }) && ["http-connect", "https-connect"].contains(nodes[nodes.count - 2].mode)'),
        ("generic execution shape", r'static func supportsGenericExecution\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'guard (2...maximumNodes).contains(nodes.count), ["shadowsocks", "hysteria2"].contains(nodes.last?.mode ?? "") else { return false } return nodes.dropLast().allSatisfy({ supportsNativePrefix($0.mode) }) || nodes.last?.mode == "shadowsocks" && nodes.count >= 3 && nodes.dropLast(2).allSatisfy({ supportsNativePrefix($0.mode) }) && nodes[nodes.count - 2].mode == "shadowsocks"'),
        ("SOCKS execution shape", r'static func supportsSOCKSExecution\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'guard (3...maximumNodes).contains(nodes.count), nodes.last?.mode == "shadowsocks", nodes[nodes.count - 2].mode == "socks5" else { return false } return nodes.dropLast(2).allSatisfy({ supportsNativePrefix($0.mode) })'),
        ("OpenVPN execution shape", r'static func supportsOpenVPNExecution\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'guard (3...maximumNodes).contains(nodes.count), nodes.last?.mode == "shadowsocks", nodes[nodes.count - 2].mode == "openvpn" else { return false } return nodes.dropLast(2).allSatisfy({ supportsNativePrefix($0.mode) })'),
        ("independent imported positions", r'static func requiresImportedNodesSource\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'let positions = nodes.dropLast().indices.filter { nodes[$0].mode == "shadowsocks" } return !positions.isEmpty && (positions.count != 1 || positions[0] != nodes.count - 2 || extendedMixedPacketCount(nodes.map(\\.mode), execution: "local") > 0)'),
        ("physical traversal depth", r'static let physicalTraversalDepth = (\d+)\s*\n', '96'),
        ("extended Local modes", r'static func extendedLocalModes\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'execution == "local" && (maximumNodes + 1...physicalTraversalDepth).contains(modes.count) && modes.first == "wg" && modes.dropFirst().allSatisfy { $0 == "shadowsocks" }'),
        ("extended selected packet and literal stream modes", r'static func extendedSelectedModeShape\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         '(maximumNodes + 1...physicalTraversalDepth).contains(modes.count) && ["wg", "awg2-fast"].contains(modes.first ?? "") && modes.dropFirst().allSatisfy { $0 == "shadowsocks" }'),
        ("extended paired Local modes", r'static func extendedPairedModes\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'execution == "local" && (maximumNodes + 1...physicalTraversalDepth).contains(modes.count) && modes.last == "shadowsocks" && modes.dropLast().allSatisfy { $0 == "wg" }'),
        ("extended mixed Local modes", r'static func extendedMixedPacketCount\([^\n]+\) -> Int\s*\{(.*?)\n    \}',
         'guard execution == "local", (maximumNodes + 1...physicalTraversalDepth).contains(modes.count), modes.last == "shadowsocks" else { return 0 } let prefix = modes.prefix(while: supportsNativePrefix).count guard prefix > 0, prefix < modes.count - 1, prefix > 1 || modes[0] != "wg", modes.dropFirst(prefix).allSatisfy({ $0 == "shadowsocks" }) else { return 0 } return prefix'),
        ("extended original modes", r'static func extendedOriginalModes\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'extendedPairedModes(modes, execution: execution) || extendedMixedPacketCount(modes, execution: execution) > 0 || extendedLocalModes(modes, execution: execution) || ["server", "auto"].contains(execution ?? "") && extendedSelectedModeShape(modes)'),
        ("extended original identities", r'static func extendedLocalSource\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'guard execution == "local", (maximumNodes + 1...physicalTraversalDepth).contains(count), let identities, identities.count == count else { return false } if schema == 1 { return identities.allSatisfy { !$0.isEmpty } } let prefix = identities.dropLast().prefix(while: { !$0.isEmpty }).count return schema == 6 && prefix > 0 && prefix < count - 1 && !identities[count - 1].isEmpty && (allowPairedStreams || identities.dropFirst(prefix).dropLast().allSatisfy { $0.isEmpty })'),
        ("multiple imported execution shape", r'static func supportsMultipleImportedExecution\([^\n]+\) -> Bool\s*\{(.*?)\n    \}',
         'guard (3...maximumNodes).contains(nodes.count) || extendedSelectedModeShape(nodes.map(\\.mode)), let first = nodes.first, supportsNativePrefix(first.mode), nodes.last?.mode == "shadowsocks", requiresImportedNodesSource(nodes) else { return false } return nodes.dropLast().allSatisfy { supportsNativePrefix($0.mode) || $0.mode == "shadowsocks" }'),
        ("independent imported execution policy", r'static func usesIndependentImports\([^\n]+\) -> Bool\s*\{([^{}]*)\}',
         'execution == "local" ? requiresImportedNodesSource(nodes) : ["server", "auto"].contains(execution ?? "") && supportsMultipleImportedExecution(nodes)'),
        ("execution family union", r'static func supportsServerExecution\([^\n]+\) -> Bool\s*\{([^{}]*)\}',
         'supportsMultipleImportedExecution(nodes) || supportsGenericExecution(nodes) || supportsCONNECTExecution(nodes) || supportsSOCKSExecution(nodes) || supportsOpenVPNExecution(nodes)'),
        ("execution selection guard", r'static func validate\([^{}]+\) throws\s*\{\s*guard\s+(.*?)\s+else\s*\{',
         '(2...maximumNodes).contains(nodes.count) || extendedOriginalModes(nodes.map(\\.mode), execution: execution), execution == "local" || ["server", "auto"].contains(execution ?? "") && supportsServerExecution(nodes), [entryID, entryMode, exitID, exitMode].allSatisfy({ $0 == nil || $0 == "" })'),
    )
    for label, pattern, expected in predicates:
        found = re.findall(pattern, selection, flags=re.S)
        if len(found) != 1 or compact(found[0]) != compact(expected):
            problems.append(f"iOS ordered profile {label}: actual admission predicate changed")
    return problems


api = require(
    "cmd/client/profile_settings.go",
    "/api/profile/settings",
    "disconnect or let the active AUTO/SMART/CUSTOM transition finish before changing Router VPN profile settings",
    "profileSettingsBusy", 'case "", "off", "failed":', "default:", "return true",
    "external exits own their protocol settings", "NormalizeRouterProfile", "syncProfileOptionStateLocked",
    "HomeLANAccess", "KillSwitchPolicy", "IPv6Mode", "BaseTunnel", "BaseFallback",
    "AutoRequireEncrypted", "AutoRequireObfuscation",
    "MTUPolicy", "ManualMTU", "DAITAEnabled", "JumboTUN", "SocksEnabled",
)
for forbidden in ("APIToken =", "NodeProofID =", "RouterAPI =", "Endpoint =", "DNSHost =", "PrivateKey"):
    if forbidden in api:
        errors.append(f"cmd/client/profile_settings.go mutates protected/non-policy field: {forbidden}")
require(
    "cmd/client/profile_settings_test.go",
    "TestProfileSettingsV2MutateOnlyAllowedPolicyFields", "TestProfileSettingsV2Validation",
    "TestProfileSettingsV2DefaultAndAutoMTUClearManualValue", "APIToken", "NodeProofID", "EffectiveMTUPathKey",
)
require(
    "cmd/client/strategy_requirements.go",
    "modeMeetsAutoRequirements", "modeHasEncryptedTransport", "modeHasObfuscation",
    "AutoRequireEncrypted", "AutoRequireObfuscation",
)
require(
    "internal/common/types.go",
    'json:"auto_require_encrypted,omitempty"', 'json:"auto_require_obfuscation,omitempty"',
    'json:"daita_enabled,omitempty"', 'json:"jumbo_tun,omitempty"', 'json:"socks_enabled,omitempty"',
)
require(
    "cmd/client/mtu_retest.go", "registerProfileSettingsRoute(h, a)", "registerStrategyRoutes(h, a)",
    "registerConnectionProfileRoutes(h, a)",
)

connection_profiles = require(
    "cmd/client/connection_profiles.go",
    "/api/connection-profiles", "/api/connection-profile/save", "/api/connection-profile/update",
    "/api/connection-profile/load", "/api/connection-profile/delete",
    "connection-profiles.json", "readPrivateRegular", "atomicWritePrivate", "profileSettingsBusy", "saved multihop profile references",
    "connect separately so the selected platform can establish and prove the requested dataplane",
    "snapshotConnectionPreferences", "CustomLayers", "DNSMode", "MultihopEntryID", "MultihopExitID",
)
require(
    "cmd/client/private_store.go",
    "0o600", "os.CreateTemp", "tmp.Sync()", "replacePrivateStoreFile(tmpPath, path)", "os.SameFile",
)
require("cmd/client/private_store_replace_windows.go", "MoveFileExW",
        "windowsPrivateReplaceExisting|windowsPrivateWriteThrough",
        "replaceWindowsPrivateStoreFile(source, target, moveWindowsPrivateStoreFile)")
require("cmd/client/private_store_replace_other.go", "os.Rename(source, target)")
for forbidden_field in (
    "APIToken string", "PrivateKey string", "PresharedKey string", "SocksUsername string",
    "SocksPassword string", "External *common.ExternalNodeConfig",
):
    if forbidden_field in connection_profiles:
        errors.append(f"connection profile persistence unexpectedly declares secret-bearing field: {forbidden_field}")
require(
    "cmd/client/connection_profiles_test.go",
    "TestConnectionProfileStoreRoundTripIsPrivateAndSecretFree",
    "TestSnapshotConnectionPreferencesNeverCopiesNodeCredentials",
    "TestConnectionProfileInputNormalization", "TOP-SECRET-API-TOKEN", "private-password", "0o600",
)

win_settings = require(
    "client/RouterVPN-Windows-ProfileSettings.ps1", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", 'Content="Auto — default" Tag="auto"', "DAITA-like", "Jumbo TUN", "SOCKS5",
    "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "Connection profiles", "Add profile", "Load", "Update", "Delete",
    "/api/connection-profiles", "/api/connection-profile/setup/save", "/api/connection-profile/setup/update",
    "/api/connection-profile/setup/load", "/api/connection-profile/setup/delete",
    "windows-selected-mode-v1.txt", "windows-custom-presets-v1.json", "never duplicate node secrets",
)
for forbidden in ("APIToken", "PrivateKey", "PresharedKey", "socks_password"):
    if forbidden in win_settings:
        errors.append(f"Windows connection profile UI should not serialize private node field marker: {forbidden}")
require_combined(
    "Windows unified product",
    ("client/RouterVPN-Windows-App.ps1", "client/RouterVPN-Windows-UnifiedShell.ps1", "client/RouterVPN-Windows-ProfileSettings.ps1"),
    "RouterVPN-Windows-ProfileSettings.ps1", "Show-RouterVPNProfileSettingsDialog", "/api/profile/settings",
    "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "UnifiedSettingsButton", "UnifiedSettingsSummary", "AUTO requirements=", "auto_require_encrypted", "auto_require_obfuscation",
    "UnifiedKillSwitch", "UnifiedMtuButton", "/api/connection-profile/setup/load",
)

mac_settings = require(
    "client/macos/RouterVPNProfileSettings.swift", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", '("Auto — default","auto")', "DAITA-like", "Jumbo TUN", "SOCKS5",
    "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "Connection profiles", "MacConnectionProfileControls", "Add", "Load", "Update", "Delete",
    "/api/connection-profiles", "/api/connection-profile/setup/save", "/api/connection-profile/setup/update",
    "/api/connection-profile/setup/load", "/api/connection-profile/setup/delete",
    "routervpn.unified.selected-mode.v1", "routervpn.unified.custom-presets.v1", "never duplicates node secrets",
)
for forbidden in ("apiToken", "privateKey", "presharedKey", "socksPassword"):
    if forbidden in mac_settings:
        errors.append(f"macOS connection profile UI should not serialize private node field marker: {forbidden}")
require_combined(
    "macOS unified product",
    ("client/macos/build-native-app.sh", "client/macos/RouterVPNMacUnifiedShell.swift", "client/macos/RouterVPNProfileSettings.swift"),
    "SETTINGS_SRC", "UNIFIED_SRC", '"$SETTINGS_SRC"', '"$UNIFIED_SRC"',
    "editProfileSettings", "/api/profile/settings", "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "unified-auto-requirements", "AUTO requirements: Off", "auto_require_encrypted", "auto_require_obfuscation",
    "/api/connection-profile/setup/load", "exact multihop graph restored",
)

require(
    "client/linux/routervpn-profile-settings-v1.inc", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "never redacted full-profile POST",
)
linux_profiles = require(
    "client/linux/routervpn-connection-profiles-v11.inc",
    "Linux v11 Profiles contract", "Add/Load/Update/Delete exact non-secret setup", "Choose Add/Load/Update/Delete",
    "/api/connection-profiles", "/api/connection-profile/setup/save", "/api/connection-profile/setup/update",
    "/api/connection-profile/setup/load", "/api/connection-profile/setup/delete",
    "linux_unified_custom_layers_for_mode_v8", "linux_unified_store_mode_v8",
    "Load never connects automatically", "linux_profile_manager_v11", "linux_install_connection_profiles_v11",
    "linux_profile_choose_hops_v11", "linux_profile_connect_v11", "linux_unified_refresh_v8",
)
for forbidden in ("api_token", "private_key", "preshared_key", "socks_password"):
    if forbidden in linux_profiles:
        errors.append(f"Linux connection profile UI should not serialize private node field marker: {forbidden}")
require(
    "client/linux/routervpn-telemetry-v9.inc", '#include "routervpn-connection-profiles-v11.inc"',
    "linux_install_connection_profiles_v11(app)", "linux_telemetry_button_v9",
)
require(
    "client/linux/build-native-app.sh", "SETTINGS_INC", '#include \"routervpn-profile-settings-v1.inc\"',
    "G_CALLBACK(on_profile_settings_v7)", "gcc -O2 -Wall -Wextra -Werror",
)
require_combined(
    "Linux unified product",
    ("client/linux/routervpn-unified-shell-v8.inc", "client/linux/routervpn-home-summary-v1.inc", "client/linux/routervpn-telemetry-v9.inc", "client/linux/routervpn-connection-profiles-v11.inc"),
    "/api/profile/settings", "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "linux_unified_settings_v8", "linux_unified_auto_requirements_v8", "AUTO requirements", "on_linux_auto_requirements_v11",
    "Kill switch", "linux_mtu_dialog_v20", "/api/connection-profile/setup/load",
)

android_settings = require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
    "home_lan_access", "kill_switch_policy", "ipv6_mode", "base_tunnel", "base_fallback",
    "auto_require_encrypted", "auto_require_obfuscation", "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "mtu_policy", "manual_mtu", "daita_enabled", "jumbo_tun", "socks_enabled",
    "External exits own their protocol settings", "store.snapshotSelection()", "store.applySettings(source,updated)",
    "Connection profiles — Add / Load / Update / Delete", "AndroidConnectionProfilesDialog.show",
    "AES-256-GCM + XOR whitening — authenticated AES plus protected obfuscation relay",
    "VpnService-owned protected local relay", "XOR is never counted as encryption",
)
if "AES-256-GCM + XOR whitening — unavailable on this Android build" in android_settings or "Android refuses AES+XOR until VpnService owns" in android_settings:
    errors.append("Android settings still advertise the retired pre-relay AES+XOR unavailable state")
android_store = require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
    "SCHEMA_VERSION=7", "connection-profiles-v4.json", "connection-profiles-v1.json", "MAX_PROFILES=64", "POLICY_KEYS", "requireIdle",
    "home_lan_access", "kill_switch_policy", "ipv6_mode", "auto_require_encrypted", "auto_require_obfuscation",
    "mtu_policy", "dns_mode", "dns_protocol", "multihop_enabled", "multihop_entry_id", "multihop_exit_id",
    "node_kind", "node_id", "custom_layers", "Connection profile contains non-whitelisted node data",
    'MULTI_ENTRY_KIND="multihop_entry_kind"',
    'normalizeEntryKind(row.optString(MULTI_ENTRY_KIND,"router-vpn"))',
    'boolean ordinary="external".equals(entryKind);',
    "schema < 1 || schema > SCHEMA_VERSION",
)
for forbidden in ('"api_token"', '"private_key"', '"preshared_key"', '"socks_password"', '"password"', '"secret"'):
    if forbidden in android_store:
        errors.append(f"Android connection profile store contains forbidden secret field literal: {forbidden}")
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfilesDialog.java",
    "Add", "Load", "Update", "Delete", "Refresh", "AndroidConnectionProfileStore",
    "never copied into these profiles", "Connect still has to establish and prove the real VPN path",
)
android_product = require(
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "AndroidProfileSettingsDialog.show", "showSettings", "LinearLayout.VERTICAL",
    "AUTO requirements: Off", "auto_require_encrypted", "auto_require_obfuscation",
)
compact_android = android_product.replace(" ", "").replace("\n", "")
if "AndroidProfileSettingsDialog.show(this,nodeStore,this::refreshAll)" not in compact_android:
    errors.append("Android ProductActivity Settings is not wired to refresh the unified surface after save")
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java",
    "auto_require_encrypted", "auto_require_obfuscation", "applyAutoRequirements",
    "collect(bundle,true,custom==null)", "applyAutoRequirements&&profile!=null",
)

require(
    "ios/RouterVPN/App/Models.swift",
    "profileSchemaVersion: 4", "profileSchemaVersion <= 4",
    "autoRequireEncrypted", 'autoRequireEncrypted = "auto_require_encrypted"',
    "autoRequireObfuscation", 'autoRequireObfuscation = "auto_require_obfuscation"',
)
ios_settings = require(
    "ios/RouterVPN/App/IOSProfileSettingsView.swift", "Allow home LAN access", "Always / strict",
    "pinned native Apple AmneziaWG PacketTunnel", "MTU policy", "Fixed / manual", "Jumbo TUN — compatible proxy paths", "DAITA-like bounded traffic padding", "p.daitaEnabled = daitaEnabled", "p.jumboTUN = jumboTUN",
    "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "autoRequireEncrypted", "autoRequireObfuscation", "model.importBundle",
    "profileMutationBlocked", ".disabled(model.profileMutationBlocked)",
    "guard !model.profileMutationBlocked else", "Disconnect or let the active VPN transition finish before changing profile settings.",
    "Connection profiles", "IOSConnectionProfilesView",
)
require("deploy/test_mobile_performance_shipping.py", "test_apple_activates_only_after_path_proof", "test_android_stages_final_policy_after_mtu_and_lan")
require("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift", "LibboxRouterApplyPerformancePolicy", "engine.activatePerformance()")
require("ios/RouterVPN/App/IOSConnectionProfilesView.swift", "profile.daitaEnabled = prefs.daitaEnabled", "profile.jumboTUN = prefs.jumboTUN")
ios_profiles = require(
    "ios/RouterVPN/App/IOSConnectionProfilesView.swift",
    "IOSConnectionProfileStore", "IOSConnectionSafePreferences", "iosConnectionProfilesSchemaVersion = 8", "IOSConnectionProfileEnvelope", "Add", "Load", "Update", "Delete",
    "routervpn.connection-profiles.v1", "routervpn.unified.mode.v1", "routervpn.unified.custom-presets.v1",
    "dnsMode", "dnsProtocol", "multihopEnabled", "multihopEntryID", "multihopExitID",
    "multihopExitMode", "iosMultihopEntryBundle(for: source)",
    "bundleData(containing: saved.nodeID, current: model.bundle)",
    "Saved multihop exit does not match the connection profile",
    "Connect separately to prove the path", "No RouterProfile/API token/private key/external secret payload",
)
# Loading a linked node must restore its own full private runtime bundle. That
# operation legitimately reads node credentials; it must not encode them into
# the separate connection-profile records. Audit the actual Codable types and
# capture/persistence path instead of banning credential reads across the file.
try:
    ios_record_types = ios_profiles.split("private struct IOSConnectionSafePreferences", 1)[1].split("@MainActor\nprivate enum IOSConnectionProfileStore", 1)[0]
    ios_capture = ios_profiles.split("static func snapshot(", 1)[1].split("static func add(", 1)[0]
    ios_persist = ios_profiles.split("private static func persist(", 1)[1].split("private static func validateStoredProfiles(", 1)[0]
except IndexError:
    errors.append("iOS profile serialization owners could not be located")
    ios_record_types = ios_capture = ios_persist = ""
for forbidden in ("apiToken", "privateKey", "presharedKey", "socksPassword", "ExternalNodeConfig"):
    if forbidden in ios_record_types + ios_capture + ios_persist:
        errors.append(f"iOS connection profile serialization references secret-bearing field/type: {forbidden}")
if "JSONEncoder().encode(envelope)" not in ios_persist:
    errors.append("iOS profile persistence no longer encodes the non-secret envelope")
require("deploy/test_ios_multihop_profiles.py", "IOSConnectionSafePreferences", "private_key", "apiToken", "expectedKeys", "multihopEntryID")
ordered_sources = {
    "profiles": ios_profiles,
    "models": read("ios/RouterVPN/App/Models.swift"),
    "private_local": read("ios/RouterVPN/App/IOSNodeChainCapture.swift"),
    "private_selected": read("ios/RouterVPN/App/IOSNodeChainExecutionCapture.swift"),
    "store": read("ios/RouterVPN/App/IOSNodeBundleStore.swift"),
    "capture": read("ios/RouterVPN/App/IOSMultihopView.swift"),
}
ordered_issues = ios_ordered_profile_issues(ordered_sources)
errors.extend(ordered_issues)
if not ordered_issues:
    # These source-gate controls must fail for their own missing boundary.
    # The separate fixture executes the actual Codable/Load/store methods.
    for owner, before, after in (
        ("profiles", "iosConnectionProfilesSchemaVersion = 8", "iosConnectionProfilesSchemaVersion = 7"),
        ("profiles", "record.chainPolicies = try members.enumerated().map", "record.chainPolicies = try members.prefix(2).enumerated().map"),
        ("profiles", "record.entryPolicy == nil", "true"),
        ("profiles", "captures.count == nodes.count", "captures.count >= 2"),
        ("profiles", "profile.nodeProofID == capture.nodeProofID", "true"),
        ("profiles", "data == original, capture.preferences == saved.preferences", "data == original"),
        ("capture", "IOSMultihopNodeSelection.supportsImportedMiddle(node.mode, position: position, count: nodes.count)", "true"),
        ("models", "guard (3...maximumNodes).contains(count), position == count - 2 else { return false }", "guard count >= 3 else { return false }"),
        ("models", 'if ["socks5", "http-connect", "https-connect", "openvpn"].contains(mode) { return true }', 'if mode != "" { return true }'),
        ("models", 'return mode == "shadowsocks"', 'return true'),
        ("models", '(2...maximumNodes).contains(nodes.count) || extendedOriginalModes(nodes.map(\\.mode), execution: execution),\n              execution', '(1...maximumNodes).contains(nodes.count) || extendedOriginalModes(nodes.map(\\.mode), execution: execution),\n              execution'),
        ("models", '["server", "auto"].contains(execution ?? "") && supportsServerExecution(nodes)', '["server", "auto"].contains(execution ?? "")'),
        ("models", '["server", "auto"].contains(execution ?? "")', '["server", "auto", "invalid"].contains(execution ?? "")'),
        ("models", 'static func supportsCONNECTExecution(_ nodes: [Self]) -> Bool {\n        guard (3...maximumNodes).contains(nodes.count)', 'static func supportsCONNECTExecution(_ nodes: [Self]) -> Bool {\n        guard nodes.count == 3'),
        ("models", 'nativePrefixModes.contains(mode)', 'true /* nativePrefixModes.contains(mode) */'),
        ("models", '(3...maximumNodes).contains(nodes.count)', '(2...maximumNodes).contains(nodes.count)'),
        ("models", 'nodes.dropLast(2).allSatisfy({ supportsNativePrefix($0.mode) }) &&', 'supportsNativePrefix(nodes[0].mode) &&'),
        ("models", '["http-connect", "https-connect"].contains(nodes[nodes.count - 2].mode)', '["http-connect", "https-connect", "socks5"].contains(nodes[nodes.count - 2].mode)'),
        ("models", 'nodes.last?.mode == "shadowsocks",\n              nodes[nodes.count - 2].mode == "socks5"', 'nodes.last?.mode != "",\n              nodes[nodes.count - 2].mode == "socks5"'),
        ("models", '(2...maximumNodes).contains(nodes.count), ["shadowsocks", "hysteria2"]', '(2...9).contains(nodes.count), ["shadowsocks", "hysteria2"]'),
        ("models", '["shadowsocks", "hysteria2"].contains(nodes.last?.mode ?? "")', 'nodes.last?.mode != ""'),
        ("models", '["shadowsocks", "hysteria2"].contains(nodes.last?.mode ?? "")', 'nodes.last?.mode == "shadowsocks"'),
        ("models", 'nodes.last?.mode == "shadowsocks" && nodes.count >= 3', 'nodes.count >= 3'),
        ("models", 'nodes.last?.mode == "shadowsocks" else { return false }', 'nodes.last?.mode != "" else { return false }'),
        ("models", 'nodes.dropLast().allSatisfy({ supportsNativePrefix($0.mode) })', 'nodes.dropLast().allSatisfy({ !$0.mode.isEmpty })'),
        ("models", 'nodes.count >= 3 && nodes.dropLast(2).allSatisfy({ supportsNativePrefix($0.mode) }) && nodes[nodes.count - 2].mode == "shadowsocks"', 'nodes.count >= 3 && supportsNativePrefix(nodes[0].mode) && nodes[nodes.count - 2].mode == "shadowsocks"'),
        ("models", 'nodes[nodes.count - 2].mode == "shadowsocks"', 'nodes[1].mode == "shadowsocks"'),
        ("models", 'supportsMultipleImportedExecution(nodes) || supportsGenericExecution(nodes)', 'supportsGenericExecution(nodes)'),
        ("models", 'positions.count != 1 || positions[0] != nodes.count - 2 ||', 'true ||'),
        ("models", 'let first = nodes.first, supportsNativePrefix(first.mode),', 'let first = nodes.first, !first.mode.isEmpty,'),
        ("models", 'nodes.last?.mode == "shadowsocks", requiresImportedNodesSource(nodes)', 'requiresImportedNodesSource(nodes)'),
        ("models", 'supportsNativePrefix($0.mode) || $0.mode == "shadowsocks" }', 'supportsNativePrefix($0.mode) || ["shadowsocks", "socks5"].contains($0.mode) }'),
        ("models", 'supportsGenericExecution(nodes) || supportsCONNECTExecution(nodes)', 'supportsCONNECTExecution(nodes)'),
        ("models", 'static func supportsSOCKSExecution(_ nodes: [Self]) -> Bool {\n        guard (3...maximumNodes).contains(nodes.count)', 'static func supportsSOCKSExecution(_ nodes: [Self]) -> Bool {\n        guard nodes.count == 3'),
        ("models", 'static func supportsSOCKSExecution(_ nodes: [Self]) -> Bool {\n        guard (3...maximumNodes).contains(nodes.count)', 'static func supportsSOCKSExecution(_ nodes: [Self]) -> Bool {\n        guard (3...9).contains(nodes.count)'),
        ("models", 'nodes[nodes.count - 2].mode == "socks5"', 'nodes[nodes.count - 2].mode != ""'),
        ("models", 'nodes[nodes.count - 2].mode == "socks5"', 'nodes[1].mode == "socks5"'),
        ("models", 'nodes[nodes.count - 2].mode == "socks5" else { return false }\n        return nodes.dropLast(2).allSatisfy({ supportsNativePrefix($0.mode) })', 'nodes[nodes.count - 2].mode == "socks5" else { return false }\n        return supportsNativePrefix(nodes[0].mode)'),
        ("models", '|| supportsSOCKSExecution(nodes)', ''),
        ("models", '|| supportsOpenVPNExecution(nodes)', ''),
        ("models", 'static func supportsOpenVPNExecution(_ nodes: [Self]) -> Bool {\n        guard (3...maximumNodes).contains(nodes.count)', 'static func supportsOpenVPNExecution(_ nodes: [Self]) -> Bool {\n        guard nodes.count == 3'),
        ("models", 'nodes[nodes.count - 2].mode == "openvpn" else { return false }\n        return nodes.dropLast(2).allSatisfy({ supportsNativePrefix($0.mode) })', 'nodes[nodes.count - 2].mode == "openvpn" else { return false }\n        return supportsNativePrefix(nodes[0].mode)'),
        ("capture", "IOSImportedShadowsocksSource.eligible(profile)", "true"),
        ("store", "replacement.updated.profiles == original.profiles", "true"),
        ("store", "guard records == originalRecords", "guard true"),
    ):
        assert before in ordered_sources[owner], before
        changed = dict(ordered_sources)
        changed[owner] = changed[owner].replace(before, after, 1)
        if not ios_ordered_profile_issues(changed):
            errors.append(f"iOS ordered profile audit accepted its missing-boundary control: {before}")
    # Each change must break its own current admission predicate.
    for owner, label, before, after in (
        ("models", "physical traversal depth", 'static let physicalTraversalDepth = 96', 'static let physicalTraversalDepth = 97'),
        ("models", "extended Local modes", '(maximumNodes + 1...physicalTraversalDepth).contains(modes.count) &&\n            modes.first', 'modes.count > maximumNodes &&\n            modes.first'),
        ("models", "extended paired Local modes", 'execution == "local" && (maximumNodes + 1...physicalTraversalDepth).contains(modes.count) &&\n            modes.last', 'execution != nil && (maximumNodes + 1...physicalTraversalDepth).contains(modes.count) &&\n            modes.last'),
        ("models", "extended paired Local modes", '(maximumNodes + 1...physicalTraversalDepth).contains(modes.count) &&\n            modes.last', 'modes.count > maximumNodes &&\n            modes.last'),
        ("models", "extended paired Local modes", 'modes.last == "shadowsocks" && modes.dropLast().allSatisfy { $0 == "wg" }', 'modes.dropLast().allSatisfy { $0 == "wg" }'),
        ("models", "extended paired Local modes", 'modes.dropLast().allSatisfy { $0 == "wg" }', 'modes.dropLast().allSatisfy { supportsNativePrefix($0) }'),
        ("models", "extended mixed Local modes", 'modes.prefix(while: supportsNativePrefix).count', 'modes.prefix(while: { !$0.isEmpty }).count'),
        ("models", "extended mixed Local modes", 'prefix > 0, prefix < modes.count - 1,', 'prefix >= 0,'),
        ("models", "extended mixed Local modes", 'prefix > 1 || modes[0] != "wg",', ''),
        ("models", "extended mixed Local modes", 'modes.dropFirst(prefix).allSatisfy({ $0 == "shadowsocks" })', 'true'),
        ("models", "extended original modes", 'extendedMixedPacketCount(modes, execution: execution) > 0 ||', 'extendedMixedPacketCount(modes, execution: "local") > 0 ||'),
        ("models", "extended original identities", 'prefix > 0 && prefix < count - 1', 'true'),
        ("models", "extended original modes", 'extendedPairedModes(modes, execution: execution) ||', 'extendedPairedModes(modes, execution: "local") ||'),
        ("models", "extended Local modes", 'modes.first == "wg"', 'supportsNativePrefix(modes.first ?? "")'),
        ("models", "extended Local modes", 'modes.first == "wg" && modes.dropFirst().allSatisfy { $0 == "shadowsocks" }', 'modes.first == "wg" && modes.dropFirst().dropLast().allSatisfy { $0 == "shadowsocks" }'),
        ("models", "extended selected packet and literal stream modes", '["wg", "awg2-fast"].contains(modes.first ?? "")', 'supportsNativePrefix(modes.first ?? "")'),
        ("models", "extended selected packet and literal stream modes", '["wg", "awg2-fast"].contains(modes.first ?? "")', 'modes.first == "wg"'),
        ("models", "extended selected packet and literal stream modes", '["wg", "awg2-fast"].contains(modes.first ?? "") && modes.dropFirst().allSatisfy', '["wg", "awg2-fast"].contains(modes.first ?? "") && modes.dropFirst(2).allSatisfy'),
        ("models", "extended selected packet and literal stream modes", '(maximumNodes + 1...physicalTraversalDepth).contains(modes.count) &&\n            ["wg", "awg2-fast"]', 'modes.count > maximumNodes &&\n            ["wg", "awg2-fast"]'),
        ("models", "extended original modes", 'extendedLocalModes(modes, execution: execution) || ["server", "auto"].contains(execution ?? "") && extendedSelectedModeShape(modes)', 'execution != nil'),
        ("models", "extended original identities", 'guard execution == "local", (maximumNodes + 1...physicalTraversalDepth).contains(count),', 'guard (maximumNodes + 1...physicalTraversalDepth).contains(count),'),
        ("models", "extended original identities", 'guard execution == "local", (maximumNodes + 1...physicalTraversalDepth).contains(count),', 'guard execution == "local", count > maximumNodes,'),
        ("models", "extended original identities", 'if schema == 1 { return identities.allSatisfy { !$0.isEmpty } }', 'if schema != 6 { return identities.allSatisfy { !$0.isEmpty } }'),
        ("models", "extended original identities", 'return identities.allSatisfy { !$0.isEmpty }', 'return !identities[0].isEmpty'),
        ("models", "extended original identities", 'return schema == 6 && prefix > 0', 'return prefix > 0'),
        ("models", "extended original identities", 'let identities, identities.count == count else { return false }', 'let identities, identities.count >= 2 else { return false }'),
        ("models", "extended original identities", '!identities[count - 1].isEmpty', 'true'),
        ("models", "extended original identities", 'identities.dropFirst(prefix).dropLast().allSatisfy { $0.isEmpty }', 'true'),
        ("models", "multiple imported execution shape", '|| extendedSelectedModeShape(nodes.map(\\.mode)), let first', '|| nodes.count > maximumNodes, let first'),
        ("models", "execution selection guard", '|| extendedOriginalModes(nodes.map(\\.mode), execution: execution),', '|| nodes.count > maximumNodes,'),
        ("private_local", "sealed Local original", 'Int(plan.extendedLocalNodeCount()) == nodes.count,', 'true,'),
        ("private_local", "sealed Local original", '!multipleExecution || schema == 6 && ["server", "auto"].contains(selectionExecution),', 'true,'),
        ("private_selected", "sealed selected original", 'Int(plan.extendedOriginalNodeCount()) == nodes.count,', 'true,'),
        ("private_selected", "sealed selected original", 'nodes == original["nodes"] as? [String], identities == original["identity_sources"] as? [String] else {', 'nodes.count == identities.count else {'),
    ):
        original = ordered_sources[owner]
        assert original.count(before) == 1, (label, before)
        changed = dict(ordered_sources, **{owner: original.replace(before, after, 1)})
        if not any(issue.startswith(f"iOS ordered profile {label}:") for issue in ios_ordered_profile_issues(changed)):
            errors.append(f"iOS ordered profile audit accepted its {label} control: {before}")
    # The current snapshot deliberately enumerates the complete captured list
    # and resolves each member by the selected ID at that position. Exercise
    # those exact shipping boundaries without changing Swift production code.
    for label, before, after in (
        ("reordered members", "record.chainPolicies = try members.enumerated().map", "record.chainPolicies = try members.reversed().enumerated().map"),
        ("partial selected order", "nodes.count == members.count", "nodes.count <= members.count"),
        ("duplicate member identity", "member.routerProfiles.filter({ $0.id == nodes[position].id }).count == 1", "member.routerProfiles.filter({ $0.id == nodes[position].id }).count >= 1"),
        ("wrong position identity", "member.routerProfiles.first(where: { $0.id == nodes[position].id })", "member.routerProfiles.first(where: { $0.id == nodes[0].id })"),
        ("missing original proof", "nodeProofID: profile.nodeProofID", "nodeProofID: nil"),
        ("borrowed control preferences", "preferences: try capturePreferences(profile)", "preferences: try capturePreferences(selected)"),
        ("commented complete capture", "record.chainPolicies = try members.enumerated().map", "/* record.chainPolicies = try members.enumerated().map */ record.chainPolicies = try members.prefix(2).enumerated().map"),
    ):
        snapshot = ordered_sources["profiles"].split("static func snapshot(", 1)[1].split("static func add(", 1)[0]
        assert snapshot.count(before) == 1, (label, before)
        changed = dict(ordered_sources)
        changed["profiles"] = changed["profiles"].replace(snapshot, snapshot.replace(before, after, 1), 1)
        if not any(issue.startswith("iOS ordered profile all-member snapshot:") for issue in ios_ordered_profile_issues(changed)):
            errors.append(f"iOS ordered profile audit accepted its snapshot control: {label}")
require("deploy/test_ios_node_chain_profiles.py", '"missing-middle"', '"changed-proof"', '"final-policy"',
        '"stale-during-prepare"', '"missing-capture"', "old-two-record-limit", "lost-ordered-selection")
require("ios/RouterVPN/test_runtime_selection_contract.py", "test_ios_node_chain_profiles.py")
require("deploy/test_ios_node_chain_connect_capture.py", "for count in 3...8", "every original paired identity retained", "[str(binary),str(compiler)]")
require("deploy/test_ios_node_chain_connect_profiles.py", "for count in 3...8", "typed profile Load keeps paired final assets", "binary_args=[compiler]")
require("deploy/validate-ios-socks-host.py", "test_ios_node_chain_connect_capture.py", "test_ios_node_chain_connect_profiles.py")
require(
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "Both AUTO requirements are Off by default", "profile-shared requirements",
)
require(
    "ios/RouterVPN/App/IOSStrategySupport.swift",
    "autoRequirementFailure", "encryptedLayers", "obfuscationLayers",
    "profile.autoRequireEncrypted", "profile.autoRequireObfuscation", "runIOSOwnedStrategy(kind: .smart", "runIOSOwnedStrategy(kind: .custom",
)
require(
    "ios/RouterVPN/App/IOSOwnedStrategy.swift",
    "IOSStrategyCatalog.autoRequirementFailure", "AUTO failed closed: no iOS-runnable candidate satisfies the saved requirements",
)
ios_home = require("ios/RouterVPN/App/IOSHomeSummaryView.swift", "IOSProfileSettingsView", "Advanced Settings")
if "Cached profile.publicIP is never used as live proof" not in ios_home:
    errors.append("iOS Home lost its live-exit trust-boundary marker while settings were wired")

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN safe cross-platform profile settings audit: PASS")
