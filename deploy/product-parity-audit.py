#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def text(path: str) -> str:
    p = ROOT / path
    try:
        return p.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{path}: unreadable: {exc}")
        return ""


def require(path: str, *markers: str) -> str:
    body = text(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing product-parity marker: {marker}")
    return body


def require_combined(label: str, paths: tuple[str, ...], *markers: str) -> str:
    body = "\n".join(text(path) for path in paths)
    for marker in markers:
        if marker not in body:
            errors.append(f"{label}: missing composed product-parity marker: {marker}")
    return body


def linux_dns_measurement_controls() -> None:
    """Follow the packaged GTK callback through its captured measurement owner."""
    build = require("client/linux/build-native-app.sh",
                    'DNS_INC="$ROOT/client/linux/routervpn-dns-measurement-v1.inc"',
                    '"$MTU_INC" "$DNS_INC" "$SHUTDOWN_INC"',
                    '#include "routervpn-dns-measurement-v1.inc"\\n',
                    'G_CALLBACK(linux_dns_parent_delete_v1)', 'G_CALLBACK(on_delete)')
    if build.find('G_CALLBACK(linux_dns_parent_delete_v1)') > build.find('G_CALLBACK(on_delete)'):
        errors.append("Linux main close no longer waits for DNS cancellation before controller teardown")
    product = require("client/linux/routervpn-gtk-product-v5.c", "Retest DNS queries")
    callback = re.search(r"(?ms)^static void on_dns_retest_v5\(.*?^\}", product)
    if callback is None or "linux_dns_retest_v1(app);" not in callback.group():
        errors.append("Linux DNS page lost the captured measurement dispatch")
    require("client/linux/apply-async-actions.py", 'linux_dns_retest_v1((App *)data);')
    require("client/linux/routervpn-dns-measurement-v1.inc",
            's->profile = g_strdup(displayed)', 'g_strcmp0(active_router_id(s->app), s->profile)',
            'g_strcmp0(profile, s->profile) != 0', 'g_strcmp0(token, s->token) != 0',
            'g_strcmp0(session, s->session) != 0', 'g_strcmp0(request, s->request) != 0',
            's->complete && s->drained', 'g_get_monotonic_time() < s->expires_at',
            'routervpn_require_mutation_idle(s->app, "saving measured DNS")',
            '"/api/dns/measurement"', '"/api/dns/measurement/cancel"', '"/api/dns/measurement/select"',
            '"/api/dns/policy"', 'post_and_log(s->app, "/api/dns/retest"',
            'linux_dns_parent_delete_v1', 'rv_http_free_v16(s->jobs[i])')
    require(".github/workflows/linux-native-app.yml", "python3 deploy/test_linux_dns_measurement.py")


def windows_profile_controls() -> None:
    """Trace the captured quick control and the separate complete Settings form."""
    require("client/RouterVPN-Windows-App.ps1",
            "$ProfileSettingsHelpers=Join-Path $PSScriptRoot 'RouterVPN-Windows-ProfileSettings.ps1'",
            "$ProfileSettingsSource=Get-Content -LiteralPath $ProfileSettingsHelpers -Raw -Encoding UTF8",
            ". ([ScriptBlock]::Create($ProfileSettingsSource))",
            "$ProductSource=Add-RouterVPNUnifiedWindowsShell -ProductSource $ProductSource")
    shell_path = "client/RouterVPN-Windows-UnifiedShell.ps1"
    shell = require(shell_path, "(Control 'UnifiedSettingsButton').Add_Click(",
                    "Show-RouterVPNProfileSettingsDialog -BaseUrl $BaseUrl -Owner $Window")
    binding = re.search(r"(?m)^\(Control 'UnifiedKillSwitch'\)\.Add_Click\(.*$", shell)
    for marker in ("$DisplayedProfileID=[string]$RouterCombo.SelectedValue",
                   "Set-RouterVPNProfileProtection -BaseUrl $BaseUrl -DisplayedProfileID $DisplayedProfileID -Enabled $On"):
        if binding is None or marker not in binding.group():
            errors.append(f"{shell_path}: quick protection binding lost captured dispatch: {marker}")
    helper_path = "client/RouterVPN-Windows-ProfileSettings.ps1"
    helper = require(helper_path, "function global:Get-RouterVPNProfileSettings",
                     "'/api/profile/settings') -Method Get", "function global:Save-RouterVPNProfileSettings",
                     "'/api/profile/settings') -Method Post", "function global:Show-RouterVPNProfileSettingsDialog",
                     "$current=Get-RouterVPNProfileSettings -BaseUrl $BaseUrl",
                     "Save-RouterVPNProfileSettings -BaseUrl $BaseUrl -Body $body")
    function = re.search(r"(?ms)^function global:Set-RouterVPNProfileProtection \{.*?^\}", helper)
    for marker in ("[string]::IsNullOrWhiteSpace($DisplayedProfileID)",
                   "'/api/profile/protection') -Method Get",
                   "[string]$captured.profile_id -cne $DisplayedProfileID",
                   "[string]::IsNullOrWhiteSpace([string]$captured.profile_token)",
                   "profile_id=$DisplayedProfileID;profile_token=[string]$captured.profile_token;kill_switch_policy=",
                   "'/api/profile/protection') -Method Post",
                   "-Body ($body | ConvertTo-Json -Compress)"):
        if function is None or marker not in function.group():
            errors.append(f"{helper_path}: captured quick protection helper is incomplete: {marker}")
    require("cmd/client/profile_settings.go", 'h.HandleFunc("/api/profile/protection", a.profileProtectionSettings)')
    require("cmd/client/profile_protection.go", "a.beginMutationOperation(r)", "decoder.DisallowUnknownFields()",
            "q.ProfileID != profile.ID || q.ProfileToken != profileStartupSettingsToken(profile)",
            "a.profiles.SelectedID != profile.ID || profileStartupSettingsToken(current) != q.ProfileToken",
            "a.closing || profileSettingsBusy(a.state.Connected, a.state.Phase)",
            'updated.KillSwitchPolicy, updated.KillSwitch = q.KillSwitchPolicy, q.KillSwitchPolicy != "off"',
            "persistErr = a.persistProfilesLocked()", "a.profiles.Profiles[i] = current")
    require("cmd/client/profile_protection_test.go", "TestProfileProtectionPreservesExternalPrivateGraphAndPolicies",
            "TestProfileProtectionRejectsStaleSourceAndBusyOrMissingOwner",
            "TestProfileProtectionRejectsMalformedInputAndRollsBackPersistenceFailure")
    require(".github/workflows/windows-native-contract.yml",
            "test_desktop_protection_settings.py --platform windows --shell pwsh",
            "test_desktop_protection_settings.py --platform windows --shell powershell.exe")


def captured_tor_dns_policy() -> None:
    """Trace idle DNS edits and connection validation to the captured Tor path."""
    def function(path: str, name: str, *markers: str) -> str:
        body = require(path)
        match = re.search(r"(?ms)^func (?:\([^\n]+\) )?" + re.escape(name) + r"\([^\n]*\{.*?^\}", body)
        for marker in markers:
            if match is None or marker not in match.group():
                errors.append(f"{path}: captured Tor DNS function {name} lost: {marker}")
        return match.group() if match is not None else ""

    def ordered(body: str, name: str, *markers: str) -> None:
        position = -1
        for marker in markers:
            following = body.find(marker, position + 1)
            if following < 0:
                errors.append(f"captured Tor DNS function {name} lost ordered admission: {marker}")
                return
            position = following

    function("cmd/client/dns_policy_external.go", "validateDesktopExternalDNSPolicy",
             'if profile.External.Protocol == "tor-bridge"',
             "_, err := capturedTorBridgeDNS(profile, entry, true)", "return err",
             "mobilemultihop.ValidateExternalDNS(string(raw), entryJSON)")
    function("cmd/client/dns_policy_external.go", "capturedTorBridgeDNS",
             "profile = cloneRouterProfile(profile)",
             "desktopTorEntryMode(profile, entry,", "profile.MultihopEntryMode = mode",
             "desktopTorRuntimePolicyJSON(profile)", "json.Marshal(entry)",
             "return mobiletor.SelectDesktopBridgeDNS(string(raw), entryJSON, idle)")
    function("cmd/client/desktop_tor_prepare.go", "desktopTorRuntimePolicyJSON",
             "json.Marshal(runtimeWire(policy))", 'fields["home_lan_access"]',
             'policy.External.Protocol == "tor-bridge"',
             'fields["multihop_exit_mode"], _ = json.Marshal(policy.External.Protocol)')
    function("cmd/client/external_profile_connect.go", "externalDNSPolicyForPath",
             'case "tor-bridge":', "direct && entry.ID !=", '!direct && entry.ID == ""',
             "_, err = capturedTorBridgeDNS(policy, entry, false)",
             "if err != nil", "return common.RouterProfile{}, err")
    function("cmd/client/tor_bridge_routes.go", "torBridgeConnectCapturedOwned",
             "a.torBridgeConnectSelectionOwned(w, profile, externalProfileConnectRequest{ProfileID: profile.ID}, startup, desktopTorConnectRuntime{})")
    function("cmd/client/tor_bridge_routes.go", "torBridgeConnectWithRuntime",
             "decodeExternalProfileConnectRequest(http.MaxBytesReader(w, r.Body, 16<<10))",
             "a.validateExternalProfileExpectedProfilesLocked(q, profile)",
             "a.torBridgeConnectSelectionOwned(w, profile, q, nil, driver)")
    function("cmd/client/external_profile_connect.go", "externalProfileConnectOwned",
             'if externalProfile.External.Protocol == "tor-bridge"',
             "a.torBridgeConnectSelectionOwned(w, externalProfile, q, startup, driver.tor)")
    selection = function("cmd/client/desktop_tor_selection.go", "captureDesktopTorSelection",
             "profile = cloneRouterProfile(profile)", "direct = *q.Direct",
             "entryID = profile.MultihopEntryID", "entry = cloneRouterProfile(entry)",
             "desktopTorEntryMode(profile, entry, q.EntryMode, base)",
             "captureDesktopTorPredecessor(a, policy, lookup)",
             "desktopTorSourceIdentityToken(entry) != selection.predecessor.profileToken",
             "policy, err = externalDNSPolicyForPath(policy, entry, direct)",
             "selection.policy = policy", "selection.current(a)")
    ordered(selection, "captureDesktopTorSelection",
            "policy, err = externalDNSPolicyForPath(policy, entry, direct)",
            "if err != nil", "return nil, err", "captureDesktopTorPredecessor(a, policy, lookup)",
            "desktopTorSourceIdentityToken(entry) != selection.predecessor.profileToken",
            "selection.policy = policy")
    function("cmd/client/desktop_tor_predecessor_external.go", "desktopTorEntryMode",
             "return desktopExternalEntryMode(control, entry, requested, base)",
             'entry.NodeKind != "external"', "!desktopExternalNativeProtocol(entry.External.Protocol)",
             "if _, err := standardExitFromExternalProfile(entry); err != nil",
             'mode != "" && mode != entry.External.Protocol', "return entry.External.Protocol, nil")
    external = function("cmd/client/desktop_tor_predecessor_external.go", "compileDesktopTorExternalPredecessor",
             "source = cloneRouterProfile(source)", "runtimeProfile := cloneRouterProfile(source)",
             "runtimeProfile.MultihopEnabled = false", "copyDNSPolicy(&runtimeProfile, policy)",
             "standardExitFromExternalProfile(runtimeProfile)",
             'compileDesktopExternalCaptured(ctx, runtimeProfile, common.RouterProfile{}, exit, true, "", nil, nil, lookup)',
             "mobiletor.NewDesktopExternalPredecessor(mode, string(raw), string(launch.external.source), assets)",
             "entry: source, profileToken: desktopTorSourceIdentityToken(source)")
    ordered(external, "compileDesktopTorExternalPredecessor",
            "copyDNSPolicy(&runtimeProfile, policy)", "standardExitFromExternalProfile(runtimeProfile)",
            "compileDesktopExternalCaptured(", "mobiletor.NewDesktopExternalPredecessor(")
    connect = function("cmd/client/tor_bridge_routes.go", "torBridgeConnectSelectionOwned",
             "lookup := driver.lookup", "if lookup == nil", "lookup = desktopTorEndpointLookup",
             "selection, err := captureDesktopTorSelection(a, profile, q, lookup)",
             "http.Error(w, err.Error(), http.StatusBadRequest)",
             "policy := selection.policy",
             "prepareTorBridgeCommandWithRuntime(a, policy, profile, selection.predecessor, driver)",
             "selection.current(a)", "a.validateExternalProfileExpectedProfiles(q, profile)",
             "if err := check(); err != nil", "a.stopModeWithIntent(true)", "prelaunch.start(check)")
    ordered(connect, "torBridgeConnectSelectionOwned",
            "lookup := driver.lookup", "lookup = desktopTorEndpointLookup",
            "captureDesktopTorSelection(a, profile, q, lookup)",
            "prepareTorBridgeCommandWithRuntime(a, policy, profile, selection.predecessor, driver)",
            "if err := check(); err != nil", "a.stopModeWithIntent(true)", "prelaunch.start(check)")
    function("cmd/client/desktop_tor_prepare.go", "prepareTorBridgeCommandWithRuntime",
             "driver.runtime = prepareTorBridgeRuntimeWithPredecessor",
             "driver.runtime(root, policy, profile, predecessor)",
             "launch.tor.predecessor != predecessor",
             "captureTorBridgePrelaunch(a, profile.ID, prepared.RuntimeDir, launch)",
             "preflightDesktopTorLaunch(a.connectionOperationContextOrBackground(), prepared.NativeBinary, launch, environment, driver.preflight)")
    start = function("cmd/client/tor_bridge_prelaunch.go", "start",
             "if err := check(); err != nil", "if err := owner.validate(); err != nil",
             "desktopTorSourceIdentityToken(profile) == launch.tor.profileToken",
             "launch.tor.entryCurrent(owner.app)",
             "desktopNodeOwners.LoadOrStore(owner.app, launch)",
             "registerActiveDNSRuntimeConfig(owner.app, owner.dns.ProfileID, owner.dns.RuntimeID, owner.dns.Config)",
             "owner.command.Start()")
    ordered(start, "torBridgePrelaunch.start",
            "desktopNodeOwners.LoadOrStore(owner.app, launch)",
            "if err := check(); err != nil", "launch.tor.entryCurrent(owner.app)",
            "registerActiveDNSRuntimeConfig(owner.app, owner.dns.ProfileID, owner.dns.RuntimeID, owner.dns.Config)",
            "owner.command.Start()")
    function("internal/mobiletor/desktop_dns.go", "SelectDesktopBridgeDNS",
             "desktopBridgeProfile(source)", '(profile["multihop_enabled"] == true) != (entryJSON != "")',
             "NewPredecessorProof(entryJSON)", 'profile["multihop_entry_id"] != entry["id"]',
             'profile["multihop_exit_id"] != profile["id"]', 'entry["id"] == profile["id"]',
             'profileString(profile, "multihop_execution") != "local"',
             "torSelectedDNS(profile, entry, idle)")
    function("internal/mobiletor/profile.go", "torSelectedDNS",
             'mode = "home"', 'if raw := profile["dns_bootstrap"]; raw != nil',
             "if entry == nil && !idle", '[]string{"adguard_ipv4", "adguard_ipv6"}',
             "if host == address", "if !matched", "address.IsPrivate() != home",
             'protocol != "tcp" && protocol != "tls" && protocol != "https" && !(home && (protocol == "udp" || protocol == "h3"))')
    require("cmd/client/desktop_tor_entry_dns_test.go",
            "TestDesktopTorEntryDNSSettingsPreserveExactPrivateNodeAndTransport",
            "TestDesktopTorEntryDNSSettingsRejectStalePrivateSelection",
            "TestDesktopTorEntryDNSRetestKeepsPrivateRouteAndRejectsChangedSource")
    require("internal/mobiletor/desktop_dns_test.go",
            "TestDesktopBridgeDNSSelectionMatchesTheNativeCapturedGraph",
            "TestDesktopBridgeDNSRejectsAnotherPrivateEntryAndKeepsIdleHomeUnresolved")


windows_profile_controls()
linux_dns_measurement_controls()
captured_tor_dns_policy()


dns_api = require(
    "cmd/client/dns_policy_api.go",
    "/api/dns/policy", 'case "home"', 'case "fastest"', 'case "custom"', 'case "dot"',
    'case "doh"', 'case "doh3"', 'case "rescue"', "beginMutationOperation(r)",
    "dnsPolicySelectionToken(current, currentEntry) != token", "current.ID != profile.ID",
    "profileSettingsBusy(a.state.Connected, a.state.Phase)", "copyDNSPolicy(&currentUpdate, updated)",
    "a.profiles.Profiles[i] = current",
    "DNS benchmark values are real A/AAAA DNS query RTTs", "profile.DNSMode = mode",
)
for forbidden in ("APIToken =", "NodeProofID =", "PrivateKey ="):
    if forbidden in dns_api:
        errors.append(f"cmd/client/dns_policy_api.go: DNS mutation unexpectedly writes secret/identity field: {forbidden}")
require("cmd/client/dns_policy_api_test.go", "TestDNSPolicyOnlyMutatesDNSFields", "TestApplyDNSPolicyEncryptedInference", "TestApplyDNSPolicyRejectsUnsafeOrUnsupported")
require("cmd/client/dns_policy_external.go", "mobilemultihop.ValidateExternalDNS", "dnsPolicySelectionToken", "copyDNSPolicy")
require("cmd/client/dns_policy_external_test.go", "TestExternalDNSPolicySavePreservesAllNinePrivateProtocolsAndOtherSettings", "TestExternalDNSPolicyRejectsStaleNodeEntryAndBenchmarkInputs", "TestExternalDNSPolicyRejectsMalformedUnownedAndFailedSaves", "TestExternalDNSPolicyRescueIsExplicitCanonicalPresetAndFastestRejectsLegacyEvidence")
require("cmd/client/logical_modes.go", "ping_min_ms", "ping_max_ms", "traffic_min_pct", "traffic_max_pct", "speed_loss_min_pct", "speed_loss_max_pct", "ready_bases", "reason")

home = require(
    "cmd/client/home_summary.go",
    "/api/home-summary", "/api/home-summary/prove-exit", "SessionID", "ActualExitStatus",
    "actual public exit is not proven for this live session", "after.ActualMode != before.ActualMode",
    "mtuStateSnapshotToken(a.state)", "a.profiles.Profiles[i].PublicIP = ip", "proof.SessionID == session.ID", "probePublicExitIP",
)
for forbidden in (
    "ActualExitIP: profile.PublicIP", "ActualExitIP: profile.Endpoint", "actualExit = profile.PublicIP",
    "actualExit = profile.Endpoint",
):
    if forbidden in home:
        errors.append(f"cmd/client/home_summary.go: cached/expected endpoint can be mislabeled as actual exit: {forbidden}")
require(
    "cmd/client/home_summary_test.go",
    "TestHomeSummaryDoesNotTreatCachedProfilePublicIPAsLiveProof",
    "TestHomeSummaryUsesOnlyProofForCurrentSession",
    "TestHomeSummaryReportsFallbackDNSAndSharedState",
)
require("cmd/client/mtu_retest.go", "registerHomeSummaryRoute(h, a)", "registerHopTelemetryRoutes(h, a)")
require(
    "cmd/client/telemetry.go",
    "/api/profile/fastest", "/api/connection/live-latency", "/api/multihop/live-latency",
    "/api/connection/speed-test", "connectionTelemetryPathContext",
    "measureRoutedProfileSpeedContext", "measureRoutedProfileSpeedViaProxyContext",
)
require(
    "cmd/client/telemetry_hops.go",
    "/api/profile/speed-test", "/api/multihop/speed-test", "measureRoutedProfileSpeed",
    "/api/benchmark/download", "/api/benchmark/upload", "routedSpeedPathContext",
    "entry_error", "exit_error", "not derived from RTT", "unchanged current client routing graph",
)
require(
    "cmd/router-agent/benchmark.go",
    "/api/benchmark/download", "/api/benchmark/upload", "s.authorized(r)", "benchmarkMaxBytes",
    "no-store, no-transform", "content-encoding", "registerClientForwardingMasterRoute",
)
require(
    "cmd/router-agent/client_forwarding_master.go",
    "/api/forwarding/master", "s.authorized(r)", "admin mutation address must remain loopback-only",
    "/api/admin/settings", 'map[string]bool{"forwarding_master": *requested}',
    "Setup Center admin token never", "authenticated tunnel-peer request proxied server-side",
)
require(
    "cmd/router-agent/client_forwarding_master_test.go",
    "TestValidatedAdminMutationBaseRequiresLoopback", "TestClientForwardingMasterGetAndPut",
    "TestClientForwardingMasterRejectsNonTunnelPeer", "admin token leaked to tunnel client response",
)

# Windows: launcher -> unified transform -> telemetry transform -> shipping WPF product.
require(
    "client/RouterVPN-Windows-App.ps1",
    "Get-Content -LiteralPath $Product -Raw -Encoding UTF8",
    'MinHeight="480" MinWidth="640"', 'Height="2*" MinHeight="140"',
    'MaxWidth="760"', 'MinHeight="180"',
    "Add-RouterVPNUnifiedWindowsShell", "Add-RouterVPNTelemetryWindowsShell",
    "SMART AUTO is the default mode", "WireGuard / AmneziaWG",
    "/api/connection/speed-test", "/api/multihop/speed-test",
)
require(
    "client/RouterVPN-Windows-UnifiedShell.ps1",
    "UnifiedShell", "UnifiedMapCanvas", "UnifiedConnectButton", "UnifiedKillSwitch",
    "UnifiedProofButton", "UnifiedEmergencyButton", "Prove actual exit", "Emergency disconnect",
    "/api/home-summary/prove-exit", "actual_exit_status", "actual_exit_ip",
    "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "/api/multihop/connect", "/api/mtu/retest", "/api/dns/policy",
    "SMART AUTO", "New CUSTOM preset", "real coordinates", "color-coded hop roles",
)
require(
    "client/RouterVPN-Windows-Telemetry.ps1",
    "UnifiedFastestNode", "UnifiedLiveLatency", "UnifiedMultihopLatency", "UnifiedForwardButton",
    "Real path speed", "/api/connection/speed-test", "Routed hop speeds", "/api/multihop/speed-test",
    "50-sample selected node", "Throughput + Auto MTU",
)
require(
    "client/RouterVPN-Windows-Product-v2.ps1",
    'Header="Layers"', 'Header="Added ms"', 'Header="Traffic"', 'Header="Speed loss"',
    'Header="Exact reason"', "layers_text", "ping_text", "traffic_text", "speed_text", "reason_text",
    "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS",
    "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "/api/dns/retest",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6", "latitude", "longitude",
    "No real node coordinates",
)

# macOS: build script must compile Product + UnifiedShell + Telemetry into RouterVPN.app.
require(
    "client/macos/RouterVPNMacProduct.swift",
    "import MapKit", "MKMapView", "latitude", "longitude", "layers: ", "added latency",
    "traffic", "speed loss", "readiness:", "reason:", "Home AdGuard", "Fastest measured",
    "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue",
    "/api/dns/policy", "/api/dns/retest", "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    ".resizable", "window.minSize",
)
require(
    "client/macos/RouterVPNHomeSummary.swift",
    "/api/home-summary", "/api/home-summary/prove-exit", 'actualExitStatus == "proved"',
    "Actual public VPN exit", "Connection:", "Logical/runtime/base", "Fallback:", "DNS:",
    "Node latency", "LAN access", "Kill switch", "Effective MTU", "Warnings:",
)
require(
    "client/macos/RouterVPNMacUnifiedShell.swift",
    "buildUnifiedUI", "CUSTOM preset builder", "Save & Connect", "Delete", "SMART AUTO — recommended",
    "AUTO — first proven path", "unified-connect", "unified-multihop-toggle", "Open settings",
    "Mode", "DNS", "systemBlue", "systemOrange", "systemPink", "real coordinates",
)
require(
    "client/macos/RouterVPNMacTelemetry.swift",
    "unified-fastest-node", "unified-live-latency", "unified-multihop-latency", "Forward",
    "Real path speed", "/api/connection/speed-test", "Routed hop speeds", "/api/multihop/speed-test",
)
require_combined(
    "macOS unified shipping product",
    ("client/macos/build-native-app.sh", "client/macos/RouterVPNMacUnifiedShell.swift", "client/macos/RouterVPNMacTelemetry.swift", "client/macos/RouterVPNHomeSummary.swift"),
    "UNIFIED_SRC", "TELEMETRY_SRC", "HOME_SRC", '"$UNIFIED_SRC"', '"$TELEMETRY_SRC"', '"$HOME_SRC"',
    "Prove actual exit", "Emergency Disconnect", "SMART AUTO", "CUSTOM", "map-first",
    "Real path speed", "Routed hop speeds",
)

# Linux: generated build source must include unified root + telemetry and compile with -Werror.
require(
    "client/linux/routervpn-gtk-product-v5.c",
    "build_modes_page_v5", "Added latency", "traffic", "speed loss", "Readiness:", "Reason:",
    "build_dns_page_v5", "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "/api/dns/policy", "linux_dns_retest_v1(app)",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6", "gtk_notebook_set_scrollable",
)
require("client/linux/routervpn-gtk-product-v4.c", "latitude", "longitude", "Map")
require(
    "client/linux/routervpn-home-summary-v1.inc",
    "/api/home-summary", "/api/home-summary/prove-exit", "Actual public VPN exit", "Connection:",
    "Logical/runtime/base", "Fallback:", "DNS:", "Node measured latency", "LAN access", "Kill switch",
    "Effective MTU", "Warnings:", "on_home_exit_v6",
)
require(
    "client/linux/routervpn-telemetry-v9.inc",
    "LinuxTelemetryV9", "⚡ Fastest", "/api/profile/fastest", "/api/connection/live-latency",
    "/api/multihop/live-latency", "Real path speed", "/api/connection/speed-test",
    "Routed hop speeds", "/api/multihop/speed-test", "Throughput + Auto MTU", "Forward",
)
require_combined(
    "Linux unified shipping product",
    ("client/linux/build-native-app.sh", "client/linux/routervpn-unified-shell-v8.inc", "client/linux/routervpn-telemetry-v9.inc", "client/linux/routervpn-home-summary-v1.inc"),
    "routervpn-unified-shell-v8.inc", "routervpn-telemetry-v9.inc", "routervpn-home-summary-v1.inc",
    "linux_install_telemetry_v9(&app);", "SMART AUTO", "CUSTOM", "Connect", "Disconnect", "Kill switch",
    "Multihop", "Settings", "Mode", "DNS", "Real path speed", "Routed hop speeds",
    "gcc -O2 -Wall -Wextra -Werror",
)

# Android: ProductActivity is the launcher. It must expose the unified map-first UX and real telemetry.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProductParity.java",
    "listDirectLibboxModes", "listDirectXrayModes", "AndroidKillSwitchPolicy.strictRequested",
    "Added latency", "traffic", "speed loss", "Readiness:", "Home AdGuard", "Fastest measured",
    "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue",
    "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6", "/api/dns/benchmark",
    "transfer-encoding: chunked", "parseContentLength", "decodeChunked", "MAX_HTTP",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidRuntimeRegistry.java",
    "static AndroidRuntimeRegistry instance", "final NativeWireGuardController wireGuard",
    "final NativeAmneziaWGController amneziaWG", "final AndroidMultihopRuntime multihop",
    "final AndroidStandardExitRuntime standardExit", "final AndroidSessionRevalidator revalidator", "revalidator.start()",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeSummary.java",
    "TRANSPORT_VPN", "getOwnerUid()", "Process.myUid()", "getNetworkHandle()",
    "AndroidPathProbe.prove", "network.openConnection", "api64.ipify.org", "api.ipify.org",
    "Actual public VPN exit", "Logical/runtime/base", "Node latency", "LAN access", "Kill switch",
    "Effective MTU", "Warnings:", "Emergency Disconnect", '"|session="+runtime.sessionId', '"|path="+runtime.pathGeneration',
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeStateStore.java",
    "session_id", "actual_exit_session", "actualExitForCurrentSession", "path_generation", "advancePathGeneration",
    "begin(", "connected(", "disconnected(",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidTelemetry.java",
    "class SpeedResult", "speedTest(AndroidNodeStore.Node", "AndroidTelemetryCapture.current", "captured::requireCurrent",
    "io.drain()", "AndroidMTUMeasurementGate.release(lease)", "AndroidNodeStatistics.save", "downloadMbps", "uploadMbps",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidTelemetryHttp.java",
    "/api/benchmark/download", "/api/benchmark/upload", "Authorization", "Accept-Encoding",
    "expectedNode.equals", "authorize.run()", "io.open()",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidTelemetryCapture.java",
    "home.activeNodeId", "home.activeExitId", "home.sessionId", "home.pathGeneration", "AndroidPrivateFileStore.read", "route.check()",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStatistics.java",
    "samples==50&&failed==0", "source_sha256", "average_ms", "trimmed_mean_ms", "p90_ms", "max_ms", "measured_at_ms", "!r.eligible()",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidForwardingMaster.java",
    "/api/forwarding/master", "vpn.openConnection", "getOwnerUid()==Process.myUid()", "isPrivate(address)",
    "state.sessionId.equals(after.sessionId)", "after.pathGeneration!=state.pathGeneration",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/RouterVpnNodeMapView.java",
    "ROLE_ENTRY", "ROLE_EXIT", "ROLE_EXTERNAL", "latencyMs", "System.currentTimeMillis", "postInvalidateDelayed",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "RouterVpnNodeMapView", "⚡ Fastest", "SMART AUTO — recommended", "New CUSTOM preset", "Details / proof",
    "showConnectionDetails", "AndroidHomeSummary.format", "AndroidHomeSummary.proveActualExit",
    "AndroidHomeSummary.emergencyDisconnect", "Prove actual exit", "Emergency disconnect",
    "AndroidProductParity.showModes", "AndroidProductParity.showDNS", "showSettings",
    "Multihop", "Add Router node", "Add custom", "Profiles", "showProfileManager",
    "Real current VPN path speed", "Routed multihop speeds", "runRoutedHopSpeeds",
    "telemetry.speedTest(entry", "telemetry.speedTest(exit", "connection.restorePending(state,callback())",
    "connection.savePending(out)", "connection.activeMultihopEntryId()", "connection.activeMultihopExitId()",
    "AndroidForwardingMaster forwardingMaster", "Forward ON", "Forward OFF", "setForwardingMaster",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java",
    "AndroidHomeStateStore.begin", "AndroidHomeStateStore.connected", "AndroidHomeStateStore.disconnected",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java",
    "AndroidHomeStateStore.begin", "AndroidHomeStateStore.connected", "AndroidHomeStateStore.disconnected",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java",
    '"SMART AUTO"', '"CUSTOM"', '"AUTO"', '"ALL"', "AndroidHomeStateStore.begin",
    "AndroidHomeStateStore.connected", "baseFor(best)", "AndroidHomeStateStore.disconnected",
)
require(
    "android/app/src/main/AndroidManifest.xml",
    "android.permission.BIND_VPN_SERVICE", 'android:usesCleartextTraffic="false"',
    'android:name=".ProductActivity"', 'android.intent.category.LAUNCHER',
    'android:name=".MainActivity" android:exported="false" android:enabled="false"',
)
require("android/test_android_session_identity_contract.py", "Android session identity contract: PASS")

# iOS/iPadOS: @main -> ProductRootView -> IOSUnifiedProductView, all App sources compiled by XcodeGen.
require("ios/RouterVPN/App/RouterVPNApp.swift", "@main", "ProductRootView()")
require(
    "ios/RouterVPN/App/ProductParitySheets.swift",
    "RouterVPNModeMetricsSheet", "RouterVPNDNSSettingsSheet", "Added latency", "traffic", "speed loss",
    "Readiness:", "Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS",
    "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue", "Cloudflare IPv6", "Google IPv6", "Quad9 IPv6",
    "/api/dns/benchmark", "NavigationStack", "List(", "Form",
)
require(
    "ios/RouterVPN/App/IOSHomeSummaryView.swift",
    "Actual public VPN exit", "selected-node proof passed", "Logical/runtime/base", "Fallback:", "DNS:",
    "Node latency", "LAN access", "Kill switch", "Effective MTU", "Warnings:", "Prove actual exit",
    "Emergency Disconnect", "api64.ipify.org", "api.ipify.org", "model.bundle?.selectedRouterID == selectedNode",
    "model.activeEngine == engine", "model.activeRawProfile == rawProfile", "Cached profile.publicIP is never used as live proof",
)
require_combined(
    "iOS/iPadOS unified root lifecycle",
    ("ios/RouterVPN/App/RouterVPNApp.swift", "ios/RouterVPN/App/ProductRootView.swift", "ios/RouterVPN/App/IOSUnifiedProductView.swift"),
    "ProductRootView()", "IOSUnifiedProductView()", "map-first", "SMART AUTO default", "CUSTOM preset builder",
    "RouterVPNProductOnboardingDoneV2",
)
require(
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "IOSUnifiedMap", "IOSHomeSummaryView", "Connect", "Disconnect", "Kill switch", "Multihop",
    "Settings", "Mode", "DNS", "SMART AUTO", "New CUSTOM preset", "real coordinates",
    "systemBlue", "systemOrange", "systemPink", "Require encrypted", "Require obfuscation",
    "Run real current VPN path speed", "telemetry.speedTest",
)
ios_telemetry = require(
    "ios/RouterVPN/App/IOSUnifiedTelemetry.swift",
    "IOSSpeedResult", "IOSNativeTelemetryReply", "IOSCurrentTelemetryCapture", "IOSNativeTelemetryTransaction",
    "IOSMTUControl.withHold", "commitNodeLatency", "requireDirectResultCurrent", "sendProviderMessage",
    "downloadMbps", "uploadMbps",
)
if "URLSession" in ios_telemetry:
    errors.append("iOS current-path telemetry bypasses the proved native channel")
require(
    "ios/RouterVPN/PacketTunnel/RouterVPNTelemetryChannel.swift",
    "RouterVPNForwardingPolicy.verifyProof", "/api/benchmark/download", "/api/benchmark/upload",
    "Authorization: Bearer", "finishCancelled", "pendingWrites", "retryWrites()",
)
require(
    "ios/RouterVPN/PacketTunnel/RouterVPNTelemetryTransport.swift",
    "nativeCancelled, pendingIO == 0", "connection.cancel()", "connection.retire()", "bodyLimit",
)
require(
    "ios/RouterVPN/PacketTunnel/RouterVPNTelemetryNativeConnection.swift",
    "RVPNTunnelTCPConnection(provider: provider", "func retire()", "observation?.invalidate()",
)
require(
    "ios/RouterVPN/App/IOSNodeLatencyStatistics.swift",
    "samples == 50, failed == 0", "latencyTrimmedMeanMs", "latencyLastTest", "measuredAt",
)
require(
    "ios/RouterVPN/App/NodeManagerSheet.swift",
    "Pair from home LAN", "Import node bundle", "Select lowest-latency node", "model.removeNode", "Edit", "updateNodeMetadata",
)
require(
    "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift",
    "WireGuardAdapter(with: self)", "RouterVPNLibboxEngine", "includeAllNetworks", "enforceRoutes",
)
require(
    "ios/RouterVPN/project.yml",
    "sources:", "- App", "- Resources", "- path: ../../LICENSE", "buildPhase: resources",
    "Verify MIT license resource", 'test -s "$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/LICENSE"',
    "NSAllowsLocalNetworking", 'TARGETED_DEVICE_FAMILY: "1,2"', "SWIFT_VERSION: \"6.0\"",
)

setup = require(
    "server/scripts/generate-setup-assets.py",
    "Server/source readiness", "Reason / next gate", "20 raw runtimes", "16 logical modes",
    "installed client still revalidates its platform engine/path", "Complex Router VPN stacks stay in the Router VPN app",
    "@media(max-width:820px)", "-webkit-overflow-scrolling:touch", "Home AdGuard", "Fastest measured",
    "Custom UDP/TCP", "DoT", "DoH", "DoH3", "DNS Rescue",
)
for stale in (
    "Multi-hop is intentionally not labeled ready here yet",
    "strict firewall kill switch and remote “kick every peer” control are not advertised as ready",
    "Shadowsocks, Hysteria2, AmneziaWG, Xray, OverTLS",
):
    if stale in setup:
        errors.append(f"server/scripts/generate-setup-assets.py: stale/superseded product claim returned: {stale}")

require(
    ".github/workflows/release-candidate-status.yml",
    "workflow_run", "Router VPN release candidate", "statuses: write", "head_sha",
)

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN current shipping cross-platform product parity audit: PASS")
