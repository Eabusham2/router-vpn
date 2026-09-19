#!/usr/bin/env python3
from pathlib import Path
import base64, re

ROOT=Path(__file__).resolve().parents[1]
HELPER=ROOT/'client/RouterVPN-Windows-SessionMutation.ps1'
LAUNCHER=ROOT/'client/RouterVPN-Windows-App.ps1'
PRODUCT=ROOT/'client/RouterVPN-Windows-Product-v2.ps1'
UNIFIED=ROOT/'client/RouterVPN-Windows-UnifiedShell.ps1'

helper=HELPER.read_text(encoding='utf-8')
launcher=LAUNCHER.read_text(encoding='utf-8')

for marker in (
    'Convert-RouterVPNWindowsProductSessionMutation',
    'Convert-RouterVPNWindowsUnifiedSessionMutation',
    'session-mutation source contract drifted',
):
    assert marker in helper, f'Windows session helper missing {marker}'
for marker in (
    'RouterVPN-Windows-SessionMutation.ps1',
    '$UnifiedShellSource=Convert-RouterVPNWindowsUnifiedSessionMutation -Source $UnifiedShellSource',
    '$ProductSource=Convert-RouterVPNWindowsProductSessionMutation -Source $ProductSource',
):
    assert marker in launcher, f'Windows launcher does not compose session hardening: {marker}'

# Parse the base64 replacement pairs from the helper and prove the exact shipping
# transforms apply cleanly to the repository baseline sources.
def pairs_for(name: str):
    m=re.search(rf'function Convert-RouterVPNWindows{name}SessionMutation \{{.*?\$Pairs=@\((.*?)\n\);return',helper,re.S)
    assert m, f'{name} transform block missing'
    pairs=[]
    for a,b in re.findall(r",@\('([^']*)','([^']*)'\)",m.group(1)):
        pairs.append((base64.b64decode(a).decode(),base64.b64decode(b).decode()))
    assert pairs, f'{name} transform has no replacements'
    return pairs

def transform(source: str, pairs):
    for old,new in pairs:
        assert source.count(old)==1, f'transform anchor count={source.count(old)} for {old[:80]!r}'
        source=source.replace(old,new,1)
    return source

product=transform(PRODUCT.read_text(encoding='utf-8'),pairs_for('Product'))
unified=transform(UNIFIED.read_text(encoding='utf-8'),pairs_for('Unified'))

for marker in (
    'function Test-RouterVPNMutationBusyFromStatus',
    'function Test-RouterVPNMutationBusy',
    'function Assert-RouterVPNMutationIdle',
    'connecting|starting|checking|trying|proving|reasserting|disconnecting|stopping|switching|reconnecting',
    'catch{return $true}',
    '$DnsSaveButton.IsEnabled=-not$MutationBusy',
    "foreach($Name in @('PairNodeButton','ImportNodeButton','DeleteNodeButton','SelectNodeButton','SelectLowestLatencyButton','ExternalDirectButton','ExternalViaEntryButton','MultihopConnectButton','AutoButton','ConnectButton'))",
    "Assert-RouterVPNMutationIdle 'opening node pairing'",
    "Assert-RouterVPNMutationIdle 'redeeming the one-time pairing code'",
    "Assert-RouterVPNMutationIdle 'importing a linked node'",
    "Assert-RouterVPNMutationIdle 'committing the lowest-latency node selection'",
    "Assert-RouterVPNMutationIdle 'removing a linked node'",
    "Assert-RouterVPNMutationIdle 'saving DNS policy'",
    '$RouterCombo.Add_SelectionChanged({if(-not $script:Busy -and $RouterCombo.SelectedValue)',
):
    assert marker in product, f'transformed Product missing {marker}'

for marker in (
    'Disconnect already in progress',
    "Assert-RouterVPNMutationIdle 'editing CUSTOM presets'",
    "Assert-RouterVPNMutationIdle 'saving a CUSTOM preset'",
    "Assert-RouterVPNMutationIdle 'deleting a CUSTOM preset'",
    '$UnifiedConnect.IsEnabled=-not$Disconnecting',
    "foreach($Name in @(''UnifiedKillSwitch'',''UnifiedMultihop'',''UnifiedModeCombo'',''UnifiedDnsCombo''))",
    "Assert-RouterVPNMutationIdle 'changing the selected mode'",
    "Assert-RouterVPNMutationIdle 'changing persistent kill-switch policy'",
    "Assert-RouterVPNMutationIdle 'changing DNS policy'",
    'Add-Type -AssemblyName System.Net.Http',
    'function StartUnifiedApiAsync',
    'function CancelUnifiedApiAsync',
    '$script:UnifiedAsyncClient.SendAsync($Req,$Cts.Token)',
    "'Cancel / Disconnect'",
    "StartUnifiedApiAsync 'Disconnecting…'",
    "StartUnifiedApiAsync 'Retesting MTU…'",
    "function StartUnifiedRefreshAsync",
    "function CancelUnifiedRefreshAsync",
    "function ApplyUnifiedRefreshSnapshot",
    "$script:UnifiedRefreshClient.SendAsync($Req,$script:UnifiedRefreshCts.Token)",
    "[void](CancelUnifiedRefreshAsync)",
    "$ProductSource.Replace('function RefreshProduct{','function RefreshProductLegacy{')",
    "function RefreshProduct{StartUnifiedRefreshAsync}",
    "UnifiedRefreshBusy",
    "$script:UnifiedRefreshClient.Dispose()",
    "$legacyMultihopOld",
    "$legacyMtuOld",
    "$legacyAutoOld",
    "$legacyConnectOld",
    "$legacyDnsOld",
    "$legacyLatencyOld",
    "$legacyExternalOld",
    "Testing 50-sample node latency…",
    "Retesting DNS…",
    "Legacy AUTO…",
    "Connecting selected mode…",
    "Connecting external exit…",
    "$ProductSource=$ProductSource.Replace($Pair[0],$Pair[1])",
):
    assert marker in unified, f'transformed UnifiedShell missing {marker}'

# Old blocking snippets are exact source-transform anchors, not executable
# shipping callbacks. Remove only those seven named here-string definitions
# before enforcing the blocking-call ban everywhere else in the helper.
old_anchor_pattern=re.compile(
    r"(?ms)^\s*\$legacy(?:Multihop|Mtu|Auto|Connect|Dns|Latency|External)Old\s*=\s*@'\n.*?^\s*'@\s*$"
)
unified_without_old_anchors, old_anchor_count=old_anchor_pattern.subn("", unified)
assert old_anchor_count == 7, f'Windows legacy async conversion anchor count drifted: {old_anchor_count}'

for forbidden in (
    "$R=Api '/api/strategy/smart-auto' 'POST'",
    "$R=Api '/api/strategy/auto' 'POST'",
    "$R=Api '/api/strategy/custom' 'POST'",
    "$R=Api '/api/multihop/connect' 'POST'",
    "$R=Api '/api/external-profile/connect' 'POST'",
    "$R=Api '/api/connect-logical' 'POST'",
    "Api '/api/mtu/retest' 'POST' @{} 130",
    "[void](Api '/api/disconnect' 'POST' @{} 20)",
):
    assert forbidden not in unified_without_old_anchors, f'Windows unified shipping transform revived blocking long action: {forbidden}'

assert '$Timer.Add_Tick({RefreshProduct})' in product, 'Windows timer no longer calls the async public refresh entrypoint'
assert '$Timer.Add_Tick({RefreshProductLegacy})' not in product, 'Windows timer revived the blocking legacy refresher'

telemetry=(ROOT/'client/RouterVPN-Windows-Telemetry.ps1').read_text(encoding='utf-8')
for marker in (
    "Assert-RouterVPNMutationIdle 'selecting a node from the VPN globe'",
    "Assert-RouterVPNMutationIdle 'selecting a Router VPN node'",
    "UnifiedFastestNode').IsEnabled=($Payload.status-and-not(Test-RouterVPNMutationBusyFromStatus $Payload.status))",
    "status=@('GET','/api/status',$null)",
    "function StartUnifiedTelemetryRefresh",
    "function CancelUnifiedTelemetryRefreshAsync",
    "$script:UnifiedTelemetryClient.SendAsync($Req,$script:UnifiedTelemetryCts.Token)",
    "StartUnifiedApiAsync 'Updating forwarding…'",
    "StartUnifiedApiAsync 'Selecting fastest node…'",
    "StartUnifiedApiAsync 'Selecting node…'",
    "Testing 50-sample node latency…",
    "Testing real path speed…",
    "Testing routed hop speeds…",
):
    assert marker in telemetry, f'Windows telemetry session/async guard missing {marker}'
assert "selecting/connecting a fastest Router VPN node" not in telemetry, 'Fastest selection must not silently connect'
for forbidden in (
    "$Live=Api '/api/connection/live-latency'",
    "$R=Api '/api/multihop/live-latency'",
    "[void](Api '/api/profile/fastest'",
    "$R=Api '/api/forwarding/master'",
    "$R=Api '/api/profile/latency'",
    "$R=Api '/api/connection/speed-test'",
    "$R=Api '/api/multihop/speed-test'",
    "Test-RouterVPNMutationBusy)",
):
    assert forbidden not in telemetry, f'Windows telemetry revived WPF-thread network action: {forbidden}'

print('Windows session mutation shipping audit: PASS')
