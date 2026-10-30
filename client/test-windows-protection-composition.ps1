param([Parameter(Mandatory=$true)][string]$ProductSource)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

# Execute the final shipping refresh and click bodies after every launcher
# transform. Widgets and HTTP completions below are explicit test boundaries;
# this fixture never creates a WPF window, controller, tunnel or firewall rule.
$Ast=[ScriptBlock]::Create($ProductSource).Ast
function Assert-ProtectionComposition([bool]$Value,[string]$Message){if(-not$Value){throw $Message}}
foreach($Name in @('Test-RouterVPNMutationBusyFromStatus','Test-RouterVPNMutationBusy','Assert-RouterVPNMutationIdle',
    'ApplyUnifiedRefreshSnapshot','UnifiedRefreshBusy','CompleteUnifiedRefreshAsync','SetUnifiedAsyncUI',
    'UnifiedTelemetryBusy','CompleteUnifiedTelemetryRefresh')){
    $Functions=@($Ast.FindAll({param($N)$N-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$N.Name-ceq$Name},$true))
    Assert-ProtectionComposition ($Functions.Count-eq1) ('Missing or duplicated composed protection function: '+$Name)
    . ([ScriptBlock]::Create($Functions[0].Extent.Text))
}
$KillMarkup=@([regex]::Matches($ProductSource,'<CheckBox\b[^>]*\bName="UnifiedKillSwitch"[^>]*/>'))
Assert-ProtectionComposition ($KillMarkup.Count-eq1) 'Composed telemetry lost or duplicated the Kill switch'
[xml]$KillXml=$KillMarkup[0].Value
Assert-ProtectionComposition ($KillXml.DocumentElement.GetAttribute('IsEnabled')-ceq'False') 'Composed telemetry enabled protection before its captured status'

$script:ProtectionControls=@{}
function Control([string]$Name){
    if(-not$script:ProtectionControls.ContainsKey($Name)){
        $C=[pscustomobject]@{Name=$Name;Text='';Content='';IsEnabled=$true;IsChecked=$null;ToolTip='';Fill='';Foreground='';ItemsSource=$null;SelectedValue='';Tag=$null;Callback=$null;Registrations=0}
        $C|Add-Member ScriptMethod Add_Click {param($Callback)$this.Callback=$Callback;$this.Registrations++}
        $script:ProtectionControls[$Name]=$C
    }
    return $script:ProtectionControls[$Name]
}
foreach($Name in @('StateText','StateDot','ConnectionDetail','LastErrorText','ProofText','DnsSaveButton','DnsButton',
    'RouterCombo','ModeCombo','BaseCombo','DnsModeCombo','DnsProtocolCombo','DnsPresetCombo','DnsHostBox','DnsPortBox',
    'DnsServerBox','DnsPathBox','MultihopEntryCombo','MultihopExitCombo','MultihopEntryModeCombo','MultihopExitModeCombo',
    'NodesGrid','AdvancedSummary','SettingsSummary','DnsSummary','ModesGrid','HeaderDetail','MultihopSummary')){
    Set-Variable -Name $Name -Value (Control $Name)
}
function DrawMap{param($Profiles,$Selected)}
function DecorateModes{param($Modes)return $Modes}
function RefreshUnifiedModeChoices{param($Modes)}
function RefreshUnifiedMultihopComparison{param($MH)}
function SetComboTag{param($Combo,$Tag)$Combo.Tag=$Tag}
$script:ProtectionLogs=@();function Log([string]$Text){$script:ProtectionLogs+=,$Text}
$script:ProtectionRefreshes=0;function RefreshProduct{$script:ProtectionRefreshes++}
$script:ProtectionRequests=@()
function Set-RouterVPNProfileProtection{
    param([string]$BaseUrl,[string]$DisplayedProfileID,[bool]$Enabled)
    $script:ProtectionRequests+=,[pscustomobject]@{ProfileID=$DisplayedProfileID;Enabled=$Enabled;BaseUrl=$BaseUrl}
}
$script:ProtectionStatus=@{connected=$false;phase='off';runtime_mode='off';mode='off';logical_mode='';base='';router_id='';last_error=''}
function Api{param([string]$Path,[string]$Method='GET',$Body,[int]$Timeout)if($Path-cne'/api/status'){throw 'Unexpected protection fixture request'};return $script:ProtectionStatus}
$BaseUrl='https://127.0.0.1:8788'
$Profile=@{id='node';node_kind='router-vpn';name='Captured node';endpoint='192.0.2.1';location='';home_lan_access=$false;kill_switch_policy='always';mtu_policy='auto';effective_mtu=1420;effective_mtu_source='';effective_mtu_tested_at='';effective_mtu_success_ratio=0;effective_mtu_mbps=0;effective_mtu_median_rtt_ms=0;multihop_enabled=$false;auto_require_encrypted=$false;auto_require_obfuscation=$false;ipv6_mode='on';dns_mode='home'}
$Store=@{selected_id='node';profiles=@($Profile)}
$Session=@{dns_proof=@{mode='home';host='192.168.50.133';status='pending';latency_ms=0;reason=''}}
$MH=@{nodes=@();entry_id='';exit_id='';platform_supported=$true;connected=$false;actual_exit_id='';runtime_exit_mode='';supported_entry_bases=@();supported_exit_modes=@()}
$Timeline=@{events=@();last_event_seq=0}
$script:Busy=$false;$script:EventSeq=[uint64]0;$script:DnsPolicySummary='Home AdGuard';$script:NodeSort='name'
$script:UnifiedProtectionPending=$false;$script:UnifiedProtectionProfileID='';$script:UnifiedAsyncClosed=$false
$script:UnifiedRefreshTasks=@{};$script:UnifiedRefreshRequests=@{};$script:UnifiedRefreshDiscard=$false
$script:UnifiedTelemetryTasks=@{};$script:UnifiedTelemetryRequests=@{};$script:UnifiedTelemetryDiscard=$false
$script:UnifiedRoutePathMs=0.0;$script:UnifiedForwardSync=$false
$script:UnifiedRefreshPoller=[pscustomobject]@{Stops=0};$script:UnifiedRefreshPoller|Add-Member ScriptMethod Stop {$this.Stops++}
$script:UnifiedTelemetryPoller=[pscustomobject]@{Stops=0};$script:UnifiedTelemetryPoller|Add-Member ScriptMethod Stop {$this.Stops++}

$Bindings=@($Ast.FindAll({param($N)$N-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and
    $N.Member-is[System.Management.Automation.Language.StringConstantExpressionAst]-and$N.Member.Value-ceq'Add_Click'-and
    $N.Expression.Extent.Text-match '^\(\s*Control\s+[''"]UnifiedKillSwitch[''"]\s*\)$'},$true))
Assert-ProtectionComposition ($Bindings.Count-eq1) 'Composed protection callback lost or duplicated'
. ([ScriptBlock]::Create($Bindings[0].Extent.Text))
Assert-ProtectionComposition ((Control 'UnifiedKillSwitch').Registrations-eq1) 'Composed protection callback not registered exactly once'

function New-ProtectionCompletion($Value,[int]$Status=200){
    $R=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$Status)
    $R.Content=[System.Net.Http.StringContent]::new((ConvertTo-Json -InputObject $Value -Depth 32 -Compress),[Text.Encoding]::UTF8,'application/json')
    $T=New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]'
    $T.SetResult($R)
    return $T.Task
}
function Complete-ProtectionSnapshot($Protection,[bool]$Discard=$false){
    $Payload=@{status=$script:ProtectionStatus;nodes=$Store;session=$Session;modes=@();multihop=$MH;events=$Timeline;protection=$Protection}
    foreach($Key in $Payload.Keys){$script:UnifiedRefreshTasks[$Key]=New-ProtectionCompletion $Payload[$Key]}
    $script:UnifiedRefreshCts=[Threading.CancellationTokenSource]::new();$script:UnifiedRefreshDiscard=$Discard
    CompleteUnifiedRefreshAsync
    Assert-ProtectionComposition ($script:UnifiedRefreshTasks.Count-eq0-and$null-eq$script:UnifiedRefreshCts) 'Composed protection refresh failed to retire its completions'
    Assert-ProtectionComposition ($StateText.Text-cne'Controller unavailable') ('Composed protection refresh failed: '+$LastErrorText.Text)
}
function Complete-ProtectionTelemetry{
    $script:UnifiedTelemetryTasks=@{status=(New-ProtectionCompletion $script:ProtectionStatus);profiles=(New-ProtectionCompletion $null);live=(New-ProtectionCompletion $null);multihop=(New-ProtectionCompletion $null);forward=(New-ProtectionCompletion $null)}
    $script:UnifiedTelemetryCts=[Threading.CancellationTokenSource]::new()
    CompleteUnifiedTelemetryRefresh
    Assert-ProtectionComposition ($script:UnifiedTelemetryTasks.Count-eq0-and$null-eq$script:UnifiedTelemetryCts) 'Telemetry did not retire its captured completions'
}

foreach($Phase in @('off-pending','off-unsaved')){
    $Protection=[pscustomobject]@{profile_id='node';profile_token='exact-target-revision';kill_switch_policy='always';protection_status=$Phase;effective_policy='off';message='Protection is off; finish saving the captured change.'}
    Complete-ProtectionSnapshot $Protection
    $Kill=Control 'UnifiedKillSwitch'
    Assert-ProtectionComposition ($script:UnifiedProtectionPending-and$script:UnifiedProtectionProfileID-ceq'node') 'Seventh refresh argument lost pending protection ownership'
    Assert-ProtectionComposition ($Kill.IsEnabled-and$null-eq$Kill.IsChecked-and$Kill.Content-ceq'Finish Off'-and$Kill.ToolTip-ceq$Protection.message) 'Composed shell hid the effective pending Off state'
    foreach($Name in @('UnifiedConnectButton','UnifiedModeCombo','UnifiedDnsCombo','UnifiedFastestNode')){
        Assert-ProtectionComposition (-not(Control $Name).IsEnabled) ('Pending Off allowed another mutation: '+$Name)
    }
    SetUnifiedAsyncUI $true 'Working'
    Assert-ProtectionComposition (-not$Kill.IsEnabled) 'Busy action left Finish Off enabled'
    SetUnifiedAsyncUI $false
    Assert-ProtectionComposition ($Kill.IsEnabled-and-not(Control 'UnifiedConnectButton').IsEnabled-and-not(Control 'UnifiedFastestNode').IsEnabled) 'Async completion lost pending Off protection'
    Complete-ProtectionTelemetry
    Assert-ProtectionComposition (-not(Control 'UnifiedFastestNode').IsEnabled) 'Late telemetry re-enabled node selection during pending Off'
    $Kill.IsChecked=$true # WPF toggles the value before invoking Add_Click.
    $Before=$script:ProtectionRequests.Count;$script:ProtectionLogs=@()
    & $Kill.Callback
    Assert-ProtectionComposition ($script:ProtectionRequests.Count-eq$Before+1-and-not$script:ProtectionRequests[-1].Enabled-and$script:ProtectionRequests[-1].ProfileID-ceq'node') 'Composed Finish Off callback enabled protection or lost the displayed owner'
    Assert-ProtectionComposition (($script:ProtectionLogs-join'|')-ceq'Kill switch disabled') ('Composed protection callback failed after the captured request: '+($script:ProtectionLogs-join'|'))
}
Write-Host 'PASS composed pending/unsaved Off refresh, exact callback and late telemetry'

$Done=[pscustomobject]@{profile_id='node';profile_token='saved-revision';kill_switch_policy='off';effective_policy='off'}
Complete-ProtectionSnapshot $Done
Assert-ProtectionComposition (-not$script:UnifiedProtectionPending-and(Control 'UnifiedKillSwitch').IsEnabled-and-not(Control 'UnifiedKillSwitch').IsChecked-and(Control 'UnifiedConnectButton').IsEnabled-and(Control 'UnifiedFastestNode').IsEnabled) 'Completed Off did not restore the ordinary controls'
Complete-ProtectionTelemetry
Assert-ProtectionComposition ((Control 'UnifiedFastestNode').IsEnabled) 'Ordinary idle telemetry no longer permits node selection'
foreach($Enabled in @($true,$false)){
    (Control 'UnifiedKillSwitch').IsChecked=$Enabled;$Before=$script:ProtectionRequests.Count;$script:ProtectionLogs=@()
    & (Control 'UnifiedKillSwitch').Callback
    Assert-ProtectionComposition ($script:ProtectionRequests.Count-eq$Before+1-and$script:ProtectionRequests[-1].Enabled-eq$Enabled-and$script:ProtectionRequests[-1].ProfileID-ceq'node') 'Composed ordinary protection callback changed the requested policy'
    $Expected=if($Enabled){'Kill switch enabled'}else{'Kill switch disabled'}
    Assert-ProtectionComposition (($script:ProtectionLogs-join'|')-ceq$Expected) 'Composed ordinary protection callback reported a false failure'
}
$script:ProtectionStatus.connected=$true;$script:ProtectionStatus.phase='connected'
Complete-ProtectionSnapshot $Done
Complete-ProtectionTelemetry
Assert-ProtectionComposition (-not(Control 'UnifiedKillSwitch').IsEnabled-and-not(Control 'UnifiedFastestNode').IsEnabled) 'Connected snapshot lost mutation guards'
Write-Host 'PASS composed completed Off and connected mutation guards'

$script:ProtectionStatus.connected=$false;$script:ProtectionStatus.phase='off'
$Done.profile_id='replacement'
Complete-ProtectionSnapshot $Done
Assert-ProtectionComposition (-not(Control 'UnifiedKillSwitch').IsEnabled-and$null-eq(Control 'UnifiedKillSwitch').IsChecked) 'Composed refresh adopted another profile protection state'
$Sentinel=(Control 'UnifiedKillSwitch').ToolTip
Complete-ProtectionSnapshot $Protection $true
Assert-ProtectionComposition ((Control 'UnifiedKillSwitch').ToolTip-ceq$Sentinel-and-not$script:UnifiedProtectionPending) 'Discarded refresh changed protection presentation'
Write-Host 'PASS composed stale owner and discarded refresh preserve current presentation'
Write-Host 'Windows composed protection/telemetry regression tests: PASS'
