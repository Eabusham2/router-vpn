param([string]$Root = (Split-Path $PSScriptRoot -Parent), [Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$ShellSource=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $Root 'client/RouterVPN-Windows-SpeedLab.ps1')
. ([ScriptBlock]::Create($ShellSource))
$Source=Add-RouterVPNSpeedLabWindowsShell 'function ShowUnifiedPerformance{}'
$Ast=[ScriptBlock]::Create($Source).Ast
$Functions=@($Ast.FindAll({param($N)$N-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$N.Name-ne'ShowUnifiedSpeedLab'-and$N.Name-ne'ShowUnifiedPerformance'-and$N.Name-ne'ShowUnifiedAdvancedPerformance'},$true))
foreach($F in $Functions){. ([ScriptBlock]::Create($F.Extent.Text))}
$Runs=@($Ast.FindAll({param($N)$N-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$N.Member.Extent.Text-eq'Add_Click'-and$N.Expression.Extent.Text-eq'$Run'},$true))
if($Runs.Count-ne1){throw 'Actual Speed Lab Run callback changed.'}
$RunCallback=$Runs[0].Arguments[0].ScriptBlock.GetScriptBlock()
$Initializers=@($Ast.FindAll({param($N)$N-is[System.Management.Automation.Language.AssignmentStatementAst]-and$N.Left.Extent.Text-eq'$Success'-and$N.Right.Extent.Text.Contains('$SpeedLabOptions.nodes=')},$true))
if($Initializers.Count-ne1){throw 'Actual options callback changed.'}
$Initializer=@($Initializers[0].Right.FindAll({param($N)$N-is[System.Management.Automation.Language.ScriptBlockExpressionAst]},$false))[0].ScriptBlock.GetScriptBlock()
$Markup=@($Ast.FindAll({param($N)($N-is[System.Management.Automation.Language.ExpandableStringExpressionAst]-or$N-is[System.Management.Automation.Language.StringConstantExpressionAst])-and$N.Value.TrimStart().StartsWith('<Window')},$true))
if($Markup.Count-ne1){throw 'Actual Speed Lab XAML changed.'};[xml]$Xml=$Markup[0].Value
foreach($Name in @('EntryMode','Execution')){if($Xml.SelectNodes('//*[@Name="'+$Name+'"]').Count-ne1){throw "Missing real $Name control."}}

# WPF selection semantics only. The actual callback, saved-default loading,
# eligibility checks and request builder above execute without replacement.
Add-Type -TypeDefinition @'
using System;
using System.Management.Automation;
public sealed class SpeedLabCombo {
    public object[] ItemsSource { get; set; }
    public SpeedLabCombo() { ItemsSource = new object[0]; }
    public object[] Items { get { return ItemsSource; } }
    public string SelectionPath = "id";
    public bool IsEnabled = true;
    public int SelectedIndex = -1;
    static object Field(object item,string name) { if(item==null)return null;var p=PSObject.AsPSObject(item).Properties[name];return p==null?null:p.Value; }
    public object SelectedItem { get { return SelectedIndex>=0&&SelectedIndex<Items.Length?Items[SelectedIndex]:null; } set { SelectedIndex=Array.IndexOf(Items,value); } }
    public string SelectedValue { get { return Convert.ToString(Field(SelectedItem,SelectionPath)); } set { SelectedIndex=Array.FindIndex(Items,i=>String.Equals(Convert.ToString(Field(i,SelectionPath)),value,StringComparison.Ordinal)); } }
}
'@
function Combo($Values,[string]$Path='id'){$C=[SpeedLabCombo]::new();$C.SelectionPath=$Path;$C.ItemsSource=@($Values);if($C.Items.Count){$C.SelectedIndex=0};return $C}
function Tags($Values){return @($Values|ForEach-Object{[pscustomobject]@{Tag=$_}})}
$Scope=Combo (Tags @('current','temporary')) 'Tag';$Topology=Combo (Tags @('system-direct','router','multihop','external')) 'Tag'
$Base=Combo (Tags @('auto','wg','awg')) 'Tag';$ExitMode=Combo (Tags @($Xml.SelectNodes('//*[@Name="ExitMode"]/*')|ForEach-Object{[string]$_.Tag})) 'Tag';$DurationMode=Combo (Tags @('auto','custom')) 'Tag'
$Mode=Combo @();$Node=Combo @();$Entry=Combo @();$Exit=Combo @();$EntryMode=Combo @();$Execution=Combo @()
$Layers=[pscustomobject]@{Text='';IsEnabled=$false};$MinTime=[pscustomobject]@{Value=4;IsEnabled=$true};$MaxTime=[pscustomobject]@{Value=12;IsEnabled=$true}
$Run=[pscustomobject]@{IsEnabled=$true};$Advanced=[pscustomobject]@{IsEnabled=$true};$Status=[pscustomobject]@{Text=''};$Detail=[pscustomobject]@{Text=''}
$Fields=@{};foreach($Name in @('DAITA','Jumbo','Encrypted','Obfuscated')){$Fields[$Name]=[pscustomobject]@{IsChecked=$false;IsEnabled=$true}}
$D=[pscustomobject]@{Tag='initial';Fields=$Fields};$D|Add-Member ScriptMethod FindName {param($Name)return $this.Fields[$Name]}
$SpeedLabOptions=@{nodes=@();router_vpn_entry_modes=@();execution_choices=@();updating=$false}
$Opt=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $Output 'speed-lab-options.json')|ConvertFrom-Json
function Check([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
function UnifiedAsyncBusy{return $false}
function RefreshProduct{}
function RefreshUnifiedTelemetry{}
$script:Captured=$null
function StartUnifiedApiAsync($Label,$Path,$Method,$Body,$Timeout,$Success,$Failure,$Finally){Check ($Path-eq'/api/speed-lab/run'-and$Method-eq'POST') 'Unexpected native Run endpoint.';$script:Captured=$Body;return $true}
& $Initializer $Opt
Check ($Node.SelectedValue-ceq'exit'-and$Entry.SelectedValue-ceq'entry'-and$EntryMode.SelectedValue-ceq'awg2-strong'-and$Execution.SelectedValue-ceq'auto') 'Saved external path was replaced by unrelated defaults.'
Check ($SpeedLabOptions.router_vpn_entry_modes.Count-eq19) 'Entry mode catalog was reduced.'
$Count=0
function Emit([string]$Name){$script:Captured=$null;& $RunCallback;Check ($null-ne$script:Captured) ('Actual Run rejected '+$Name+': '+$Detail.Text);[IO.File]::WriteAllText((Join-Path $Output ($Name+'.json')),($script:Captured|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false));$script:Count++}
function Reject([string]$Name){$script:Captured=$null;& $RunCallback;Check ($null-eq$script:Captured) ('Invalid path reached controller: '+$Name);$script:Count++}
Emit 'speed-lab-current'
$Scope.SelectedValue='temporary';$Topology.SelectedValue='external'
foreach($M in $SpeedLabOptions.router_vpn_entry_modes){foreach($E in @('local','server','auto')){$EntryMode.SelectedValue=[string]$M.id;$Execution.SelectedValue=$E;Emit ('speed-lab-external-'+$M.id+'-'+$E)}}
$Entry.SelectedValue='';SpeedLabPathChanged 'entry';Check ($Execution.SelectedValue-eq'local') 'Direct retained Server execution.';Emit 'speed-lab-external-direct'
$Execution.SelectedValue='server';Reject 'Direct Server';$Entry.SelectedValue='external-entry';SpeedLabPathChanged 'entry';Emit 'speed-lab-external-entry'
$Execution.SelectedValue='auto';Reject 'ordinary entry Compare';$Entry.SelectedValue='entry';SpeedLabPathChanged 'entry';$Execution.SelectedValue='auto'
SelectSpeedLabChoice $EntryMode 'missing-mode';Reject 'stale mode';$EntryMode.SelectedValue='wg'
SelectSpeedLabChoice $Entry 'missing-entry';Reject 'stale entry';$Entry.SelectedValue='entry'
SelectSpeedLabChoice $Execution 'invalid';Reject 'stale execution';$Execution.SelectedValue='auto'
$ExitValue=SpeedLabFind 'nodes' 'exit';$ExitValue.has_response_probe=$false;Reject 'missing response probe';$ExitValue.has_response_probe=$true
$ExitValue.has_openvpn_pairing=$false;Reject 'missing independent OpenVPN pairing';$ExitValue.has_openvpn_pairing=$true
$Original=$SpeedLabOptions.nodes;$SpeedLabOptions.nodes=@($Original)+@($ExitValue);Reject 'duplicate exit identity';$SpeedLabOptions.nodes=$Original
$ExitValue.multihop_entry_id='removed-entry';SetSpeedLabDefaults;Check ($Entry.SelectedValue-ceq'removed-entry') 'Unavailable saved entry silently became Direct.';Reject 'removed saved entry';$ExitValue.multihop_entry_id='entry';SetSpeedLabDefaults
$Topology.SelectedValue='multihop';SpeedLabPathChanged 'topology';$Entry.SelectedValue='entry';$Exit.SelectedValue='exit-router'
foreach($E in @('local','server','auto')){$Execution.SelectedValue=$E;Emit ('speed-lab-multihop-'+$E)}
Check ((@($ExitMode.Items|ForEach-Object{[string]$_.Tag})-join',')-ceq(@($SpeedLabOptions.supported_exit_modes)-join',')) 'UI and native exit catalogs differ.'
foreach($M in @($SpeedLabOptions.supported_exit_modes)){$ExitMode.SelectedValue=$M;foreach($E in @('local','server','auto')){$Execution.SelectedValue=$E;Emit ('speed-lab-multihop-'+$M+'-'+$E)}}
$ExitMode.SelectedValue='removed-exit-mode';Reject 'unknown exit transport';$ExitMode.SelectedValue='naive-h3'
$OriginalModes=$SpeedLabOptions.supported_exit_modes;$SpeedLabOptions.supported_exit_modes=@($OriginalModes|Where-Object{$_-cne'naive-h3'});Reject 'runtime unavailable exit';$SpeedLabOptions.supported_exit_modes=$OriginalModes
$SpeedLabOptions.current=[pscustomobject]@{entry_id='entry';exit_id='exit-router';exit_mode='reality-pq-vision'};SetSpeedLabDefaults;Check ((SelectedTag $ExitMode)-ceq'reality-pq-vision') 'Matching current graph lost its exact exit mode.'
$SpeedLabOptions.current.entry_id='different-entry';$ExitMode.SelectedValue='naive-h2';SetSpeedLabDefaults;Check ((SelectedTag $ExitMode)-ceq'naive-h2') 'Unrelated graph replaced selected exit mode.'
$Exit.SelectedValue='entry';Reject 'identical multihop nodes';$Exit.SelectedValue='exit-router'
$Topology.SelectedValue='system-direct';Emit 'speed-lab-system-direct'
Write-Output ("Actual Windows Speed Lab options/defaults/Run callback: $Count checks PASS")
