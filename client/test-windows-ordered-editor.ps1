param([string]$Root=(Split-Path $PSScriptRoot -Parent),[switch]$WPF)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
$Client=Join-Path $Root 'client'
Import-Module (Join-Path $Client 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
$Settings=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-ProfileSettings.ps1'),[Text.Encoding]::UTF8)
. ([ScriptBlock]::Create($Settings))
$Unified=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-UnifiedShell.ps1'),[Text.Encoding]::UTF8)
. ([ScriptBlock]::Create($Unified))
$ProductSource=Add-RouterVPNUnifiedWindowsShell ([IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-Product-v2.ps1'),[Text.Encoding]::UTF8))
$script:Checks=0
function Check([bool]$Value,[string]$Message){if(-not$Value){throw ('ORDERED-EDITOR: '+$Message)};$script:Checks++}
function ShippingFunction([string]$Name){
    $found=@(([ScriptBlock]::Create($ProductSource)).Ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$Name},$true))
    if($found.Count-ne1){throw ('Shipping editor function missing: '+$Name)};return $found[0].Extent.Text
}
$Editor=ShippingFunction 'ShowUnifiedOrderedNodes';$EditorAST=([ScriptBlock]::Create($Editor)).Ast
function Callback([string]$Name){
    $target='$dialog.FindName('''+$Name+''')'
    $found=@($EditorAST.FindAll({param($n)$n-is[Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Member.Extent.Text-ceq'Add_Click'-and$n.Expression.Extent.Text-ceq$target},$true))
    if($found.Count-ne1){throw ('Shipping editor callback missing: '+$Name)}
    $text=$found[0].Arguments[0].ScriptBlock.Extent.Text;return [ScriptBlock]::Create($text.Substring(1,$text.Length-2))
}
foreach($name in @('$refresh','$move')){
    $found=@($EditorAST.FindAll({param($n)$n-is[Management.Automation.Language.AssignmentStatementAst]-and$n.Left.Extent.Text-ceq$name},$true))
    if($found.Count-ne1){throw ('Shipping editor action missing: '+$name)}
    . ([ScriptBlock]::Create($found[0].Extent.Text))
}
foreach($name in @('RefreshUnifiedOrderedSelection','RefreshUnifiedOrderedControls')){. ([ScriptBlock]::Create((ShippingFunction $name)))}
$xaml=[regex]::Match($Editor,'(?s)\[xml\]\$x=@"\r?\n(.*?)\r?\n"@')
Check $xaml.Success 'actual editor XAML missing'
[xml]$xml=$xaml.Groups[1].Value
foreach($name in @('Available','Order','Add','Up','Down','Remove','Final','Status','Cancel','Apply')){
    Check ($null-ne$xml.SelectSingleNode("//*[@Name='$name']")) ('actual editor control missing '+$name)
}
function New-Widget {
    $widget=[pscustomobject]@{ItemsSource=@();SelectedIndex=-1;Text='';IsEnabled=$true;IsChecked=$false;Tag=$null;Visibility='Visible'}
    $widget|Add-Member ScriptProperty Items {return ,@($this.ItemsSource)}
    $widget|Add-Member ScriptProperty SelectedItem {if($this.SelectedIndex-ge0-and$this.SelectedIndex-lt@($this.ItemsSource).Count){return $this.ItemsSource[$this.SelectedIndex]};return $null}
    $widget|Add-Member ScriptProperty SelectedValue {if($null-ne$this.SelectedItem){return $this.SelectedItem.id};return $null}
    return $widget
}
if($WPF){
    Add-Type -AssemblyName PresentationFramework
    $dialog=[Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xml))
    $dialog.Show();$dialog.UpdateLayout()
    Check ($dialog.ActualWidth-ge510-and$dialog.ActualHeight-ge440) 'native editor layout did not render at its supported size'
}else{
    $dialog=[pscustomobject]@{Controls=@{};Closed=$false}
    $dialog|Add-Member ScriptMethod FindName {param($name)return $this.Controls[$name]}
    $dialog|Add-Member ScriptMethod Close {$this.Closed=$true}
    foreach($name in @('Available','Order','Add','Up','Down','Remove','Final','Status','Cancel','Apply')){$dialog.Controls[$name]=New-Widget}
}
try{
    $rows=New-Object 'Collections.Generic.List[object]';$id='selected-final'
    $store=[pscustomobject]@{selected_id=$id;profiles=@()}
    for($i=0;$i-lt7;$i++){$store.profiles+=[pscustomobject]@{id=('prefix-'+$i);name=('Prefix '+$i);node_kind='router-vpn';api_token='must-not-copy'}}
    $store.profiles+=[pscustomobject]@{id=$id;name='Selected final';node_kind='router-vpn'}
    $store.profiles+=[pscustomobject]@{id='external';name='External';node_kind='external'}
    $available=$dialog.FindName('Available');$list=$dialog.FindName('Order');$status=$dialog.FindName('Status')
    $rootControls=@{}
    foreach($name in @('UnifiedNodeChainButton','UnifiedOrdered','UnifiedMultihop','UnifiedNodeChainSummary','UnifiedComparisonText','UnifiedEntryCombo','UnifiedExitCombo','UnifiedEntryMode','UnifiedExitMode','UnifiedBaseCombo','UnifiedExecution','UnifiedCandidatesButton','UnifiedModeCombo','UnifiedOrderedModeSummary','UnifiedPresetsButton')){$rootControls[$name]=New-Widget}
    $RouterCombo=[pscustomobject]@{SelectedValue=$id};$rootControls['UnifiedNodeChainButton'].Tag=[pscustomobject]@{control_id=$id;nodes=@()}
    function Control($Name){return $rootControls[$Name]}
    function Api($Path,$Timeout){if($Path-cne'/api/profiles'){throw 'unexpected editor network operation'};return $script:CurrentStore}
    function Assert-RouterVPNMutationIdle($Reason){if($script:EditorBusy){throw 'captured mutation is busy'}}
    $script:CurrentStore=$store;$script:EditorBusy=$false
    $add=Callback 'Add';$up=Callback 'Up';$down=Callback 'Down';$remove=Callback 'Remove';$apply=Callback 'Apply'
    &$refresh
    Check ($available.Items.Count-eq7-and$list.Items.Count-eq0) 'initial choices included final/external nodes or invented a prefix'
    for($i=0;$i-lt7;$i++){
        &$add
        Check ($rows.Count-eq$i+1-and$list.Items.Count-eq$i+1) 'Add did not append the chosen node'
        Check ($rows[$i].id-ceq('prefix-'+$i)-and$rows[$i].mode-ceq'wg') 'Add changed the selected node or transport'
        Check ($available.Items.Count-eq6-$i) 'Add left an already used node selectable'
    }
    Check (-not$dialog.FindName('Add').IsEnabled) 'eighth prefix remained enabled'
    &$add;Check ($rows.Count-eq7) 'Add exceeded the eight-node complete path bound'
    $list.SelectedIndex=3;&$up
    Check ($rows[2].id-ceq'prefix-3'-and$rows[3].id-ceq'prefix-2'-and$list.SelectedIndex-eq2) 'Move up changed another node or lost selection'
    &$down;Check (($rows.id-join',')-ceq'prefix-0,prefix-1,prefix-2,prefix-3,prefix-4,prefix-5,prefix-6') 'Move down did not restore exact order'
    $list.SelectedIndex=2;&$remove
    Check ($rows.Count-eq6-and($rows.id-join',')-ceq'prefix-0,prefix-1,prefix-3,prefix-4,prefix-5,prefix-6') 'Remove deleted another prefix'
    Check ($available.Items.Count-eq1-and$available.SelectedValue-ceq'prefix-2') 'Removed node was not restored as a choice'
    $original=$rootControls['UnifiedNodeChainButton'].Tag
    $script:EditorBusy=$true;&$apply
    Check ([object]::ReferenceEquals($original,$rootControls['UnifiedNodeChainButton'].Tag)) 'busy Apply replaced the original draft'
    $script:EditorBusy=$false;$script:CurrentStore=$store|ConvertTo-Json -Depth 8|ConvertFrom-Json;$script:CurrentStore.selected_id='replacement'
    &$apply;Check ([object]::ReferenceEquals($original,$rootControls['UnifiedNodeChainButton'].Tag)) 'changed selected exit replaced the draft'
    $script:CurrentStore=$store;$RouterCombo.SelectedValue='replacement'
    &$apply;Check ([object]::ReferenceEquals($original,$rootControls['UnifiedNodeChainButton'].Tag)) 'changed visible exit replaced the draft'
    $RouterCombo.SelectedValue=$id;&$apply
    $saved=$rootControls['UnifiedNodeChainButton'].Tag
    Check ($saved.control_id-ceq$id-and$saved.nodes.Count-eq7-and$saved.nodes[-1].id-ceq$id-and$saved.nodes[-1].mode-ceq'shadowsocks') 'Apply lost the fixed selected final or full prefix list'
    Check (($saved.nodes.id-join',')-ceq'prefix-0,prefix-1,prefix-3,prefix-4,prefix-5,prefix-6,selected-final') 'Apply reordered the visible path'
    Check ($rootControls['UnifiedOrdered'].IsChecked-and$rootControls['UnifiedMultihop'].IsChecked) 'Apply did not choose the complete ordered path'
    Check (($saved|ConvertTo-Json -Depth 8)-notmatch'must-not-copy') 'editor copied private node credentials'
    Check ($rootControls['UnifiedNodeChainSummary'].Text.Contains('Prefix 3')-and$rootControls['UnifiedNodeChainSummary'].Text.Contains('Selected final')) 'summary omitted a middle or final node'
    foreach($name in @('UnifiedEntryCombo','UnifiedExitCombo','UnifiedEntryMode','UnifiedExitMode','UnifiedBaseCombo','UnifiedExecution','UnifiedCandidatesButton')){Check (-not$rootControls[$name].IsEnabled) 'ordered path left contradictory pair controls enabled'}
    Check ($rootControls['UnifiedModeCombo'].Visibility-ceq'Collapsed'-and$rootControls['UnifiedOrderedModeSummary'].Visibility-ceq'Visible'-and-not$rootControls['UnifiedPresetsButton'].IsEnabled) 'ordered mode display claimed another direct transport'
    $rootControls['UnifiedMultihop'].IsChecked=$false;RefreshUnifiedOrderedControls
    Check ($rootControls['UnifiedModeCombo'].Visibility-ceq'Visible'-and$rootControls['UnifiedOrderedModeSummary'].Visibility-ceq'Collapsed') 'direct mode display remained hidden after disabling multihop'
    $saved.nodes[1].id='altered';Check ($rows[1].id-ceq'prefix-1') 'committed draft retained mutable editor rows'
    Write-Output ("Actual ordered node editor callbacks: $script:Checks checks PASS; WPF=$WPF")
}finally{if($WPF-and$dialog.IsVisible){$dialog.Close()}}
