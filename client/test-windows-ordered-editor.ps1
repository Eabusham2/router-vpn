param([string]$Root=(Split-Path $PSScriptRoot -Parent),[switch]$WPF,[string]$NegativeControl='',[switch]$PositiveOnly,
    [ValidateSet('all','editor','wg','awg2-fast','awg2-strong','socks','openvpn')][string]$Group='all')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
$controls=@{'local-imported-position'='Local imported nodes lost complete original path';'local-imported-capability'='Local imported nodes accepted invalid source capability';'hysteria-final-layer-required'='Hysteria final layer was not offered';'hysteria-final-layer-type'='Hysteria accepted malformed final layer';'hysteria-execution-global'='Hysteria execution borrowed unrelated global capability';'openvpn-execution-global'='OpenVPN execution borrowed unrelated global capability';'openvpn-execution-capability'='OpenVPN execution accepted absent or nonboolean native hint';'openvpn-execution-final-layer'='OpenVPN execution refused captured final layer';'connect-execution-final-layer-required'='CONNECT execution refused captured final layer';'socks-execution-final-layer'='SOCKS execution refused captured final layer';'socks-execution-old-trio'='SOCKS execution refused a complete later prefix';'connect-execution-prefix-layer'='CONNECT execution admitted a malformed paired prefix layer';'hostname-minimum'='hostname trio acquired suffix packet authority';'hostname-conflict'='hostname execution accepted conflicting source capabilities';'hostname-capability'='hostname execution lost complete saved prefix';'imported-execution-prefix'='complete imported execution prefix refused';'connect-execution-global'='CONNECT execution borrowed unrelated global capability';'connect-execution-final'='CONNECT execution admitted malformed final layer';'imported-execution-capability'='imported execution accepted absent or nonboolean native capability';'connect-protocol'='CONNECT request borrowed a different saved protocol';'connect-mode'='CONNECT Add substituted its exact saved transport';'socks-mode'='SOCKS Add substituted its saved transport';'final-mode'='Apply substituted the explicitly selected Hysteria2 final';'raw-mode'='raw ordered mode whitelist admitted an alias or unsupported transport';'add-mode'='Add changed the selected node or transport';'change-mode'='Change mode replaced its original node or ignored selected transport';'row-label'='editor row mislabeled its captured transport';'source-token'='relinked middle node replaced the original editor draft';'summary-reset'='new incomplete ordered selection displayed a previous path transport summary';'socks-execution-global'='SOCKS execution borrowed unrelated global capability';'socks-execution-capability'='SOCKS execution accepted absent or nonboolean native hint';'socks-execution-entry-layer'='SOCKS execution accepted malformed entry layer';'socks-execution-layer'='SOCKS execution admitted layered middle or final'}
if($NegativeControl-and$controls.Keys-cnotcontains$NegativeControl){throw 'Unknown ordered editor causal control.'}
if($PositiveOnly-and$NegativeControl){throw 'Positive editor phase cannot select a causal control.'}
$Client=Join-Path $Root 'client'
Import-Module (Join-Path $Client 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
$Settings=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-ProfileSettings.ps1'),[Text.Encoding]::UTF8)
if($NegativeControl-ceq'local-imported-position'){
    $anchor="$"+"Mode-ceq'shadowsocks'-and`$Count-ge3-and`$Count-le(Get-RouterVPNOrderedPhysicalTraversalDepth)-and`$Position-gt0-and`$Position-lt(`$Count-1)"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'Local imported position guard changed.'}
    $Settings=$Settings.Replace($anchor,"`$Mode-ceq'shadowsocks'-and`$Count-ge3-and`$Count-le(Get-RouterVPNOrderedPhysicalTraversalDepth)-and`$Position-gt0-and`$Position-eq(`$Count-2)")
}
if($NegativeControl-ceq'local-imported-capability'){
    $anchor='$allowed-isnot[bool]-or-not$allowed'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'Local imported capability guard changed.'}
    $Settings=$Settings.Replace($anchor,'$false')
}
if($NegativeControl-ceq'hysteria-final-layer-required'-or$NegativeControl-ceq'hysteria-final-layer-type'){
    $anchor="`$layer-is[string]-and`$layer-cin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')-and-not`$imported"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'Hysteria final layer guard changed.'}
    $replacement=if($NegativeControl-ceq'hysteria-final-layer-required'){"`$layer-is[string]-and`$layer-cin@('','off')-and-not`$imported"}else{'-not$imported'}
    $Settings=$Settings.Replace($anchor,$replacement)
}
if($NegativeControl-ceq'hostname-minimum'){
    $anchor='$nodes.Count-ge4'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'Hostname minimum guard changed.'}
    $Settings=$Settings.Replace($anchor,'$nodes.Count-ge3')
}
if($NegativeControl-ceq'hostname-conflict'){
    $anchor='-or($executionMiddle-and$hostnameMiddle)'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'Hostname capability conflict guard changed.'}
    $Settings=$Settings.Replace($anchor,'')
}
if($NegativeControl-ceq'hostname-capability'){
    $anchor='$executionMiddle=$hostnameMiddle'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'Hostname capability branch changed.'}
    $Settings=$Settings.Replace($anchor,'$executionMiddle=$false')
}
if($NegativeControl-ceq'raw-mode'){$Settings=$Settings.Replace("@('wg','awg2-fast','awg2-strong')-ccontains`$Mode","@('wg','awg2-fast','awg2-strong')-contains`$Mode")}
if($NegativeControl-ceq'source-token'){$Settings=$Settings.Replace("-or[string](Get-RouterVPNOrderedValue `$profile 'profile_token')-cne`$token",'')}
if($NegativeControl-ceq'connect-protocol'){
    $before='$node.mode-cne(Get-RouterVPNOrderedImportedMode $profile)'
    if(([regex]::Matches($Settings,[regex]::Escape($before))).Count-ne1){throw 'Shipping CONNECT protocol guard changed.'}
    $Settings=$Settings.Replace($before,'($node.mode-cne(Get-RouterVPNOrderedImportedMode $profile)-and$node.mode-cnotin@(''http-connect'',''https-connect''))')
}
if($NegativeControl-ceq'imported-execution-prefix'){
    $anchor='$nodes.Count-lt3-or$nodes.Count-gt8-or$position-ne($nodes.Count-2)'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'Shipping imported prefix guard changed.'}
    $Settings=$Settings.Replace($anchor,'$nodes.Count-ne3-or$position-ne1')
}
if($NegativeControl-ceq'imported-execution-capability'){
    $anchor='$executionMiddle-isnot[bool]-or-not$executionMiddle'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'Shipping imported execution capability guard changed.'}
    $Settings=$Settings.Replace($anchor,'$false')
}
if($NegativeControl-ceq'connect-execution-prefix-layer'){
    $anchor="`$connectLayer-cnotin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'CONNECT prefix layer guard changed.'}
    $Settings=$Settings.Replace($anchor,'$false')
}
if($NegativeControl-ceq'connect-execution-final'){
    $anchor="`$connectFinalLayer-isnot[string]-or`$connectFinalLayer-cnotin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'CONNECT execution layer guard changed.'}
    $Settings=$Settings.Replace($anchor,'$false')
}
if($NegativeControl-ceq'connect-execution-final-layer-required'){
    $anchor="`$connectFinalLayer-cnotin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'CONNECT original final layer guard changed.'}
    $Settings=$Settings.Replace($anchor,"`$connectFinalLayer-cnotin@('','off')")
}
if($NegativeControl-ceq'connect-execution-global'){
    $anchor="return 'ordered_connect_trio_executions'"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'CONNECT global capability changed.'}
    $Settings=$Settings.Replace($anchor,"return 'ordered_executions'")
}
if($NegativeControl-ceq'socks-execution-global'){
    $anchor="return 'ordered_socks_trio_executions'"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'SOCKS global capability changed.'}
    $Settings=$Settings.Replace($anchor,"return 'ordered_connect_trio_executions'")
}
if($NegativeControl-ceq'socks-execution-capability'){
    $anchor='$executionMiddle-isnot[bool]-or-not$executionMiddle'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'SOCKS execution hint guard changed.'}
    $Settings=$Settings.Replace($anchor,'(-not$socksMiddle-and($executionMiddle-isnot[bool]-or-not$executionMiddle))')
}
if($NegativeControl-ceq'socks-execution-old-trio'){
    $anchor='$socksCount-lt3-or$socksCount-gt8'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'SOCKS complete prefix guard changed.'}
    $Settings=$Settings.Replace($anchor,'$socksCount-ne3')
}
if($NegativeControl-ceq'socks-execution-final-layer'){
    $anchor='$socksPosition-ne($socksCount-2)'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'SOCKS final layer admission changed.'}
    $Settings=$Settings.Replace($anchor,'$socksPosition-lt$socksCount-2')
}
if($NegativeControl-ceq'socks-execution-entry-layer'){
    $anchor="$"+"socksLayer-cnotin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'SOCKS entry layer guard changed.'}
    $Settings=$Settings.Replace($anchor,'$false')
}
if($NegativeControl-ceq'socks-execution-layer'){
    $anchor="elseif(`$socksLayer-cnotin@('','off')){return `$false}"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'SOCKS middle/final layer guard changed.'}
    $Settings=$Settings.Replace($anchor,'elseif($false){return $false}')
}
if($NegativeControl-ceq'openvpn-execution-global'){
    $anchor="return 'ordered_openvpn_executions'"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'OpenVPN global capability changed.'}
    $Settings=$Settings.Replace($anchor,"return 'ordered_executions'")
}
if($NegativeControl-ceq'openvpn-execution-capability'){
    $anchor='$executionMiddle-isnot[bool]-or-not$executionMiddle'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'OpenVPN execution hint guard changed.'}
    $Settings=$Settings.Replace($anchor,'(-not$openVPNMiddle-and($executionMiddle-isnot[bool]-or-not$executionMiddle))')
}
if($NegativeControl-ceq'openvpn-execution-final-layer'){
    $anchor='$openvpnPosition-ne($openvpnCount-2)'
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'OpenVPN final layer admission changed.'}
    $Settings=$Settings.Replace($anchor,'$openvpnPosition-lt$openvpnCount-2')
}
if($NegativeControl-ceq'hysteria-execution-global'){
    $anchor="return 'ordered_hysteria_executions'"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'Hysteria global capability changed.'}
    $Settings=$Settings.Replace($anchor,"return 'ordered_executions'")
}
. ([ScriptBlock]::Create($Settings))
$Unified=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-UnifiedShell.ps1'),[Text.Encoding]::UTF8)
if($NegativeControl-ceq'summary-reset'){$Unified=$Unified.Replace("`$description.Text='Choose each intermediate transport and the final node.'",'')}
. ([ScriptBlock]::Create($Unified))
$ProductSource=Add-RouterVPNUnifiedWindowsShell ([IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-Product-v2.ps1'),[Text.Encoding]::UTF8))
$script:Checks=0
function Check([bool]$Value,[string]$Message){if(-not$Value){throw ('ORDERED-EDITOR: '+$Message)};$script:Checks++}
$ProductAST=([ScriptBlock]::Create($ProductSource)).Ast
function ShippingFunction([string]$Name){
    $found=@($ProductAST.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$Name},$true))
    if($found.Count-ne1){throw ('Shipping editor function missing: '+$Name)};return $found[0].Extent.Text
}
$Editor=ShippingFunction 'ShowUnifiedOrderedNodes'
if($NegativeControl-ceq'add-mode'){$Editor=$Editor.Replace('id=[string]$available.SelectedValue;mode=$mode',"id=[string]`$available.SelectedValue;mode='wg'")}
if($NegativeControl-ceq'change-mode'){$Editor=$Editor.Replace('id=$rows[$position].id;mode=$mode',"id=`$rows[`$position].id;mode='wg'")}
if($NegativeControl-ceq'final-mode'){$Editor=$Editor.Replace('mode=[string]$finalMode.SelectedValue',"mode='shadowsocks'")}
if($NegativeControl-ceq'row-label'){$Editor=$Editor.Replace('(Get-RouterVPNOrderedModeTitle $node.mode)',"'WireGuard'")}
if($NegativeControl-ceq'socks-mode'){
    $anchor='$mode=Get-RouterVPNOrderedImportedMode $available.SelectedItem'
    if(([regex]::Matches($Editor,[regex]::Escape($anchor))).Count-ne1){throw 'Shipping SOCKS Add anchor changed.'}
    $Editor=$Editor.Replace($anchor,'$mode=''shadowsocks''')
}
if($NegativeControl-ceq'connect-mode'){
    $anchor='$mode=Get-RouterVPNOrderedImportedMode $available.SelectedItem'
    if(([regex]::Matches($Editor,[regex]::Escape($anchor))).Count-ne1){throw 'Shipping CONNECT Add anchor changed.'}
    $Editor=$Editor.Replace($anchor,$anchor+';if($mode-ceq''https-connect''){$mode=''http-connect''}')
}
$EditorAST=([ScriptBlock]::Create($Editor)).Ast
function Callback([string]$Name){
    $target='$dialog.FindName('''+$Name+''')'
    $found=@($EditorAST.FindAll({param($n)$n-is[Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Member.Extent.Text-ceq'Add_Click'-and$n.Expression.Extent.Text-ceq$target},$true))
    if($found.Count-ne1){throw ('Shipping editor callback missing: '+$Name)}
    $text=$found[0].Arguments[0].ScriptBlock.Extent.Text;return [ScriptBlock]::Create($text.Substring(1,$text.Length-2))
}
foreach($name in @('$refresh','$move','$captureEditor')){
    $found=@($EditorAST.FindAll({param($n)$n-is[Management.Automation.Language.AssignmentStatementAst]-and$n.Left.Extent.Text-ceq$name},$true))
    if($found.Count-ne1){throw ('Shipping editor action missing: '+$name)}
    . ([ScriptBlock]::Create($found[0].Extent.Text))
}
foreach($name in @('RefreshUnifiedOrderedSelection','RefreshUnifiedOrderedControls')){. ([ScriptBlock]::Create((ShippingFunction $name)))}
$xaml=[regex]::Match($Editor,'(?s)\[xml\]\$x=@"\r?\n(.*?)\r?\n"@')
Check $xaml.Success 'actual editor XAML missing'
[xml]$xml=$xaml.Groups[1].Value
foreach($name in @('Available','PrefixMode','Order','Add','Up','Down','Remove','ChangeMode','Final','FinalMode','Status','Cancel','Apply')){
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
    foreach($name in @('Available','PrefixMode','Order','Add','Up','Down','Remove','ChangeMode','Final','FinalMode','Status','Cancel','Apply')){$dialog.Controls[$name]=New-Widget}
}
try{
    if($Group -notin @('socks','openvpn')) {
    $rows=New-Object 'Collections.Generic.List[object]';$id='selected-final'
    $store=[pscustomobject]@{selected_id=$id;profiles=@()}
    for($i=0;$i-lt7;$i++){$store.profiles+=[pscustomobject]@{id=('prefix-'+$i);name=('Prefix '+$i);node_kind='router-vpn';api_token='must-not-copy';profile_token=('{0:x64}' -f ($i+1))}}
    $store.profiles+=[pscustomobject]@{id=$id;name='Selected final';node_kind='router-vpn';profile_token=('e'*64)}
    $store.profiles+=[pscustomobject]@{id='external';name='External';node_kind='external'}
    $available=$dialog.FindName('Available');$list=$dialog.FindName('Order');$status=$dialog.FindName('Status');$prefixMode=$dialog.FindName('PrefixMode');$finalMode=$dialog.FindName('FinalMode')
    foreach($name in @('$prefixMode.ItemsSource','$prefixMode.SelectedIndex')){
        $found=@($EditorAST.FindAll({param($n)$n-is[Management.Automation.Language.AssignmentStatementAst]-and$n.Left.Extent.Text-ceq$name},$true))
        if($found.Count-ne1){throw ('Shipping mode initialization missing: '+$name)};. ([ScriptBlock]::Create($found[0].Extent.Text))
    }
    Check (($prefixMode.ItemsSource.id-join',')-ceq'wg,awg2-fast,awg2-strong,shadowsocks,socks5,http-connect,https-connect,openvpn') 'mode picker offered an unsupported or normalized transport'
    foreach($invalid in @('WG','AWG2-FAST','awg','awg2-pq','wg-pq','shadowsocks','socks5','http-connect','https-connect',' awg2-fast','awg2-strong ',$null,1)){
        $refused=$false;try{[void](Copy-RouterVPNOrderedNodes @([pscustomobject]@{id='prefix-0';mode=$invalid},[pscustomobject]@{id=$id;mode='shadowsocks'}) $id)}catch{$refused=$true}
        Check $refused 'raw ordered mode whitelist admitted an alias or unsupported transport'
    }
    $rootControls=@{}
    foreach($name in @('UnifiedNodeChainButton','UnifiedOrdered','UnifiedMultihop','UnifiedNodeChainSummary','UnifiedComparisonText','UnifiedEntryCombo','UnifiedExitCombo','UnifiedEntryMode','UnifiedExitMode','UnifiedBaseCombo','UnifiedExecution','UnifiedCandidatesButton','UnifiedModeCombo','UnifiedOrderedModeSummary','UnifiedPresetsButton')){$rootControls[$name]=New-Widget}
    $rootControls['UnifiedExecution'].ItemsSource=@([pscustomobject]@{id='local';Tag='local';Content='Local'},[pscustomobject]@{id='server';Tag='server';Content='Server'},[pscustomobject]@{id='auto';Tag='auto';Content='Compare'});$rootControls['UnifiedExecution'].SelectedIndex=0
    $RouterCombo=[pscustomobject]@{SelectedValue=$id};$rootControls['UnifiedNodeChainButton'].Tag=[pscustomobject]@{control_id=$id;nodes=@()}
    function Control($Name){return $rootControls[$Name]}
    function Api($Path,$Timeout){if($Path-cne'/api/profiles'){throw 'unexpected editor network operation'};return $script:CurrentStore}
    function Assert-RouterVPNMutationIdle($Reason){if($script:EditorBusy){throw 'captured mutation is busy'}}
    $script:CurrentStore=$store;$script:EditorBusy=$false
    $add=Callback 'Add';$changeMode=Callback 'ChangeMode';$up=Callback 'Up';$down=Callback 'Down';$remove=Callback 'Remove';$apply=Callback 'Apply'
    $measureNext=Callback 'MeasureNext'
    function ShowOrderedCandidates($Draft,$Position,$Editor) {
        $script:MeasuredBody=$Draft
        $next=$Position+1
        $all=[Collections.Generic.List[object]]::new()
        foreach($original in $Draft.nodes){$all.Add($original)}
        $all.Insert($next,[pscustomobject]@{id='prefix-2';mode='awg2-strong'})
        $tokens=@{};foreach($node in $all){$match=@($store.profiles|Where-Object{$_.id-ceq$node.id});$tokens[$node.id]=$match[0].profile_token}
        $choice=[pscustomobject]@{requested_execution=$Draft.execution;candidate_id='prefix-2';expected_selected_node_id=$id;expected_profile_tokens=[pscustomobject]$tokens;proposed_path=$all.ToArray()}
        switch($script:DraftFault){
            'execution' {$choice.requested_execution='local'}
            'editor' {$rootControls['UnifiedExecution'].SelectedIndex=0}
            'selection' {$RouterCombo.SelectedValue='foreign'}
            'token' {$choice.expected_profile_tokens.'prefix-1'='0'*64}
            'suffix' {$choice.proposed_path[-1]=[pscustomobject]@{id=$id;mode='hysteria2'}}
        }
        return $choice
    }
    foreach($index in @(1,2)){
        foreach($fault in @('execution','editor','selection','token','suffix','valid')){
            $rows.Clear();foreach($original in @([pscustomobject]@{id='prefix-0';mode='wg'},[pscustomobject]@{id='prefix-1';mode='awg2-fast'})){$rows.Add($original)}
            $RouterCombo.SelectedValue=$id;$rootControls['UnifiedExecution'].SelectedIndex=$index;&$refresh;$list.SelectedIndex=1
            $script:DraftFault=$fault;$script:MeasuredBody=$null;&$measureNext
            Check ($null-ne$MeasuredBody-and$MeasuredBody.execution-ceq@('local','server','auto')[$index]-and$MeasuredBody.nodes.Count-eq3-and$MeasuredBody.expected_profile_tokens.Count-eq3) 'Measure next failed to capture the complete selected graph'
            if($fault-ceq'valid'){
                Check (($rows.id-join',')-ceq'prefix-0,prefix-1,prefix-2'-and$rows[2].mode-ceq'awg2-strong'-and$rootControls['UnifiedExecution'].SelectedIndex-eq$index) 'Measure next did not insert one original measured member'
            }else{Check (($rows.id-join',')-ceq'prefix-0,prefix-1') ('Measure next adopted another draft: '+$fault)}
        }
    }
    # Each mutation must first reach its own named witness. The full source
    # matrix, including its explicit invalid routes, runs on the shipping code.
    $originalProfiles=$store.profiles
    if(-not $NegativeControl){
    $import=@{id='import-b';name='Imported B';node_kind='external';profile_token='b'*64;start_layer='off';external=@{protocol='shadowsocks';ordered_middle_supported=$true;ordered_local_imported_nodes_supported=$true}}
    $store.profiles+=@($import)
    $rows.Clear();$rows.Add([pscustomobject]@{id='prefix-0';mode='wg'});$rows.Add([pscustomobject]@{id=$import.id;mode='shadowsocks'})
    foreach($case in @('eligible','server','compare','layer','entry-layer','awg','capability','changed')){
        $rootControls['UnifiedExecution'].SelectedIndex=switch($case){'server'{1};'compare'{2};default{0}}
        $rows[0].mode=if($case -ceq 'awg'){'awg2-fast'}else{'wg'}
        $originalProfiles[0] | Add-Member NoteProperty start_layer $(if($case -ceq 'entry-layer'){'aes-256-gcm'}else{'off'}) -Force
        $import.start_layer=if($case -ceq 'layer'){'aes-256-gcm'}else{'off'}
        $import.external.ordered_local_imported_nodes_supported=$case -cne 'capability'
        $script:CurrentStore=if($case -ceq 'changed'){[pscustomobject]@{selected_id=$id;profiles=$originalProfiles}}else{$store}
        $RouterCombo.SelectedValue=$id;&$refresh;$list.SelectedIndex=1
        $script:MeasuredBody=$null;$script:DraftFault='valid';&$measureNext
        Check (($null -ne $MeasuredBody) -eq ($case -cin @('eligible','awg'))) ('wrong Local response admission for '+$case)
        if($null -ne $MeasuredBody){Check ($MeasuredBody.nodes[1].id -ceq $import.id -and $MeasuredBody.expected_profile_tokens[$import.id] -ceq $import.profile_token) 'private-response draft lost original imported source'}
        if($rows.Count -gt 2){$rows.RemoveAt(2)}
    }
    if($Group -in @('all','editor')){
        $store.profiles=@($originalProfiles)+@(7..14|ForEach-Object{[pscustomobject]@{id=('prefix-'+$_);name=('Prefix '+$_);node_kind='router-vpn';start_layer='off';profile_token=('{0:x64}' -f ($_+1))}})
        $script:CurrentStore=$store;$rows.Clear();$prefixMode.SelectedIndex=0;$finalMode.Tag='shadowsocks'
        $rootControls['UnifiedExecution'].SelectedIndex=0;&$refresh
        foreach($n in 1..15){&$add;Check ($rows.Count -eq $n -and $rows[-1].id -ceq ('prefix-'+($n-1))) 'Deep Local Add lost an original paired prefix'}
        Check ($finalMode.Items.Count -eq 1 -and $finalMode.SelectedValue -ceq 'shadowsocks') 'Extended WG path offered an unsupported final'
        $list.SelectedIndex=13;$prefixMode.SelectedIndex=1;&$changeMode
        Check ($rows[13].mode -ceq 'wg') 'Deep paired path acquired an unsupported AWG interior'
        foreach($count in @(9,16,96)){
            $keepID=$id;$id='stream-final';$store.selected_id=$id;$RouterCombo.SelectedValue=$id;$rows.Clear()
            $store.profiles=@([pscustomobject]@{id=$id;name=$id;node_kind='router-vpn';profile_token='f'*64;start_layer='off'})
            foreach($i in 0..($count-2)){
                $nodeID='stream-'+$i;$mode=if($i){'shadowsocks'}else{'wg'}
                $origin=@{id=$nodeID;name=$nodeID;node_kind='router-vpn';start_layer='off';profile_token=('{0:x64}' -f ($i+201))}
                if($i){$origin.node_kind='external';$origin.external=@{protocol='shadowsocks';ordered_middle_supported=$true;ordered_local_imported_nodes_supported=$true}}
                $store.profiles+=$origin;$rows.Add([pscustomobject]@{id=$nodeID;mode=$mode})
            }
            $script:CurrentStore=$store;$rootControls['UnifiedExecution'].SelectedIndex=0;$finalMode.Tag='shadowsocks';&$refresh
            $all=@($rows.ToArray())+@([pscustomobject]@{id=$id;mode='shadowsocks'})
            foreach($fault in @('none','remote','final-layer','late-nonliteral','late-packet')){
                $execution=if($fault -ceq 'remote'){'server'}else{'local'}
                if($fault -ceq 'final-layer'){$store.profiles[0].start_layer='aes-256-gcm'}
                if($fault -ceq 'late-nonliteral'){$store.profiles[-1].external.ordered_local_imported_nodes_supported=$false}
                if($fault -ceq 'late-packet'){$all[-2].mode='wg'}
                Check ((Test-RouterVPNOrderedCandidatePosition $all 7 $execution $store.profiles) -eq ($fault -ceq 'none')) ('deep SS closed source accepted '+$fault)
                $store.profiles[0].start_layer='off';$store.profiles[-1].external.ordered_local_imported_nodes_supported=$true;$all[-2].mode='shadowsocks'
            }
            $script:MeasuredBody=$null;$list.SelectedIndex=$count-2;&$measureNext
            Check ($null -ne $MeasuredBody -and $MeasuredBody.nodes.Count -eq $count -and $MeasuredBody.expected_profile_tokens.Count -eq $count) ('deep measured final lost its original captured draft '+$count+' '+$status.Text)
            $id=$keepID;$store.selected_id=$id;$RouterCombo.SelectedValue=$id
        }
        $members=@();$sources=@();$tokens=@{}
        foreach($i in 0..4){
            $source=@{id="named-$i";node_kind='router-vpn';start_layer='off';profile_token=('{0:x64}' -f ($i+20))}
            if($i -in @(1,3)){$source.node_kind='external';$source.external=@{protocol='shadowsocks';ordered_middle_supported=$true;ordered_local_imported_nodes_supported=$true}}
            $members+=[pscustomobject]@{id=$source.id;mode=$(if($i){'shadowsocks'}else{'wg'})}
            $sources+=$source;$tokens[$source.id]=$source.profile_token
        }
        $model=@{profiles=$sources;selected_id='named-4'}
        $saved=@{nodes=$members;execution='local';control_id='named-4';profile_tokens=$tokens}
        $request=New-RouterVPNOrderedConnectPayload $saved $model
        Check ((Test-RouterVPNOrderedCandidatePosition $members 2 'local' $sources) -and (Test-RouterVPNOrderedCandidatePosition $members 3 'local' $sources)) 'Recursive private response lost its paired or later imported position'
        Check (($request.nodes.id -join ',') -ceq ($members.id -join ',') -and $request.expected_profile_tokens.Count -eq 5) 'Named paired stream Connect lost an original source'
        foreach($fault in @('layer','server','changed')){
            if($fault -eq 'layer'){$sources[3].start_layer='aes-256-gcm'}
            if($fault -eq 'server'){$saved.execution='server'}
            if($fault -eq 'changed'){$sources[3].profile_token='e'*64}
            $allowed=$true;try{[void](New-RouterVPNOrderedConnectPayload $saved $model)}catch{$allowed=$false}
            Check (-not $allowed) ('Named paired stream accepted '+$fault)
            $sources[3].start_layer='off';$saved.execution='local';$sources[3].profile_token=$tokens[$sources[3].id]
        }
        $members=@();$sources=@();$tokens=@{}
        foreach($i in 0..8){
            $source=@{id="recursive-$i";node_kind='router-vpn';start_layer='off';profile_token=('{0:x64}' -f ($i+30))}
            if($i -in @(1,4,6,7)){$source.node_kind='external';$source.external=@{protocol='shadowsocks';ordered_middle_supported=$true;ordered_local_imported_nodes_supported=$true}}
            $members+=[pscustomobject]@{id=$source.id;mode=$(if($i){'shadowsocks'}else{'wg'})}
            $sources+=$source;$tokens[$source.id]=$source.profile_token
        }
        $model=@{profiles=$sources;selected_id='recursive-8'}
        $saved=@{nodes=$members;execution='local';control_id=$model.selected_id;profile_tokens=$tokens}
        $request=New-RouterVPNOrderedConnectPayload $saved $model
        Check (($request.nodes.id -join ',') -ceq ($members.id -join ',') -and (Test-RouterVPNOrderedCandidatePosition $members 3 'local' $sources) -and (Test-RouterVPNOrderedCandidatePosition $members 6 'local' $sources)) 'Extended consecutive private streams lost their source positions'
        $hostSource=$sources[1]
        $hostSource.dns_mode='custom';$hostSource.dns_protocol='tcp';$hostSource.dns_host='10.78.0.53';$hostSource.dns_port=5353
        $hostSource.external.ordered_local_imported_nodes_supported=$false
        $hostSource.external.ordered_execution_middle_supported=$false
        $hostSource.external.ordered_hostname_execution_middle_supported=$true
        $request=New-RouterVPNOrderedConnectPayload $saved $model
        Check (($request.nodes.id -join ',') -ceq ($members.id -join ',') -and (Test-RouterVPNOrderedCandidatePosition $members 1 'local' $sources) -and (Test-RouterVPNOrderedCandidatePosition $members 6 'local' $sources)) 'The original hostname or its following measured stream lost the saved route'
        $sources[4].external.ordered_hostname_execution_middle_supported=$true
        Check (-not(Test-RouterVPNOrderedLocalImportedPath $members $sources)) 'A second hostname replaced an original literal stream'
        $sources[4].external.Remove('ordered_hostname_execution_middle_supported')
        foreach($count in @(9,16,96)){
            foreach($mode in @('wg','awg2-fast','awg2-strong')){
                $packets=if($mode -ceq 'awg2-fast'){1}else{2}
                $profiles=@();$members=@();$tokens=@{}
                for($i=0;$i -lt $count;$i++){
                    $source=@{id=('mixed-'+$i);node_kind='router-vpn';start_layer='off';profile_token=('{0:x64}' -f ($i+10))}
                    if($i -ge $packets -and $i -lt $count-1){$source.node_kind='external';$source.external=@{protocol='shadowsocks';ordered_middle_supported=$true;ordered_local_imported_nodes_supported=$true}}
                    $profiles+=$source;$tokens[$source.id]=$source.profile_token
                    $members+=[pscustomobject]@{id=$source.id;mode=$(if($i -lt $packets){$mode}else{'shadowsocks'})}
                }
                $model=@{profiles=$profiles;selected_id=$members[-1].id}
                $captured=@{nodes=$members;execution='local';control_id=$model.selected_id;profile_tokens=$tokens}
                $payload=New-RouterVPNOrderedConnectPayload $captured $model
                Check ($payload.nodes.Count -eq $count -and $payload.expected_profile_tokens.Count -eq $count -and (Get-RouterVPNOrderedMixedPacketCount $payload.nodes) -eq $packets) 'Mixed original source lost packet boundary or linked tokens'
                Check (Test-RouterVPNOrderedCandidatePosition $members ($count-2) 'local' $profiles) 'Mixed imported penultimate lost native authenticated response'
                Check ((Test-RouterVPNOrderedCandidatePosition $members ($packets-1) 'local' $profiles) -eq ($count -lt 96)) 'Mixed candidate lost original packet prefix or exceeded insertion capacity'
                foreach($fault in @('server','auto','late-token','late-kind','packet-layer','gap')){
                    if($fault -cin @('server','auto')){$captured.execution=$fault}
                    if($fault -ceq 'late-token'){$profiles[-2].profile_token='e'*64}
                    if($fault -ceq 'late-kind'){$profiles[-2].node_kind='router-vpn'}
                    if($fault -ceq 'packet-layer'){$profiles[0].start_layer='aes-256-gcm'}
                    if($fault -ceq 'gap'){$members[-2].mode='wg'}
                    $allowed=$true;try{[void](New-RouterVPNOrderedConnectPayload $captured $model)}catch{$allowed=$false}
                    Check (-not $allowed) ('Mixed original admitted '+$fault)
                    $captured.execution='local';$profiles[-2].profile_token=$tokens[$profiles[-2].id];$profiles[-2].node_kind='external';$profiles[0].start_layer='off';$members[-2].mode='shadowsocks'
                }
            }
        }
        $eight=@([pscustomobject]@{id='packet-8';mode='wg'})+@($members[($members.Count-7)..($members.Count-1)])
        $eightProfiles=@(@{id='packet-8';node_kind='router-vpn';start_layer='off'})+@($profiles[($profiles.Count-7)..($profiles.Count-1)])
        Check (Test-RouterVPNOrderedCandidatePosition $eight 0 'local' $eightProfiles) 'Native packet insertion could not grow an eight-node source into a qualified nine-node mixed path'
        $eightProfiles[4].start_layer='aes-256-gcm'
        Check (-not(Test-RouterVPNOrderedCandidatePosition $eight 0 'local' $eightProfiles)) 'Mixed nine-node future ignored layered imported source'
        $mixedMembers=@();$mixedSources=@()
        for($i=0;$i -lt 16;$i++){
            $source=@{id=('late-packet-'+$i);node_kind='router-vpn';start_layer='off'}
            if($i -ge 9 -and $i -lt 15){$source.node_kind='external';$source.external=@{protocol='shadowsocks';ordered_middle_supported=$true;ordered_local_imported_nodes_supported=$true}}
            $mixedSources+=$source;$mixedMembers+=[pscustomobject]@{id=$source.id;mode=$(if($i -lt 9){'wg'}else{'shadowsocks'})}
        }
        Check (Test-RouterVPNOrderedCandidatePosition $mixedMembers 8 'local' $mixedSources) 'Mixed position eight lost native packet measurement'
        $mixedSources[13].external.ordered_local_imported_nodes_supported=$false
        Check (-not(Test-RouterVPNOrderedCandidatePosition $mixedMembers 8 'local' $mixedSources)) 'Late packet measurement survived a changed imported suffix'
        foreach($packets in @(1,2,6)){
            $profiles=@();$path=@();for($i=0;$i -lt $packets;$i++){$profiles+=@{id=('packet-'+$i);node_kind='router-vpn';start_layer='off'};$path+=[pscustomobject]@{id=('packet-'+$i);mode='awg2-strong'}}
            $hostname=@{id='name';node_kind='external';start_layer='off';dns_mode='custom';dns_protocol='tcp';dns_host='10.99.0.1';dns_port=53;external=@{protocol='shadowsocks';ordered_middle_supported=$true;ordered_hostname_execution_middle_supported=$true;ordered_local_imported_nodes_supported=$false}}
            $profiles+=@($hostname,@{id='final';node_kind='router-vpn';start_layer='off'});$path+=@([pscustomobject]@{id='name';mode='shadowsocks'},[pscustomobject]@{id='final';mode='shadowsocks'})
            Check (Test-RouterVPNOrderedResponsePrefix $path $packets 'local' $profiles) 'Original hostname Custom TCP response was lost'
            foreach($fault in @('udp','resolver','mixed','layer')){
                if($fault -ceq 'udp'){$hostname.dns_protocol='udp'};if($fault -ceq 'resolver'){$hostname.dns_host='not-literal.invalid'};if($fault -ceq 'mixed'){$hostname.external.ordered_local_imported_nodes_supported=$true};if($fault -ceq 'layer'){$profiles[0].start_layer='aes-256-gcm'}
                Check (-not(Test-RouterVPNOrderedResponsePrefix $path $packets 'local' $profiles)) ('Hostname response accepted '+$fault)
                $hostname.dns_protocol='tcp';$hostname.dns_host='10.99.0.1';$hostname.external.ordered_local_imported_nodes_supported=$false;$profiles[0].start_layer='off'
            }
        }
        foreach($count in @(9,16,96,97)){
            $deepProfiles=@();$deepNodes=@();$tokens=@{}
            foreach($i in 0..($count-1)){
                $original=[pscustomobject]@{id=('paired-'+$i);node_kind='router-vpn';start_layer='off';profile_token=('{0:x64}' -f ($i+101))}
                $deepProfiles+=$original;$tokens[$original.id]=$original.profile_token
                $deepNodes+=[pscustomobject]@{id=$original.id;mode=$(if($i -eq ($count-1)){'shadowsocks'}else{'wg'})}
            }
            $deepStore=@{selected_id=$deepNodes[-1].id;profiles=$deepProfiles};$draft=@{control_id=$deepNodes[-1].id;execution='local';nodes=$deepNodes;profile_tokens=$tokens}
            $payload=$null;try{$payload=New-RouterVPNOrderedConnectPayload $draft $deepStore}catch{if($count -ne 97){throw}}
            if($count -eq 97){Check ($null -eq $payload) 'Deep paired path exceeded physical traversal capacity';continue}
            Check ($payload.expected_profile_tokens.Count -eq $count -and ($payload.nodes.id -join ',') -ceq ($deepNodes.id -join ',')) 'Deep paired source was truncated'
            foreach($fault in @('server','auto','layer','import','relink')){
                $draft.execution=if($fault -cin @('server','auto')){$fault}else{'local'}
                if($fault -ceq 'layer'){$deepProfiles[-2].start_layer='aes-256-gcm'}
                if($fault -ceq 'import'){$deepProfiles[-2].node_kind='external'}
                if($fault -ceq 'relink'){$deepProfiles[-2].profile_token='e'*64}
                $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $draft $deepStore)}catch{$rejected=$true}
                Check $rejected ('Deep paired path accepted '+$fault)
                $deepProfiles[-2].start_layer='off';$deepProfiles[-2].node_kind='router-vpn';$deepProfiles[-2].profile_token=$tokens[$deepNodes[-2].id]
            }
        }
    }
    }
    $store.profiles=$originalProfiles;$script:CurrentStore=$store
    $rows.Clear();$RouterCombo.SelectedValue=$id;$rootControls['UnifiedExecution'].SelectedIndex=0
    &$refresh
    Check ($available.Items.Count-eq7-and$list.Items.Count-eq0) 'initial choices included final/external nodes or invented a prefix'
    for($i=0;$i-lt7;$i++){
        $prefixMode.SelectedIndex=$i%3
        &$add
        Check ($rows.Count-eq$i+1-and$list.Items.Count-eq$i+1) 'Add did not append the chosen node'
        Check ($rows[$i].id-ceq('prefix-'+$i)-and$rows[$i].mode-ceq@('wg','awg2-fast','awg2-strong')[$i%3]) 'Add changed the selected node or transport'
        Check ($list.Items[$i].display.Contains((Get-RouterVPNOrderedModeTitle $rows[$i].mode))) 'editor row mislabeled its captured transport'
        Check ($available.Items.Count-eq6-$i) 'Add left an already used node selectable'
    }
    Check (-not$dialog.FindName('Add').IsEnabled) 'eighth prefix remained enabled'
    &$add;Check ($rows.Count-eq7) 'Add exceeded the eight-node complete path bound'
    $list.SelectedIndex=0;$prefixMode.SelectedIndex=2;&$changeMode
    Check ($rows[0].id-ceq'prefix-0'-and$rows[0].mode-ceq'awg2-strong') 'Change mode replaced its original node or ignored selected transport'
    $list.SelectedIndex=3;&$up
    Check ($rows[2].id-ceq'prefix-3'-and$rows[2].mode-ceq'wg'-and$rows[3].id-ceq'prefix-2'-and$rows[3].mode-ceq'awg2-strong'-and$list.SelectedIndex-eq2) 'Move up changed another node or lost selection'
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
    $RouterCombo.SelectedValue=$id;$script:CurrentStore=$store|ConvertTo-Json -Depth 8|ConvertFrom-Json
    $script:CurrentStore.profiles[1].profile_token=('f'*64)
    &$apply;Check ([object]::ReferenceEquals($original,$rootControls['UnifiedNodeChainButton'].Tag)) 'relinked middle node replaced the original editor draft'
    $script:CurrentStore=$store;$status.Text='';&$apply
    $saved=$rootControls['UnifiedNodeChainButton'].Tag
    Check ($saved.control_id-ceq$id-and$saved.nodes.Count-eq7-and$saved.nodes[-1].id-ceq$id-and$saved.nodes[-1].mode-ceq'shadowsocks') ('Apply lost the fixed selected final or full prefix list. '+$status.Text)
    Check (($saved.nodes.id-join',')-ceq'prefix-0,prefix-1,prefix-3,prefix-4,prefix-5,prefix-6,selected-final') 'Apply reordered the visible path'
    Check (($saved.nodes.mode-join',')-ceq'awg2-strong,awg2-fast,wg,awg2-fast,awg2-strong,wg,shadowsocks') 'Apply replaced the original per-position transports'
    Check ($rootControls['UnifiedOrdered'].IsChecked-and$rootControls['UnifiedMultihop'].IsChecked) 'Apply did not choose the complete ordered path'
    Check (($saved|ConvertTo-Json -Depth 8)-notmatch'must-not-copy') 'editor copied private node credentials'
    Check ($saved.profile_tokens.Count-eq7-and$saved.profile_tokens['prefix-1']-ceq$store.profiles[1].profile_token) 'editor lost all-source public preconditions'
    $conflict=@{selected_id=$id;profiles=$store.profiles+@($store.profiles[0],$store.profiles[0])}
    $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $saved $conflict)}catch{$rejected=$true}
    Check $rejected 'a repeated original catalog ID became an unambiguous source'
    $otherCase=@{id='PREFIX-0';node_kind='router-vpn';profile_token=('f'*64)}
    $distinct=@{selected_id=$id;profiles=$store.profiles+@($otherCase,$otherCase)}
    $originalRequest=New-RouterVPNOrderedConnectPayload $saved $distinct
    Check ($originalRequest.expected_profile_tokens['prefix-0']-ceq$store.profiles[0].profile_token) 'an unrelated differently cased ID replaced the selected source'
    Check ($rootControls['UnifiedNodeChainSummary'].Text.Contains('Prefix 3')-and$rootControls['UnifiedNodeChainSummary'].Text.Contains('Selected final')) 'summary omitted a middle or final node'
    Check ($rootControls['UnifiedNodeChainSummary'].Text.Contains('AmneziaWG Strong')-and$rootControls['UnifiedNodeChainSummary'].Text.Contains('AmneziaWG Fast')-and$rootControls['UnifiedOrderedModeSummary'].Text.Contains('AmneziaWG Strong')) 'summary concealed selected per-node AWG transports'
    foreach($name in @('UnifiedEntryCombo','UnifiedExitCombo','UnifiedEntryMode','UnifiedExitMode','UnifiedBaseCombo','UnifiedCandidatesButton')){Check (-not$rootControls[$name].IsEnabled) 'ordered path left contradictory pair controls enabled'}
    Check $rootControls['UnifiedExecution'].IsEnabled 'ordered path disabled its explicit execution choice'
    foreach($index in @(1,2,0)){
        $rootControls['UnifiedExecution'].SelectedIndex=$index;&$apply
        $choice=$rootControls['UnifiedNodeChainButton'].Tag
        Check ($choice.execution-ceq$rootControls['UnifiedExecution'].SelectedItem.Tag) 'editor replaced explicit ordered execution'
        Check (($choice.nodes.id-join',')-ceq($saved.nodes.id-join',')) 'execution choice dropped original ordered members'
    }
    Check ($rootControls['UnifiedModeCombo'].Visibility-ceq'Collapsed'-and$rootControls['UnifiedOrderedModeSummary'].Visibility-ceq'Visible'-and-not$rootControls['UnifiedPresetsButton'].IsEnabled) 'ordered mode display claimed another direct transport'
    $rootControls['UnifiedMultihop'].IsChecked=$false;RefreshUnifiedOrderedControls
    Check ($rootControls['UnifiedModeCombo'].Visibility-ceq'Visible'-and$rootControls['UnifiedOrderedModeSummary'].Visibility-ceq'Collapsed') 'direct mode display remained hidden after disabling multihop'
    $saved.nodes[1].id='altered';Check ($rows[1].id-ceq'prefix-1') 'committed draft retained mutable editor rows'
    foreach($selectedID in @('prefix-2','missing-final')){
        $rootControls['UnifiedOrderedModeSummary'].Text='AmneziaWG Strong '+[char]0x2192+' previous final'
        $replacement=$store|ConvertTo-Json -Depth 8|ConvertFrom-Json;$replacement.selected_id=$selectedID
        RefreshUnifiedOrderedSelection $replacement
        $rootControls['UnifiedMultihop'].IsChecked=$true;$rootControls['UnifiedOrdered'].IsChecked=$true;RefreshUnifiedOrderedControls
        Check ($rootControls['UnifiedOrderedModeSummary'].Text-ceq'Choose each intermediate transport and the final node.') 'new incomplete ordered selection displayed a previous path transport summary'
    }
    # Invoke the shipping Add/Apply callbacks with an explicitly advertised
    # original external middle; its public receipt never supplies paired secrets.
    $rows.Clear();$store.selected_id=$id;$script:CurrentStore=$store
    $custom=[pscustomobject]@{id='custom-middle';name='Custom SS2022';node_kind='external';profile_token=('c'*64);external=[pscustomobject]@{protocol='shadowsocks';ordered_middle_supported=$true}}
    $store.profiles+=$custom
    &$refresh;$available.SelectedIndex=[array]::IndexOf(@($available.ItemsSource.id),'prefix-0');$prefixMode.SelectedIndex=0;&$add
    $available.SelectedIndex=[array]::IndexOf(@($available.ItemsSource.id),'custom-middle');&$add
    Check ($rows.Count-eq2-and$rows[1].id-ceq'custom-middle'-and$rows[1].mode-ceq'shadowsocks') 'custom Add invented a paired transport'
    &$apply;$customSaved=$rootControls['UnifiedNodeChainButton'].Tag
    Check (($customSaved.nodes.id-join',')-ceq'prefix-0,custom-middle,selected-final') 'custom Apply lost original order'
    Check ($customSaved.profile_tokens['custom-middle']-ceq('c'*64)) 'custom Apply lost original source token'
    $custom.external.ordered_middle_supported=$false
    $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $customSaved $store)}catch{$rejected=$true};Check $rejected 'unsupported external middle retained admission'
    $custom.external.ordered_middle_supported='true'
    $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $customSaved $store)}catch{$rejected=$true};Check $rejected 'malformed custom capability retained admission'
    $custom.external.ordered_middle_supported=$true
    $swapped=[pscustomobject]@{control_id=$id;profile_tokens=$customSaved.profile_tokens;nodes=@($customSaved.nodes[1],$customSaved.nodes[0],$customSaved.nodes[2])}
    $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $swapped $store)}catch{$rejected=$true};Check $rejected 'external source became physical entry'
    $custom.profile_token=('d'*64)
    $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $customSaved $store)}catch{$rejected=$true};Check $rejected 'relinked custom source retained admission'
    # Each imported member has an independent catalog owner. These use the
    # shipping capture/payload functions; no native transport is doubled here.
    $localLayouts=@(
        @{count=3;positions=@(0,1)},
        @{count=4;positions=@(1)},@{count=4;positions=@(1,2)},
        @{count=5;positions=@(1,3)},@{count=6;positions=@(1,3)},
        @{count=8;positions=@(1,4,6)},@{count=8;positions=@(1,2,3,4,5,6)},@{count=9;positions=@(1..7)},@{count=16;positions=@(1..14)}
    )
    if($Group -in @('all','editor')) {
    foreach($layout in $localLayouts){foreach($packet in @('wg','awg2-fast','awg2-strong')){
        $localNodes=@();$localProfiles=@();$localTokens=@{}
        for($position=0;$position-lt$layout.count;$position++){
            $memberID='independent-'+$position;$isImport=$layout.positions-contains$position
            $mode=if($isImport-or$position-eq($layout.count-1)){'shadowsocks'}else{$packet}
            $localNodes+=[pscustomobject]@{id=$memberID;mode=$mode}
            $profile=@{id=$memberID;node_kind='router-vpn';profile_token=('{0:x64}' -f ($position+701));start_layer=@('off','aes-256-gcm','aes-256-gcm+xor-whitening')[$position%3]}
            if($layout.count-gt8){$profile.start_layer='off'}
            if($isImport){$profile.node_kind='external';$profile.external=@{protocol='shadowsocks';ordered_middle_supported=$true;ordered_execution_middle_supported=$true;ordered_local_imported_nodes_supported=$true;password=('private-import-'+$position)}}
            $localProfiles+=$profile;$localTokens[$memberID]=$profile.profile_token
        }
        $finalID=$localNodes[-1].id;$localStore=@{selected_id=$finalID;profiles=$localProfiles}
        $localDraft=@{control_id=$finalID;nodes=$localNodes;execution='local';profile_tokens=$localTokens}
        try{$localPayload=New-RouterVPNOrderedConnectPayload $localDraft $localStore}catch{Check $false 'Local imported nodes lost complete original path'}
        Check (($localPayload.nodes.id-join',')-ceq($localNodes.id-join',')-and($localPayload.nodes.mode-join',')-ceq($localNodes.mode-join',')-and$localPayload.execution-ceq'local') 'Local imported nodes changed original order or modes'
        Check ($localPayload.expected_profile_tokens.Count-eq$layout.count-and($localPayload|ConvertTo-Json -Depth 12)-notmatch'private-import-|password|start_layer') 'Local imported nodes lost source references or copied secrets'
        foreach($position in $layout.positions){
            $source=$localProfiles[$position].external
            foreach($badFlag in @($false,1,'true',$null)){
                $source.ordered_local_imported_nodes_supported=$badFlag;$refused=$false
                try{[void](New-RouterVPNOrderedConnectPayload $localDraft $localStore)}catch{$refused=$true}
                Check $refused 'Local imported nodes accepted invalid source capability'
            }
            $source.Remove('ordered_local_imported_nodes_supported');$refused=$false
            try{[void](New-RouterVPNOrderedConnectPayload $localDraft $localStore)}catch{$refused=$true}
            Check $refused 'Local imported nodes accepted invalid source capability'
            $source.ordered_local_imported_nodes_supported=$true
            $source.protocol='socks5';$refused=$false
            try{[void](New-RouterVPNOrderedConnectPayload $localDraft $localStore)}catch{$refused=$true}
            Check $refused 'Local imported nodes substituted a saved transport';$source.protocol='shadowsocks'
        }
        for($position=0;$position-lt$layout.count;$position++){
            $originalToken=$localProfiles[$position].profile_token;$localProfiles[$position].profile_token='f'*64;$refused=$false
            try{[void](New-RouterVPNOrderedConnectPayload $localDraft $localStore)}catch{$refused=$true}
            Check $refused 'Local imported nodes accepted a replaced source';$localProfiles[$position].profile_token=$originalToken
        }
        foreach($executionChoice in @('server','auto')){
            $localDraft.execution=$executionChoice;$refused=$false
            try{[void](New-RouterVPNOrderedConnectPayload $localDraft $localStore)}catch{$refused=$true}
            Check $refused 'Local imported nodes borrowed Server or Compare authority'
            foreach($j in $layout.positions){$localProfiles[$j].external.ordered_multiple_imported_execution_supported=$true}
            if($layout.positions-notcontains0){
                $payload=New-RouterVPNOrderedConnectPayload $localDraft $localStore
                Check ($payload.execution-ceq$executionChoice-and($payload.nodes.id-join',')-ceq($localNodes.id-join',')-and($payload.nodes.mode-join',')-ceq($localNodes.mode-join',')-and(Get-RouterVPNOrderedExecutionCapability $localNodes $executionChoice)-ceq'ordered_multiple_imported_executions') 'Multiple imported execution lost its native family or complete selected order'
                foreach($j in $layout.positions){
                    $localProfiles[$j].external.ordered_multiple_imported_execution_supported='true'
                    $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $localDraft $localStore)}catch{$refused=$true}
                    Check $refused 'Multiple imported execution accepted an untyped member capability'
                    $localProfiles[$j].external.ordered_multiple_imported_execution_supported=$true
                }
            }else{
                $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $localDraft $localStore)}catch{$refused=$true}
                Check $refused 'Custom entry borrowed multiple-import execution'
            }
            foreach($j in $layout.positions){$localProfiles[$j].external.Remove('ordered_multiple_imported_execution_supported')}
        };$localDraft.execution='local'
        $localNodes[-1].mode='hysteria2';$refused=$false
        try{[void](New-RouterVPNOrderedConnectPayload $localDraft $localStore)}catch{$refused=$true}
        Check $refused 'Local imported nodes acquired an unsupported final';$localNodes[-1].mode='shadowsocks'
        $originalID=$localNodes[1].id;$localNodes[1].id=$localNodes[0].id;$refused=$false
        try{[void](New-RouterVPNOrderedConnectPayload $localDraft $localStore)}catch{$refused=$true}
        Check $refused 'Local imported nodes accepted a duplicate source';$localNodes[1].id=$originalID
    }}
    }
    # The same visible editor now selects a distinct paired final transport.
    $rows.Clear();$finalMode.SelectedIndex=0
    $socks=[pscustomobject]@{id='socks-middle';name='Original SOCKS5';node_kind='external';profile_token=('e'*64);external=[pscustomobject]@{protocol='socks5';ordered_middle_supported=$true}}
    $store.profiles+=$socks;$script:CurrentStore=$store;&$refresh
    $available.SelectedIndex=[array]::IndexOf(@($available.ItemsSource.id),'prefix-0');$prefixMode.SelectedIndex=1;&$add
    $available.SelectedIndex=[array]::IndexOf(@($available.ItemsSource.id),'socks-middle');&$add
    Check ($rows.Count-eq2-and$rows[1].id-ceq'socks-middle'-and$rows[1].mode-ceq'socks5') 'SOCKS Add substituted its saved transport'
    Check (($finalMode.ItemsSource.id-join',')-ceq'shadowsocks') 'SOCKS middle offered an unsupported final'
    $list.SelectedIndex=1;$prefixMode.SelectedIndex=3;&$changeMode
    Check ($rows[1].mode-ceq'socks5') 'SOCKS Change mode substituted Shadowsocks'
    &$apply;$socksSaved=$rootControls['UnifiedNodeChainButton'].Tag
    $socksPayload=New-RouterVPNOrderedConnectPayload $socksSaved $store
    Check (($socksPayload.nodes.mode-join',')-ceq'awg2-fast,socks5,shadowsocks'-and$socksPayload.execution-ceq'local') 'SOCKS Connect lost complete Local ordering'
    Check ($socksPayload.expected_profile_tokens['socks-middle']-ceq('e'*64)) 'SOCKS Connect lost original source token'
    Check ($rootControls['UnifiedNodeChainSummary'].Text.Contains('SOCKS5')) 'SOCKS summary concealed selected transport'
    foreach($foreign in @('shadowsocks','SOCKS5','socks5 ','http-connect')){
        $socks.external.protocol=$foreign;$rejected=$false
        try{[void](New-RouterVPNOrderedConnectPayload $socksSaved $store)}catch{$rejected=$true}
        Check $rejected 'SOCKS Connect accepted a different saved transport'
    }
    $socks.external.protocol='socks5';$socks.external.ordered_middle_supported=$false
    $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $socksSaved $store)}catch{$rejected=$true};Check $rejected 'SOCKS Connect ignored native capability'
    $socks.external.ordered_middle_supported=$true
    $swapped=[pscustomobject]@{control_id=$id;profile_tokens=$socksSaved.profile_tokens;nodes=@($socksSaved.nodes[1],$socksSaved.nodes[0],$socksSaved.nodes[2])}
    $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $swapped $store)}catch{$rejected=$true};Check $rejected 'SOCKS middle became physical entry'
    $socks.profile_token=('f'*64)
    $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $socksSaved $store)}catch{$rejected=$true};Check $rejected 'SOCKS relinking retained old draft authority'
    # Run the real Add/Apply and request-source guard for both original CONNECT
    # protocols. Capability remains explicit and no native admission is invented.
    $originalProfiles=$store.profiles
    $packetModes = switch ($Group) {
        'all' { 'wg'; 'awg2-fast'; 'awg2-strong' }
        'editor' { }
        default { $Group }
    }
    foreach($protocol in @('http-connect','https-connect','openvpn','socks5','shadowsocks')){foreach($packet in $packetModes){
        foreach($count in @(3..8)){
        $middle=$count-2
        $rows.Clear();$finalMode.SelectedIndex=0
        $middleID='connect-'+$protocol+'-'+$packet+'-'+$count
        $connect=[pscustomobject]@{id=$middleID;name=('Original '+$protocol);node_kind='external';profile_token=('b'*64);external=[pscustomobject]@{protocol=$protocol;ordered_middle_supported=$true}}
        $store.profiles=$originalProfiles+@($connect);$script:CurrentStore=$store;&$refresh
        for($prefix=0;$prefix-lt$middle;$prefix++){
            $available.SelectedIndex=[array]::IndexOf(@($available.ItemsSource.id),('prefix-'+$prefix))
            $prefixMode.SelectedIndex=[array]::IndexOf(@($prefixMode.ItemsSource.id),$packet);&$add
        }
        $available.SelectedIndex=[array]::IndexOf(@($available.ItemsSource.id),$middleID);&$add
        Check ($rows.Count-eq($count-1)-and$rows[0].mode-ceq$packet-and$rows[$middle].id-ceq$middleID-and$rows[$middle].mode-ceq$protocol) 'CONNECT Add substituted its exact saved transport'
        Check (($finalMode.ItemsSource.id-join',')-ceq'shadowsocks') 'CONNECT middle offered an unsupported final'
        $list.SelectedIndex=$middle;$prefixMode.SelectedIndex=3;&$changeMode
        Check ($rows[$middle].mode-ceq$protocol) 'CONNECT Change mode substituted another protocol'
        &$apply;$connectSaved=$rootControls['UnifiedNodeChainButton'].Tag
        $payload=New-RouterVPNOrderedConnectPayload $connectSaved $store
        Check (($payload.nodes.mode-join',')-ceq((@($packet)*$middle+@($protocol,'shadowsocks'))-join',')-and$payload.execution-ceq'local') 'CONNECT request lost complete Local ordering'
        Check ($payload.expected_profile_tokens[$middleID]-ceq('b'*64)-and$payload.expected_selected_node_id-ceq$id) 'CONNECT request lost original source tokens or final owner'
        Check ($rootControls['UnifiedNodeChainSummary'].Text.Contains((Get-RouterVPNOrderedModeTitle $protocol))) 'CONNECT summary concealed selected protocol'
        $serialized=$payload|ConvertTo-Json -Depth 8
        Check ($serialized-notmatch'must-not-copy|api_token|password') 'CONNECT editor copied private credentials'
        $roundTrip=$serialized|ConvertFrom-Json
        Check (($roundTrip.nodes.mode-join',')-ceq((@($packet)*$middle+@($protocol,'shadowsocks'))-join',')) 'CONNECT JSON transport changed protocol'
        $other=if($protocol-ceq'http-connect'){'https-connect'}else{'http-connect'}
        foreach($foreign in @($other,$(if($protocol-ceq'shadowsocks'){'socks5'}else{'shadowsocks'}),$protocol.ToUpperInvariant(),($protocol+' '))){
            $connect.external.protocol=$foreign;$rejected=$false
            try{[void](New-RouterVPNOrderedConnectPayload $connectSaved $store)}catch{$rejected=$true}
            Check $rejected 'CONNECT request borrowed a different saved protocol'
        }
        $connect.external.protocol=$protocol
        foreach($flag in @($false,1,'true',$null)){
            $connect.external.ordered_middle_supported=$flag;$rejected=$false
            try{[void](New-RouterVPNOrderedConnectPayload $connectSaved $store)}catch{$rejected=$true}
            Check $rejected 'CONNECT request accepted invalid native capability'
        }
        $connect.external.ordered_middle_supported=$true
        $badRows=@($connectSaved.nodes);$badRows[$middle]=$connectSaved.nodes[$middle-1];$badRows[$middle-1]=$connectSaved.nodes[$middle]
        $swapped=[pscustomobject]@{control_id=$id;profile_tokens=$connectSaved.profile_tokens;nodes=$badRows}
        $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $swapped $store)}catch{$rejected=$true};Check $rejected 'CONNECT middle acquired physical entry authority'
        $wrongFinal=@([pscustomobject]@{id='prefix-0';mode=$packet},[pscustomobject]@{id=$middleID;mode=$protocol},[pscustomobject]@{id=$id;mode='hysteria2'})
        $rejected=$false;try{[void](Copy-RouterVPNOrderedNodes $wrongFinal $id)}catch{$rejected=$true};Check $rejected 'CONNECT middle acquired unsupported final authority'
        $connect.profile_token=('c'*64);$rejected=$false
        try{[void](New-RouterVPNOrderedConnectPayload $connectSaved $store)}catch{$rejected=$true}
        Check $rejected 'CONNECT relinking retained old source authority'
    }}}
    $store.profiles=$originalProfiles
    $rows.Clear();$finalMode.SelectedIndex=0;&$refresh
    $available.SelectedIndex=[array]::IndexOf(@($available.ItemsSource.id),'prefix-0');$prefixMode.SelectedIndex=2;&$add
    Check (($finalMode.ItemsSource.id-join',')-ceq'shadowsocks,hysteria2') 'unlayered paired final choices omitted Hysteria2'
    $finalMode.SelectedIndex=1;&$apply;$hysteriaSaved=$rootControls['UnifiedNodeChainButton'].Tag
    Check ($hysteriaSaved.nodes[-1].mode-ceq'hysteria2'-and$hysteriaSaved.nodes[0].mode-ceq'awg2-strong') 'Apply substituted the explicitly selected Hysteria2 final'
    Check ($rootControls['UnifiedNodeChainSummary'].Text.Contains('Hysteria2')-and$rootControls['UnifiedOrderedModeSummary'].Text.Contains('Hysteria2')) 'summary hid the selected Hysteria2 final'
    $beforeRows=$rows.Count;$available.SelectedIndex=[array]::IndexOf(@($available.ItemsSource.id),'custom-middle');&$add
    Check ($rows.Count-eq$beforeRows) 'imported middle was added to a Hysteria2 final'
    $finalSource=@($store.profiles|Where-Object{[string]$_.id-ceq$id})[0]
    foreach($layer in @('aes-256-gcm','aes-256-gcm+xor-whitening')){
        $finalSource|Add-Member -NotePropertyName start_layer -NotePropertyValue $layer -Force
        Check ((@(Get-RouterVPNOrderedFinalModes $finalSource $rows)-join',')-ceq'shadowsocks,hysteria2') 'Hysteria final layer was not offered'
        $layered=New-RouterVPNOrderedConnectPayload $hysteriaSaved $store
        Check ($layered.nodes[-1].mode-ceq'hysteria2'-and$finalSource.start_layer-ceq$layer) 'Hysteria final layer was replaced'
    }
    foreach($badLayer in @('xor-only','AES-256-GCM','off ',$null,$true,7)){
        $finalSource.start_layer=$badLayer;$rejected=$false
        try{[void](New-RouterVPNOrderedConnectPayload $hysteriaSaved $store)}catch{$rejected=$true}
        Check $rejected 'Hysteria accepted malformed final layer'
    }
    $finalSource.start_layer='off'
    [void](New-RouterVPNOrderedConnectPayload $hysteriaSaved $store)
    foreach($hysteriaCount in @(2,4,8)){foreach($hysteriaChoice in @('server','auto')){
        $hysteriaNodes=@();$hysteriaTokens=@{}
        for($position=0;$position-lt($hysteriaCount-1);$position++){
            $nodeID='prefix-'+$position;$hysteriaNodes+=@([pscustomobject]@{id=$nodeID;mode=@('wg','awg2-fast','awg2-strong')[$position%3]})
            $source=@($store.profiles|Where-Object{[string]$_.id-ceq$nodeID})[0];$hysteriaTokens[$nodeID]=$source.profile_token
        }
        $hysteriaNodes+=@([pscustomobject]@{id=$id;mode='hysteria2'});$hysteriaTokens[$id]=$finalSource.profile_token
        $hysteriaExecution=[pscustomobject]@{control_id=$id;nodes=$hysteriaNodes;profile_tokens=$hysteriaTokens;execution=$hysteriaChoice}
        $hysteriaPayload=New-RouterVPNOrderedConnectPayload $hysteriaExecution $store
        Check (($hysteriaPayload.nodes.mode-join',')-ceq($hysteriaNodes.mode-join',')-and$hysteriaPayload.execution-ceq$hysteriaChoice) 'Hysteria execution changed original ordered request'
        Check ((Get-RouterVPNOrderedExecutionCapability $hysteriaNodes $hysteriaChoice)-ceq'ordered_hysteria_executions') 'Hysteria execution borrowed unrelated global capability'
        Check ((Get-RouterVPNOrderedExecutionCapability $hysteriaNodes 'local')-ceq'ordered_executions') 'Hysteria Local capability changed'
        foreach($hysteriaLayer in @('aes-256-gcm','aes-256-gcm+xor-whitening')){
            $finalSource.start_layer=$hysteriaLayer
            $layered=New-RouterVPNOrderedConnectPayload $hysteriaExecution $store
            Check ($layered.execution-ceq$hysteriaChoice-and$layered.nodes[-1].mode-ceq'hysteria2'-and$finalSource.start_layer-ceq$hysteriaLayer) 'Hysteria execution replaced independent final layer'
        }
        $finalSource.start_layer='off'
    }}
    foreach($badMode in @('HYSTERIA2','hysteria2 ','wg','reality-vision',$null,1)){
        $rejected=$false;try{[void](Copy-RouterVPNOrderedNodes @([pscustomobject]@{id='prefix-0';mode='wg'},[pscustomobject]@{id=$id;mode=$badMode}) $id)}catch{$rejected=$true}
        Check $rejected 'ordered final accepted an alias or unsupported family'
    }
    $mixed=@([pscustomobject]@{id='prefix-0';mode='wg'},[pscustomobject]@{id='custom-middle';mode='shadowsocks'},[pscustomobject]@{id=$id;mode='hysteria2'})
    $rejected=$false;try{[void](Copy-RouterVPNOrderedNodes $mixed $id)}catch{$rejected=$true};Check $rejected 'imported schema two acquired Hysteria2 final authority'
    # Actual Connect builder consumes a capability hint and original token set;
    # native source/lease/proof admission remains the controller's authority.
    foreach($nodeCount in @(3,4,8)){foreach($executionChoice in @('server','auto')){
        $executionNodes=@([pscustomobject]@{id='entry';mode='wg'},[pscustomobject]@{id='middle';mode='shadowsocks'},[pscustomobject]@{id='exit';mode='shadowsocks'})
        $executionProfiles=@([pscustomobject]@{id='entry';node_kind='router-vpn';profile_token=('a'*64)},[pscustomobject]@{id='middle';node_kind='external';profile_token=('b'*64);external=@{protocol='shadowsocks';ordered_middle_supported=$true;ordered_execution_middle_supported=$true}},[pscustomobject]@{id='exit';node_kind='router-vpn';profile_token=('c'*64)})
        $extraNodes=@();$extraProfiles=@();$extraTokens=@{}
        for($i=0;$i-lt$nodeCount-3;$i++){
            $id='prefix-'+$i;$token=('{0:x64}' -f ($i+16))
            $extraNodes+=[pscustomobject]@{id=$id;mode=@('wg','awg2-fast','awg2-strong')[$i%3]}
            $extraProfiles+=[pscustomobject]@{id=$id;node_kind='router-vpn';profile_token=$token};$extraTokens[$id]=$token
        }
        $executionNodes=@($executionNodes[0])+$extraNodes+@($executionNodes[1],$executionNodes[2])
        $executionProfiles=@($executionProfiles[0])+$extraProfiles+@($executionProfiles[1],$executionProfiles[2])
        $executionStore=@{selected_id='exit';profiles=$executionProfiles}
        $executionDraft=@{control_id='exit';nodes=$executionNodes;execution=$executionChoice;profile_tokens=@{entry=('a'*64);middle=('b'*64);exit=('c'*64)}}
        foreach($id in $extraTokens.Keys){$executionDraft.profile_tokens[$id]=$extraTokens[$id]}
        try{$request=New-RouterVPNOrderedConnectPayload $executionDraft $executionStore}catch{Check $false 'complete imported execution prefix refused';throw}
        Check ($request.execution-ceq$executionChoice-and$request.nodes.Count-eq$nodeCount-and$request.nodes[$nodeCount-2].id-ceq'middle') 'literal imported execution changed original trio or purpose'
        foreach($hint in @($false,$null,1,'true')){
            $executionProfiles[$nodeCount-2].external.ordered_execution_middle_supported=$hint
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'imported execution accepted absent or nonboolean native capability'
        }
        $executionProfiles[$nodeCount-2].external.ordered_execution_middle_supported=$true
        $middleHints=$executionProfiles[$nodeCount-2].external
        $middleHints.ordered_execution_middle_supported=$false
        $middleHints.ordered_hostname_execution_middle_supported=$true
        $refused=$false;try{$hostnameRequest=New-RouterVPNOrderedConnectPayload $executionDraft $executionStore}catch{$refused=$true}
        if($nodeCount-eq3){Check $refused 'hostname trio acquired suffix packet authority'}else{
            Check (-not$refused-and$hostnameRequest.nodes.Count-eq$nodeCount-and$hostnameRequest.execution-ceq$executionChoice) 'hostname execution lost complete saved prefix'
            foreach($hint in @($false,$null,1,'true')){
                $middleHints.ordered_hostname_execution_middle_supported=$hint
                $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
                Check $refused 'hostname execution accepted absent or nonboolean capability'
            }
            $middleHints.ordered_hostname_execution_middle_supported=$true
            $middleHints.ordered_execution_middle_supported=$true
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'hostname execution accepted conflicting source capabilities'
        }
        $middleHints.Remove('ordered_hostname_execution_middle_supported')
        $middleHints.ordered_execution_middle_supported=$true
        $executionProfiles[$nodeCount-2].profile_token='d'*64
        $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
        Check $refused 'imported execution borrowed changed original source token'
    }}
    foreach($nodeCount in @(3..8)){foreach($protocolName in @('http-connect','https-connect')){foreach($executionChoice in @('server','auto')){
        $executionNodes=@([pscustomobject]@{id='entry';mode='wg'},[pscustomobject]@{id='middle';mode=$protocolName},[pscustomobject]@{id='exit';mode='shadowsocks'})
        $executionProfiles=@([pscustomobject]@{id='entry';node_kind='router-vpn';profile_token=('a'*64)},[pscustomobject]@{id='middle';node_kind='external';profile_token=('b'*64);external=@{protocol=$protocolName;ordered_middle_supported=$true;ordered_connect_execution_middle_supported=$true}},[pscustomobject]@{id='exit';node_kind='router-vpn';profile_token=('c'*64);start_layer='off'})
        $executionTokens=@{entry=('a'*64);middle=('b'*64);exit=('c'*64)}
        for($i=0;$i-lt$nodeCount-3;$i++){
            $prefixID='connect-prefix-'+$i
            $executionNodes=@([pscustomobject]@{id=$prefixID;mode=@('wg','awg2-fast','awg2-strong')[$i%3]})+$executionNodes
            $executionProfiles=@([pscustomobject]@{id=$prefixID;node_kind='router-vpn';profile_token=('d'*64);start_layer=@('off','aes-256-gcm','aes-256-gcm+xor-whitening')[$i%3]})+$executionProfiles
            $executionTokens[$prefixID]='d'*64
        }
        $executionStore=@{selected_id='exit';profiles=$executionProfiles}
        $executionDraft=@{control_id='exit';nodes=$executionNodes;execution=$executionChoice;profile_tokens=$executionTokens}
        $request=New-RouterVPNOrderedConnectPayload $executionDraft $executionStore
        Check ($request.execution-ceq$executionChoice-and$request.nodes[$nodeCount-2].mode-ceq$protocolName) 'CONNECT execution lost original complete typed path'
        Check ($request.nodes.Count-eq$nodeCount-and$request.expected_profile_tokens.Count-eq$nodeCount) 'CONNECT execution dropped an original member or source token'
        Check ((Get-RouterVPNOrderedExecutionCapability $executionNodes $executionChoice)-ceq'ordered_connect_trio_executions') 'CONNECT execution borrowed unrelated global capability'
        Check ((Get-RouterVPNOrderedExecutionCapability $executionNodes 'local')-ceq'ordered_executions') 'CONNECT Local capability changed'
        foreach($hint in @($false,$null,1,'true')){
            $executionProfiles[$nodeCount-2].external.ordered_connect_execution_middle_supported=$hint
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'CONNECT execution accepted unrelated native hint'
        }
        $executionProfiles[$nodeCount-2].external.ordered_connect_execution_middle_supported=$true
        for($position=0;$position-lt$nodeCount-2;$position++){
            $capturedLayer=Get-RouterVPNOrderedValue $executionProfiles[$position] 'start_layer' ''
            foreach($badLayer in @('aes-256-gcm ',$true)){
                $executionProfiles[$position]|Add-Member -NotePropertyName start_layer -NotePropertyValue $badLayer -Force
                $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
                Check $refused 'CONNECT execution admitted a malformed paired prefix layer'
            }
            $executionProfiles[$position].start_layer=$capturedLayer
        }
        foreach($finalLayer in @('aes-256-gcm','aes-256-gcm+xor-whitening')){
            $executionProfiles[$nodeCount-1].start_layer=$finalLayer
            $accepted=$true;$layeredRequest=$null
            try{$layeredRequest=New-RouterVPNOrderedConnectPayload $executionDraft $executionStore}catch{$accepted=$false}
            Check ($accepted-and$null-ne$layeredRequest) 'CONNECT execution refused captured final layer'
            Check ($layeredRequest.nodes.Count-eq$nodeCount-and$layeredRequest.execution-ceq$executionChoice-and$executionProfiles[$nodeCount-1].start_layer-ceq$finalLayer) 'CONNECT execution replaced original final layer'
        }
        foreach($badFinalLayer in @('xor-only','AES-256-GCM','aes-256-gcm ',$true)){
            $executionProfiles[$nodeCount-1].start_layer=$badFinalLayer
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'CONNECT execution admitted malformed final layer'
        }
        $executionProfiles[$nodeCount-1].start_layer='off'
    }}}
    }
    if($Group -in @('all','socks')) {
    foreach($socksCount in 3..8){foreach($prefixMode in @('wg','awg2-fast','awg2-strong')){foreach($executionChoice in @('server','auto')){foreach($entryLayer in @('off','aes-256-gcm','aes-256-gcm+xor-whitening')){
        $socksMiddle=$socksCount-2;$socksFinal=$socksCount-1
        $executionNodes=@();$executionProfiles=@();$executionTokens=@{}
        foreach($position in 0..($socksCount-1)){
            $nodeID=if($position-eq$socksMiddle){'middle'}elseif($position-eq$socksFinal){'exit'}elseif($position-eq0){'entry'}else{'paired-'+$position}
            $nodeMode=if($position-eq$socksMiddle){'socks5'}elseif($position-eq$socksFinal){'shadowsocks'}else{$prefixMode}
            $token=('{0:x64}' -f ($position+1));$executionTokens[$nodeID]=$token
            $source=[pscustomobject]@{id=$nodeID;node_kind='router-vpn';profile_token=$token;start_layer=$(if($position-lt$socksMiddle){$entryLayer}else{'off'})}
            if($position-eq$socksMiddle){$source.node_kind='external';$source|Add-Member -NotePropertyName external -NotePropertyValue @{protocol='socks5';ordered_middle_supported=$true;ordered_socks_execution_middle_supported=$true;password='private-socks-secret'}}
            $executionNodes+=[pscustomobject]@{id=$nodeID;mode=$nodeMode};$executionProfiles+=$source
        }
        $executionStore=@{selected_id='exit';profiles=$executionProfiles}
        $executionDraft=@{control_id='exit';nodes=$executionNodes;execution=$executionChoice;profile_tokens=$executionTokens}
        $request=New-RouterVPNOrderedConnectPayload $executionDraft $executionStore
        Check ($request.execution-ceq$executionChoice-and$request.nodes.Count-eq$socksCount-and$request.nodes[0].mode-ceq$prefixMode-and$request.nodes[$socksMiddle].mode-ceq'socks5') 'SOCKS execution lost original typed trio'
        Check ((Get-RouterVPNOrderedExecutionCapability $executionNodes $executionChoice)-ceq'ordered_socks_trio_executions') 'SOCKS execution borrowed unrelated global capability'
        Check ((Get-RouterVPNOrderedExecutionCapability $executionNodes 'local')-ceq'ordered_executions') 'SOCKS Local capability changed'
        $encoded=$request|ConvertTo-Json -Depth 30 -Compress
        Check (-not$encoded.Contains('private-socks-secret')-and$request.expected_profile_tokens.Count-eq$socksCount) 'SOCKS execution copied credentials or lost original source inventory'
        foreach($hint in @($false,$null,1,'true')){
            $executionProfiles[$socksMiddle].external.ordered_socks_execution_middle_supported=$hint
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'SOCKS execution accepted absent or nonboolean native hint'
        }
        $executionProfiles[$socksMiddle].external.Remove('ordered_socks_execution_middle_supported')
        $executionProfiles[$socksMiddle].external.ordered_execution_middle_supported=$true
        $executionProfiles[$socksMiddle].external.ordered_connect_execution_middle_supported=$true
        $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
        Check $refused 'SOCKS execution accepted absent or nonboolean native hint'
        $executionProfiles[$socksMiddle].external.ordered_socks_execution_middle_supported=$true
        foreach($badLayer in @('AES-256-GCM','aes-256-gcm ',$true,7)){
            $executionProfiles[0].start_layer=$badLayer
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'SOCKS execution accepted malformed entry layer'
        }
        $executionProfiles[0].start_layer=$entryLayer
        if($socksMiddle-gt1){foreach($prefixPosition in 1..($socksMiddle-1)){
            $executionProfiles[$prefixPosition].start_layer='unsupported'
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'SOCKS execution admitted malformed later prefix layer'
            $executionProfiles[$prefixPosition].start_layer=$entryLayer
        }}
        foreach($position in @($socksMiddle,$socksFinal)){$badLayers=if($position-eq$socksMiddle){@('aes-256-gcm','aes-256-gcm+xor-whitening',$true,7)}else{@('AES-256-GCM','aes-256-gcm ',$true,7)};foreach($badLayer in $badLayers){
            $executionProfiles[$position].start_layer=$badLayer
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'SOCKS execution admitted layered middle or final'
        };$executionProfiles[$position].start_layer='off'}
        foreach($position in 0..($socksCount-1)){
            $originalToken=$executionProfiles[$position].profile_token;$executionProfiles[$position].profile_token='f'*64
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'SOCKS execution borrowed a relinked original member'
            $executionProfiles[$position].profile_token=$originalToken
        }
        $longNodes=@([pscustomobject]@{id='prefix-extra';mode='wg'})+$executionNodes
        $longProfiles=@([pscustomobject]@{id='prefix-extra';node_kind='router-vpn';profile_token=('d'*64)})+$executionProfiles
        $longTokens=$executionTokens.Clone();$longTokens['prefix-extra']='d'*64
        $longDraft=@{control_id='exit';nodes=$longNodes;execution=$executionChoice;profile_tokens=$longTokens}
        $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $longDraft @{selected_id='exit';profiles=$longProfiles})}catch{$refused=$true}
        if($socksCount-eq8){Check $refused 'SOCKS execution escaped maximum path length'}else{Check (-not$refused) 'SOCKS execution refused a complete later prefix'}
        Check ($executionProfiles[0].start_layer-ceq$entryLayer-and$executionProfiles[$socksMiddle].start_layer-ceq'off'-and$executionProfiles[$socksFinal].start_layer-ceq'off') 'SOCKS execution changed captured Start Layers'
        foreach($finalLayer in @('aes-256-gcm','aes-256-gcm+xor-whitening')){
            $executionProfiles[$socksFinal].start_layer=$finalLayer
            try{$layeredRequest=New-RouterVPNOrderedConnectPayload $executionDraft $executionStore}catch{Check $false 'SOCKS execution refused captured final layer'}
            Check ($layeredRequest.nodes.Count-eq$socksCount-and$layeredRequest.execution-ceq$executionChoice-and$layeredRequest.expected_profile_tokens.Count-eq$socksCount) 'SOCKS layered execution changed source or choice'
            Check ($executionProfiles[0].start_layer-ceq$entryLayer-and$executionProfiles[$socksFinal].start_layer-ceq$finalLayer) 'SOCKS layered execution replaced captured policy'
        };$executionProfiles[$socksFinal].start_layer='off'

    }}}}
    }
    if($Group -in @('all','openvpn')) {
    foreach($openvpnCount in 3..8){foreach($prefixMode in @('wg','awg2-fast','awg2-strong')){foreach($executionChoice in @('server','auto')){foreach($entryLayer in @('off','aes-256-gcm','aes-256-gcm+xor-whitening')){
        $openvpnMiddle=$openvpnCount-2;$openvpnFinal=$openvpnCount-1
        $executionNodes=@();$executionProfiles=@();$executionTokens=@{}
        foreach($position in 0..($openvpnCount-1)){
            $nodeID=if($position-eq$openvpnMiddle){'middle'}elseif($position-eq$openvpnFinal){'exit'}elseif($position-eq0){'entry'}else{'paired-'+$position}
            $nodeMode=if($position-eq$openvpnMiddle){'openvpn'}elseif($position-eq$openvpnFinal){'shadowsocks'}else{$prefixMode}
            $token=('{0:x64}' -f ($position+1));$executionTokens[$nodeID]=$token
            $source=[pscustomobject]@{id=$nodeID;node_kind='router-vpn';profile_token=$token;start_layer=$(if($position-lt$openvpnMiddle){$entryLayer}else{'off'})}
            if($position-eq$openvpnMiddle){$source.node_kind='external';$source|Add-Member -NotePropertyName external -NotePropertyValue @{protocol='openvpn';ordered_middle_supported=$true;ordered_openvpn_execution_middle_supported=$true;private_pairing='private-openvpn-secret'}}
            $executionNodes+=[pscustomobject]@{id=$nodeID;mode=$nodeMode};$executionProfiles+=$source
        }
        $executionStore=@{selected_id='exit';profiles=$executionProfiles}
        $executionDraft=@{control_id='exit';nodes=$executionNodes;execution=$executionChoice;profile_tokens=$executionTokens}
        $request=New-RouterVPNOrderedConnectPayload $executionDraft $executionStore
        Check ($request.execution-ceq$executionChoice-and$request.nodes.Count-eq$openvpnCount-and$request.nodes[0].mode-ceq$prefixMode-and$request.nodes[$openvpnMiddle].mode-ceq'openvpn') 'OpenVPN execution lost original typed trio'
        Check ((Get-RouterVPNOrderedExecutionCapability $executionNodes $executionChoice)-ceq'ordered_openvpn_executions') 'OpenVPN execution borrowed unrelated global capability'
        Check ((Get-RouterVPNOrderedExecutionCapability $executionNodes 'local')-ceq'ordered_executions') 'OpenVPN Local capability changed'
        $encoded=$request|ConvertTo-Json -Depth 30 -Compress
        Check (-not$encoded.Contains('private-openvpn-secret')-and$request.expected_profile_tokens.Count-eq$openvpnCount) 'OpenVPN execution copied credentials or lost original source inventory'
        foreach($hint in @($false,$null,1,'true')){
            $executionProfiles[$openvpnMiddle].external.ordered_openvpn_execution_middle_supported=$hint
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'OpenVPN execution accepted absent or nonboolean native hint'
        }
        $executionProfiles[$openvpnMiddle].external.Remove('ordered_openvpn_execution_middle_supported')
        $executionProfiles[$openvpnMiddle].external.ordered_execution_middle_supported=$true
        $executionProfiles[$openvpnMiddle].external.ordered_connect_execution_middle_supported=$true
        $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
        Check $refused 'OpenVPN execution accepted absent or nonboolean native hint'
        $executionProfiles[$openvpnMiddle].external.ordered_openvpn_execution_middle_supported=$true
        foreach($badLayer in @('AES-256-GCM','aes-256-gcm ',$true,7)){
            $executionProfiles[0].start_layer=$badLayer
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'OpenVPN execution accepted malformed entry layer'
        }
        $executionProfiles[0].start_layer=$entryLayer
        if($openvpnMiddle-gt1){foreach($prefixPosition in 1..($openvpnMiddle-1)){
            $executionProfiles[$prefixPosition].start_layer='unsupported'
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'OpenVPN execution admitted malformed later prefix layer'
            $executionProfiles[$prefixPosition].start_layer=$entryLayer
        }}
        foreach($position in @($openvpnMiddle,$openvpnFinal)){$badLayers=if($position-eq$openvpnMiddle){@('aes-256-gcm','aes-256-gcm+xor-whitening',$true,7)}else{@('AES-256-GCM','aes-256-gcm ',$true,7)};foreach($badLayer in $badLayers){
            $executionProfiles[$position].start_layer=$badLayer
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'OpenVPN execution admitted layered middle or final'
        };$executionProfiles[$position].start_layer='off'}
        foreach($position in 0..($openvpnCount-1)){
            $originalToken=$executionProfiles[$position].profile_token;$executionProfiles[$position].profile_token='f'*64
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'OpenVPN execution borrowed a relinked original member'
            $executionProfiles[$position].profile_token=$originalToken
        }
        $longNodes=@([pscustomobject]@{id='prefix-extra';mode='wg'})+$executionNodes
        $longProfiles=@([pscustomobject]@{id='prefix-extra';node_kind='router-vpn';profile_token=('d'*64)})+$executionProfiles
        $longTokens=$executionTokens.Clone();$longTokens['prefix-extra']='d'*64
        $longDraft=@{control_id='exit';nodes=$longNodes;execution=$executionChoice;profile_tokens=$longTokens}
        $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $longDraft @{selected_id='exit';profiles=$longProfiles})}catch{$refused=$true}
        if($openvpnCount-eq8){Check $refused 'OpenVPN execution escaped maximum path length'}else{Check (-not$refused) 'OpenVPN execution refused a complete later prefix'}
        Check ($executionProfiles[0].start_layer-ceq$entryLayer-and$executionProfiles[$openvpnMiddle].start_layer-ceq'off'-and$executionProfiles[$openvpnFinal].start_layer-ceq'off') 'OpenVPN execution changed captured Start Layers'
        foreach($finalLayer in @('aes-256-gcm','aes-256-gcm+xor-whitening')){
            $executionProfiles[$openvpnFinal].start_layer=$finalLayer
            try{$layeredRequest=New-RouterVPNOrderedConnectPayload $executionDraft $executionStore}catch{Check $false 'OpenVPN execution refused captured final layer'}
            Check ($layeredRequest.nodes.Count-eq$openvpnCount-and$layeredRequest.execution-ceq$executionChoice-and$layeredRequest.expected_profile_tokens.Count-eq$openvpnCount) 'OpenVPN layered execution changed source or choice'
            Check ($executionProfiles[0].start_layer-ceq$entryLayer-and$executionProfiles[$openvpnFinal].start_layer-ceq$finalLayer) 'OpenVPN layered execution replaced captured policy'
        };$executionProfiles[$openvpnFinal].start_layer='off'

    }}}}
    }
    if(-not$NegativeControl-and-not$PositiveOnly){
        foreach($key in $controls.Keys){
            $command="try { & '"+$PSCommandPath.Replace("'","''")+"' -Root '"+$Root.Replace("'","''")+"' -NegativeControl '"+$key+"' } catch { [Console]::Error.WriteLine(`$_.Exception.Message); exit 1 }"
            $child=New-Object Diagnostics.Process
            try{
                $child.StartInfo.FileName=(Get-Process -Id $PID).Path
                $child.StartInfo.Arguments='-NoProfile -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
                $child.StartInfo.UseShellExecute=$false;$child.StartInfo.CreateNoWindow=$true
                $child.StartInfo.RedirectStandardOutput=$true;$child.StartInfo.RedirectStandardError=$true
                [void]$child.Start();$stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
                if(-not$child.WaitForExit(45000)){$child.Kill();throw ('Causal editor child exceeded its bound: '+$key)}
                $output=$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()
                Check ($child.ExitCode-eq1-and$output.Contains($controls[$key])) ('causal control missed its exact defect: '+$key)
                Write-Output ('Actual ordered editor causal control '+$key+': rejected')
            }finally{$child.Dispose()}
        }
    }
    Write-Output ("Actual ordered node editor callbacks ($Group): $script:Checks checks PASS; WPF=$WPF")
}finally{if($WPF-and$dialog.IsVisible){$dialog.Close()}}
