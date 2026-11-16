param([string]$Root=(Split-Path $PSScriptRoot -Parent),[switch]$WPF,[string]$NegativeControl='',[switch]$PositiveOnly)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
$controls=@{'connect-execution-prefix-layer'='CONNECT execution admitted a malformed paired prefix layer';'hostname-minimum'='hostname trio acquired suffix packet authority';'hostname-conflict'='hostname execution accepted conflicting source capabilities';'hostname-capability'='hostname execution lost complete saved prefix';'imported-execution-prefix'='complete imported execution prefix refused';'connect-execution-global'='CONNECT execution borrowed unrelated global capability';'connect-execution-final'='CONNECT execution admitted layered final';'imported-execution-capability'='imported execution accepted absent or nonboolean native capability';'connect-protocol'='CONNECT request borrowed a different saved protocol';'connect-mode'='CONNECT Add substituted its exact saved transport';'socks-mode'='SOCKS Add substituted its saved transport';'final-mode'='Apply substituted the explicitly selected Hysteria2 final';'raw-mode'='raw ordered mode whitelist admitted an alias or unsupported transport';'add-mode'='Add changed the selected node or transport';'change-mode'='Change mode replaced its original node or ignored selected transport';'row-label'='editor row mislabeled its captured transport';'source-token'='relinked middle node replaced the original editor draft';'summary-reset'='new incomplete ordered selection displayed a previous path transport summary';'socks-execution-global'='SOCKS execution borrowed unrelated global capability';'socks-execution-capability'='SOCKS execution accepted absent or nonboolean native hint';'socks-execution-entry-layer'='SOCKS execution accepted malformed entry layer';'socks-execution-layer'='SOCKS execution admitted layered middle or final'}
if($NegativeControl-and$controls.Keys-cnotcontains$NegativeControl){throw 'Unknown ordered editor causal control.'}
if($PositiveOnly-and$NegativeControl){throw 'Positive editor phase cannot select a causal control.'}
$Client=Join-Path $Root 'client'
Import-Module (Join-Path $Client 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
$Settings=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-ProfileSettings.ps1'),[Text.Encoding]::UTF8)
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
if($NegativeControl-ceq'source-token'){$Settings=$Settings.Replace("-or[string](Get-RouterVPNOrderedValue `$matchingProfiles[0] 'profile_token')-cne`$token",'')}
if($NegativeControl-ceq'connect-protocol'){
    $before='$node.mode-cne(Get-RouterVPNOrderedImportedMode $matchingProfiles[0])'
    if(([regex]::Matches($Settings,[regex]::Escape($before))).Count-ne1){throw 'Shipping CONNECT protocol guard changed.'}
    $Settings=$Settings.Replace($before,'($node.mode-cne(Get-RouterVPNOrderedImportedMode $matchingProfiles[0])-and$node.mode-cnotin@(''http-connect'',''https-connect''))')
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
    $anchor="-or[string](Get-RouterVPNOrderedValue `$finals[0] 'start_layer' '')-cnotin@('','off')"
    if(([regex]::Matches($Settings,[regex]::Escape($anchor))).Count-ne1){throw 'CONNECT execution layer guard changed.'}
    $Settings=$Settings.Replace($anchor,'')
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
. ([ScriptBlock]::Create($Settings))
$Unified=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-UnifiedShell.ps1'),[Text.Encoding]::UTF8)
if($NegativeControl-ceq'summary-reset'){$Unified=$Unified.Replace("`$description.Text='Choose each intermediate transport and the final node.'",'')}
. ([ScriptBlock]::Create($Unified))
$ProductSource=Add-RouterVPNUnifiedWindowsShell ([IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-Product-v2.ps1'),[Text.Encoding]::UTF8))
$script:Checks=0
function Check([bool]$Value,[string]$Message){if(-not$Value){throw ('ORDERED-EDITOR: '+$Message)};$script:Checks++}
function ShippingFunction([string]$Name){
    $found=@(([ScriptBlock]::Create($ProductSource)).Ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$Name},$true))
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
foreach($name in @('$refresh','$move')){
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
    $script:CurrentStore=$store;&$apply
    $saved=$rootControls['UnifiedNodeChainButton'].Tag
    Check ($saved.control_id-ceq$id-and$saved.nodes.Count-eq7-and$saved.nodes[-1].id-ceq$id-and$saved.nodes[-1].mode-ceq'shadowsocks') 'Apply lost the fixed selected final or full prefix list'
    Check (($saved.nodes.id-join',')-ceq'prefix-0,prefix-1,prefix-3,prefix-4,prefix-5,prefix-6,selected-final') 'Apply reordered the visible path'
    Check (($saved.nodes.mode-join',')-ceq'awg2-strong,awg2-fast,wg,awg2-fast,awg2-strong,wg,shadowsocks') 'Apply replaced the original per-position transports'
    Check ($rootControls['UnifiedOrdered'].IsChecked-and$rootControls['UnifiedMultihop'].IsChecked) 'Apply did not choose the complete ordered path'
    Check (($saved|ConvertTo-Json -Depth 8)-notmatch'must-not-copy') 'editor copied private node credentials'
    Check ($saved.profile_tokens.Count-eq7-and$saved.profile_tokens['prefix-1']-ceq$store.profiles[1].profile_token) 'editor lost all-source public preconditions'
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
    foreach($protocol in @('http-connect','https-connect','openvpn','socks5','shadowsocks')){foreach($packet in @('wg','awg2-fast','awg2-strong')){
        foreach($count in @(3..8)){
        $middle=$count-2
        $rows.Clear();$finalMode.SelectedIndex=0
        $middleID='connect-'+$protocol+'-'+$packet+'-'+$count
        $connect=[pscustomobject]@{id=$middleID;name=('Original '+$protocol);node_kind='external';profile_token=('b'*64);external=[pscustomobject]@{protocol=$protocol;ordered_middle_supported=$true}}
        $store.profiles+=$connect;$script:CurrentStore=$store;&$refresh
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
        $rejected=$false;try{[void](New-RouterVPNOrderedConnectPayload $hysteriaSaved $store)}catch{$rejected=$true}
        Check $rejected 'layered Hysteria2 final gained ordered admission'
        Check ((@(Get-RouterVPNOrderedFinalModes $finalSource $rows)-join',')-ceq'shadowsocks') 'final picker offered unimplemented Hysteria2 layers'
    }
    $finalSource.start_layer='off'
    [void](New-RouterVPNOrderedConnectPayload $hysteriaSaved $store)
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
        $executionProfiles[$nodeCount-1].start_layer='aes-256-gcm'
        $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
        Check $refused 'CONNECT execution admitted layered final'
    }}}
    foreach($prefixMode in @('wg','awg2-fast','awg2-strong')){foreach($executionChoice in @('server','auto')){foreach($entryLayer in @('off','aes-256-gcm','aes-256-gcm+xor-whitening')){
        $executionNodes=@([pscustomobject]@{id='entry';mode=$prefixMode},[pscustomobject]@{id='middle';mode='socks5'},[pscustomobject]@{id='exit';mode='shadowsocks'})
        $executionProfiles=@([pscustomobject]@{id='entry';node_kind='router-vpn';profile_token=('a'*64);start_layer=$entryLayer},[pscustomobject]@{id='middle';node_kind='external';profile_token=('b'*64);start_layer='off';external=@{protocol='socks5';ordered_middle_supported=$true;ordered_socks_execution_middle_supported=$true;password='private-socks-secret'}},[pscustomobject]@{id='exit';node_kind='router-vpn';profile_token=('c'*64);start_layer='off'})
        $executionStore=@{selected_id='exit';profiles=$executionProfiles}
        $executionDraft=@{control_id='exit';nodes=$executionNodes;execution=$executionChoice;profile_tokens=@{entry=('a'*64);middle=('b'*64);exit=('c'*64)}}
        $request=New-RouterVPNOrderedConnectPayload $executionDraft $executionStore
        Check ($request.execution-ceq$executionChoice-and$request.nodes.Count-eq3-and$request.nodes[0].mode-ceq$prefixMode-and$request.nodes[1].mode-ceq'socks5') 'SOCKS execution lost original typed trio'
        Check ((Get-RouterVPNOrderedExecutionCapability $executionNodes $executionChoice)-ceq'ordered_socks_trio_executions') 'SOCKS execution borrowed unrelated global capability'
        Check ((Get-RouterVPNOrderedExecutionCapability $executionNodes 'local')-ceq'ordered_executions') 'SOCKS Local capability changed'
        $encoded=$request|ConvertTo-Json -Depth 30 -Compress
        Check (-not$encoded.Contains('private-socks-secret')-and$request.expected_profile_tokens.Count-eq3) 'SOCKS execution copied credentials or lost original source inventory'
        foreach($hint in @($false,$null,1,'true')){
            $executionProfiles[1].external.ordered_socks_execution_middle_supported=$hint
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'SOCKS execution accepted absent or nonboolean native hint'
        }
        $executionProfiles[1].external.Remove('ordered_socks_execution_middle_supported')
        $executionProfiles[1].external.ordered_execution_middle_supported=$true
        $executionProfiles[1].external.ordered_connect_execution_middle_supported=$true
        $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
        Check $refused 'SOCKS execution accepted absent or nonboolean native hint'
        $executionProfiles[1].external.ordered_socks_execution_middle_supported=$true
        foreach($badLayer in @('AES-256-GCM','aes-256-gcm ',$true,7)){
            $executionProfiles[0].start_layer=$badLayer
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'SOCKS execution accepted malformed entry layer'
        }
        $executionProfiles[0].start_layer=$entryLayer
        foreach($position in @(1,2)){foreach($badLayer in @('aes-256-gcm','aes-256-gcm+xor-whitening',$true,7)){
            $executionProfiles[$position].start_layer=$badLayer
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'SOCKS execution admitted layered middle or final'
        };$executionProfiles[$position].start_layer='off'}
        foreach($position in @(0,1,2)){
            $originalToken=$executionProfiles[$position].profile_token;$executionProfiles[$position].profile_token='f'*64
            $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $executionDraft $executionStore)}catch{$refused=$true}
            Check $refused 'SOCKS execution borrowed a relinked original member'
            $executionProfiles[$position].profile_token=$originalToken
        }
        $longNodes=@([pscustomobject]@{id='prefix-extra';mode='wg'})+$executionNodes
        $longProfiles=@([pscustomobject]@{id='prefix-extra';node_kind='router-vpn';profile_token=('d'*64)})+$executionProfiles
        $longDraft=@{control_id='exit';nodes=$longNodes;execution=$executionChoice;profile_tokens=@{entry=('a'*64);middle=('b'*64);exit=('c'*64);'prefix-extra'=('d'*64)}}
        $refused=$false;try{[void](New-RouterVPNOrderedConnectPayload $longDraft @{selected_id='exit';profiles=$longProfiles})}catch{$refused=$true}
        Check $refused 'SOCKS execution escaped exact native trio'
        Check ($executionProfiles[0].start_layer-ceq$entryLayer-and$executionProfiles[1].start_layer-ceq'off'-and$executionProfiles[2].start_layer-ceq'off') 'SOCKS execution changed captured Start Layers'
    }}}
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
    Write-Output ("Actual ordered node editor callbacks: $script:Checks checks PASS; WPF=$WPF")
}finally{if($WPF-and$dialog.IsVisible){$dialog.Close()}}
