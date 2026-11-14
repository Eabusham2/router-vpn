param(
    [string]$Root = (Split-Path $PSScriptRoot -Parent),
    [ValidateSet('shipping','capture-two-modes','load-fallback','connect-fallback','entry-capture-fallback','entry-load-fallback','entry-connect-fallback','startup-deadline','ordered-drop-middle','ordered-final-owner','ordered-capability','ordered-source','ordered-locked-source','setup-expectation','setup-current-receipt','setup-response-source','setup-response-order','setup-load-inventory','setup-refresh-retirement','setup-uncertain-owner')][string]$Mutation = 'shipping'
)
$ErrorActionPreference='Stop'
# The real launcher composes these sources before opening WPF. Exercise that
# composition, its actual Settings callbacks, and its actual selection helpers.
# Only widget properties, the local HTTP boundary, and the state directory are
# doubled. This test neither starts a VPN nor claims to render WPF.
$Client=Join-Path $Root 'client'
Import-Module (Join-Path $Client 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
$Launcher=Get-Content -LiteralPath (Join-Path $Client 'RouterVPN-Windows-App.ps1') -Raw -Encoding UTF8
$FixtureStateRoot=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-profile-modes-'+[Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $FixtureStateRoot)
$script:Count=0
function Check([bool]$Value,[string]$Message){$script:Count++;if(-not$Value){throw ('PROFILE-CHECK: '+$Message)}}
function ShippingFunction([string]$Source,[string]$Name){
    $Found=@(([ScriptBlock]::Create($Source)).Ast.FindAll({param($Node)$Node-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$Node.Name-ceq$Name},$true))
    if($Found.Count-ne1){throw ('Shipping function count drifted: '+$Name)}
    return $Found[0].Extent.Text
}
function ShippingCallback([string]$Source,[string]$Control){
    $Found=@(([ScriptBlock]::Create($Source)).Ast.FindAll({param($Node)$Node-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$Node.Member.Extent.Text-ceq'Add_Click'-and$Node.Expression.Extent.Text-ceq$Control},$true))
    if($Found.Count-ne1-or$Found[0].Arguments.Count-ne1-or$Found[0].Arguments[0]-isnot[System.Management.Automation.Language.ScriptBlockExpressionAst]){throw ('Shipping callback count drifted: '+$Control)}
    $Text=$Found[0].Arguments[0].ScriptBlock.Extent.Text
    return [ScriptBlock]::Create($Text.Substring(1,$Text.Length-2))
}
function ReplaceOnce([string]$Source,[string]$Old,[string]$New){
    if(($Source.Length-$Source.Replace($Old,'').Length)/$Old.Length-ne1){throw ('Mutation seam drifted: '+$Old)}
    return $Source.Replace($Old,$New)
}
try{
    $LoadStart=$Launcher.IndexOf('$ProfileSettingsHelpers=')
    $LoadEnd=$Launcher.IndexOf('# The shipping Windows product',$LoadStart)
    $ComposeStart=$Launcher.IndexOf('$Product=Join-Path')
    $ComposeEnd=$Launcher.IndexOf('$ProductScript=[ScriptBlock]::Create($ProductSource)',$ComposeStart)
    if($LoadStart-lt0-or$LoadEnd-le$LoadStart-or$ComposeStart-lt0-or$ComposeEnd-le$ComposeStart){throw 'Launcher composition seams changed'}
    . ([ScriptBlock]::Create($Launcher.Substring($LoadStart,$LoadEnd-$LoadStart).Replace('$PSScriptRoot','$Client')))
    . ([ScriptBlock]::Create((ShippingFunction $Launcher 'Set-RouterVPNProductHelpBinding')))
    . ([ScriptBlock]::Create($Launcher.Substring($ComposeStart,$ComposeEnd-$ComposeStart).Replace('$PSScriptRoot','$Client')))
    [void][ScriptBlock]::Create($ProductSource)

    $Helpers=''
    foreach($Name in @('global:Get-RouterVPNCurrentModeSnapshot','global:Set-RouterVPNLoadedModeSnapshot','global:Get-RouterVPNSetupGraphIDs','global:Get-RouterVPNSetupViewKey','global:Get-RouterVPNSetupCapture','global:Confirm-RouterVPNSetupResponse','global:Invoke-RouterVPNConnectionSetup','global:Get-RouterVPNVisibleConnectionSnapshot','global:Apply-RouterVPNLoadedConnectionSnapshot','global:Get-RouterVPNOrderedValue','global:Test-RouterVPNOrderedPrefixMode','global:Copy-RouterVPNOrderedNodes','global:New-RouterVPNOrderedConnectPayload','global:Get-RouterVPNOrderedConnectionSnapshot','global:Set-RouterVPNLoadedOrderedSnapshot')){
        # Type and storage boundaries only; all selection and payload logic is
        # taken unchanged from the functions loaded by the shipping launcher.
        $Helpers+=(ShippingFunction $ProfileSettingsSource $Name).Replace('[System.Windows.Window]','[object]').Replace('$PSScriptRoot','$FixtureStateRoot')+"`n"
    }
    $Connect=(ShippingFunction $ProductSource 'UnifiedConnect')
    $Choice=(ShippingFunction $ProductSource 'MultihopExitModeChoice')+"`n"+(ShippingFunction $ProductSource 'MultihopEntryModeChoice')+"`n"+(ShippingFunction $ProductSource 'UnifiedMultihopStartupTimeout')
    switch($Mutation){
        'capture-two-modes'{$Helpers=ReplaceOnce $Helpers '$result.multihop_exit_mode=[string]$exitMode.SelectedItem.Tag' '$result.multihop_exit_mode=if($exitMode.SelectedIndex-eq1){''hysteria2''}else{''shadowsocks''}'}
        'load-fallback'{$Helpers=ReplaceOnce $Helpers '$exitMode.SelectedIndex=-1' '$exitMode.SelectedIndex=0'}
        'connect-fallback'{$Choice=ReplaceOnce $Choice "throw 'Select a supported exit transport.'" "return 'shadowsocks'"}
        'entry-capture-fallback'{$Helpers=ReplaceOnce $Helpers '$result.multihop_entry_mode=[string]$entryMode.SelectedItem.Tag' '$result.multihop_entry_mode="wg"'}
        'entry-load-fallback'{$Helpers=ReplaceOnce $Helpers '$entryMode.SelectedIndex=-1' '$entryMode.SelectedIndex=0'}
        'entry-connect-fallback'{$Connect=ReplaceOnce $Connect 'entry_mode=(MultihopEntryModeChoice)' 'entry_mode="wg"'}
        'startup-deadline'{$Connect=ReplaceOnce $Connect '$Timeout=UnifiedMultihopStartupTimeout $Body' '$Timeout=200'}
        'ordered-drop-middle'{$Helpers=ReplaceOnce $Helpers 'return $copy.ToArray()' 'return @($copy[0],$copy[$copy.Count-1])'}
        'ordered-final-owner'{$Helpers=ReplaceOnce $Helpers '$copy[$copy.Count-1].id-cne$ControlID' '$false'}
        'ordered-capability'{$Connect=ReplaceOnce $Connect '$Supported-isnot[bool]-or-not$Supported' '$false'}
        'ordered-source'{$Helpers=ReplaceOnce $Helpers "-or[string](Get-RouterVPNOrderedValue `$matchingProfiles[0] 'profile_token')-cne`$token" '-or$false'}
        'ordered-locked-source'{$Helpers=ReplaceOnce $Helpers 'expected_profile_tokens=$tokens' 'expected_profile_tokens=@{}'}
        'setup-expectation'{$Helpers=ReplaceOnce $Helpers '$request.expected_profile_tokens=$capture.Tokens' '$request.expected_profile_tokens=@{}'}
        'setup-current-receipt'{$Helpers=ReplaceOnce $Helpers '-or(Get-RouterVPNSetupViewKey $Owner)-cne$Capture.ViewKey' '-or$false'}
        'setup-response-source'{$Helpers=ReplaceOnce $Helpers 'if(-not$Capture.Loading-and$token-cne$Capture.Tokens[$id])' 'if($false)'}
        'setup-response-order'{$Helpers=ReplaceOnce $Helpers "if(`$null-eq`$nodes-or`$null-eq`$expectedNodes-or@(`$nodes).Count-ne@(`$expectedNodes).Count-or(@(`$nodes.id)-join',')-cne(@(`$expectedNodes.id)-join',')-or(@(`$nodes.mode)-join',')-cne(@(`$expectedNodes.mode)-join','))" 'if($false)'}
        'setup-load-inventory'{$Helpers=ReplaceOnce $Helpers 'if($Loading-or[string](Get-RouterVPNOrderedValue $control[0]' 'if($false-or[string](Get-RouterVPNOrderedValue $control[0]'}
        'setup-refresh-retirement'{$Helpers=ReplaceOnce $Helpers '[void](CancelUnifiedRefreshAsync)' '[void]0'}
        'setup-uncertain-owner'{$Helpers=ReplaceOnce $Helpers '{$selected.SelectedValue=$null}' '{[void]0}'}
    }
    . ([ScriptBlock]::Create($Helpers))
    . ([ScriptBlock]::Create($Choice))
    $SettingsAST=([ScriptBlock]::Create($ProfileSettingsSource)).Ast
    $BodyAssignments=@($SettingsAST.FindAll({param($Node)$Node-is[System.Management.Automation.Language.AssignmentStatementAst]-and$Node.Left.Extent.Text-ceq'$makeSetupBody'},$true))
    if($BodyAssignments.Count-ne1){throw 'Settings body callback count drifted'}
    . ([ScriptBlock]::Create($BodyAssignments[0].Extent.Text))
    $AddCallback=ShippingCallback $ProfileSettingsSource '$profileAdd'
    $UpdateCallback=ShippingCallback $ProfileSettingsSource '$profileUpdate'
    $LoadCallback=ShippingCallback $ProfileSettingsSource '$profileLoad'

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
public sealed class ProfileModeItem { public string Tag {get;set;} public ProfileModeItem(string tag){Tag=tag;} }
public sealed class ProfileModeCombo {
 public List<ProfileModeItem> Items=new List<ProfileModeItem>();
 public string SelectedValue {get;set;}
 public int SelectedIndex {get;set;}
 public ProfileModeItem SelectedItem {get{return SelectedIndex>=0&&SelectedIndex<Items.Count?Items[SelectedIndex]:null;}set{SelectedIndex=Items.IndexOf(value);}}
 public ProfileModeCombo(){SelectedIndex=-1;}
}
public sealed class ProfileModeOwner {
 public Dictionary<string,object> Controls=new Dictionary<string,object>();
 public object FindName(string name){object value;return Controls.TryGetValue(name,out value)?value:null;}
}
'@
    $Owner=New-Object ProfileModeOwner
    $RouterCombo=[pscustomobject]@{SelectedValue='private-node';Tag=[pscustomobject]@{selected_id='private-node';profiles=@([pscustomobject]@{id='private-node';node_kind='router-vpn';profile_token=('1'*64)},[pscustomobject]@{id='entry_private';profile_token=('2'*64)},[pscustomobject]@{id='exit_private';profile_token=('3'*64)})}}
    $Owner.Controls['UnifiedNodeCombo']=$RouterCombo
    $toggle=[pscustomobject]@{IsChecked=$true}
    $Owner.Controls.Add('UnifiedMultihop',$toggle)
    $entry=New-Object ProfileModeCombo;$exit=New-Object ProfileModeCombo
    $Owner.Controls.Add('UnifiedEntryCombo',$entry);$Owner.Controls.Add('UnifiedExitCombo',$exit)
    # Populate value-only controls from the final product's actual XAML tags.
    foreach($Control in @('UnifiedExitMode','UnifiedExecution','UnifiedEntryMode')){
        $Match=[regex]::Match($ProductSource,'<ComboBox\b[^>]*\bName="'+$Control+'"[^>]*>(.*?)</ComboBox>','Singleline')
        if(-not$Match.Success){throw ('Missing generated control '+$Control)}
        $Combo=New-Object ProfileModeCombo
        foreach($Tag in [regex]::Matches($Match.Groups[1].Value,'\bTag="([^"]*)"')){$Combo.Items.Add((New-Object ProfileModeItem $Tag.Groups[1].Value))}
        $Owner.Controls.Add($Control,$Combo)
    }
    $MultihopExitModeCombo=$Owner.FindName('UnifiedExitMode');$execution=$Owner.FindName('UnifiedExecution')
    $MultihopEntryModeCombo=$Owner.FindName('UnifiedEntryMode');$MultihopEntryModeCombo.SelectedIndex=0
    $ExpectedEntries=@('','wg','awg2-fast','awg2-strong','wg-pq','awg2-pq','shadowsocks','hysteria2','reality-vision','reality-pq-vision','reality-xhttp','naive-h2','naive-h3','ss-v2ray','split','max','max-tls-wg','max-tls-awg','max-quic-wg','max-quic-awg','wireguard','amneziawg','socks5','http-connect','https-connect','openvpn')
    Check ((@($MultihopEntryModeCombo.Items|ForEach-Object{$_.Tag})-join',')-ceq($ExpectedEntries-join',')) 'Generated entry choices changed or disappeared'
    $ExpectedModes=@('shadowsocks','hysteria2','reality-vision','reality-pq-vision','reality-xhttp','naive-h2','naive-h3','wg','awg2-fast','awg2-strong','ss-v2ray','split','max','wg-pq','awg2-pq','max-tls-wg','max-tls-awg','max-quic-wg','max-quic-awg')
    $ExpectedExecutions=@('local','server','auto')
    Check ((@($MultihopExitModeCombo.Items|ForEach-Object{$_.Tag})-join',')-ceq($ExpectedModes-join',')) 'Generated exit choices changed or disappeared'
    Check ((@($execution.Items|ForEach-Object{$_.Tag})-join',')-ceq($ExpectedExecutions-join',')) 'Generated execution choices changed or disappeared'
    $BaseUrl='http://127.0.0.1:8788';$ConnectionSnapshot=$null
    $profileName=[pscustomobject]@{Text='Saved "whole" path'};$profileStatus=[pscustomobject]@{Text=''}
    $profileCombo=[pscustomobject]@{SelectedValue='saved-profile'}
    $syncProfileMutationState={return $script:Busy};$script:Busy=$false;$refreshProfiles={}
    $script:LoadedCallbacks=0;$OnConnectionProfileLoaded={$script:LoadedCallbacks++}
    $script:Requests=New-Object System.Collections.ArrayList;$script:Loaded=$null;$script:BeforeReply=$null;$script:ReplyTransform=$null;$script:Retirements=0
    function CancelUnifiedRefreshAsync {$script:Retirements++;return $true}
    function global:Invoke-RestMethod {
        param($Uri,$Method,$ContentType,$Body,$TimeoutSec)
        Check ($Method-ceq'Post'-and$ContentType-ceq'application/json') 'Profile callback changed HTTP operation'
        Check ($Uri-in@(($BaseUrl+'/api/connection-profile/setup/save'),($BaseUrl+'/api/connection-profile/setup/update'),($BaseUrl+'/api/connection-profile/setup/load'))) 'Unexpected endpoint or automatic connection'
        $Payload=$Body|ConvertFrom-Json
        [void]$script:Requests.Add([pscustomobject]@{Uri=$Uri;Body=$Payload})
        Check ($Payload.expected_selected_node_id-ceq$RouterCombo.SelectedValue-and$null-ne$Payload.expected_profile_tokens) 'Setup action omitted its original selected node/source expectations'
        Check (@($Payload.expected_profile_tokens.PSObject.Properties).Count-gt0) 'Setup action discarded its original source inventory'
        if($Uri.EndsWith('/load')){
            $current=@($RouterCombo.Tag.profiles|Where-Object{$_.id-ceq$RouterCombo.SelectedValue})[0]
            $expectedIDs=@($RouterCombo.SelectedValue)
            if((Get-RouterVPNOrderedValue $current 'multihop_enabled' $false)-eq$true){
                $savedNodes=Get-RouterVPNOrderedValue $current 'multihop_nodes'
                if($null-ne$savedNodes-and@($savedNodes).Count-gt0){$expectedIDs+=@($savedNodes.id)}
                else{$expectedIDs+=@($current.multihop_entry_id,$current.multihop_exit_id)}
            }
            $expectedIDs=@($expectedIDs|Sort-Object -Unique)
            Check ((@($Payload.expected_profile_tokens.PSObject.Properties.Name|Sort-Object)-join',')-ceq($expectedIDs-join',')) 'Load discarded an original saved selection source'
        }
        if($Uri.EndsWith('/load')){$reply=$script:Loaded|ConvertTo-Json -Depth 16|ConvertFrom-Json}
        else{
            $reply=$Payload|ConvertTo-Json -Depth 16|ConvertFrom-Json
            $reply|Add-Member -NotePropertyName profile -NotePropertyValue ([pscustomobject]@{name=$Payload.name;mode=$Payload.mode})
            $reply|Add-Member -NotePropertyName selected_node_id -NotePropertyValue $Payload.expected_selected_node_id
            $reply|Add-Member -NotePropertyName profile_tokens -NotePropertyValue $Payload.expected_profile_tokens
        }
        if($null-ne$script:ReplyTransform){$reply=&$script:ReplyTransform $reply}
        if($null-ne$script:BeforeReply){&$script:BeforeReply}
        return $reply
    }
    function VerifyBody($Body,[string]$Mode,[string]$Execution,[bool]$Updating,[string]$EntryMode){
        $Keys=@('expected_selected_node_id','expected_profile_tokens','name','mode','custom_layers','multihop_enabled','multihop_entry_id','multihop_exit_id','multihop_exit_mode','multihop_execution','multihop_entry_mode');if($Updating){$Keys+='id'}
        Check ((@($Body.PSObject.Properties.Name|Sort-Object)-join',')-ceq(@($Keys|Sort-Object)-join',')) 'Private fields copied or snapshot fields missing'
        Check ($Body.multihop_enabled-and$Body.multihop_entry_id-ceq'entry_private'-and$Body.multihop_exit_id-ceq'exit_private') 'Exact graph identities changed'
        Check ($Body.multihop_exit_mode-ceq$Mode) 'Snapshot replaced the selected exit mode'
        Check ($Body.multihop_execution-ceq$Execution) 'Snapshot replaced the selected execution'
        Check ($Body.multihop_entry_mode-ceq$EntryMode) 'Snapshot replaced the selected entry mode'
        Check ($Body.mode-ceq'custom:Saved layers'-and(@($Body.custom_layers)-join',')-ceq'wg,pq') 'Snapshot changed the mode or CUSTOM layers'
        if($Updating){Check ($Body.id-ceq'saved-profile') 'Update changed the saved profile identity'}
    }
    for($m=0;$m-lt$ExpectedModes.Count;$m++){
        for($e=0;$e-lt$ExpectedExecutions.Count;$e++){
            $toggle.IsChecked=$true;$entry.SelectedValue='entry_private';$exit.SelectedValue='exit_private'
            $MultihopExitModeCombo.SelectedIndex=$m;$execution.SelectedIndex=$e
            $EntryIndex=($m*3+$e)%$ExpectedEntries.Count;$MultihopEntryModeCombo.SelectedIndex=$EntryIndex
            Set-RouterVPNLoadedModeSnapshot ([pscustomobject]@{mode='custom:Saved layers';custom_layers=@('wg','pq')})
            $Before=$script:Requests.Count;& $AddCallback
            Check ($script:Requests.Count-eq$Before+1-and$profileStatus.Text.StartsWith('Added ')) ('Actual Add callback failed: '+$profileStatus.Text)
            VerifyBody $script:Requests[-1].Body $ExpectedModes[$m] $ExpectedExecutions[$e] $false $ExpectedEntries[$EntryIndex]
            $script:Loaded=$script:Requests[-1].Body
            $script:Loaded|Add-Member -NotePropertyName profile -NotePropertyValue ([pscustomobject]@{name='Loaded profile'})
            $script:Loaded|Add-Member -NotePropertyName selected_node_id -NotePropertyValue 'private-node'
            $script:Loaded|Add-Member -NotePropertyName profile_tokens -NotePropertyValue $script:Requests[-1].Body.expected_profile_tokens
            $script:Loaded|Add-Member -NotePropertyName private_key -NotePropertyValue 'must-not-copy'
            $toggle.IsChecked=$false;$entry.SelectedValue='replacement-entry';$exit.SelectedValue='replacement-exit';$MultihopExitModeCombo.SelectedIndex=($m+1)%$ExpectedModes.Count;$execution.SelectedIndex=($e+1)%3;$MultihopEntryModeCombo.SelectedIndex=($EntryIndex+1)%$ExpectedEntries.Count
            Set-RouterVPNLoadedModeSnapshot ([pscustomobject]@{mode='auto';custom_layers=@()})
            $Before=$script:Requests.Count;$Callbacks=$script:LoadedCallbacks;& $LoadCallback
            Check ($script:Requests.Count-eq$Before+1-and$script:LoadedCallbacks-eq$Callbacks+1-and$profileStatus.Text.StartsWith('Loaded ')) ('Actual Load callback failed or connected: '+$profileStatus.Text)
            Check ((MultihopExitModeChoice)-ceq$ExpectedModes[$m]) 'Load changed the visible exit transport'
            Check ($execution.SelectedItem.Tag-ceq$ExpectedExecutions[$e]) 'Load changed the visible execution'
            Check ((MultihopEntryModeChoice)-ceq$ExpectedEntries[$EntryIndex]) 'Load changed the visible entry mode'
            $Before=$script:Requests.Count;& $UpdateCallback
            Check ($script:Requests.Count-eq$Before+1-and$profileStatus.Text.StartsWith('Updated ')) 'Actual Update callback failed'
            VerifyBody $script:Requests[-1].Body $ExpectedModes[$m] $ExpectedExecutions[$e] $true $ExpectedEntries[$EntryIndex]
        }
    }
    # Execute the actual generated Connect callback as well as profile storage.
    . ([ScriptBlock]::Create($Connect))
    . ([ScriptBlock]::Create((ShippingFunction $ProductSource 'UnifiedSelectedProfile')))
    . ([ScriptBlock]::Create((ShippingFunction $ProductSource 'BaseChoice')))
    . ([ScriptBlock]::Create((ShippingFunction $ProductSource 'UnifiedMultihopValue')))
    . ([ScriptBlock]::Create((ShippingFunction $ProductSource 'GetUnifiedStopRetryToken')))
    . ([ScriptBlock]::Create((ShippingFunction $ProductSource 'Test-RouterVPNMutationBusyFromStatus')))
    $script:UnifiedStopRetryToken='';$script:UnifiedAsyncOwnedStopRetry=$false;$script:UnifiedProtectionPending=$false
    $MultihopEntryCombo=$entry;$MultihopExitCombo=$exit;$BaseCombo=New-Object ProfileModeCombo
    $BaseCombo.Items.Add((New-Object ProfileModeItem 'auto'));$BaseCombo.SelectedIndex=0
    function Control([string]$Name){return $Owner.FindName($Name)}
    function UnifiedAsyncBusy{return $false}
    function Api($Path,$Method,$Body,$Timeout){
        if($Path-ceq'/api/status'){return [pscustomobject]@{connected=$false;phase='off'}}
        if($Path-ceq'/api/profiles'){return $RouterCombo.Tag}
        if($Path-ceq'/api/multihop/status'){return $script:OrderedCapability}
        throw 'Unexpected Connect boundary'
    }
    $script:ConnectLogs=New-Object System.Collections.ArrayList
    function Log($Message){[void]$script:ConnectLogs.Add([string]$Message)}
    function RefreshProduct{}
    $script:ConnectBody=$null
    function StartUnifiedApiAsync($Label,$Path,$Method,$Body,$Timeout,$Success,$Failure,$Finally){
        Check ($Path-ceq'/api/multihop/connect'-and$Method-ceq'POST') 'Main Connect changed its endpoint'
        $script:ConnectTimeout=$Timeout;$script:ConnectBody=($Body|ConvertTo-Json -Depth 8)|ConvertFrom-Json;return $true
    }
    for($i=0;$i-lt$ExpectedEntries.Count;$i++){for($e=0;$e-lt3;$e++){
        $toggle.IsChecked=$true;$entry.SelectedValue='entry_private';$exit.SelectedValue='exit_private'
        $MultihopEntryModeCombo.SelectedIndex=$i;$MultihopExitModeCombo.SelectedIndex=$i%$ExpectedModes.Count;$execution.SelectedIndex=$e
        $script:ConnectBody=$null;$script:ConnectLogs.Clear();UnifiedConnect;$body=$script:ConnectBody
        Check ($null-ne$body) ('Main Connect did not submit its selected path: '+($script:ConnectLogs -join '; '))
        Check ((@($body.PSObject.Properties.Name|Sort-Object)-join',')-ceq'base,entry_id,entry_mode,execution,exit_id,exit_mode') 'Main Connect copied private fields or omitted graph choices'
        Check ($body.entry_mode-ceq$ExpectedEntries[$i]-and$body.exit_mode-ceq$ExpectedModes[$i%$ExpectedModes.Count]-and$body.execution-ceq$ExpectedExecutions[$e]) 'Main Connect replaced the captured entry, exit or execution'
        Check ($body.entry_id-ceq'entry_private'-and$body.exit_id-ceq'exit_private'-and$body.base-ceq'auto') 'Main Connect replaced exact identities or saved base fallback'
        $KeyModes=@('wg-pq','awg2-pq','max-tls-wg','max-tls-awg','max-quic-wg','max-quic-awg')
        $Phases=0;if(-not$ExpectedEntries[$i]-or$ExpectedEntries[$i]-cin$KeyModes){$Phases+=120};if($ExpectedModes[$i%$ExpectedModes.Count]-cin$KeyModes){$Phases+=120}
        $ExpectedTimeout=if($ExpectedExecutions[$e]-ceq'auto'-and$Phases-gt0){210+$Phases}else{200}
        Check ($script:ConnectTimeout-eq$ExpectedTimeout) 'Main Connect lost the captured native startup deadline'

    }}
    foreach($i in @(-1,$ExpectedEntries.Count,100)){
        $MultihopEntryModeCombo.SelectedIndex=$i;$script:ConnectBody=$null;UnifiedConnect
        Check ($null-eq$script:ConnectBody) 'Unavailable main entry reached Connect'
    }
    $MultihopExitModeCombo.SelectedIndex=0;$execution.SelectedIndex=0
    foreach($BadEntry in @('stale-mode','WG','wg ', 'auto','OpenVPN','WireGuard','amneziawg ')){
        $script:Loaded.multihop_exit_mode=$ExpectedModes[0];$script:Loaded.multihop_entry_mode=$BadEntry
        & $LoadCallback
        Check ($null-eq$MultihopEntryModeCombo.SelectedItem) 'Unsupported loaded entry silently became a valid mode'
        $Rejected=$false;try{[void](MultihopEntryModeChoice)}catch{$Rejected=$true}
        Check $Rejected 'Invalid loaded entry accepted by shipping Connect'
        foreach($Callback in @($AddCallback,$UpdateCallback)){$Before=$script:Requests.Count;&$Callback;Check ($script:Requests.Count-eq$Before) 'Invalid entry reached the profile controller'}
    }
    $script:Loaded.PSObject.Properties.Remove('multihop_entry_mode');$MultihopEntryModeCombo.SelectedIndex=4
    & $LoadCallback
    Check ((MultihopEntryModeChoice)-ceq'') 'Legacy profile did not clear the previous explicit entry mode'
    $MultihopEntryModeCombo.SelectedIndex=0
    foreach($InvalidIndex in @(-1,$ExpectedModes.Count,100)){
        $MultihopExitModeCombo.SelectedIndex=$InvalidIndex
        $Rejected=$false;try{[void](MultihopExitModeChoice)}catch{$Rejected=$true}
        Check $Rejected 'Out-of-range exit index accepted by the shipping Connect selector'
        $Rejected=$false;try{[void](Get-RouterVPNVisibleConnectionSnapshot -Owner $Owner)}catch{$Rejected=$true}
        Check $Rejected 'Out-of-range exit index was captured as a usable profile'
        foreach($Callback in @($AddCallback,$UpdateCallback)){$Before=$script:Requests.Count;&$Callback;Check ($script:Requests.Count-eq$Before) 'Out-of-range exit index reached the controller'}
    }
    foreach($Invalid in @('stale-mode','',$null)){
        $MultihopExitModeCombo.SelectedIndex=0;$script:Loaded.multihop_exit_mode=$Invalid
        & $LoadCallback
        Check ($null-eq$MultihopExitModeCombo.SelectedItem) 'Unsupported loaded mode silently became a valid exit'
        $Rejected=$false;try{[void](MultihopExitModeChoice)}catch{$Rejected=$true}
        Check $Rejected 'Missing exit mode accepted by the shipping Connect selector'
        $Rejected=$false;try{[void](Get-RouterVPNVisibleConnectionSnapshot -Owner $Owner)}catch{$Rejected=$true}
        Check $Rejected 'Unsupported loaded mode was captured as a usable profile'
        foreach($Callback in @($AddCallback,$UpdateCallback)){$Before=$script:Requests.Count;&$Callback;Check ($script:Requests.Count-eq$Before) 'Invalid profile mode reached the controller'}
    }
    $BadItem=New-Object ProfileModeItem 'SHADOWSOCKS';$MultihopExitModeCombo.Items.Add($BadItem);$MultihopExitModeCombo.SelectedItem=$BadItem
    $Rejected=$false;try{[void](MultihopExitModeChoice)}catch{$Rejected=$true}
    Check $Rejected 'Malformed current tag accepted by the shipping Connect selector'
    $script:Busy=$true
    foreach($Callback in @($AddCallback,$LoadCallback,$UpdateCallback)){$Before=$script:Requests.Count;&$Callback;Check ($script:Requests.Count-eq$Before) 'Busy profile mutation reached the controller'}
    $script:Busy=$false;$toggle.IsChecked=$false
    $Disabled=Get-RouterVPNVisibleConnectionSnapshot -Owner $Owner
    Check (-not$Disabled.multihop_enabled-and$Disabled.multihop_entry_id-ceq''-and$Disabled.multihop_exit_id-ceq''-and$Disabled.multihop_exit_mode-ceq''-and$Disabled.multihop_execution-ceq'') 'Disabled multihop retained another graph'

    # Ordered paths execute the same actual Add/Load/Update/Connect callbacks.
    # Widget and HTTP boundaries are doubled; no private node source is copied.
    $Window=$Owner;$ordered=[pscustomobject]@{IsChecked=$true};$chainButton=[pscustomobject]@{Tag=$null}
    $Owner.Controls['UnifiedOrdered']=$ordered;$Owner.Controls['UnifiedNodeChainButton']=$chainButton;$Owner.Controls['UnifiedNodeCombo']=$RouterCombo
    $script:OrderedCapability=[pscustomobject]@{ordered_nodes_supported=$true}
    $orderedCases=@()
    foreach($importedMode in @('http-connect','https-connect')){foreach($prefixMode in @('wg','awg2-fast','awg2-strong')){
        $orderedCases+=[pscustomobject]@{final='shadowsocks';mixed=$false;count=3;imported=$importedMode;prefix=$prefixMode}
    }}
    foreach($finalMode in @('shadowsocks','hysteria2')){foreach($mixed in @($false,$true)){foreach($nodeCount in @(2,3,4,8)){
        $orderedCases+=[pscustomobject]@{final=$finalMode;mixed=$mixed;count=$nodeCount;imported='';prefix=''}
    }}}
    foreach($orderedCase in $orderedCases){
        $finalMode=$orderedCase.final;$mixed=$orderedCase.mixed;$nodeCount=$orderedCase.count
        $nodes=@();$profiles=@();$tokens=@{}
        for($i=0;$i-lt$nodeCount;$i++){
            $id='ordered-'+$i;$mode=if($i-eq$nodeCount-1){$finalMode}elseif($mixed){@('awg2-fast','wg','awg2-strong')[$i%3]}else{'wg'}
            if($orderedCase.imported){if($i-eq0){$mode=$orderedCase.prefix}elseif($i-eq1){$mode=$orderedCase.imported}}
            $nodes+=[pscustomobject]@{id=$id;mode=$mode;private_key='never-copy-member-secret'}
            $tokens[$id]=('{0:x64}' -f ($i+1))
            $profiles+=[pscustomobject]@{id=$id;name=('Node '+$i);node_kind='router-vpn';api_token='never-copy-token';profile_token=$tokens[$id]}
            if($orderedCase.imported-and$i-eq1){
                $profiles[-1].node_kind='external'
                $profiles[-1]|Add-Member -NotePropertyName external -NotePropertyValue ([pscustomobject]@{protocol=$orderedCase.imported;ordered_middle_supported=$true})
            }
        }
        $control=$nodes[-1].id;$RouterCombo.SelectedValue=$control;$RouterCombo.Tag=[pscustomobject]@{selected_id=$control;profiles=$profiles}
        $toggle.IsChecked=$true;$ordered.IsChecked=$true;$chainButton.Tag=[pscustomobject]@{control_id=$control;nodes=$nodes;profile_tokens=$tokens}
        $MultihopEntryModeCombo.SelectedIndex=-1;$MultihopExitModeCombo.SelectedIndex=-1
        foreach($callback in @($AddCallback,$UpdateCallback)){
            $before=$script:Requests.Count;&$callback
            Check ($script:Requests.Count-eq$before+1) ('Ordered profile write failed: '+$profileStatus.Text)
            $body=$script:Requests[-1].Body
            Check ($body.mode-ceq$finalMode-and@($body.custom_layers).Count-eq0-and$body.multihop_execution-ceq'local') 'Ordered profile borrowed an unrelated logical mode or execution'
            Check (@($body.multihop_nodes).Count-eq$nodeCount-and(@($body.multihop_nodes.id)-join',')-ceq(@($nodes.id)-join',')) 'Ordered profile truncated or reordered a middle node'
            Check ((@($body.multihop_nodes.mode)-join',')-ceq(@($nodes.mode)-join',')) 'Ordered profile changed per-position transports'
            foreach($field in @('multihop_entry_id','multihop_exit_id','multihop_entry_mode','multihop_exit_mode')){Check ($null-eq$body.PSObject.Properties[$field]) 'Ordered profile mixed legacy pair fields'}
            Check (($body|ConvertTo-Json -Depth 8)-notmatch'never-copy') 'Ordered profile copied private sources'
            Check ($body.expected_selected_node_id-ceq$control-and@($body.expected_profile_tokens.PSObject.Properties).Count-eq$nodeCount) 'Ordered setup request lost an original source expectation'
            foreach($node in $nodes){Check ((Get-RouterVPNOrderedValue $body.expected_profile_tokens $node.id)-ceq$tokens[$node.id]) 'Ordered setup request replaced an original member source'}
        }
        $script:Loaded=$script:Requests[-1].Body
        $script:Loaded|Add-Member -NotePropertyName selected_node_id -NotePropertyValue $control
        $script:Loaded|Add-Member -NotePropertyName profile_tokens -NotePropertyValue $tokens
        $script:Loaded|Add-Member -NotePropertyName profile -NotePropertyValue ([pscustomobject]@{name='Ordered saved profile';mode=$finalMode})
        $chainButton.Tag=$null;$ordered.IsChecked=$false;$toggle.IsChecked=$false;$script:ConnectBody=$null
        &$LoadCallback
        Check ($null-eq$script:ConnectBody-and$ordered.IsChecked-and$toggle.IsChecked) 'Ordered Load connected or lost its enabled choice'
        Check ($chainButton.Tag.control_id-ceq$control-and@($chainButton.Tag.nodes).Count-eq$nodeCount-and(@($chainButton.Tag.nodes.id)-join',')-ceq(@($nodes.id)-join',')) 'Ordered Load lost a middle or selected final node'
        Check ((@($chainButton.Tag.nodes.mode)-join',')-ceq(@($nodes.mode)-join',')) 'Ordered Load replaced selected WG/AWG modes'
        UnifiedConnect;$body=$script:ConnectBody
        Check ($null-ne$body-and(@($body.PSObject.Properties.Name|Sort-Object)-join',')-ceq'execution,expected_profile_tokens,expected_selected_node_id,nodes') 'Ordered Connect sent legacy pair/private fields or omitted source owners'
        Check ($body.expected_selected_node_id-ceq$control-and@($body.expected_profile_tokens.PSObject.Properties).Count-eq$nodeCount) 'Ordered Connect lost original selected control or all-source hash preconditions'
        foreach($node in $nodes){Check ((Get-RouterVPNOrderedValue $body.expected_profile_tokens $node.id)-ceq$tokens[$node.id]) 'Ordered Connect changed a source token'}
        Check ($body.execution-ceq'local'-and(@($body.nodes.id)-join',')-ceq(@($nodes.id)-join',')-and$body.nodes[-1].mode-ceq$finalMode) 'Ordered Connect changed its complete path'
        Check ((@($body.nodes.mode)-join',')-ceq(@($nodes.mode)-join',')) 'Ordered Connect changed exact captured WG/AWG modes'
        $copy=@(Copy-RouterVPNOrderedNodes $nodes $control);$copy[0].id='replacement'
        Check ($nodes[0].id-ceq'ordered-0') 'Ordered copy retained mutable member references'
        foreach($capability in @([pscustomobject]@{},[pscustomobject]@{ordered_nodes_supported=$false},[pscustomobject]@{ordered_nodes_supported='true'})){
            $script:OrderedCapability=$capability;$script:ConnectBody=$null;UnifiedConnect
            Check ($null-eq$script:ConnectBody) 'An older controller received ordered nodes as a legacy pair'
        }
        $script:OrderedCapability=[pscustomobject]@{ordered_nodes_supported=$true}
        foreach($fault in @('missing-middle','duplicate-middle','external-middle','changed-selected','relinked-middle')){
            $saved=$RouterCombo.Tag
            $changed=$saved|ConvertTo-Json -Depth 8|ConvertFrom-Json
            switch($fault){
                'missing-middle'{$changed.profiles=@($changed.profiles|Where-Object{$_.id-cne$nodes[0].id})}
                'duplicate-middle'{$changed.profiles+=,$changed.profiles[0]}
                'external-middle'{$changed.profiles[0].node_kind='external'}
                'changed-selected'{$changed.selected_id='replacement'}
                'relinked-middle'{$changed.profiles[0].profile_token=('f'*64)}
            }
            $RouterCombo.Tag=$changed;$script:ConnectBody=$null;UnifiedConnect
            Check ($null-eq$script:ConnectBody) ('Changed ordered selection reached Connect: '+$fault)
            $RouterCombo.Tag=$saved
        }
    }
    # Actual callbacks retain their original public owner and complete source
    # map across the request. No network, private source, or WPF is simulated.
    $originalStore=$RouterCombo.Tag|ConvertTo-Json -Depth 32|ConvertFrom-Json
    $originalDraft=$chainButton.Tag|ConvertTo-Json -Depth 16|ConvertFrom-Json
    $originalLoaded=$script:Loaded|ConvertTo-Json -Depth 16|ConvertFrom-Json
    foreach($callback in @($AddCallback,$UpdateCallback,$LoadCallback)){
        foreach($fault in @('visible-off','catalog-replaced','selected-replaced','source-relinked')){
            $RouterCombo.Tag=$originalStore|ConvertTo-Json -Depth 32|ConvertFrom-Json;$RouterCombo.SelectedValue=$control
            $chainButton.Tag=$originalDraft|ConvertTo-Json -Depth 16|ConvertFrom-Json;$ordered.IsChecked=$true;$toggle.IsChecked=$true
            $script:BeforeReply={
                switch($fault){
                    'visible-off'{$toggle.IsChecked=$false}
                    'catalog-replaced'{$RouterCombo.Tag=$RouterCombo.Tag|ConvertTo-Json -Depth 32|ConvertFrom-Json}
                    'selected-replaced'{$RouterCombo.SelectedValue=$nodes[0].id}
                    'source-relinked'{$RouterCombo.Tag.profiles[0].profile_token=('e'*64)}
                }
            }
            $before=$script:LoadedCallbacks;$retired=$script:Retirements;&$callback
            Check ($profileStatus.Text-match'^(Add|Update|Load) failed:') ('A changed setup owner was adopted: '+$fault)
            Check ($script:LoadedCallbacks-eq$before) 'A changed setup owner received a Load callback'
            Check ($script:Retirements-eq$retired+1) 'Setup kept its pending catalog refresh'
            if($fault-ceq'visible-off'){Check (-not$toggle.IsChecked) 'Late setup completion reversed a newer Off decision'}
            $script:BeforeReply=$null
        }
    }
    foreach($callback in @($AddCallback,$UpdateCallback)){
        foreach($fault in @('missing-token','extra-token','changed-token','reordered-members','changed-mode','wrong-final-mode')){
            $RouterCombo.Tag=$originalStore|ConvertTo-Json -Depth 32|ConvertFrom-Json;$RouterCombo.SelectedValue=$control
            $chainButton.Tag=$originalDraft|ConvertTo-Json -Depth 16|ConvertFrom-Json;$ordered.IsChecked=$true;$toggle.IsChecked=$true
            $beforeDraft=$chainButton.Tag
            $script:ReplyTransform={param($reply)
                switch($fault){
                    'missing-token'{$reply.profile_tokens.PSObject.Properties.Remove($nodes[0].id)}
                    'extra-token'{$reply.profile_tokens|Add-Member -NotePropertyName unrelated -NotePropertyValue ('d'*64)}
                    'changed-token'{$reply.profile_tokens.($nodes[0].id)=('c'*64)}
                    'reordered-members'{$first=$reply.multihop_nodes[0];$reply.multihop_nodes[0]=$reply.multihop_nodes[1];$reply.multihop_nodes[1]=$first}
                    'changed-mode'{$reply.multihop_nodes[0].mode='awg2-strong'}
                    'wrong-final-mode'{$reply.profile.mode='smart-auto'}
                }
                return $reply
            }
            &$callback
            Check ($profileStatus.Text-match'^(Add|Update) failed:') ('Malformed setup reply was adopted: '+$fault)
            Check ([object]::ReferenceEquals($beforeDraft,$chainButton.Tag)) 'Rejected setup reply replaced the original editor receipt'
            $script:ReplyTransform=$null
        }
    }
    # Load may replace the selected node only from its complete finalized
    # response. Its expectation still protects the old saved catalog graph.
    $RouterCombo.Tag=$originalStore|ConvertTo-Json -Depth 32|ConvertFrom-Json;$RouterCombo.SelectedValue=$control
    $chainButton.Tag=$originalDraft|ConvertTo-Json -Depth 16|ConvertFrom-Json;$ordered.IsChecked=$true;$toggle.IsChecked=$true
    $targetNodes=@([pscustomobject]@{id=$nodes[0].id;mode='awg2-fast'},[pscustomobject]@{id=$nodes[1].id;mode='shadowsocks'})
    $targetTokens=@{};$targetTokens[$nodes[0].id]=('a'*64);$targetTokens[$nodes[1].id]=('b'*64)
    $script:Loaded=[pscustomobject]@{profile=[pscustomobject]@{name='Different original target';mode='shadowsocks'};mode='shadowsocks';custom_layers=@();selected_node_id=$nodes[1].id;profile_tokens=$targetTokens;multihop_enabled=$true;multihop_nodes=$targetNodes;multihop_execution='local'}
    $before=$script:LoadedCallbacks;&$LoadCallback
    Check ($script:LoadedCallbacks-eq$before+1-and$profileStatus.Text.StartsWith('Loaded ')) ('Original captured target Load failed: '+$profileStatus.Text)
    $request=$script:Requests[-1].Body
    Check ($request.expected_selected_node_id-ceq$control-and@($request.expected_profile_tokens.PSObject.Properties).Count-eq$nodeCount) 'Load replaced its current original inventory with a target or draft inventory'
    Check ($RouterCombo.SelectedValue-ceq$nodes[1].id-and$RouterCombo.Tag.selected_id-ceq$nodes[1].id-and$chainButton.Tag.control_id-ceq$nodes[1].id) 'Loaded selected-node receipt was not adopted atomically'
    Check (@($chainButton.Tag.nodes).Count-eq2-and(Get-RouterVPNOrderedValue $chainButton.Tag.profile_tokens $nodes[0].id)-ceq('a'*64)) 'Load lost its finalized graph or source tokens'
    $profileName.Text='Save loaded target';&$AddCallback
    Check ($profileStatus.Text.StartsWith('Added ')-and$script:Requests[-1].Body.expected_selected_node_id-ceq$nodes[1].id-and(Get-RouterVPNOrderedValue $script:Requests[-1].Body.expected_profile_tokens $nodes[0].id)-ceq('a'*64)) 'The next setup action recaptured stale pre-Load source tokens'
    foreach($fault in @('timeout','missing-response-source')){
        $RouterCombo.Tag=$originalStore|ConvertTo-Json -Depth 32|ConvertFrom-Json;$RouterCombo.SelectedValue=$control
        $chainButton.Tag=$originalDraft|ConvertTo-Json -Depth 16|ConvertFrom-Json;$ordered.IsChecked=$true;$toggle.IsChecked=$true
        $script:Loaded=$originalLoaded|ConvertTo-Json -Depth 16|ConvertFrom-Json
        if($fault-ceq'timeout'){$script:BeforeReply={throw 'Captured Load response timed out'}}
        else{$script:ReplyTransform={param($reply)$reply.profile_tokens.PSObject.Properties.Remove($nodes[0].id);return $reply}}
        $before=$script:LoadedCallbacks;&$LoadCallback
        Check ($profileStatus.Text.StartsWith('Load failed:')-and$script:LoadedCallbacks-eq$before-and[string]::IsNullOrEmpty([string]$RouterCombo.SelectedValue)) 'Uncertain Load retained the old selected-node authority'
        $script:BeforeReply=$null;$script:ReplyTransform=$null;$before=$script:Requests.Count;&$AddCallback
        Check ($script:Requests.Count-eq$before) 'Uncertain Load authorized a later setup write without a fresh catalog'
    }
    $RouterCombo.Tag=$originalStore;$RouterCombo.SelectedValue=$control;$chainButton.Tag=$originalDraft;$script:Loaded=$originalLoaded
    foreach($bad in @(@(),@([pscustomobject]@{id='final';mode='shadowsocks'}),@($nodes+$nodes[0]),@([pscustomobject]@{id='same';mode='wg'},[pscustomobject]@{id='same';mode='shadowsocks'}),@([pscustomobject]@{id='wrong final';mode='wg'},[pscustomobject]@{id='final';mode='shadowsocks'}),@([pscustomobject]@{id='entry';mode='WG'},[pscustomobject]@{id='final';mode='shadowsocks'}),@([pscustomobject]@{id='entry';mode='wg'},[pscustomobject]@{id='another';mode='shadowsocks'}))){
        $rejected=$false;try{[void](Copy-RouterVPNOrderedNodes $bad 'final')}catch{$rejected=$true}
        Check $rejected 'Invalid or foreign-final ordered selection was accepted'
    }
    $toggle.IsChecked=$false
    Check (-not(Get-RouterVPNVisibleConnectionSnapshot -Owner $Owner).ContainsKey('multihop_nodes')) 'Disabled ordered path leaked into a direct profile'
    Write-Output ("Actual WPF profile Add/Load/Update and main Connect callbacks: $script:Count checks PASS")
}finally{
    if(Test-Path -LiteralPath $FixtureStateRoot){Remove-Item -LiteralPath $FixtureStateRoot -Recurse -Force}
}
