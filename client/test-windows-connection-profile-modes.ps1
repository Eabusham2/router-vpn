param(
    [string]$Root = (Split-Path $PSScriptRoot -Parent),
    [ValidateSet('shipping','capture-two-modes','load-fallback','connect-fallback')][string]$Mutation = 'shipping'
)
$ErrorActionPreference='Stop'
# The real launcher composes these sources before opening WPF. Exercise that
# composition, its actual Settings callbacks, and its actual selection helpers.
# Only widget properties, the local HTTP boundary, and the state directory are
# doubled. This test neither starts a VPN nor claims to render WPF.
$Client=Join-Path $Root 'client'
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
    foreach($Name in @('global:Get-RouterVPNCurrentModeSnapshot','global:Set-RouterVPNLoadedModeSnapshot','global:Get-RouterVPNVisibleConnectionSnapshot','global:Apply-RouterVPNLoadedConnectionSnapshot')){
        # Type and storage boundaries only; all selection and payload logic is
        # taken unchanged from the functions loaded by the shipping launcher.
        $Helpers+=(ShippingFunction $ProfileSettingsSource $Name).Replace('[System.Windows.Window]','[object]').Replace('$PSScriptRoot','$FixtureStateRoot')+"`n"
    }
    $Choice=ShippingFunction $ProductSource 'MultihopExitModeChoice'
    switch($Mutation){
        'capture-two-modes'{$Helpers=ReplaceOnce $Helpers '$result.multihop_exit_mode=[string]$exitMode.SelectedItem.Tag' '$result.multihop_exit_mode=if($exitMode.SelectedIndex-eq1){''hysteria2''}else{''shadowsocks''}'}
        'load-fallback'{$Helpers=ReplaceOnce $Helpers '$exitMode.SelectedIndex=-1' '$exitMode.SelectedIndex=0'}
        'connect-fallback'{$Choice=ReplaceOnce $Choice "throw 'Select a supported exit transport.'" "return 'shadowsocks'"}
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
    $toggle=[pscustomobject]@{IsChecked=$true}
    $Owner.Controls.Add('UnifiedMultihop',$toggle)
    $entry=New-Object ProfileModeCombo;$exit=New-Object ProfileModeCombo
    $Owner.Controls.Add('UnifiedEntryCombo',$entry);$Owner.Controls.Add('UnifiedExitCombo',$exit)
    # Populate value-only controls from the final product's actual XAML tags.
    foreach($Control in @('UnifiedExitMode','UnifiedExecution')){
        $Match=[regex]::Match($ProductSource,'<ComboBox\b[^>]*\bName="'+$Control+'"[^>]*>(.*?)</ComboBox>','Singleline')
        if(-not$Match.Success){throw ('Missing generated control '+$Control)}
        $Combo=New-Object ProfileModeCombo
        foreach($Tag in [regex]::Matches($Match.Groups[1].Value,'\bTag="([^"]+)"')){$Combo.Items.Add((New-Object ProfileModeItem $Tag.Groups[1].Value))}
        $Owner.Controls.Add($Control,$Combo)
    }
    $MultihopExitModeCombo=$Owner.FindName('UnifiedExitMode');$execution=$Owner.FindName('UnifiedExecution')
    $ExpectedModes=@('shadowsocks','hysteria2','reality-vision','reality-pq-vision','reality-xhttp','naive-h2','naive-h3','wg','awg2-fast','awg2-strong','ss-v2ray','split','max','wg-pq','awg2-pq')
    $ExpectedExecutions=@('local','server','auto')
    Check ((@($MultihopExitModeCombo.Items|ForEach-Object{$_.Tag})-join',')-ceq($ExpectedModes-join',')) 'Generated exit choices changed or disappeared'
    Check ((@($execution.Items|ForEach-Object{$_.Tag})-join',')-ceq($ExpectedExecutions-join',')) 'Generated execution choices changed or disappeared'
    $BaseUrl='http://127.0.0.1:8788';$ConnectionSnapshot=$null
    $profileName=[pscustomobject]@{Text='Saved "whole" path'};$profileStatus=[pscustomobject]@{Text=''}
    $profileCombo=[pscustomobject]@{SelectedValue='saved-profile'}
    $syncProfileMutationState={return $script:Busy};$script:Busy=$false;$refreshProfiles={}
    $script:LoadedCallbacks=0;$OnConnectionProfileLoaded={$script:LoadedCallbacks++}
    $script:Requests=New-Object System.Collections.ArrayList;$script:Loaded=$null
    function global:Invoke-RestMethod {
        param($Uri,$Method,$ContentType,$Body,$TimeoutSec)
        Check ($Method-ceq'Post'-and$ContentType-ceq'application/json') 'Profile callback changed HTTP operation'
        Check ($Uri-in@(($BaseUrl+'/api/connection-profile/setup/save'),($BaseUrl+'/api/connection-profile/setup/update'),($BaseUrl+'/api/connection-profile/setup/load'))) 'Unexpected endpoint or automatic connection'
        $Payload=$Body|ConvertFrom-Json
        [void]$script:Requests.Add([pscustomobject]@{Uri=$Uri;Body=$Payload})
        if($Uri.EndsWith('/load')){return $script:Loaded}
        return [pscustomobject]@{profile=[pscustomobject]@{name=$Payload.name;mode=$Payload.mode}}
    }
    function VerifyBody($Body,[string]$Mode,[string]$Execution,[bool]$Updating){
        $Keys=@('name','mode','custom_layers','multihop_enabled','multihop_entry_id','multihop_exit_id','multihop_exit_mode','multihop_execution');if($Updating){$Keys+='id'}
        Check ((@($Body.PSObject.Properties.Name|Sort-Object)-join',')-ceq(@($Keys|Sort-Object)-join',')) 'Private fields copied or snapshot fields missing'
        Check ($Body.multihop_enabled-and$Body.multihop_entry_id-ceq'entry "private"'-and$Body.multihop_exit_id-ceq'exit "private"') 'Exact graph identities changed'
        Check ($Body.multihop_exit_mode-ceq$Mode) 'Snapshot replaced the selected exit mode'
        Check ($Body.multihop_execution-ceq$Execution) 'Snapshot replaced the selected execution'
        Check ($Body.mode-ceq'custom:Saved layers'-and(@($Body.custom_layers)-join',')-ceq'wg,pq') 'Snapshot changed the mode or CUSTOM layers'
        if($Updating){Check ($Body.id-ceq'saved-profile') 'Update changed the saved profile identity'}
    }
    for($m=0;$m-lt$ExpectedModes.Count;$m++){
        for($e=0;$e-lt$ExpectedExecutions.Count;$e++){
            $toggle.IsChecked=$true;$entry.SelectedValue='entry "private"';$exit.SelectedValue='exit "private"'
            $MultihopExitModeCombo.SelectedIndex=$m;$execution.SelectedIndex=$e
            Set-RouterVPNLoadedModeSnapshot ([pscustomobject]@{mode='custom:Saved layers';custom_layers=@('wg','pq')})
            $Before=$script:Requests.Count;& $AddCallback
            Check ($script:Requests.Count-eq$Before+1-and$profileStatus.Text.StartsWith('Added ')) ('Actual Add callback failed: '+$profileStatus.Text)
            VerifyBody $script:Requests[-1].Body $ExpectedModes[$m] $ExpectedExecutions[$e] $false
            $script:Loaded=$script:Requests[-1].Body
            $script:Loaded|Add-Member -NotePropertyName profile -NotePropertyValue ([pscustomobject]@{name='Loaded profile'})
            $script:Loaded|Add-Member -NotePropertyName selected_node_id -NotePropertyValue 'private-node'
            $script:Loaded|Add-Member -NotePropertyName private_key -NotePropertyValue 'must-not-copy'
            $toggle.IsChecked=$false;$entry.SelectedValue='replacement-entry';$exit.SelectedValue='replacement-exit';$MultihopExitModeCombo.SelectedIndex=($m+1)%$ExpectedModes.Count;$execution.SelectedIndex=($e+1)%3
            Set-RouterVPNLoadedModeSnapshot ([pscustomobject]@{mode='auto';custom_layers=@()})
            $Before=$script:Requests.Count;$Callbacks=$script:LoadedCallbacks;& $LoadCallback
            Check ($script:Requests.Count-eq$Before+1-and$script:LoadedCallbacks-eq$Callbacks+1-and$profileStatus.Text.StartsWith('Loaded ')) 'Actual Load callback failed or connected'
            Check ((MultihopExitModeChoice)-ceq$ExpectedModes[$m]) 'Load changed the visible exit transport'
            Check ($execution.SelectedItem.Tag-ceq$ExpectedExecutions[$e]) 'Load changed the visible execution'
            $Before=$script:Requests.Count;& $UpdateCallback
            Check ($script:Requests.Count-eq$Before+1-and$profileStatus.Text.StartsWith('Updated ')) 'Actual Update callback failed'
            VerifyBody $script:Requests[-1].Body $ExpectedModes[$m] $ExpectedExecutions[$e] $true
        }
    }
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
    Write-Output ("Actual WPF profile Add/Load/Update callbacks: $script:Count checks PASS")
}finally{
    if(Test-Path -LiteralPath $FixtureStateRoot){Remove-Item -LiteralPath $FixtureStateRoot -Recurse -Force}
}
