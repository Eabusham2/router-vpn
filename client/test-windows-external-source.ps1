param([string]$Root=(Split-Path $PSScriptRoot -Parent),[Parameter(Mandatory=$true)][string]$Catalog)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Source=Get-Content -LiteralPath (Join-Path $Root 'client/RouterVPN-Windows-TorBridge.ps1') -Raw -Encoding UTF8
$Ast=[ScriptBlock]::Create($Source).Ast
$Bodies=@($Ast.FindAll({param($Node)$Node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $Node.Value.StartsWith('function TestUnifiedExternalMutationIdle')},$true))
if($Bodies.Count-ne1){throw 'Shipping external source functions moved.'}
. ([ScriptBlock]::Create($Bodies[0].Value))
$Unified=Get-Content -LiteralPath (Join-Path $Root 'client/RouterVPN-Windows-UnifiedShell.ps1') -Raw -Encoding UTF8
$Block=[regex]::Match($Unified,'(?ms)^    \$extraState = @''\r?\n(.*?)\r?\n''@')
if(-not$Block.Success){throw 'Shipping unified functions moved.'}
$Lookup=@([ScriptBlock]::Create($Block.Groups[1].Value).Ast.FindAll({param($Node)$Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name-eq'UnifiedSelectedProfile'},$true))
if($Lookup.Count-ne1){throw 'Shipping selected profile lookup moved.'}
. ([ScriptBlock]::Create($Lookup[0].Extent.Text))
$Baseline=Get-Content -Raw -LiteralPath $Catalog -Encoding UTF8|ConvertFrom-Json
function Clone($Object){return ($Object|ConvertTo-Json -Depth 32|ConvertFrom-Json)}
function Check([bool]$Value,[string]$Message){if(-not$Value){throw $Message};$script:Checks++}
$script:Checks=0;$script:Current=$null;$script:OnCapability=$null;$script:Reads=0
function Api($Path,$Method='GET',$Body=$null,$Timeout=0){
    $script:Reads++
    if($Path-eq'/api/external-profile/capabilities'){if($null-ne$script:OnCapability){&$script:OnCapability};return [pscustomobject]@{profile_source_preconditions=$true}}
    if($Path-eq'/api/nodes'){return $script:Current}
    throw ('Unexpected profile reread during displayed capture: '+$Path)
}
foreach($Fault in @('none','entry-relink','exit-relink','entry-missing','entry-duplicate','selected-id','profile-mismatch')){
    $Opened=Clone $Baseline;$Profile=$Opened.profiles[0];$script:Current=Clone $Opened;$script:OnCapability=$null
    switch($Fault){
        'entry-relink'{$script:Current.profiles[1].profile_token='f'*64}
        'exit-relink'{$script:Current.profiles[0].profile_token='f'*64}
        'entry-missing'{$script:Current.profiles=@($script:Current.profiles[0])}
        'entry-duplicate'{$script:Current.profiles+=@(Clone $script:Current.profiles[1])}
        'selected-id'{$script:Current.selected_id='entry'}
        'profile-mismatch'{$Profile=Clone $Profile;$Profile.profile_token='f'*64;$script:Current.profiles[0].profile_token='f'*64}
    }
    $Result=$null;$Rejected=$false;try{$Result=NewUnifiedExternalPrimaryBody $Profile $Opened}catch{$Rejected=$true}
    if($Fault-eq'none'){Check (-not$Rejected -and $Result.expected_profile_tokens['entry']-ceq$Baseline.profiles[1].profile_token) 'Primary omitted the actual displayed saved entry.'}
    else{Check $Rejected ('Primary silently adopted displayed-source fault '+$Fault)}
}
foreach($Fault in @('entry-relink','entry-missing','empty-selection','null-selection','missing-selection','numeric-selection','selected-relink')){
    $Opened=Clone $Baseline;$Profile=$Opened.profiles[0];$script:OnCapability=$null
    if($Fault-eq'empty-selection'){$Opened.selected_id=''}
    if($Fault-eq'null-selection'){$Opened.selected_id=$null}
    if($Fault-eq'missing-selection'){$Opened.PSObject.Properties.Remove('selected_id')}
    if($Fault-eq'numeric-selection'){$Opened.selected_id=0}
    if($Fault-eq'selected-relink'){$Opened.selected_id='entry'}
    $script:Current=Clone $Opened
    if($Fault-in@('entry-relink','selected-relink')){$script:Current.profiles[1].profile_token='f'*64}
    if($Fault-eq'entry-missing'){$script:Current.profiles=@($script:Current.profiles[0])}
    $Result=$null;$Rejected=$false;try{$Result=NewUnifiedExternalPrimaryBody $Profile $Opened $true $false}catch{$Rejected=$true}
    if($Fault-in@('entry-relink','entry-missing','empty-selection')){
        Check (-not$Rejected -and $Result.direct-eq$true -and $Result.execution-ceq'local' -and $Result.expected_profile_tokens.Count-eq1) ('Explicit Direct adopted its disabled saved entry or lost typed selection: '+$Fault)
        if($Fault-eq'empty-selection'){Check ($Result.expected_selected_node_id -is [string] -and $Result.expected_selected_node_id-ceq'') 'Explicit empty selection was downgraded or coerced.'}
    }else{Check $Rejected ('Direct adopted malformed or changed selected identity: '+$Fault)}
}
$Opened=Clone $Baseline;$Profile=$Opened.profiles[0];$script:Current=Clone $Opened
$script:OnCapability={ $Opened.profiles[1].profile_token='f'*64 }
$Result=NewUnifiedExternalPrimaryBody $Profile $Opened
Check ($Result.expected_profile_tokens['entry']-ceq$Baseline.profiles[1].profile_token) 'Later public catalog mutation changed the already captured primary path.'
$script:OnCapability=$null
$RouterCombo=[pscustomobject]@{Tag=(Clone $Baseline);SelectedValue='exit'};$script:Reads=0
$Displayed=UnifiedSelectedProfile
Check ($null-ne$Displayed -and $Displayed.id-ceq'exit' -and $script:Reads-eq0) 'Primary selected profile was reread instead of using its rendered catalog.'
$RouterCombo.SelectedValue='entry'
Check ($null-eq(UnifiedSelectedProfile)) 'Displayed widget and committed rendered selection disagreed without rejection.'
Write-Output ('PASS independent displayed-source primary/Direct regressions: '+$script:Checks+' checks')
