param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert-Wrapper([bool]$Value,[string]$Message){if(-not$Value){throw $Message}}
$Source=Get-Content -LiteralPath (Join-Path $Root 'client/native-multihop-windows.ps1') -Raw -Encoding UTF8
$Ast=[ScriptBlock]::Create($Source).Ast
$Admin=@($Ast.FindAll({param($Node)$Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'Test-Administrator'},$true))
Assert-Wrapper ($Admin.Count-eq1) 'Shipping administrator capability boundary changed.'
# Full shipping wrapper control flow executes. Only OS privilege/process and
# firewall APIs are local doubles; the process identity reader is unchanged.
$Source=$Source.Remove($Admin[0].Extent.StartOffset,$Admin[0].Extent.EndOffset-$Admin[0].Extent.StartOffset).Insert($Admin[0].Extent.StartOffset,'function Test-Administrator{return $true}')
$TaskRoot=Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-windows-owner-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($TaskRoot)
$FixtureClient=Join-Path $TaskRoot 'client';[void][IO.Directory]::CreateDirectory($FixtureClient)
$Wrapper=Join-Path $FixtureClient 'native-multihop-windows.ps1'
[IO.File]::WriteAllText($Wrapper,$Source,[Text.UTF8Encoding]::new($false))
$RealPrivate=(Join-Path $Root 'client/Private-RouterVPN-State.ps1').Replace("'","''")
$Overrides=@'
function Start-Sleep{}
function Start-Process{
    param($FilePath,$ArgumentList,$WorkingDirectory,[switch]$PassThru,$WindowStyle)
    [IO.File]::WriteAllText($env:WRAPPER_STARTED,'started')
    $script:FixtureChild=[pscustomobject]@{Id=111;StartTime=[datetime]'2026-01-01T00:00:00Z';Path=[string]$FilePath;HasExited=($env:WRAPPER_CASE-eq'early');ExitCode=23}
    $script:FixtureChild|Add-Member ScriptMethod Refresh {}
    return $script:FixtureChild
}
function Write-RouterVPNProcessRecord($Path,$Process){
    $record=Get-RouterVPNProcessIdentity $Process
    [IO.File]::WriteAllText($Path,($record|ConvertTo-Json -Compress))
}
function Test-RouterVPNControllerStopping{
    [IO.File]::WriteAllText((Join-Path $env:WRAPPER_RUNTIME 'native-multihop.process.json'),'replacement-record')
    if($env:WRAPPER_CASE-eq'changed'){$script:FixtureChild.Id=222;$script:FixtureChild.StartTime=[datetime]'2026-01-02T00:00:00Z'}
    return $true
}
function Stop-Process{param($InputObject,[switch]$Force,$ErrorAction);[IO.File]::AppendAllText($env:WRAPPER_STOPPED,([string]$InputObject.Id+"`n"));$InputObject.HasExited=$true}
function Stop-RouterVPNRecordedProcess($Path){[IO.File]::AppendAllText($env:WRAPPER_STOPPED,"replacement-registry-owner`n");return $true}
# Windows PowerShell resolves this standard alias before a same-named
# function. Retain that command environment on non-Windows test hosts too.
Set-Alias -Name kill -Value Stop-Process -Scope Script -Option AllScope
'@
[IO.File]::WriteAllText((Join-Path $FixtureClient 'Private-RouterVPN-State.ps1'),(". '"+$RealPrivate+"'`n"+$Overrides),[Text.UTF8Encoding]::new($false))
$Core=Join-Path $TaskRoot 'core.ps1'
[IO.File]::WriteAllText($Core,'param([string]$Mode); if($Mode-ne''check''){throw ''Unexpected native invocation''}; exit ([int]$env:WRAPPER_CHECK_RESULT)',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $FixtureClient 'Select-Standard-Engine.ps1'),'function Get-RouterVPNStandardEngine($Root){return $env:WRAPPER_CORE}',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $FixtureClient 'windows-kill-switch.ps1'),'param($Action,$Root,$Endpoint,$TunnelAlias);[IO.File]::AppendAllText($env:WRAPPER_POLICY,($Action+"`n"));exit 0',[Text.UTF8Encoding]::new($false))
$Names=@('HOMEVPN_ROOT','HOMEVPN_STANDARD_ENGINE','HOMEVPN_EXTERNAL_SESSION','WRAPPER_RUNTIME','WRAPPER_CORE','WRAPPER_POLICY','WRAPPER_STARTED','WRAPPER_STOPPED','WRAPPER_CASE','WRAPPER_CHECK_RESULT','WRAPPER_DISPATCH_LOG','WRAPPER_POLICY_FAIL')
$Saved=@{};foreach($Name in $Names){$Saved[$Name]=[Environment]::GetEnvironmentVariable($Name,'Process')}
$Shell=(Get-Process -Id $PID).Path

function Assert-ShippingKillSwitchDispatch([string]$RepositoryRoot,[string]$Relative,[string]$Helper,[string[]]$ExpectedActions){
    $Body=Get-Content -LiteralPath (Join-Path $RepositoryRoot $Relative) -Raw -Encoding UTF8
    $Tree=[ScriptBlock]::Create($Body).Ast
    $Definitions=@($Tree.FindAll({param($Node)$Node-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$Node.Name-eq$Helper},$true))
    Assert-Wrapper ($Definitions.Count-eq1) ('Shipping kill-switch helper changed: '+$Relative)
    $Calls=@($Tree.FindAll({param($Node)$Node-is[System.Management.Automation.Language.CommandAst]-and$Node.GetCommandName()-eq$Helper},$true))
    Assert-Wrapper ($Calls.Count-eq$ExpectedActions.Count) ('Shipping kill-switch call sites changed: '+$Relative)
    $Root=$TaskRoot;$Endpoint='203.0.113.20';$BridgeEndpoint=$Endpoint;$TunnelAlias='captured-tunnel';$alias='verified-openvpn-tunnel'
    $KillSwitch=Join-Path $TaskRoot ('dispatch-'+$Helper+'.ps1')
    $env:WRAPPER_DISPATCH_LOG=Join-Path $TaskRoot ('dispatch-'+$Helper+'.jsonl')
    $Policy=@'
param($Action,$Root,$Endpoint,$TunnelAlias)
[IO.File]::AppendAllText($env:WRAPPER_DISPATCH_LOG,(@{action=$Action;root=$Root;endpoint=$Endpoint;tunnel=$TunnelAlias}|ConvertTo-Json -Compress)+"`n")
if($env:WRAPPER_POLICY_FAIL-eq'1'){exit 17}
exit 0
'@
    [IO.File]::WriteAllText($KillSwitch,$Policy,[Text.UTF8Encoding]::new($false))
    function Stop-Process{throw 'Windows kill alias dispatched process teardown instead of the captured firewall helper.'}
    # Windows PowerShell 5.1's built-in alias already has AllScope. Preserve
    # that option when reproducing its command resolution on other hosts.
    Set-Alias -Name kill -Value Stop-Process -Scope Local -Option AllScope
    . ([ScriptBlock]::Create($Definitions[0].Extent.Text))
    $env:WRAPPER_POLICY_FAIL='0'
    foreach($Call in $Calls){& ([ScriptBlock]::Create($Call.Extent.Text))}
    $Records=@([IO.File]::ReadAllLines($env:WRAPPER_DISPATCH_LOG)|ForEach-Object{$_|ConvertFrom-Json})
    Assert-Wrapper ($Records.Count-eq$ExpectedActions.Count) 'A shipping helper did not invoke its captured firewall operation.'
    for($Index=0;$Index-lt$Records.Count;$Index++){
        $Record=$Records[$Index]
        Assert-Wrapper ($Record.action-ceq$ExpectedActions[$Index]-and$Record.root-ceq$Root-and$Record.endpoint-ceq$Endpoint) ('A shipping helper changed the captured firewall operation or owner: '+$Relative+' '+$Index+' '+($Record|ConvertTo-Json -Compress))
        $ExpectedTunnel=if($Relative-like'*openvpn*'){if($Record.action-eq'tunnel'){$alias}else{''}}else{$TunnelAlias}
        Assert-Wrapper ([string]$Record.tunnel-ceq$ExpectedTunnel) 'A shipping helper changed the verified tunnel interface.'
    }
    $env:WRAPPER_POLICY_FAIL='1'
    $Failed=$false
    try{& ([ScriptBlock]::Create($Calls[0].Extent.Text))}catch{$Failed=$_.Exception.Message-like'*kill-switch*failed*'}
    Assert-Wrapper $Failed 'A failed firewall helper was accepted as successful.'
    $env:WRAPPER_POLICY_FAIL='0'
    # Negative control: the former helper spelling resolves to the Windows
    # alias even when its function body is present. Do not remove the alias.
    . ([ScriptBlock]::Create($Definitions[0].Extent.Text.Replace($Helper,'Kill')))
    $Collision=$false
    try{& ([ScriptBlock]::Create($Calls[0].Extent.Text.Replace($Helper,'Kill')))}catch{$Collision=$_.Exception.Message-like'Windows kill alias dispatched*'}
    Assert-Wrapper $Collision 'The alias collision regression control did not exercise real PowerShell command resolution.'
}

$Count=0
try{
    Assert-ShippingKillSwitchDispatch $Root 'client/native-multihop-windows.ps1' 'Invoke-RouterVPNNativeKillSwitch' @('release','check','prepare')
    Assert-ShippingKillSwitchDispatch $Root 'client/native-openvpn-windows.ps1' 'Invoke-RouterVPNOpenVPNKillSwitch' @('release','check','prepare','tunnel')
    Assert-ShippingKillSwitchDispatch $Root 'client/native-tor-bridge-windows.ps1' 'Invoke-RouterVPNTorKillSwitch' @('release','check','prepare')
    foreach($Case in @('check','failed-check','down','up','changed','early')){
        $PrivateRoot=Join-Path $TaskRoot $Case;$Runtime=Join-Path $PrivateRoot 'run/native-node/one';[void][IO.Directory]::CreateDirectory($Runtime)
        [IO.File]::WriteAllText((Join-Path $Runtime 'sing-box.json'),'{}');[IO.File]::WriteAllText((Join-Path $Runtime 'replacement.marker'),'retained')
        $env:HOMEVPN_ROOT=$PrivateRoot;$env:HOMEVPN_STANDARD_ENGINE='native';$env:HOMEVPN_EXTERNAL_SESSION=('a'*32)
        $env:WRAPPER_RUNTIME=$Runtime;$env:WRAPPER_CORE=$Core;$env:WRAPPER_CASE=$Case;$env:WRAPPER_CHECK_RESULT=if($Case-eq'failed-check'){'19'}else{'0'}
        $env:WRAPPER_POLICY=Join-Path $PrivateRoot 'policy.log';$env:WRAPPER_STARTED=Join-Path $PrivateRoot 'started';$env:WRAPPER_STOPPED=Join-Path $PrivateRoot 'stopped'
        $Action=if($Case-eq'check'-or$Case-eq'failed-check'){'check'}elseif($Case-eq'down'){'down'}else{'up'}
        $Log=Join-Path $PrivateRoot 'wrapper.log'
        $ErrorLog=Join-Path $PrivateRoot 'wrapper.err'
        $Arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$Wrapper+'"'),'-Action',$Action,'-RuntimeDir',('"'+$Runtime+'"'),'-Endpoint','203.0.113.20','-TunnelAlias','router-vpn')
        $Run=Start-Process -FilePath $Shell -ArgumentList $Arguments -RedirectStandardOutput $Log -RedirectStandardError $ErrorLog -Wait -PassThru
        $Code=$Run.ExitCode
        $ExpectedFailure=$Case-eq'failed-check'-or$Case-eq'early'
        Assert-Wrapper (($Code-ne0)-eq$ExpectedFailure) ('Unexpected '+$Case+' result: '+[IO.File]::ReadAllText($Log)+[IO.File]::ReadAllText($ErrorLog))
        Assert-Wrapper ([IO.File]::ReadAllText((Join-Path $Runtime 'replacement.marker'))-ceq'retained') 'Wrapper erased the current workspace.'
        $Policies=if(Test-Path -LiteralPath $env:WRAPPER_POLICY){@([IO.File]::ReadAllLines($env:WRAPPER_POLICY))}else{@()}
        Assert-Wrapper (-not($Policies-contains'release')) 'Wrapper released protection outside controller ownership.'
        if($Action-eq'check'-or$Action-eq'down'){
            Assert-Wrapper (-not(Test-Path -LiteralPath $env:WRAPPER_STARTED)-and-not(Test-Path -LiteralPath $env:WRAPPER_STOPPED)) 'Check/down changed process ownership.'
            Assert-Wrapper (-not($Policies-contains'prepare')) 'Check/down prepared the firewall.'
        }
        if($Case-eq'up'){
            Assert-Wrapper (([IO.File]::ReadAllText($env:WRAPPER_STOPPED)).Trim()-ceq'111') 'Retiring wrapper stopped the current registry owner instead of its captured child.'
            Assert-Wrapper ([IO.File]::ReadAllText((Join-Path $Runtime 'native-multihop.process.json'))-ceq'replacement-record') 'Retiring wrapper erased replacement process ownership.'
        }
        if($Case-eq'changed'){Assert-Wrapper (-not(Test-Path -LiteralPath $env:WRAPPER_STOPPED)) 'Changed process identity was force-stopped.'}
        $Count++
    }
    Write-Host ('PASS full shipping Windows native wrapper: '+$Count+' check/failure/owner/replacement cases; 10 shipping firewall dispatches and 3 alias/failure negative controls')
}finally{
    foreach($Name in $Names){[Environment]::SetEnvironmentVariable($Name,$Saved[$Name],'Process')}
    if(Test-Path -LiteralPath $TaskRoot){[IO.Directory]::Delete($TaskRoot,$true)}
}
