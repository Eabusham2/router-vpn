param([string]$Root=(Split-Path $PSScriptRoot -Parent),[string]$Adapter='',
      [ValidateSet('requests','handoff','bounds')][string]$Case='requests')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
if(-not$Adapter){$Adapter=Join-Path $Root 'client/RouterVPN-Windows-ControllerTransport.psm1'}
$Module=Import-Module $Adapter -Global -PassThru -ErrorAction Stop
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $Root 'client/RouterVPN-Windows-HomeSummary.ps1'),[Text.Encoding]::UTF8)))
$script:Checks=0;$global:RouterVPNAdapterLegacyCalls=0
function Check([bool]$Condition,[string]$Message){if(-not$Condition){throw ('CONTROL '+$Message)};$script:Checks++}
function Reject([scriptblock]$Action,[string]$Message){$Rejected=$false;try{[void](&$Action)}catch{$Rejected=$true};Check $Rejected $Message}
function global:Invoke-RestMethod { $global:RouterVPNAdapterLegacyCalls++;throw 'Unexpected ordinary HTTP fallback' }

if($Case-ceq'handoff'){
    Reject {Initialize-RouterVPNControllerTransport -ControllerPipe 'invalid' -ControllerParentHandle 1} 'invalid handoff was accepted'
    Reject {Initialize-RouterVPNControllerTransport} 'failed native handoff reset to legacy'
    Reject {New-RouterVPNControllerClient} 'failed native handoff created an ordinary HTTP client'
    Reject {Invoke-RouterVPNControllerRequest -Uri 'http://127.0.0.1:8788/api/status'} 'failed native handoff sent an ordinary request'
    Close-RouterVPNControllerTransport
    Reject {Initialize-RouterVPNControllerTransport} 'closed failed handoff reset its owner'
    Check ($global:RouterVPNAdapterLegacyCalls-eq0) 'failed handoff fell back to ordinary HTTP'
    Write-Host "PASS controller PowerShell adapter handoff checks=$script:Checks"
    return
}

Add-Type -AssemblyName System.Net.Http
$Code=[IO.File]::ReadAllText((Join-Path $Root 'client/RouterVPN-Windows-ControllerTransport.cs'),[Text.Encoding]::UTF8)
foreach($Name in @('transport_tests.cs','adapter_tests.cs')){$Code+=[Environment]::NewLine+[IO.File]::ReadAllText((Join-Path $Root ('deploy/fixtures/windows-controller-transport/'+$Name)),[Text.Encoding]::UTF8)}
$Compile=@{TypeDefinition=$Code;ErrorAction='Stop'}
if($PSVersionTable.PSEdition-eq'Desktop'){
    $Parameters=New-Object System.CodeDom.Compiler.CompilerParameters
    $Parameters.CompilerOptions='/langversion:5';$Parameters.GenerateExecutable=$false;$Parameters.GenerateInMemory=$true
    foreach($Reference in @('System.dll','System.Core.dll','System.Net.Http.dll')){[void]$Parameters.ReferencedAssemblies.Add($Reference)}
    $Compile.CompilerParameters=$Parameters
}else{$Compile.CompilerOptions='/langversion:5'}
Add-Type @Compile
$Fixture=[RouterVPN.ControllerUI.Tests.TransportTests+AdapterHarness]::new()
# Module-private setup is confined to this executable fixture. Production
# callers have only the real process-handle/pipe ConnectAsync entry point.
& $Module {param($Captured) $script:ControllerMode='owned';$script:ControllerChannel=$Captured;$script:ControllerPipe='captured-test-pipe';$script:ControllerParentHandle=[long]123} $Fixture.Channel
$Client=$null;$Other=$null;$Request=$null;$Cts=$null;$Response=$null
try{
    if($Case-ceq'bounds'){
        Reject {Invoke-RouterVPNControllerRequest -Uri 'https://127.0.0.1:8788/api/status' -ResponseLimit 16} 'bounded adapter accepted an oversized response'
        Reject {Invoke-RouterVPNControllerRequest -Uri 'http://127.0.0.1:8788/api/status'} 'failed bounded channel fell back to HTTP'
        Check ($global:RouterVPNAdapterLegacyCalls-eq0) 'response failure used ordinary HTTP'
        Write-Host "PASS controller PowerShell adapter bounds checks=$script:Checks"
        return
    }
    try{$Result=Invoke-RouterVPNControllerRequest -Uri 'https://127.0.0.1:8788/api/status' -TimeoutSec 5}catch{throw ('CONTROL sync JSON did not use the captured channel: '+$_.Exception.Message)}
    Check ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Result.path))-ceq'/api/status') 'sync JSON request lost its captured target'
    Check ($Result.method-eq1-and$Result.bytes-eq0-and$Result.timeout-gt0-and$Result.timeout-le5000) 'sync JSON request lost its method or deadline'
    $Result=Get-RouterVPNHomeSummary -BaseUrl 'https://127.0.0.1:8788/'
    Check ($Result.method-eq1-and[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Result.path))-ceq'/api/home-summary') 'packaged Home summary escaped its captured channel'
    $Result=Prove-RouterVPNHomeExit -BaseUrl 'https://127.0.0.1:8788'
    Check ($Result.method-eq2-and$Result.bytes-eq2-and[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Result.path))-ceq'/api/home-summary/prove-exit') 'packaged exit proof escaped its captured channel'
    $JSON='{"name":"captured '+[char]0x03bb+'"}'
    $Result=Invoke-RouterVPNControllerRequest -Uri 'https://127.0.0.1:8788/api/profile/device' -Method Post -Body $JSON -TimeoutSec 8
    Check ($Result.method-eq2-and$Result.sha256-ceq[RouterVPN.ControllerUI.Tests.TransportTests+AdapterHarness]::Hash([Text.Encoding]::UTF8.GetBytes($JSON))) 'sync JSON changed its UTF-8 bytes'
    $Result=Invoke-RouterVPNControllerRequest -Uri 'https://127.0.0.1:8788/api/speed-lab/run' -Method Post -Body '{}' -TimeoutSec 960
    Check ($Result.timeout-gt950000-and$Result.timeout-le960000) 'Speed Lab lost its captured 960-second budget'
    Reject {Invoke-RouterVPNControllerRequest -Uri 'https://127.0.0.1:8788/api/status' -TimeoutSec 901} 'ordinary adapter operation borrowed the Speed Lab deadline'
    foreach($Length in @(32769,33554432)){
        $Bytes=[RouterVPN.ControllerUI.Tests.TransportTests+AdapterHarness]::Pattern($Length)
        $Result=Invoke-RouterVPNControllerRequest -Uri 'https://127.0.0.1:8788/api/profile/import' -Method Post -Body $Bytes -TimeoutSec 20
        Check ($Result.bytes-eq$Length-and$Result.sha256-ceq[RouterVPN.ControllerUI.Tests.TransportTests+AdapterHarness]::Hash($Bytes)) 'raw import changed its exact captured bytes'
    }
    $Before=$Fixture.Calls
    Reject {Invoke-RouterVPNControllerRequest -Uri 'https://127.0.0.1:8788/api/external-profile/import' -Method Post -Body $Bytes} 'another endpoint acquired the 32MiB import exception'
    foreach($URI in @('http://127.0.0.1:8788/api/status','https://localhost:8788/api/status','https://127.0.0.1:8789/api/status','https://127.0.0.1:8788/api/controller/identity','https://127.0.0.1:8788/api/%73tatus')){
        Reject {Invoke-RouterVPNControllerRequest -Uri $URI} 'noncaptured adapter target reached the controller'
    }
    Check ($Fixture.Calls-eq$Before) 'invalid adapter requests escaped before rejection'
    Reject {Invoke-RouterVPNControllerRequest -Uri 'https://127.0.0.1:8788/api/fail'} 'failed HTTP status became successful JSON'
    Reject {Initialize-RouterVPNControllerTransport -ControllerPipe 'replacement' -ControllerParentHandle 456} 'another handoff replaced a live UI owner'
    $Client=New-RouterVPNControllerClient -TimeoutMilliseconds 15000 -ResponseLimit 4096
    $Other=New-RouterVPNControllerClient -TimeoutMilliseconds 15000 -ResponseLimit 4096
    $Request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,'https://127.0.0.1:8788/api/status')
    Set-RouterVPNControllerRequestTimeout $Request 6000
    $Response=$Client.SendAsync($Request).GetAwaiter().GetResult()
    $Result=ConvertFrom-Json -InputObject $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    Check ($Result.timeout-gt0-and$Result.timeout-le6000) 'async adapter extended its per-request deadline'
    $Response.Dispose();$Response=$null;$Request.Dispose();$Request=$null
    $Client.Dispose();$Client=$null
    $Response=$Other.GetAsync('https://127.0.0.1:8788/api/status').GetAwaiter().GetResult()
    Check $Response.IsSuccessStatusCode 'feature disposal closed the shared channel'
    $Response.Dispose();$Response=$null
    $Cts=[Threading.CancellationTokenSource]::new()
    $Pending=$Other.GetAsync('https://127.0.0.1:8788/api/hold',$Cts.Token)
    Check ($Fixture.Entered.Wait(5000)) 'actual pending adapter request never entered'
    $Cts.Cancel()
    Reject {$Pending.GetAwaiter().GetResult()} 'cancelled feature published an old response'
    $Response=$Other.GetAsync('https://127.0.0.1:8788/api/status').GetAwaiter().GetResult()
    Check ($Response.IsSuccessStatusCode-and$Fixture.Cancelled-eq1) 'feature cancellation lost its frame or closed another client'
    $Response.Dispose();$Response=$null
    $Fixture.Revoke()
    Reject {Invoke-RouterVPNControllerRequest -Uri 'https://127.0.0.1:8788/api/status'} 'revoked peer retained request authority'
    Close-RouterVPNControllerTransport
    Reject {New-RouterVPNControllerClient} 'closed owner created another client'
    Reject {Initialize-RouterVPNControllerTransport} 'closed owner reset to a legacy channel'
    Reject {Invoke-RouterVPNControllerRequest -Uri 'http://127.0.0.1:8788/api/status'} 'old callback used HTTP after channel retirement'
    Check ($global:RouterVPNAdapterLegacyCalls-eq0) 'owned UI used ordinary HTTP fallback'
    Write-Host "PASS controller PowerShell adapter requests checks=$script:Checks"
}finally{
    if($null-ne$Response){$Response.Dispose()};if($null-ne$Request){$Request.Dispose()}
    if($null-ne$Cts){$Cts.Cancel();$Cts.Dispose()}
    if($null-ne$Client){$Client.Dispose()};if($null-ne$Other){$Other.Dispose()}
    Close-RouterVPNControllerTransport
    $Fixture.Dispose()
}
