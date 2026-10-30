param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][string]$ControllerPipe,
      [Parameter(Mandatory=$true)][long]$ControllerParentHandle,[Parameter(Mandatory=$true)][string]$Report,
      [ValidateSet('roundtrip','cancel','reject-peer','reject-request')][string]$Mode='roundtrip',
      [ValidateRange(0,30000)][int]$StartupDelayMilliseconds=0)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
$Client=$null;$Other=$null;$Request=$null;$Response=$null;$Cts=$null
function Check([bool]$Value,[string]$Message){if(-not$Value){throw ('CONTROL '+$Message)}}
function Reject([scriptblock]$Action,[string]$Message){$Rejected=$false;try{[void](&$Action)}catch{$Rejected=$true};Check $Rejected $Message}
function Save([string]$Value){[IO.File]::WriteAllText($Report,$Value,[Text.UTF8Encoding]::new($false))}
function global:Invoke-RestMethod {throw 'CONTROL owned PowerShell used ordinary HTTP'}
try{
    Import-Module (Join-Path $Root 'client/RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
    $env:HOMEVPN_ROOT=Join-Path ([IO.Path]::GetDirectoryName($Report)) 'captured-data'
    $CapturedDataRoot=$env:HOMEVPN_ROOT
    Check ($null-eq(Get-RouterVPNControllerDataRoot)) 'unproved PowerShell trusted its ambient Data directory'
    if($StartupDelayMilliseconds-gt0){Start-Sleep -Milliseconds $StartupDelayMilliseconds}
    if($Mode-ceq'reject-peer'){
        Reject {Initialize-RouterVPNControllerTransport -ControllerPipe $ControllerPipe -ControllerParentHandle $ControllerParentHandle} 'unproved native parent acquired the PowerShell channel'
        Reject {Initialize-RouterVPNControllerTransport} 'failed native handoff reset to legacy'
        Reject {New-RouterVPNControllerClient} 'failed native handoff created a fallback client'
        Reject {Get-RouterVPNControllerDataRoot} 'failed native handoff retained UI state access'
        Save 'REJECTED PEER'
    }else{
        $Base=Initialize-RouterVPNControllerTransport -ControllerPipe $ControllerPipe -ControllerParentHandle $ControllerParentHandle
        Check ($Base-ceq'https://127.0.0.1:8788') 'native PowerShell lost the captured HTTPS origin'
        $env:HOMEVPN_ROOT=Join-Path ([IO.Path]::GetDirectoryName($Report)) 'replacement-data'
        Check ((Get-RouterVPNControllerDataRoot)-ceq$CapturedDataRoot) 'native PowerShell did not retain its authenticated Data directory'
        if($Mode-ceq'reject-request'){
            Reject {Invoke-RouterVPNControllerRequest -Uri ($Base+'/api/ui/status') -TimeoutSec 5} 'wrong TLS pin reached the PowerShell controller'
            Reject {Invoke-RouterVPNControllerRequest -Uri 'http://127.0.0.1:8788/api/ui/status'} 'failed TLS request used ordinary HTTP'
            Save 'REJECTED REQUEST'
        }elseif($Mode-ceq'roundtrip'){
            $Value=Invoke-RouterVPNControllerRequest -Uri ($Base+'/api/ui/status') -TimeoutSec 5
            Check ($Value.owner-ceq'captured') 'PowerShell sync request lost its actual native owner'
            $Json='{"name":"captured '+[char]0x03bb+'"}'
            $Value=Invoke-RouterVPNControllerRequest -Uri ($Base+'/api/ui/body') -Method Post -Body $Json -TimeoutSec 8
            Check ($Value.exact-eq$true) 'PowerShell JSON bytes changed before pinned TLS'
            $Bytes=New-Object byte[] 32769
            for($Index=0;$Index-lt$Bytes.Length;$Index++){$Bytes[$Index]=[byte](($Index*29+7)-band255)}
            $Value=Invoke-RouterVPNControllerRequest -Uri ($Base+'/api/profile/import') -Method Post -Body $Bytes -TimeoutSec 10
            Check ($Value.bytes-eq32769-and$Value.exact-eq$true) 'PowerShell raw import changed before pinned TLS'
            $Client=New-RouterVPNControllerClient -TimeoutMilliseconds 6000 -ResponseLimit 4096
            $Other=New-RouterVPNControllerClient -TimeoutMilliseconds 6000 -ResponseLimit 4096
            $Client.Dispose();$Client=$null
            $Response=$Other.GetAsync($Base+'/api/ui/status').GetAwaiter().GetResult()
            $Value=ConvertFrom-Json -InputObject ($Response.Content.ReadAsStringAsync().GetAwaiter().GetResult())
            Check ($Value.owner-ceq'captured') 'feature disposal retired another PowerShell client'
            $Response.Dispose();$Response=$null
            Close-RouterVPNControllerTransport
            Reject {Initialize-RouterVPNControllerTransport} 'retired PowerShell owner reset to legacy'
            Reject {New-RouterVPNControllerClient} 'retired PowerShell owner created another client'
            Reject {Get-RouterVPNControllerDataRoot} 'retired PowerShell owner retained UI state access'
            Reject {Invoke-RouterVPNControllerRequest -Uri 'http://127.0.0.1:8788/api/ui/status'} 'old PowerShell callback used ordinary HTTP'
            Save 'PASS ROUNDTRIP'
        }else{
            $Client=New-RouterVPNControllerClient -TimeoutMilliseconds 15000 -ResponseLimit 4096
            $Other=New-RouterVPNControllerClient -TimeoutMilliseconds 6000 -ResponseLimit 4096
            $Cts=[Threading.CancellationTokenSource]::new()
            $Pending=$Client.GetAsync($Base+'/api/hold',$Cts.Token)
            $Response=$Other.GetAsync($Base+'/api/entered').GetAwaiter().GetResult()
            Check (($Response.Content.ReadAsStringAsync().GetAwaiter().GetResult())-ceq'entered') 'pending PowerShell request never reached its actual controller'
            $Response.Dispose();$Response=$null
            $Cts.Cancel();Reject {$Pending.GetAwaiter().GetResult()} 'cancelled PowerShell request published a late result'
            $Response=$Other.GetAsync($Base+'/api/drained').GetAwaiter().GetResult()
            Check (($Response.Content.ReadAsStringAsync().GetAwaiter().GetResult())-ceq'drained') 'PowerShell cancellation did not join pinned HTTP'
            $Response.Dispose();$Response=$null
            $Client.Dispose();$Client=$null
            $Value=Invoke-RouterVPNControllerRequest -Uri ($Base+'/api/ui/status') -TimeoutSec 5
            Check ($Value.owner-ceq'captured') 'PowerShell cancellation retired another request owner'
            Save 'PASS CANCEL'
        }
    }
}catch{
    Save ('FAIL '+$_.Exception.ToString())
    exit 1
}finally{
    if($null-ne$Response){$Response.Dispose()};if($null-ne$Request){$Request.Dispose()}
    if($null-ne$Cts){$Cts.Cancel();$Cts.Dispose()}
    if($null-ne$Client){$Client.Dispose()};if($null-ne$Other){$Other.Dispose()}
    if(Get-Command Close-RouterVPNControllerTransport -ErrorAction SilentlyContinue){Close-RouterVPNControllerTransport}
}
