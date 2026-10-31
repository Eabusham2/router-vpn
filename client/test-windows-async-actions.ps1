param([string]$Root = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Net.Http
Import-Module (Join-Path $Root 'client/RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
$source = Get-Content -LiteralPath (Join-Path $Root 'client/RouterVPN-Windows-UnifiedShell.ps1') -Raw -Encoding UTF8
# Extract the actual emitted function definitions without constructing WPF or opening a VPN.
$extra = [regex]::Match($source, '(?ms)^    \$extraState = @''\r?\n(.*?)\r?\n''@')
if (-not $extra.Success) { throw 'Shipping async source block not found.' }
$ast = [ScriptBlock]::Create($extra.Groups[1].Value).Ast
$names = @('UnifiedAsyncBusy','UnifiedMultihopValue','GetUnifiedMultihopComparisonText','RefreshUnifiedMultihopComparison','UnifiedCapturedComparisonRequestID','UnifiedCapturedComparisonTimeout','UnifiedCapturedComparisonStatus','SetUnifiedAsyncUI','StartUnifiedApiAsync','CancelUnifiedApiAsync','CompleteUnifiedApiAsync','StartUnifiedComparisonProgress','StopUnifiedComparisonProgress','UnifiedComparisonProgressOwned','PollUnifiedComparisonProgress')
foreach ($name in $names) {
    $nodes = @($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}, $true))
    if ($nodes.Count -ne 1) { throw "Expected one shipping function: $name" }
    . ([ScriptBlock]::Create($nodes[0].Extent.Text))
}
function Assert([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Log([string]$Text) { $script:Messages.Add($Text) }
function Control([string]$Name) { if (-not $script:Controls.ContainsKey($Name)) { $script:Controls[$Name] = [pscustomobject]@{IsEnabled=$true;Content='Connect';Text=''} }; return $script:Controls[$Name] }
function CancelUnifiedRefreshAsync { return $false }
function RefreshProduct { $script:Refreshes++ }
function Reset-Fixture {
    $script:BaseUrl='http://127.0.0.1:8788'
    $script:Messages=New-Object 'System.Collections.Generic.List[string]'
    $script:Controls=@{}; $script:Refreshes=0; $script:Successes=0; $script:Finalizers=0; $script:Failures=0
    $script:UnifiedAsyncTask=$null; $script:UnifiedAsyncRequest=$null; $script:UnifiedAsyncCts=$null; $script:UnifiedAsyncResponse=$null
    $script:UnifiedAsyncSuccess=$null; $script:UnifiedAsyncFailure=$null; $script:UnifiedAsyncFinally=$null
    $script:UnifiedAsyncLabel=''; $script:UnifiedAsyncCancelled=$false; $script:UnifiedAsyncDisconnectAfterCancel=$false
    $script:UnifiedAsyncActive=$false; $script:UnifiedAsyncCompleting=$false; $script:UnifiedAsyncClosed=$false
    $script:UnifiedProtectionPending=$false
    $script:UnifiedAsyncPoller=[pscustomobject]@{Starts=0;Stops=0}
    $script:UnifiedAsyncPoller | Add-Member ScriptMethod Start {$this.Starts++}
    $script:UnifiedAsyncPoller | Add-Member ScriptMethod Stop {$this.Stops++}
    # Comparison functions are the shipping definitions above, not no-op stubs.
    # Only their timer/transport dependencies are doubled; no observer request
    # or VPN connection is made by this isolated lifecycle suite.
    $script:UnifiedComparisonWatching=$false; $script:UnifiedComparisonCts=$null
    $script:UnifiedComparisonGeneration='';$script:UnifiedComparisonTaskGeneration='';$script:UnifiedComparisonExpectedID='';$script:UnifiedComparisonCallback=$null
    $script:UnifiedComparisonTask=$null;$script:UnifiedComparisonRequest=$null;$script:UnifiedComparisonCompleting=$false;$script:UnifiedComparisonDeadline=[DateTime]::MinValue
    $script:UnifiedComparisonLastID='old-comparison'; $script:UnifiedComparisonOldID=''
    $script:ProgressCallbacks=0;$script:ProgressText=''
    $script:UnifiedComparisonClient=[pscustomobject]@{Sends=0;Pending=$null;LastPath='';LastMethod='';SeenCts=$null}
    $script:UnifiedComparisonClient|Add-Member ScriptMethod SendAsync {
        param($Request,$Token)
        $this.Sends++;$this.LastPath=$Request.RequestUri.AbsoluteUri;$this.LastMethod=$Request.Method.Method;$this.SeenCts=$script:UnifiedComparisonCts
        $this.Pending=New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]'
        return $this.Pending.Task
    }
    $script:UnifiedComparisonNext=[DateTime]::MinValue
    $script:UnifiedComparisonPoller=[pscustomobject]@{Starts=0;Stops=0}
    $script:UnifiedComparisonPoller | Add-Member ScriptMethod Start {$this.Starts++}
    $script:UnifiedComparisonPoller | Add-Member ScriptMethod Stop {$this.Stops++}
    $script:UnifiedAsyncClient=[pscustomobject]@{Sends=0;Pending=$null;LastPath='';ThrowOnSend=$false;SeenCts=$null}
    $script:UnifiedAsyncClient | Add-Member ScriptMethod SendAsync {
        param($Request,$Token)
        $this.Sends++; $this.LastPath=$Request.RequestUri.AbsolutePath; $this.SeenCts=$script:UnifiedAsyncCts
        if ($this.ThrowOnSend) { throw 'Injected transport construction failure' }
        $this.Pending=New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]'
        return $this.Pending.Task
    }
}
function Finish-Response([int]$Status = 200) {
    $r=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$Status)
    $r.Content=[System.Net.Http.StringContent]::new('{"ok":true}')
    [void]$script:UnifiedAsyncClient.Pending.TrySetResult($r)
    return $r
}

# A settled HTTP action cannot re-enable connection/profile mutations while
# the captured protection owner is still pending. Explicit protection recovery
# stays reachable when idle, and an in-flight action retains Cancel/Disconnect.
Reset-Fixture
$MutationControls=@('UnifiedSettingsButton','UnifiedPresetsButton','UnifiedNodesButton','UnifiedModeCombo','UnifiedMultihop','UnifiedEntryCombo','UnifiedExitCombo','UnifiedExecution','UnifiedCandidatesButton','UnifiedFastestNode','UnifiedForwardButton','UnifiedPerformanceButton','UnifiedNodeCombo','UnifiedDnsCombo','UnifiedTorButton','UnifiedExternalNodeButton','UnifiedExternalPathButton')
SetUnifiedAsyncUI $false
foreach($Name in $MutationControls){Assert (Control $Name).IsEnabled ('Idle action did not release '+$Name)}
$script:UnifiedProtectionPending=$true
SetUnifiedAsyncUI $false
foreach($Name in $MutationControls){Assert (-not(Control $Name).IsEnabled) ('Pending protection enabled mutation '+$Name)}
Assert ((Control 'UnifiedKillSwitch').IsEnabled-and-not(Control 'UnifiedConnectButton').IsEnabled) 'Pending protection hid explicit recovery or enabled Connect'
SetUnifiedAsyncUI $true 'Connect'
foreach($Name in $MutationControls){Assert (-not(Control $Name).IsEnabled) ('Busy action enabled mutation '+$Name)}
Assert (-not(Control 'UnifiedKillSwitch').IsEnabled-and(Control 'UnifiedConnectButton').IsEnabled-and(Control 'UnifiedConnectButton').Content-ceq'Cancel / Disconnect') 'Busy protected action lost Cancel/Disconnect or enabled a protection mutation'
$script:UnifiedProtectionPending=$false
SetUnifiedAsyncUI $false
foreach($Name in $MutationControls){Assert (Control $Name).IsEnabled ('Drained protection did not release '+$Name)}
Assert ((Control 'UnifiedKillSwitch').IsEnabled-and(Control 'UnifiedConnectButton').IsEnabled) 'Drained protection did not release idle connection controls'

Reset-Fixture
Assert (StartUnifiedApiAsync 'Connect' '/api/connect-logical' 'POST' @{} 30 $null $null $null) 'Pending-protection completion fixture did not start'
[void](Finish-Response)
$script:UnifiedProtectionPending=$true
CompleteUnifiedApiAsync
foreach($Name in $MutationControls){Assert (-not(Control $Name).IsEnabled) ('HTTP completion overrode pending protection for '+$Name)}
Assert (-not(UnifiedAsyncBusy)-and(Control 'UnifiedKillSwitch').IsEnabled-and-not(Control 'UnifiedConnectButton').IsEnabled) 'HTTP completion confused its reservation with pending protection'
Write-Host 'PASS pending protection survives HTTP completion and preserves exact recovery/cancel controls'

Reset-Fixture
Assert (StartUnifiedApiAsync 'Connect' '/api/connect-logical' 'POST' @{} 30 {param($r)$script:Successes++} $null $null) 'First request did not start'
$r=Finish-Response
$owner=$script:UnifiedAsyncTask
Assert (UnifiedAsyncBusy) 'Completed HTTP task released ownership before the UI callback drained it'
Assert (-not (StartUnifiedApiAsync 'Second' '/api/strategy/auto' 'POST' @{})) 'Second action replaced an undrained result'
Assert ([object]::ReferenceEquals($owner,$script:UnifiedAsyncTask)) 'Pending result identity changed'
CompleteUnifiedApiAsync
Assert ($script:Successes -eq 1 -and -not (UnifiedAsyncBusy)) 'Successful completion did not settle exactly once'
Write-Host 'PASS completed-but-undrained response owns the action'

Reset-Fixture
$script:ReentrantAccepted=$false; $script:CallbackBusy=$false; $script:FinalizerBusy=$false
[void](StartUnifiedApiAsync 'Connect' '/api/connect-logical' 'POST' @{} 30 {
    param($r)
    $script:Successes++; $script:CallbackBusy=UnifiedAsyncBusy
    $script:ReentrantAccepted=StartUnifiedApiAsync 'Nested' '/api/strategy/auto' 'POST' @{}
    CompleteUnifiedApiAsync
} $null {$script:Finalizers++;$script:FinalizerBusy=UnifiedAsyncBusy})
$r=Finish-Response
CompleteUnifiedApiAsync
Assert ($script:CallbackBusy -and $script:FinalizerBusy -and -not $script:ReentrantAccepted) 'Callbacks lost their operation reservation'
Assert ($script:Successes -eq 1 -and $script:Finalizers -eq 1 -and $script:UnifiedAsyncClient.Sends -eq 1) 'Reentrant completion ran twice'
Assert (-not (UnifiedAsyncBusy)) 'Completion leaked reservation'
Write-Host 'PASS callback/finalizer reentrancy cannot replace the action'

Reset-Fixture
[void](StartUnifiedApiAsync 'Connect' '/api/connect-logical' 'POST' @{} 30 {param($r)$script:Successes++} $null $null)
$r=Finish-Response
Assert (CancelUnifiedApiAsync $true) 'Cancellation ignored a completed undrained response'
CompleteUnifiedApiAsync
Assert ($script:Successes -eq 0) 'Cancelled response executed success callback'
Assert ($script:UnifiedAsyncClient.Sends -eq 2 -and $script:UnifiedAsyncClient.LastPath -eq '/api/disconnect') 'Cancel did not start the authoritative disconnect'
Assert (UnifiedAsyncBusy) 'Disconnect did not retain the new reservation'
$r=Finish-Response
CompleteUnifiedApiAsync
Assert (-not (UnifiedAsyncBusy)) 'Disconnect failed to settle'
Write-Host 'PASS late cancel suppresses success and owns disconnect'

Reset-Fixture
[void](StartUnifiedApiAsync 'Retest' '/api/mtu/retest' 'POST' @{} 30 $null $null {throw 'Injected finalizer failure'})
$r=Finish-Response
CompleteUnifiedApiAsync
Assert (-not (UnifiedAsyncBusy)) 'Throwing finalizer left the action busy'
Assert ($null -eq $script:UnifiedAsyncTask -and $null -eq $script:UnifiedAsyncCts) 'Throwing finalizer retained task resources'
$disposed=$false;try { $null=$r.Content.ReadAsStringAsync().GetAwaiter().GetResult() } catch { $disposed=$true }
Assert $disposed 'Response was not disposed after finalizer failure'
Write-Host 'PASS finalizer failure still releases resources'

Reset-Fixture
$script:UnifiedAsyncClient.ThrowOnSend=$true
$result=StartUnifiedApiAsync 'Retest' '/api/mtu/retest' 'POST' @{} 30 $null {param($e)$script:Failures++} {$script:Finalizers++}
Assert (-not $result -and -not (UnifiedAsyncBusy)) 'Synchronous send failure retained operation ownership'
Assert ($script:Failures -eq 1 -and $script:Finalizers -eq 1) 'Send failure callbacks were not exactly once'
Assert ($null -eq $script:UnifiedAsyncRequest -and $null -eq $script:UnifiedAsyncCts) 'Send failure leaked request state'
Assert ($null -ne $script:UnifiedAsyncClient.SeenCts) 'Fixture did not capture the cancellation source'
$disposed=$false;try { $null=$script:UnifiedAsyncClient.SeenCts.get_Token() } catch { $disposed=$true }
Assert $disposed 'Send failure leaked cancellation source'
Write-Host 'PASS synchronous send failure cleans its reservation and resources'

Reset-Fixture
[void](StartUnifiedApiAsync 'Retest' '/api/mtu/retest' 'POST' @{} 30 {param($r)$script:Successes++} $null {$script:Finalizers++})
$r=Finish-Response
$script:UnifiedAsyncClosed=$true
[void](CancelUnifiedApiAsync $false)
CompleteUnifiedApiAsync
Assert ($script:Successes -eq 0 -and $script:Finalizers -eq 0 -and $script:Refreshes -eq 0) 'Closed window received a UI callback'
Assert (-not (StartUnifiedApiAsync 'Late' '/api/strategy/auto' 'POST' @{})) 'Closed window accepted a new request'
Write-Host 'PASS closed window suppresses callbacks and new actions'

# A multihop request owns its independent read-only observer. Cancelling an
# already completed HTTP request must still cancel the observer and suppress
# success before the authoritative Disconnect begins.
Reset-Fixture
[void](StartUnifiedApiAsync 'Compare multihop' '/api/multihop/connect' 'POST' @{execution='auto'} 180 {param($r)$script:Successes++} $null $null)
Assert ($script:UnifiedComparisonWatching -and $script:UnifiedComparisonPoller.Starts -eq 1) 'Multihop did not start its shipping progress observer'
Assert ($script:UnifiedComparisonOldID -eq 'old-comparison') 'Observer did not freeze the previous comparison identity'
$script:UnifiedComparisonCts=[System.Threading.CancellationTokenSource]::new()
$observerCts=$script:UnifiedComparisonCts
$r=Finish-Response
[void](CancelUnifiedApiAsync $true)
Assert (-not $script:UnifiedComparisonWatching -and $observerCts.IsCancellationRequested) 'Cancel left the comparison observer running'
CompleteUnifiedApiAsync
Assert ($script:Successes -eq 0 -and $script:UnifiedAsyncClient.LastPath -eq '/api/disconnect') 'Cancelled comparison skipped Disconnect or ran success'
Assert (-not $script:UnifiedComparisonWatching) 'Disconnect restarted the old comparison observer'
$r=Finish-Response
CompleteUnifiedApiAsync
$observerCts.Dispose();$script:UnifiedComparisonCts=$null
Write-Host 'PASS multihop observer cancellation retains exact action ownership'

Reset-Fixture
StartUnifiedComparisonProgress
$script:UnifiedComparisonCts=[System.Threading.CancellationTokenSource]::new()
$observerCts=$script:UnifiedComparisonCts
StopUnifiedComparisonProgress
StopUnifiedComparisonProgress
Assert (-not $script:UnifiedComparisonWatching -and $observerCts.IsCancellationRequested) 'Repeated observer stop did not remain cancelled'
$observerCts.Dispose();$script:UnifiedComparisonCts=$null
Write-Host 'PASS repeated comparison observer cancellation is idempotent'

# Real emitted observer/control methods with an explicit private HTTP transport
# boundary. No public Tor circuits or synthetic network success are claimed.
function Tor-Body([string]$RequestID,[bool]$Speed=$false){
    if($Speed){return @{scope='temporary';topology='external';node_id='tor';entry_id='private';execution='auto';comparison_request_id=$RequestID}}
    return @{profile_id='tor';execution='auto';comparison_request_id=$RequestID}
}
function Progress-Value([string]$RequestID,[bool]$Complete=$false){
    return @{execution='local';comparison=@{id='opaque-native-progress';request_id=$RequestID;stage='measured';complete=$Complete;last_node_measurement='tor-last-relay-http';external_measurement='same-captured-endpoint-http';measurements=@(@{candidate=@{execution='local';transport='tor'};eligible=$true;last_node_ms=20;external_ms=40;score_ms=30})}}
}
function Finish-Progress($Value,[string]$Prefix=''){
    $r=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK)
    $r.Content=[System.Net.Http.StringContent]::new($Prefix+($Value|ConvertTo-Json -Depth 12 -Compress))
    [void]$script:UnifiedComparisonClient.Pending.TrySetResult($r)
    PollUnifiedComparisonProgress
}
$nonce='a'*32;$nextNonce='b'*32
foreach($speed in @($false,$true)){
    Reset-Fixture
    $path=if($speed){'/api/speed-lab/run'}else{'/api/external-profile/connect'}
    $body=Tor-Body $nonce $speed
    Assert ((UnifiedCapturedComparisonTimeout $path (UnifiedCapturedComparisonRequestID $path 'POST' $body) 180)-eq$(if($speed){960}else{540})) 'Captured Tor comparison used the wrong bounded HTTP budget.'
    Assert (StartUnifiedApiAsync 'Tor Compare' $path 'POST' $body 180 $null $null $null {param($status,$text)$script:ProgressCallbacks++;$script:ProgressText=$text}) 'Captured Tor comparison did not start.'
    Assert ($script:UnifiedComparisonWatching-and$script:UnifiedComparisonExpectedID-ceq$nonce) 'Tor request did not retain its exact observer identity.'
    PollUnifiedComparisonProgress
    Assert ($script:UnifiedComparisonClient.LastPath-ceq'http://127.0.0.1:8788/api/multihop/status'-and$script:UnifiedComparisonClient.LastMethod-ceq'GET') 'Observer escaped the read-only loopback status endpoint.'
    foreach($fault in @('wrong-request','missing-request','wrong-last','wrong-external','oversized')){
        $value=Progress-Value $nonce
        switch($fault){
            'wrong-request'{$value.comparison.request_id=$nextNonce}
            'missing-request'{$value.comparison.Remove('request_id')}
            'wrong-last'{$value.comparison.last_node_measurement='icmp'}
            'wrong-external'{$value.comparison.external_measurement='different-endpoint'}
        }
        Finish-Progress $value $(if($fault-ceq'oversized'){' '*32769}else{''})
        Assert ($script:ProgressCallbacks-eq0-and-not(Control 'UnifiedComparisonText').Text) ('Foreign/malformed comparison reached UI: '+$fault)
        $script:UnifiedComparisonNext=[DateTime]::MinValue;PollUnifiedComparisonProgress
    }
    Finish-Progress (Progress-Value $nonce)
    Assert ($script:ProgressCallbacks-eq1-and$script:ProgressText-like'*last-relay HTTP*same external-server HTTP*'-and$script:ProgressText-like'*30.0 ms*') 'Exact Tor progress did not render its actual HTTP measurements.'
    $script:UnifiedComparisonNext=[DateTime]::MinValue;PollUnifiedComparisonProgress
    Finish-Progress (Progress-Value $nonce $true)
    Assert ($script:ProgressCallbacks-eq2-and-not$script:UnifiedComparisonWatching-and$null-eq$script:UnifiedComparisonCallback-and(UnifiedAsyncBusy)) 'Comparison completion incorrectly ended throughput/connection work or retained its callback.'
    [void](Finish-Response);CompleteUnifiedApiAsync
}
Write-Host 'PASS Tor Connect and Speed Lab exact request, truthful measurement labels, bounded observer and terminal ownership'

foreach($fault in @('uppercase','short','number','local','unrelated-path','current-scope')){
    Reset-Fixture;$path='/api/speed-lab/run';$body=Tor-Body $nonce $true
    switch($fault){'uppercase'{$body.comparison_request_id='A'*32};'short'{$body.comparison_request_id='a'};'number'{$body.comparison_request_id=7};'local'{$body.execution='local'};'unrelated-path'{$path='/api/profiles'};'current-scope'{$body.scope='current'}}
    Assert (-not(StartUnifiedApiAsync 'Invalid comparison' $path 'POST' $body 180)) ('Invalid request identity reached transport: '+$fault)
    Assert ($script:UnifiedAsyncClient.Sends-eq0-and-not(UnifiedAsyncBusy)-and-not$script:UnifiedComparisonWatching) 'Invalid comparison retained an owner or sent a request.'
}
Write-Host 'PASS malformed/non-Tor request correlation is rejected before transport'

Reset-Fixture
[void](StartUnifiedApiAsync 'First Tor' '/api/external-profile/connect' 'POST' (Tor-Body $nonce) 180 $null $null $null {param($s,$t)$script:ProgressCallbacks+=100})
PollUnifiedComparisonProgress;$oldPending=$script:UnifiedComparisonClient.Pending;$oldCts=$script:UnifiedComparisonCts
[void](CancelUnifiedApiAsync $false);[void](Finish-Response);CompleteUnifiedApiAsync
Assert $oldCts.IsCancellationRequested 'Cancelled comparison did not revoke its exact observer socket.'
[void](StartUnifiedApiAsync 'Replacement Tor' '/api/external-profile/connect' 'POST' (Tor-Body $nextNonce) 180 $null $null $null {param($s,$t)$script:ProgressCallbacks++;$script:ProgressText=$t})
# Even a stale task that happens to return the replacement nonce cannot change
# the replacement action: the task carries its separately captured generation.
$r=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK);$r.Content=[System.Net.Http.StringContent]::new(((Progress-Value $nextNonce)|ConvertTo-Json -Depth 12 -Compress));[void]$oldPending.TrySetResult($r)
PollUnifiedComparisonProgress
Assert ($script:ProgressCallbacks-eq0-and$script:UnifiedComparisonWatching-and$script:UnifiedComparisonExpectedID-ceq$nextNonce) 'Late prior-generation response mutated or stopped the replacement observer.'
$script:UnifiedComparisonNext=[DateTime]::MinValue;PollUnifiedComparisonProgress;Finish-Progress (Progress-Value $nextNonce)
Assert ($script:ProgressCallbacks-eq1) 'Current replacement observer could not progress after old resources drained.'
$script:UnifiedComparisonNext=[DateTime]::MinValue;PollUnifiedComparisonProgress;$ownerCts=$script:UnifiedComparisonCts
$script:UnifiedAsyncClosed=$true;PollUnifiedComparisonProgress;Finish-Progress (Progress-Value $nextNonce)
Assert ($script:ProgressCallbacks-eq1-and-not$script:UnifiedComparisonWatching-and$null-eq$script:UnifiedComparisonCallback) 'Closed window accepted a late comparison callback.'
[void](CancelUnifiedApiAsync $false);[void](Finish-Response);CompleteUnifiedApiAsync
Write-Host 'PASS exact observer generation survives old completion and close cancels its retained UI callback'

Reset-Fixture
[void](StartUnifiedApiAsync 'Tor Compare' '/api/external-profile/connect' 'POST' (Tor-Body $nonce) 180 $null $null $null {
    param($s,$t);$script:ProgressCallbacks++;StartUnifiedComparisonProgress ('b'*32) 540 {param($s,$t)$script:ProgressCallbacks+=10}
})
PollUnifiedComparisonProgress;Finish-Progress (Progress-Value $nonce $true)
Assert ($script:ProgressCallbacks-eq1-and$script:UnifiedComparisonWatching-and$script:UnifiedComparisonExpectedID-ceq$nextNonce) 'Old terminal callback stopped a replacement observer generation.'
$script:UnifiedComparisonNext=[DateTime]::MinValue;PollUnifiedComparisonProgress;Finish-Progress (Progress-Value $nextNonce)
Assert ($script:ProgressCallbacks-eq11) 'Nested replacement observer callback lost ownership.'
$script:UnifiedComparisonDeadline=[DateTime]::UtcNow.AddMilliseconds(-1);PollUnifiedComparisonProgress
Assert (-not$script:UnifiedComparisonWatching-and$null-eq$script:UnifiedComparisonCallback) 'Expired observer retained progress authority.'
[void](Finish-Response);CompleteUnifiedApiAsync
Write-Host 'PASS terminal callback replacement and bounded observer expiry preserve exact ownership'

# Parse the emitted handlers, not just the transformer that contains them as strings.
$handlers=[regex]::Match($source, '(?ms)^    \$handlers = @''\r?\n(.*?)\r?\n''@')
Assert $handlers.Success 'Shipping handler block missing'
$tokens=$null;$errors=$null
[void][System.Management.Automation.Language.Parser]::ParseInput($handlers.Groups[1].Value,[ref]$tokens,[ref]$errors)
Assert ($errors.Count -eq 0) ('Shipping event-handler parse failed: '+(($errors|ForEach-Object Message)-join '; '))
Write-Host 'PASS generated window event handlers parse'
Write-Host 'Windows async action regression tests: PASS (14 groups)'
