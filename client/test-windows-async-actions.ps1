param([string]$Root = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Net.Http
$source = Get-Content -LiteralPath (Join-Path $Root 'client/RouterVPN-Windows-UnifiedShell.ps1') -Raw -Encoding UTF8
# Extract the actual emitted function definitions without constructing WPF or opening a VPN.
$extra = [regex]::Match($source, '(?ms)^    \$extraState = @''\r?\n(.*?)\r?\n''@')
if (-not $extra.Success) { throw 'Shipping async source block not found.' }
$ast = [ScriptBlock]::Create($extra.Groups[1].Value).Ast
$names = @('UnifiedAsyncBusy','SetUnifiedAsyncUI','StartUnifiedApiAsync','CancelUnifiedApiAsync','CompleteUnifiedApiAsync','StartUnifiedComparisonProgress','StopUnifiedComparisonProgress')
foreach ($name in $names) {
    $nodes = @($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}, $true))
    if ($nodes.Count -ne 1) { throw "Expected one shipping function: $name" }
    . ([ScriptBlock]::Create($nodes[0].Extent.Text))
}
function Assert([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Log([string]$Text) { $script:Messages.Add($Text) }
function Control([string]$Name) { if (-not $script:Controls.ContainsKey($Name)) { $script:Controls[$Name] = [pscustomobject]@{IsEnabled=$true;Content='Connect'} }; return $script:Controls[$Name] }
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
    $script:UnifiedAsyncPoller=[pscustomobject]@{Starts=0;Stops=0}
    $script:UnifiedAsyncPoller | Add-Member ScriptMethod Start {$this.Starts++}
    $script:UnifiedAsyncPoller | Add-Member ScriptMethod Stop {$this.Stops++}
    # Comparison functions are the shipping definitions above, not no-op stubs.
    # Only their timer/transport dependencies are doubled; no observer request
    # or VPN connection is made by this isolated lifecycle suite.
    $script:UnifiedComparisonWatching=$false; $script:UnifiedComparisonCts=$null
    $script:UnifiedComparisonLastID='old-comparison'; $script:UnifiedComparisonOldID=''
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

# Parse the emitted handlers, not just the transformer that contains them as strings.
$handlers=[regex]::Match($source, '(?ms)^    \$handlers = @''\r?\n(.*?)\r?\n''@')
Assert $handlers.Success 'Shipping handler block missing'
$tokens=$null;$errors=$null
[void][System.Management.Automation.Language.Parser]::ParseInput($handlers.Groups[1].Value,[ref]$tokens,[ref]$errors)
Assert ($errors.Count -eq 0) ('Shipping event-handler parse failed: '+(($errors|ForEach-Object Message)-join '; '))
Write-Host 'PASS generated window event handlers parse'
Write-Host 'Windows async action regression tests: PASS (9 groups)'
