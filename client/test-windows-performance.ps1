param([string]$Root = (Split-Path $PSScriptRoot -Parent), [string]$Mutant = "")
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Reuse the real async-owner fixture's transport/timer boundaries, not a second
# implementation of admission, cancellation or completed-task retirement.
$OwnerFixture=Get-Content -Raw -Encoding UTF8 (Join-Path $Root 'client/test-windows-async-actions.ps1')
$Boundary=$OwnerFixture.IndexOf('# A settled HTTP action')
if($Boundary-lt0){throw 'Actual async fixture boundary changed'}
. ([ScriptBlock]::Create($OwnerFixture.Substring(0,$Boundary))) -Root $Root
$Client=Join-Path $Root 'client'
$Launcher=Get-Content -Raw -Encoding UTF8 (Join-Path $Client 'RouterVPN-Windows-App.ps1')
$LauncherAst=[ScriptBlock]::Create($Launcher).Ast
$Help=@($LauncherAst.FindAll({param($n)$n-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Set-RouterVPNProductHelpBinding'},$true))
if($Help.Count-ne1){throw 'Actual Help transform changed'}
. ([ScriptBlock]::Create($Help[0].Extent.Text))
$LoadStart=$Launcher.IndexOf('$ProfileSettingsHelpers=');$LoadEnd=$Launcher.IndexOf('# The shipping Windows product',$LoadStart)
$ComposeStart=$Launcher.IndexOf('$Product=Join-Path');$ComposeEnd=$Launcher.IndexOf('$ProductScript=[ScriptBlock]::Create($ProductSource)',$ComposeStart)
if($LoadStart-lt0-or$LoadEnd-le$LoadStart-or$ComposeStart-lt0-or$ComposeEnd-le$ComposeStart){throw 'Shipping composition seam changed'}
# Execute the launcher's actual helper loading and all transforms, never WPF,
# ProductScript, a controller request or a VPN connection.
. ([ScriptBlock]::Create($Launcher.Substring($LoadStart,$LoadEnd-$LoadStart).Replace('$PSScriptRoot','$Client')))
. ([ScriptBlock]::Create($Launcher.Substring($ComposeStart,$ComposeEnd-$ComposeStart).Replace('$PSScriptRoot','$Client')))
# Causal controls alter only the materialized shipping code in this process.
# The normal fixture always executes the exact final composition unchanged.
$Mutations=@{
 'close-cancel'=@('$D.Add_Closed({CloseUnifiedPerformance $State}.GetNewClosure())','$D.Add_Closed({}.GetNewClosure())')
 'closed-result'=@('return -not$State.Closed-and[object]::ReferenceEquals($State.Current,$Token)','return [object]::ReferenceEquals($State.Current,$Token)')
 'foreign-cancel'=@('$null-ne$State.Task-and[object]::ReferenceEquals($State.Task,$script:UnifiedAsyncTask)-and(UnifiedAsyncBusy)','$null-ne$State.Task-and(UnifiedAsyncBusy)')
}
# Single-quoted strings retain the original emitted variables literally.
$Mutations['draft-hops']=@(' $State.Timer.Stop();$Body=$State.Pending;$State.Pending=$null',' $State.Timer.Stop();$Body=$State.Pending;$State.Pending=$null;if($null-ne$Body){$Body.entry_id=[string]$MultihopEntryCombo.SelectedValue;$Body.exit_id=[string]$MultihopExitCombo.SelectedValue}')
if($Mutant){
 if(-not$Mutations.ContainsKey($Mutant)){throw 'Unknown Performance mutant'}
 $Pair=$Mutations[$Mutant]
 if(-not$ProductSource.Contains($Pair[0])){throw 'Performance mutation anchor missing'}
 $ProductSource=$ProductSource.Replace($Pair[0],$Pair[1])
}
$Ast=[ScriptBlock]::Create($ProductSource).Ast
foreach($Name in @($names)+@('UnifiedPerformanceOwned','SetUnifiedPerformanceIdle','CancelUnifiedPerformance','CloseUnifiedPerformance','FinishUnifiedPerformanceRequest','StartUnifiedPerformanceRequest','ContinueUnifiedPerformanceHop','ShowUnifiedAdvancedPerformance')){
 $Found=@($Ast.FindAll({param($n)$n-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$Name},$true))
 if($Found.Count-ne1){throw ('Actual composed function missing or duplicated: '+$Name)}
 . ([ScriptBlock]::Create($Found[0].Extent.Text))
}
$Panel=@($Ast.FindAll({param($n)$n-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'ShowUnifiedAdvancedPerformance'},$true))[0]
$Events=@($Panel.FindAll({param($n)$n-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Member.Extent.Text-like'Add_*'},$true))
function Panel-Event([string]$Receiver,[string]$Event){
 $Found=@($Events|Where-Object{$_.Expression.Extent.Text-ceq$Receiver-and$_.Member.Extent.Text-ceq$Event})
 if($Found.Count-ne1){throw "Actual panel event missing or duplicated: $Receiver $Event"}
 $Blocks=@($Found[0].Arguments[0].FindAll({param($n)$n-is[System.Management.Automation.Language.ScriptBlockExpressionAst]},$true))
 if($Blocks.Count-ne1){throw 'Actual panel event callback changed'}
 return $Blocks[0].ScriptBlock.GetScriptBlock()
}
$Live=Panel-Event "`$D.FindName('Live')" 'Add_Click'
$Durable=Panel-Event "`$D.FindName('Durable')" 'Add_Click'
$Speed=Panel-Event "`$D.FindName('Speed')" 'Add_Click'
$Hop=Panel-Event "`$D.FindName('HopSpeed')" 'Add_Click'
$ConnectedCandidates=Panel-Event "`$D.FindName('PrefixCandidates')" 'Add_Click'
$SavedCandidates=Panel-Event "`$D.FindName('SavedCandidates')" 'Add_Click'
$SavedPrefixCandidates=Panel-Event "`$D.FindName('SavedPrefixCandidates')" 'Add_Click'
$Cancel=Panel-Event "`$D.FindName('CancelTest')" 'Add_Click'
$Closed=Panel-Event '$D' 'Add_Closed'
$Tick=Panel-Event '$State.Timer' 'Add_Tick'
$script:Checks=0
function Check([bool]$Value,[string]$Message){$script:Checks++;if(-not$Value){[Console]::Error.WriteLine("WINDOWS_PERFORMANCE_ASSERT: "+$Message);throw $Message}}
function New-Panel {
 $Timer=[pscustomobject]@{Starts=0;Stops=0};$Timer|Add-Member ScriptMethod Start {$this.Starts++};$Timer|Add-Member ScriptMethod Stop {$this.Stops++}
 $Dialog=[pscustomobject]@{Activations=0};$Dialog|Add-Member ScriptMethod Activate {$this.Activations++;return $true}
 return [pscustomobject]@{Dialog=$Dialog;Result=[pscustomobject]@{Text='ready'};Cancel=[pscustomobject]@{IsEnabled=$false};Buttons=@([pscustomobject]@{IsEnabled=$true});Current=$null;Task=$null;Pending=$null;Closed=$false;Timer=$Timer}
}
function Reset-Performance {
 Reset-Fixture
 $script:UnifiedPerformancePanel=$null
 $script:ClosePerformanceDuringSend=$null
 $script:Requests=New-Object 'System.Collections.Generic.List[object]'
 $script:UnifiedAsyncClient|Add-Member -Force ScriptMethod SendAsync {
  param($Request,$Token)
  $this.Sends++;$this.LastPath=$Request.RequestUri.AbsolutePath;$this.SeenCts=$script:UnifiedAsyncCts
  $Raw=if($null-ne$Request.Content){$Request.Content.ReadAsStringAsync().GetAwaiter().GetResult()}else{''}
  $script:Requests.Add([pscustomobject]@{Path=$this.LastPath;Method=$Request.Method.Method;Body=$Raw})
  if($this.ThrowOnSend){throw 'Injected transport construction failure'}
  $this.Pending=New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]'
  if($null-ne$script:ClosePerformanceDuringSend){CloseUnifiedPerformance $script:ClosePerformanceDuringSend}
  return $this.Pending.Task
 }
}
function Finish-Performance([string]$JSON='{"measurement":"actual-result"}'){
 $R=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK)
 $R.Content=[System.Net.Http.StringContent]::new($JSON)
 [void]$script:UnifiedAsyncClient.Pending.TrySetResult($R)
 CompleteUnifiedApiAsync
}
function SelectedNode {return [pscustomobject]@{id='selected-node'}}
Reset-Performance;$State=New-Panel;& $Live
Check ($Requests[0].Path-ceq'/api/connection/live-latency'-and($Requests[0].Body|ConvertFrom-Json).samples-eq5) 'Live RTT no longer uses its distinct endpoint'
Finish-Performance
Reset-Performance;$State=New-Panel;& $Durable;$NodeBody=$Requests[0].Body|ConvertFrom-Json
Check ($Requests[0].Path-ceq'/api/profile/latency'-and$NodeBody.id-ceq'selected-node'-and$NodeBody.samples-eq50) 'Selected-node sampling changed its capture or count'
Finish-Performance
# Closing during synchronous UI admission still cancels once the actual task
# is returned; the per-panel token cannot be released early.
Reset-Performance;$State=New-Panel;$script:ClosePerformanceDuringSend=$State;& $Speed
Check ($State.Closed-and$null-ne$State.Current-and(UnifiedAsyncBusy)-and$script:UnifiedAsyncCts.IsCancellationRequested) 'Close during admission left the returned request uncancelled'
Finish-Performance

# Actual click + actual global owner: Cancel retains both until HTTP completion,
# even if the transport returns a successful result after cancellation.
Reset-Performance;$State=New-Panel;$script:UnifiedPerformancePanel=$State
& $Speed;$Token=$State.Current;$Task=$State.Task
Check ((UnifiedAsyncBusy)-and$null-ne$Token-and[object]::ReferenceEquals($Task,$script:UnifiedAsyncTask)) 'Speed did not retain the actual request owner'
Check ($Requests.Count-eq1-and$Requests[0].Path-ceq'/api/connection/speed-test'-and$Requests[0].Method-ceq'POST') 'Speed used another endpoint'
Check (-not$State.Buttons[0].IsEnabled-and$State.Cancel.IsEnabled) 'Running panel lost request controls'
$Second=New-Panel
Check (-not(StartUnifiedPerformanceRequest $Second 'duplicate' '/api/connection/speed-test' @{} 45 8 $false)) 'Concurrent panel replaced the owner'
& $Cancel
Check ((UnifiedAsyncBusy)-and[object]::ReferenceEquals($State.Current,$Token)-and$script:UnifiedAsyncCts.IsCancellationRequested) 'Cancel freed an unjoined request'
$Text=$State.Result.Text;Finish-Performance
Check (-not(UnifiedAsyncBusy)-and$null-eq$State.Current-and$State.Result.Text-ceq$Text-and$State.Buttons[0].IsEnabled) 'Cancelled completion adopted a late result or failed to retire'

# A second Advanced opening activates the same panel, and a closed-but-pending
# panel stays retained until its original async completion.
Reset-Performance;$State=New-Panel;$script:UnifiedPerformancePanel=$State
ShowUnifiedAdvancedPerformance
Check ($State.Dialog.Activations-eq1-and$Requests.Count-eq0) 'Duplicate Advanced panel was created'
& $Speed;$OldTask=$State.Task;$OldToken=$State.Current;$LateSuccess=$script:UnifiedAsyncSuccess;$LateFailure=$script:UnifiedAsyncFailure
& $Closed
Check ($State.Closed-and(UnifiedAsyncBusy)-and[object]::ReferenceEquals($State.Current,$OldToken)-and$script:UnifiedAsyncCts.IsCancellationRequested) 'Window close did not cancel while retaining original request'
$Text=$State.Result.Text;& $LateSuccess ([pscustomobject]@{measurement='stale'});& $LateFailure 'stale error'
Check ($State.Result.Text-ceq$Text) 'Closed dialog adopted a late callback'
ShowUnifiedAdvancedPerformance
Check ([object]::ReferenceEquals($script:UnifiedPerformancePanel,$State)) 'Closing panel was replaced before drain'
Finish-Performance
Check ($null-eq$script:UnifiedPerformancePanel-and$null-eq$State.Current-and-not(UnifiedAsyncBusy)) 'Closed panel was not released after actual completion'
$Old=$State;$State=New-Panel;& $Speed;$CurrentTask=$State.Task
# An old captured callback cannot cancel another action even with a retained
# stale local task/token; exact global task identity is required.
$Old.Current=$OldToken;$Old.Task=$OldTask;CloseUnifiedPerformance $Old
Check (-not$script:UnifiedAsyncCts.IsCancellationRequested-and[object]::ReferenceEquals($CurrentTask,$script:UnifiedAsyncTask)) 'Old window close cancelled a replacement request'
Finish-Performance

# Active status is captured before routed speed. Draft selectors deliberately
# disagree; callback completion cannot submit reentrantly while owner is busy.
Reset-Performance;$State=New-Panel
$MultihopEntryCombo=[pscustomobject]@{SelectedValue='draft-entry'};$MultihopExitCombo=[pscustomobject]@{SelectedValue='draft-exit'}
& $Hop
Check ($Requests.Count-eq1-and$Requests[0].Path-ceq'/api/multihop/status'-and$Requests[0].Method-ceq'GET') 'Hop test did not request the active graph first'
Finish-Performance '{"connected":true,"entry_id":"active-entry","exit_id":"active-exit"}'
Check ($Requests.Count-eq1-and$null-ne$State.Pending-and$State.Timer.Starts-eq1-and-not(UnifiedAsyncBusy)) 'Preflight did not retain the captured pending handoff'
& $Tick
$Body=$Requests[1].Body|ConvertFrom-Json
Check ($Requests.Count-eq2-and$Requests[1].Path-ceq'/api/multihop/speed-test'-and$Body.entry_id-ceq'active-entry'-and$Body.exit_id-ceq'active-exit'-and$Body.bytes-eq4194304) 'Hop test borrowed draft node IDs'
Finish-Performance
Check ($State.Result.Text.Contains('actual-result')-and$null-eq$State.Current) 'Actual hop result was not adopted'

# Ordered native routes capture every member through an opaque exact-owner token.
Reset-Performance;$State=New-Panel;& $Hop
$Capture=('a'*64)
Finish-Performance ('{"connected":true,"entry_id":"active-entry","exit_id":"active-exit","ordered_capture":"'+$Capture+'","ordered_nodes":3}')
& $Tick
$Body=$Requests[1].Body|ConvertFrom-Json
Check ($Body.ordered_capture-ceq$Capture-and$Body.bytes-eq8388608-and$Body.entry_id-ceq'active-entry'-and$Body.exit_id-ceq'active-exit') 'Ordered hop preflight lost exact capture or payload'
Finish-Performance '{"hops":[{"role":"entry","router_id":"a"},{"role":"intermediate","router_id":"middle-kept","speed_label":"Cumulative path through node 2 of 3"},{"role":"exit","router_id":"c"}]}'
Check ($State.Result.Text.Contains('middle-kept')-and$State.Result.Text.Contains('Cumulative path through node 2 of 3')) 'Ordered Performance dropped intermediate result or cumulative label'
foreach($Ordered in @('{"ordered_nodes":3}','{"ordered_capture":"bad","ordered_nodes":3}',('{"ordered_capture":"'+$Capture+'","ordered_nodes":true}'),('{"ordered_capture":"'+$Capture+'","ordered_nodes":9}'))){
 Reset-Performance;$State=New-Panel;& $Hop
 $Invalid='{"connected":true,"entry_id":"a","exit_id":"b",'+$Ordered.Substring(1)
 Finish-Performance $Invalid;& $Tick
 Check ($Requests.Count-eq1-and$null-eq$State.Pending) 'Invalid ordered capture reached pair endpoint'
}

foreach($Invalid in @('{}','{"connected":false,"entry_id":"a","exit_id":"b"}','{"connected":"true","entry_id":"a","exit_id":"b"}','{"connected":true,"entry_id":"a","exit_id":"a"}','{"connected":true,"entry_id":" ","exit_id":"b"}','{"connected":true,"entry_id":1,"exit_id":"b"}','{"connected":true,"entry_id":"a"}')){
 Reset-Performance;$State=New-Panel;& $Hop;Finish-Performance $Invalid;& $Tick
 Check ($Requests.Count-eq1-and$null-eq$State.Pending-and$null-eq$State.Current-and$State.Buttons[0].IsEnabled) ('Invalid active graph reached speed endpoint: '+$Invalid)
}
foreach($Action in @('cancel','close','superseded')){
 Reset-Performance;$State=New-Panel;& $Hop;Finish-Performance '{"connected":true,"entry_id":"a","exit_id":"b"}'
 if($Action-eq'cancel'){& $Cancel}elseif($Action-eq'close'){& $Closed}else{[void](StartUnifiedApiAsync 'unrelated' '/api/profile/latency' 'POST' @{id='other'} 20)}
 & $Tick
 Check (@($Requests|Where-Object{$_.Path-ceq'/api/multihop/speed-test'}).Count-eq0) ('Retired preflight issued a hop test: '+$Action)
 if($Action-eq'superseded'){Check (-not$script:UnifiedAsyncCts.IsCancellationRequested) 'Old preflight cancelled the new action';Finish-Performance}
}
# Same panel, later request: all callbacks are token-bound, including finalizers.
Reset-Performance;$State=New-Panel;& $Speed
$OldSuccess=$script:UnifiedAsyncSuccess;$OldFailure=$script:UnifiedAsyncFailure;$OldFinally=$script:UnifiedAsyncFinally
Finish-Performance;& $Speed;$Token=$State.Current;$Text=$State.Result.Text
& $OldSuccess ([pscustomobject]@{measurement='old'});& $OldFailure 'old error';& $OldFinally
Check ($State.Result.Text-ceq$Text-and[object]::ReferenceEquals($State.Current,$Token)) 'Old callback mutated a later request'
Finish-Performance
Reset-Performance;$State=New-Panel;$script:UnifiedAsyncClient.ThrowOnSend=$true;& $Speed
Check ($null-eq$State.Current-and-not(UnifiedAsyncBusy)-and$State.Buttons[0].IsEnabled) 'Transport startup failure leaked ownership'
# Execute the actual composed button callbacks. Only the destination dialog is
# doubled; these buttons must preserve three distinct captured test purposes.
$script:CandidateLaunches=New-Object 'System.Collections.Generic.List[object]'
function ShowOrderedCandidates([bool]$SavedPath=$false,[bool]$SavedPrefix=$false){$script:CandidateLaunches.Add([pscustomobject]@{SavedPath=$SavedPath;SavedPrefix=$SavedPrefix})}
try {
 & $ConnectedCandidates;& $SavedCandidates;& $SavedPrefixCandidates
 Check ($CandidateLaunches.Count-eq3) 'Candidate buttons did not invoke their original native dialog'
 Check (-not$CandidateLaunches[0].SavedPath-and-not$CandidateLaunches[0].SavedPrefix) 'Connected candidate button changed its purpose'
 Check ($CandidateLaunches[1].SavedPath-and-not$CandidateLaunches[1].SavedPrefix) 'Complete saved candidate button changed its purpose'
 Check (-not$CandidateLaunches[2].SavedPath-and$CandidateLaunches[2].SavedPrefix) 'Selected-prefix button launched a complete saved connection'
} finally {Remove-Item Function:ShowOrderedCandidates}
Write-Host "Composed Windows Advanced Performance: PASS ($script:Checks checks; actual callbacks and async owner, transport/WPF boundaries doubled)"
