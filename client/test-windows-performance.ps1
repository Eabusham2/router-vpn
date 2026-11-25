param([string]$Root = (Split-Path $PSScriptRoot -Parent), [string]$Mutant = "", [string]$NativeOriginals = "")
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
$RoleCheck='-or$current.RolesJSON-cne$Original.RolesJSON'
$Mutations['local-roles']=@($RoleCheck,'-or($Original.Winner-and$current.RolesJSON-cne$Original.RolesJSON)')
$Mutations['selected-roles']=@($RoleCheck,'-or(-not$Original.Winner-and$current.RolesJSON-cne$Original.RolesJSON)')
$Mutations['draft-hops']=@(' $State.Timer.Stop();$Body=$State.Pending;$State.Pending=$null',' $State.Timer.Stop();$Body=$State.Pending;$State.Pending=$null;if($null-ne$Body){$Body.entry_id=[string]$MultihopEntryCombo.SelectedValue;$Body.exit_id=[string]$MultihopExitCombo.SelectedValue}')
if($Mutant){
 if(-not$Mutations.ContainsKey($Mutant)){throw 'Unknown Performance mutant'}
 $Pair=$Mutations[$Mutant]
 if(-not$ProductSource.Contains($Pair[0])){throw 'Performance mutation anchor missing'}
 $ProductSource=$ProductSource.Replace($Pair[0],$Pair[1])
}
$Ast=[ScriptBlock]::Create($ProductSource).Ast
foreach($Name in @($names)+@('GetUnifiedGlobeHopColor','GetUnifiedGlobeActiveRoute','UnifiedPerformanceOwned','SetUnifiedPerformanceIdle','GetUnifiedPerformanceLocalSource','TestUnifiedPerformanceLocalResult','CancelUnifiedPerformance','CloseUnifiedPerformance','FinishUnifiedPerformanceRequest','StartUnifiedPerformanceRequest','ContinueUnifiedPerformanceHop','ShowUnifiedAdvancedPerformance')){
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
 return [pscustomobject]@{Dialog=$Dialog;Result=[pscustomobject]@{Text='ready'};Cancel=[pscustomobject]@{IsEnabled=$false};Buttons=@([pscustomobject]@{IsEnabled=$true});Current=$null;Task=$null;Pending=$null;PendingThroughput=$null;Closed=$false;Timer=$Timer}
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
foreach($case in @('9','16','server','duplicate','foreign','reordered','short','borrowed','paired-9','paired-16','paired-absent','paired-changed','paired-mixed','paired-foreign','paired-type','selected-local','selected-server','selected-private-local','selected-private-server','selected-private-lost','selected-private-swap','selected-private-label','selected-private-first','selected-private-second','selected-generation','selected-winner','selected-mixed','mixed-9','mixed-16','mixed-96','mixed-type','mixed-range','mixed-both','mixed-removed','mixed-shift','mixed-label','roles-9','roles-16','roles-96','roles-removed','roles-swapped','roles-reported','roles-label','roles-packets','roles-paired','roles-selected','roles-space','roles-public-interiors')){
 $n=if($case -cin @('mixed-96','roles-96')){96}elseif($case-cin@('16','paired-16','selected-server','mixed-16','roles-16')){16}else{9};$ids=@('active-entry')+@(1..($n-2)|ForEach-Object{"public-$_"})+@('active-exit')
 $source=@{source_sha256=('b'*64);config_sha256=('c'*64);node_ids=$ids}
 $graph=@{connected=$true;entry_id=$ids[0];exit_id=$ids[-1];ordered_capture=$Capture;ordered_nodes=$n;execution='local';ordered_local_source=$source}
 $selected=$case.StartsWith('selected-');$winner=if($case -cin @('selected-local','selected-private-local')){'local'}else{'server'}
 $mixed=$case.StartsWith('mixed-');if($mixed){$source.paired_prefix_nodes=2}
 $roleSource=$case.StartsWith('roles-')
 if($roleSource){
  $roles=@(for($i=0;$i -lt $n;$i++){if($i -in @(0,2,3,($n-2),($n-1))){'private-node'}else{'public-path'}})
  if($case -ceq 'roles-public-interiors'){for($i=1;$i -lt $n-1;$i++){$roles[$i]='public-path'}}
  $source.local_roles_json=ConvertTo-Json -InputObject $roles -Compress
  if($case -ceq 'roles-packets'){$source.paired_prefix_nodes=1}
  if($case -ceq 'roles-paired'){$source.paired_wireguard=$true}
  if($case -ceq 'roles-space'){$source.local_roles_json=' '+$source.local_roles_json}
  if($case -ceq 'roles-selected'){$selected=$true;$winner='server'}
 }
 if($case -ceq 'mixed-type'){$source.paired_prefix_nodes='2'};if($case -ceq 'mixed-range'){$source.paired_prefix_nodes=$n-1};if($case -ceq 'mixed-both'){$source.paired_wireguard=$true}
 $selectedPrivate=$case.StartsWith('selected-private-')
 if($selectedPrivate){
  $roles=@(for($i=0;$i -lt $n;$i++){if($i -in @(0,($n-2),($n-1))){'private-node'}else{'public-path'}})
  if($case -ceq 'selected-private-first'){$roles[1]='private-node';$roles[-2]='public-path'}
  if($case -ceq 'selected-private-second'){$roles[2]='private-node'}
  $source.selected_roles_json=ConvertTo-Json -InputObject $roles -Compress
 }
 $paired=$case.StartsWith('paired-');if($paired -and $case -cne 'paired-foreign'){$source.paired_wireguard=if($case -ceq 'paired-type'){'true'}else{$true}}
 if($selected){$graph.Remove('ordered_local_source');$source.selected_execution=$winner;$source.generation_sha256='d'*64;$graph.ordered_original_source=$source;$graph.execution=$winner}
 if($case-ceq'selected-mixed'){$graph.ordered_local_source=$source}
 if($case-ceq'server'){$graph.execution='server'};if($case-ceq'duplicate'){$ids[2]=$ids[1]}
 $view=$graph.Clone();if($case-ceq'borrowed'){$view.ordered_nodes=3;$view.Remove('ordered_local_source')}
 Reset-Performance;$State=New-Panel;& $Hop;Finish-Performance ($view|ConvertTo-Json -Depth 8 -Compress);& $Tick
 if($case-cin@('server','duplicate','selected-mixed','paired-type','mixed-type','mixed-range','mixed-both','roles-packets','roles-paired','roles-space','roles-selected','roles-public-interiors','selected-private-first','selected-private-second')){Check ($Requests.Count-eq1) 'Unqualified depth consumed throughput';continue}
 $body=$Requests[1].Body|ConvertFrom-Json
 Check ($Requests.Count-eq2-and$body.bytes-eq8388608-and$body.ordered_capture-ceq$Capture) 'Extended original throughput POST omitted'
 $rows=@(for($i=0;$i-lt$n;$i++){
  $role=if($i-eq0){'entry'}elseif($i-eq($n-1)){'exit'}else{'intermediate'}
  $prefix=if($selected){"Cumulative $winner path"}else{"Cumulative path"};$label="$prefix through node $($i+1) of $n";if($roleSource -or $selectedPrivate){
   $public=$roles[$i] -ceq 'public-path';if($case -cin @('roles-label','selected-private-label') -and $i -eq $n-2){$public=$true}
   if($public){$label+=' to the public benchmark'}
  }elseif($role-ceq'intermediate' -and (-not $mixed -or $i -ge 2 -or $case -ceq 'mixed-label') -and (-not $paired -or ($case -ceq 'paired-mixed' -and $i -eq ($n-2)))){$label+=' to the public benchmark'}
  @{role=$role;router_id=$ids[$i];speed_label=($label+' transfer');latency_label=($label+' HTTP response');speed=@{router_id=$ids[$i];bytes=8388608};latency=@{router_id=$ids[$i]}}
 })
 if($case -ceq 'roles-removed'){$source.Remove('local_roles_json')}
 if($case -ceq 'roles-swapped' -or $case -ceq 'roles-reported'){
  $roles[1],$roles[2]=$roles[2],$roles[1];$source.local_roles_json=ConvertTo-Json -InputObject $roles -Compress
  if($case -ceq 'roles-reported'){
   for($i=1;$i -le 2;$i++){$prefix="Cumulative path through node $($i+1) of $n";if($roles[$i] -ceq 'public-path'){$prefix+=' to the public benchmark'};$rows[$i].speed_label=$prefix+' transfer';$rows[$i].latency_label=$prefix+' HTTP response'}
  }
 }
 if($case -ceq 'selected-private-lost'){$source.Remove('selected_roles_json')}
 if($case -ceq 'selected-private-swap'){$roles[2]='private-node';$roles[-2]='public-path';$source.selected_roles_json=ConvertTo-Json -InputObject $roles -Compress}
 if($case -ceq 'mixed-removed'){$source.Remove('paired_prefix_nodes')};if($case -ceq 'mixed-shift'){$source.paired_prefix_nodes=3}
 if($case -ceq 'paired-absent'){$source.Remove('paired_wireguard')};if($case -ceq 'paired-changed'){$source.paired_wireguard=$false}
 if($case-ceq'foreign'){$source.config_sha256='d'*64};if($case-ceq'reordered'){$rows[2],$rows[3]=$rows[3],$rows[2]};if($case-ceq'short'){$rows=$rows[0..($n-2)]}
 if($case-ceq'selected-generation'){$source.generation_sha256='e'*64}
 if($case-ceq'selected-winner'){$source.selected_execution='local'}
 if(-not$selected){$graph.Remove('execution')};$graph.mode='multihop';$graph.bytes=8388608;$graph.hops=$rows
 Finish-Performance ($graph|ConvertTo-Json -Depth 8 -Compress)
 if($case-cin@('9','16','selected-local','selected-server','mixed-9','mixed-16','mixed-96')){Check ($State.Result.Text.Contains($ids[-2])-and$State.Result.Text.Contains('to the public benchmark transfer')) 'Extended Local original late hop not displayed'}
 elseif($case -cin @('selected-private-local','selected-private-server')){
  $published=$State.Result.Text|ConvertFrom-Json
  Check ($published.ordered_original_source.selected_roles_json -ceq $source.selected_roles_json -and $published.hops[-2].speed_label -ceq "Cumulative $winner path through node $($n-1) of $n transfer") 'Selected private member lost its original transfer label'
 }
 elseif($case -cin @('roles-9','roles-16','roles-96')){
  $published=$State.Result.Text|ConvertFrom-Json
  Check ($published.ordered_local_source.local_roles_json -ceq $source.local_roles_json -and $published.hops[-2].speed_label -ceq "Cumulative path through node $($n-1) of $n transfer" -and $published.hops[1].speed_label.Contains('to the public benchmark')) 'Mixed private stream throughput roles were lost'
 }
 elseif($case -ceq 'roles-removed'){Check ($State.Result.Text.Contains('another ordered route')) 'Result stripped the retained throughput role source'}
 elseif($case -ceq 'selected-private-lost'){Check ($State.Result.Text.Contains('another ordered route')) 'Result stripped the selected throughput role source'}
 elseif($case -ceq 'roles-reported'){Check ($State.Result.Text.Contains('another ordered route')) 'Changed source and relabeled rows replaced the retained throughput roles'}
 elseif($case -cin @('paired-9','paired-16')){Check ($State.Result.Text.Contains($ids[-2]) -and -not $State.Result.Text.Contains('to the public benchmark')) 'Paired throughput lost the private late hop'}
 else{Check ($State.Result.Text.Contains('another ordered route')) 'Foreign extended throughput results adopted'}
}
if($NativeOriginals){
 foreach($n in @(9,16)){
  $preflight=Get-Content -Raw -Encoding UTF8 (Join-Path $NativeOriginals "$n-get.json")
  $original=$preflight|ConvertFrom-Json
  $result=Get-Content -Raw -Encoding UTF8 (Join-Path $NativeOriginals "$n-post.json")
  Reset-Performance;$State=New-Panel;& $Hop;Finish-Performance $preflight;& $Tick
  $body=$Requests[1].Body|ConvertFrom-Json
  Check ($Requests.Count-eq2-and$body.entry_id-ceq$original.entry_id-and$body.exit_id-ceq$original.exit_id-and$body.ordered_capture-ceq$original.ordered_capture-and$body.bytes-eq8388608) 'Native exact throughput POST lost original ownership'
  Finish-Performance $result
  $displayed=$State.Result.Text|ConvertFrom-Json;$measured=$result|ConvertFrom-Json
  Check ($displayed.hops.Count-eq$n-and($displayed|ConvertTo-Json -Depth 20 -Compress)-ceq($measured|ConvertTo-Json -Depth 20 -Compress)) 'Native throughput display changed original receipts'
  Write-Output "PowerShell displayed all $n exact native throughput rows"
 }
}
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
foreach($count in @(2,8,9,16,96,97)){
 $ids=@(1..$count | ForEach-Object {"saved-node-$_"})
 $status=[pscustomobject]@{connected=$true;actual_entry_id=$ids[0];actual_exit_id=$ids[-1];active_node_ids=$ids;active_route_id='a'*64}
 $route=GetUnifiedGlobeActiveRoute $status
 if($count-gt96){Check ($null-eq$route) 'Globe adopted over-budget graph';continue}
 Check ($route.RouteID-ceq$status.active_route_id-and($route.IDs-join ',')-ceq($ids-join ',')) 'Globe dropped or reordered the active route'
 for($position=0;$position-lt$count;$position++){
  $color=GetUnifiedGlobeHopColor $position $count
  if($position-eq0){Check ($color-ceq'#3791FF') 'Globe changed the entry color'}
  elseif($position-eq$count-1){Check ($color-ceq'#FF9A32') 'Globe changed the exit color'}
  else{Check ($color-cin@('#44C878','#C29BFF','#F2D05D','#56CFD5','#F25BAC','#889BFF')) 'Globe dropped a late interior color'}
 }
 if($count-gt8){$status.active_node_ids[$count-2]=$ids[0];Check ($null-eq(GetUnifiedGlobeActiveRoute $status)) 'Globe accepted duplicate late member'}
}
Write-Host "Composed Windows Advanced Performance: PASS ($script:Checks checks; actual callbacks and async owner, transport/WPF boundaries doubled)"
