param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
# Execute the actual launcher composition and existing asynchronous ownership
# witness, then extract this new dialog's shipping functions and callbacks.
. (Join-Path $Root 'client/test-windows-performance.ps1') -Root $Root
$Ast=[ScriptBlock]::Create($ProductSource).Ast
foreach($Name in @('ExternalComparisonValue','ExternalComparisonToken','OrderedCandidateScore','TestOrderedCandidateResponseSource','TestOrderedCandidateResponseProposal','TestOrderedCandidateLegacyConnectedResponse','TestOrderedCandidateLocalResponse','TestOrderedCandidatePublicSource','TestOrderedCandidatePublicPath','OrderedCandidateViewMetric','TestOrderedCandidateDraftInsertion','OrderedCandidateFinalProfileChoice','OrderedCandidateBase','OrderedCandidateScope','OrderedCandidateCatalogPath','UseExistingOrderedCandidateDialog','OrderedCandidateScopedBody','OrderedCandidateNumber','TestOrderedCandidateDraftExecution','OrderedCandidateSavedEnvelope','OrderedCandidateBeforeStart','OrderedCandidateCancelBody','OrderedCandidateReady','SetOrderedCandidateControls','ReceiveOrderedCandidates','TickOrderedCandidates')){
 $F=@($Ast.FindAll({param($n)$n-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$Name},$true));if($F.Count-ne1){throw "Missing shipping candidate function $Name"};. ([ScriptBlock]::Create($F[0].Extent.Text))
}
$Count=0
function Assert-Candidate($OK,[string]$Why){$script:Count++;if(-not$OK){throw ('ORDERED-CANDIDATE-CHECK: '+$Why)}}
$Show=@($Ast.FindAll({param($n)$n-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'ShowOrderedCandidates'},$true))[0].Extent.Text
$ViewBoundary=$Show.IndexOf(' [xml]$X=@')
Assert-Candidate ($ViewBoundary-gt0) 'candidate launcher boundary missing'
# Run the real launcher up to WPF construction and observe whether a new purpose can open.
. ([ScriptBlock]::Create($Show.Substring(0,$ViewBoundary)+" return 'new-window'
}"))
$script:RouterVPNOrderedCandidates=@{Closed=$false;SavedPath=$true;SavedPrefix=$true;Draft=$null;Task=$null;PendingDrain=$false;Status=[pscustomobject]@{Text=''}}
$Old=$script:RouterVPNOrderedCandidates
$Old.Dialog=[pscustomobject]@{State=$Old;FocusCount=0;CloseCount=0}
$Old.Dialog|Add-Member ScriptMethod Activate {$this.FocusCount++;return $true}
$Old.Dialog|Add-Member ScriptMethod Close {$this.CloseCount++;$this.State.Closed=$true}
$Opened=ShowOrderedCandidates -SavedPrefix $true
Assert-Candidate ($null-eq$Opened-and$Old.Dialog.FocusCount-eq1-and-not$Old.Closed) 'same candidate purpose reopened its window'
foreach($Busy in @('Task','PendingDrain')){
 if($Busy-ceq'Task'){$Old.Task=[object]::new()}else{$Old.PendingDrain=$true}
 $Opened=ShowOrderedCandidates
 Assert-Candidate ($null-eq$Opened-and$Old.Dialog.CloseCount-eq0-and$Old.Status.Text.Contains('current candidate test')) 'candidate purpose switch displaced a retained request or cleanup'
 $Old.Task=$null;$Old.PendingDrain=$false
}
$Opened=ShowOrderedCandidates
Assert-Candidate ($Opened-ceq'new-window'-and$Old.Closed-and$Old.Dialog.CloseCount-eq1) 'idle saved-prefix window blocked the connected candidate action'
$script:RouterVPNOrderedCandidates=$null

$Now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
function New-CandidateRow {return @{measurement='routed-tcp-connect';complete=$true;drained=$true;stage='complete';candidate_id='custom-original';measured_at=$Now;expires_at=$Now+120000;results=@(@{node_id='custom-original';kind='tcp-connect';role='candidate';ready=$true;benchmark=@{measurement='routed-tcp-connect';attempts=50;failed=0;trimmed_mean_ms=2.0;distribution=@{samples=50;min_ms=1.0;max_ms=3.0}}})}}
$R=New-CandidateRow;Assert-Candidate ((OrderedCandidateScore $R $Now)-eq2) 'complete exact TCP row rejected'
Assert-Candidate ($null-eq(OrderedCandidateScore $R ($Now+120000))) 'status polling renewed expired receipt'
foreach($metric in @('routed-tcp-connect','routed-candidate-response')){
 foreach($fault in @('complete','drained','ready','fractional-attempts','text-failures','fractional-samples','text-score','fractional-time')){
    $R=New-CandidateRow;$R.measurement=$metric;$R.results[0].benchmark.measurement=$metric
    if($metric -ceq 'routed-candidate-response'){$R.results[0].kind='private-agent-response'}
    switch($fault){
      'complete'{$R.complete='false'} 'drained'{$R.drained='false'} 'ready'{$R.results[0].ready='false'}
      'fractional-attempts'{$R.results[0].benchmark.attempts=49.9} 'text-failures'{$R.results[0].benchmark.failed='0'}
      'fractional-samples'{$R.results[0].benchmark.distribution.samples=49.9} 'text-score'{$R.results[0].benchmark.trimmed_mean_ms='2.0'}
      'fractional-time'{$R.measured_at=[double]$Now-0.25}
    }
    Assert-Candidate ($null -eq (OrderedCandidateScore $R $Now $metric)) ('malformed candidate score was selectable: '+$metric+' '+$fault)
 }
}
foreach($Field in @('attempts','failed')){$R=New-CandidateRow;$R.results[0].benchmark[$Field]=if($Field-ceq'attempts'){49}else{1};Assert-Candidate ($null-eq(OrderedCandidateScore $R $Now)) ('incomplete '+$Field+' became sortable')}
$R=New-CandidateRow;$R.results[0].benchmark.trimmed_mean_ms=[double]::NaN;Assert-Candidate ($null-eq(OrderedCandidateScore $R $Now)) 'nonfinite score became sortable'
$R=New-CandidateRow;$R.results[0].node_id='foreign';Assert-Candidate ($null-eq(OrderedCandidateScore $R $Now)) 'foreign candidate row became sortable'
$R=New-CandidateRow;$R.measurement='icmp';Assert-Candidate ($null-eq(OrderedCandidateScore $R $Now)) 'ICMP masqueraded as routed TCP'
$S=@{Closed=$false;CancelWanted=$false;CloseWanted=$false;Next=[DateTime]::UtcNow.AddSeconds(1);Position=0;View=$null;Receipt=$null;Rows=@();Table=[pscustomobject]@{ItemsSource=$null;SelectedItem=$null};Prefix=[pscustomobject]@{ItemsSource=$null;SelectedValue=$null;IsEnabled=$false};Status=[pscustomobject]@{Text=''};RequestID=('b'*32);PendingDrain=$true;Task=$null;Refresh=[pscustomobject]@{IsEnabled=$false};Run=[pscustomobject]@{IsEnabled=$false};Save=[pscustomobject]@{IsEnabled=$false};Cancel=[pscustomobject]@{IsEnabled=$false}}
$Path=@(@{id='entry';mode='wg'},@{id='custom-original';mode='shadowsocks'},@{id='final';mode='shadowsocks'})
$Catalog=@{samples=50;measurement='routed-tcp-connect';view_token=('a'*64);prefix_position=0;expires_at=$Now+120000;prefixes=@(@{position=0;name='Original entry';mode='wg'});candidates=@(@{id='custom-original';name='Original custom';proposed_path=$Path;save_reason=''})}
ReceiveOrderedCandidates $S $Catalog 'catalog';Assert-Candidate ($S.View.view_token-ceq('a'*64)-and$S.Rows.Count-eq1) 'actual catalog capture lost original candidate'
$Value=@{measurement='routed-tcp-connect';request_id=$S.RequestID;view_token=$Catalog.view_token;prefix_position=0;drained=$true;accepted=$true;results=@((New-CandidateRow));failure=''}
ReceiveOrderedCandidates $S $Value 'run';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
Assert-Candidate ($S.Save.IsEnabled-and-not$S.PendingDrain-and$S.Rows[0].ID-ceq'custom-original') 'joined current receipt did not enable explicit profile save'
function StartOrderedCandidateRequest($State,$Phase,$Path,$Body){$script:SavedRequest=@{Phase=$Phase;Path=$Path;Body=$Body}}
$S.Next=[DateTime]::UtcNow.AddSeconds(-1);$script:SavedRequest=$null;TickOrderedCandidates $S
Assert-Candidate ($SavedRequest.Phase-ceq'poll'-and$SavedRequest.Path-ceq('/api/multihop/prefix-candidates?request_id='+$S.RequestID)) 'actual timer did not observe the original completed owner'
$Lost=@{measurement='routed-tcp-connect';request_id=$S.RequestID;view_token=$Catalog.view_token;prefix_position=0;drained=$true;accepted=$false;results=@();failure='Original reader changed'}
ReceiveOrderedCandidates $S $Lost 'poll';SetOrderedCandidateControls $S;Assert-Candidate ($S.Rows.Count-eq0-and-not$S.Save.IsEnabled) 'stale proof status left scored selectable rows'
ReceiveOrderedCandidates $S $Value 'poll';$S.Table.SelectedItem=$S.Rows[0]
$S.CancelWanted=$true;ReceiveOrderedCandidates $S $Value 'run';SetOrderedCandidateControls $S;Assert-Candidate ($S.PendingDrain-and$null-eq$S.Receipt-and$S.Rows.Count-eq0-and-not$S.Save.IsEnabled) 'late successful completion revived cancelled job'
$S.CancelWanted=$false;ReceiveOrderedCandidates $S $Value 'poll';$S.Table.SelectedItem=$S.Rows[0]

$S.Prefix.SelectedValue=1;SetOrderedCandidateControls $S;Assert-Candidate (-not$S.Run.IsEnabled-and-not$S.Save.IsEnabled) 'new unbound prefix selection reused old result';$S.Prefix.SelectedValue=0;SetOrderedCandidateControls $S
$S.Rows[0].Receipt.expires_at=$Now-1;SetOrderedCandidateControls $S;Assert-Candidate (-not$S.Save.IsEnabled) 'expired row still enabled adoption'
$Rejected=$false;try{ReceiveOrderedCandidates $S @{request_id=('c'*32);drained=$true} 'cancel'}catch{$Rejected=$true};Assert-Candidate $Rejected 'foreign cancellation retired original dialog'
$S.PendingDrain=$true;ReceiveOrderedCandidates $S @{request_id=$S.RequestID;drained=$true} 'cancel';Assert-Candidate (-not$S.PendingDrain-and$null-eq$S.Receipt) 'exact cancellation retained selectable row'
$Dialog=@($Ast.FindAll({param($n)$n-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'ShowOrderedCandidates'},$true));Assert-Candidate ($Dialog.Count-eq1) 'actual shipping native dialog missing'
$SaveEvent=@($Dialog[0].FindAll({param($n)$n-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Expression.Extent.Text-ceq'$S.Save'-and$n.Member.Extent.Text-ceq'Add_Click'},$true));Assert-Candidate ($SaveEvent.Count-eq1) 'actual explicit save callback missing'
$Click=$SaveEvent[0].Arguments[0].Expression.ScriptBlock.GetScriptBlock()
$UseEvent=@($Dialog[0].FindAll({param($n)$n-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Expression.Extent.Text-ceq'$S.UseDraft'-and$n.Member.Extent.Text-ceq'Add_Click'},$true))
Assert-Candidate ($UseEvent.Count -eq 1) 'explicit unsaved Use callback missing'
$UseClick=$UseEvent[0].Arguments[0].Expression.ScriptBlock.GetScriptBlock()
$PreviewEvent=@($Dialog[0].FindAll({param($n)$n-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Expression.Extent.Text-ceq'$S.Table'-and$n.Member.Extent.Text-ceq'Add_SelectionChanged'},$true))
$PreviewChoice=$PreviewEvent[0].Arguments[0].Expression.ScriptBlock.GetScriptBlock()
$RunEvent=@($Dialog[0].FindAll({param($n)$n-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Expression.Extent.Text-ceq'$S.Run'-and$n.Member.Extent.Text-ceq'Add_Click'},$true));Assert-Candidate ($RunEvent.Count-eq1) 'actual test callback missing'
$CaptureEvent=@($Dialog[0].FindAll({param($n)$n-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Expression.Extent.Text-ceq'$S.Refresh'-and$n.Member.Extent.Text-ceq'Add_Click'},$true))
Assert-Candidate ($CaptureEvent.Count-eq1) 'candidate capture callback missing'
$CaptureClick=$CaptureEvent[0].Arguments[0].Expression.ScriptBlock.GetScriptBlock()
$Sparse=@{}+$Catalog;$Sparse.prefixes=@(0,2,4,6|ForEach-Object{@{position=$_;name=("Packet "+$_);mode='awg2-fast'}})
ReceiveOrderedCandidates $S $Sparse 'catalog'
Assert-Candidate ((@($S.Prefix.ItemsSource|ForEach-Object{$_.position})-join',')-ceq'0,2,4,6') 'sparse connected packet positions changed in the picker'
$S.Prefix.SelectedValue=4;$S.Draft=$null
&$CaptureClick
Assert-Candidate ($S.Position-eq4-and$null-eq$S.View-and$SavedRequest.Path-ceq'/api/multihop/prefix-candidates/catalog?prefix_position=4&server_response=true'-and$null-eq$SavedRequest.Body) 'sparse connected packet click did not recapture its exact original position'
$Sparse.prefix_position=4;$Sparse.view_token='b'*64;ReceiveOrderedCandidates $S $Sparse 'catalog'
Assert-Candidate ($S.View.view_token-ceq('b'*64)-and$S.Prefix.SelectedValue-eq4) 'sparse connected packet recapture lost its current token or position'
$S.Position=0;ReceiveOrderedCandidates $S $Catalog 'catalog'
$RunClick=$RunEvent[0].Arguments[0].Expression.ScriptBlock.GetScriptBlock();$OriginalView=$S.View;$S.View=@{}+$Catalog;$S.View.expires_at=$Now-1;$OriginalID=$S.RequestID
foreach($SavedPurpose in @($false,$true)){$S.SavedPath=$SavedPurpose;$script:SavedRequest=$null;&$RunClick;Assert-Candidate ($null-eq$SavedRequest-and-not$S.PendingDrain-and$S.RequestID-ceq$OriginalID-and$S.Status.Text.Contains('expired')) 'expired captured view created a request or retained cancellation owner'}
$S.SavedPath=$false;$S.View=$OriginalView
$S.Rows=@([pscustomobject]@{ID='custom-original';Choice=$Catalog.candidates[0];Receipt=(New-CandidateRow)});$S.Table.SelectedItem=$S.Rows[0];$S.Receipt=$Value;$S.ProfileName=[pscustomobject]@{Text='Named next connection'};$S.View=$Catalog
$script:SavedRequest=$null
function StartOrderedCandidateRequest($State,$Phase,$Path,$Body){$script:SavedRequest=@{Phase=$Phase;Path=$Path;Body=$Body}}
&$Click
Assert-Candidate ($SavedRequest.Path-ceq'/api/multihop/prefix-candidates/save-profile'-and$SavedRequest.Body.candidate_id-ceq'custom-original'-and$SavedRequest.Body.name-ceq'Named next connection'-and$SavedRequest.Body.proposed_path.Count-eq3-and$SavedRequest.Body.view_token-ceq$Catalog.view_token) 'actual save callback did not preserve exact proposed path and explicit name'
$S.ProfileName.Text=' ';$script:SavedRequest=$null;&$Click;Assert-Candidate ($null-eq$SavedRequest) 'blank profile name was submitted'
$S.Table.SelectedItem.Choice=@{id='custom-original';save_reason='Unsupported insertion position'};SetOrderedCandidateControls $S;Assert-Candidate (-not$S.Save.IsEnabled) 'unsupported candidate without proposed_path caused adoption'
$Response=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Conflict);$Response.Content=[System.Net.Http.StringContent]::new('Original source is no longer current')
$Completion=New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]';[void]$Completion.TrySetResult($Response);$S.Task=$Completion.Task;$S.Phase='poll';$S.Request=$null;$S.Cts=$null;$S.Receipt=$Value;$S.Rows=@([pscustomobject]@{Timing='2 ms';Receipt=(New-CandidateRow)})
TickOrderedCandidates $S;Assert-Candidate ($null-eq$S.Receipt-and$S.Rows.Count-eq0-and-not$S.Save.IsEnabled) 'failed status request left scored rows visible'
# The saved-path purpose keeps its physical observer while the tunnel is DOWN.
# Review can therefore enable Save while the exact request remains undrained;
# it must never enable another measurement or ordinary path replacement.
$S.SavedPath=$true;$S.SavedProfileID='';$S.CancelWanted=$false;$S.CloseWanted=$false;$S.RequestID=('d'*32);$S.PendingDrain=$false;$S.Table.SelectedItem=$null
$Catalog=@{}+$Catalog;$Catalog.scope='saved-complete-local';$Catalog.schema=1;$Catalog.measurement='routed-tcp-connect';$Catalog.samples=50
$PurposeFaults=@(@{key='scope';value='connected-prefix'},@{key='schema';value=2},@{key='schema';value='1'},@{key='measurement';value='icmp'},@{key='prefix_position';value=1},@{key='prefix_position';value='0'},@{key='prefix_position';value=$null})
foreach($Fault in $PurposeFaults){$Bad=@{}+$Catalog;$Bad[$Fault.key]=$Fault.value;$Before=$S.View;$Rejected=$false;try{ReceiveOrderedCandidates $S $Bad 'catalog'}catch{$Rejected=$true};Assert-Candidate ($Rejected-and[object]::ReferenceEquals($Before,$S.View)) ('foreign saved catalog purpose was accepted: '+$Fault.key)}
$Bad=@{}+$Catalog;$Bad.Remove('scope');$Rejected=$false;try{ReceiveOrderedCandidates $S $Bad 'catalog'}catch{$Rejected=$true};Assert-Candidate $Rejected 'missing saved catalog scope was accepted'
ReceiveOrderedCandidates $S $Catalog 'catalog';SetOrderedCandidateControls $S
Assert-Candidate ((OrderedCandidateBase $S)-ceq'/api/multihop/saved-candidates'-and$S.Run.IsEnabled-and$S.Status.Text.Contains('Disconnected')) 'saved dialog did not capture its separate temporary purpose'
$Now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$SavedValue=@{request_id=$S.RequestID;view_token=$Catalog.view_token;prefix_position=0;running=$true;drained=$false;accepted=$false;native_down=$false;reviewing=$false;cleanup_pending=$false;results=@((New-CandidateRow));failure=''}
function Add-SavedCandidateEnvelope($Value){$Value.schema=1;$Value.scope='saved-complete-local';$Value.prefix_position=0;$Value.measurement='routed-tcp-connect';$Value.active_path_changed=$false;return $Value}
$SavedValue=Add-SavedCandidateEnvelope $SavedValue
foreach($Phase in @('run','poll','save','cancel')){foreach($Fault in $PurposeFaults){$Bad=@{}+$SavedValue;$Bad[$Fault.key]=$Fault.value;$Before=$S.Receipt;$Pending=$S.PendingDrain;$Rejected=$false;try{ReceiveOrderedCandidates $S $Bad $Phase}catch{$Rejected=$true};Assert-Candidate ($Rejected-and[object]::ReferenceEquals($Before,$S.Receipt)-and$Pending-eq$S.PendingDrain-and-not$S.SavedProfileID) ('foreign saved response purpose was accepted: '+$Phase+'/'+$Fault.key)}}
$Bad=@{}+$SavedValue;$Bad.Remove('active_path_changed');$Rejected=$false;try{ReceiveOrderedCandidates $S $Bad 'poll'}catch{$Rejected=$true};Assert-Candidate $Rejected 'missing saved path-change proof was accepted'
ReceiveOrderedCandidates $S $SavedValue 'run';SetOrderedCandidateControls $S
Assert-Candidate ($S.PendingDrain-and$S.Rows.Count-eq0-and-not$S.Save.IsEnabled-and-not$S.Run.IsEnabled-and$S.Cancel.IsEnabled) '202 response exposed results or lost the original temporary request'
$S.Next=[DateTime]::UtcNow.AddSeconds(-1);$script:SavedRequest=$null;TickOrderedCandidates $S
Assert-Candidate ($SavedRequest.Path-ceq('/api/multihop/saved-candidates?request_id='+$S.RequestID)) 'temporary test polling used another purpose or request'
$SavedValue.accepted=$true;$SavedValue.running=$false;$SavedValue.reviewing=$true
ReceiveOrderedCandidates $S $SavedValue 'poll';SetOrderedCandidateControls $S
Assert-Candidate ($S.Rows.Count-eq0-and-not$S.Save.IsEnabled) 'accepted result before native DOWN exposed a selectable choice'
$SavedValue.native_down=$true;ReceiveOrderedCandidates $S $SavedValue 'poll';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
Assert-Candidate ($S.Save.IsEnabled-and$S.PendingDrain-and-not$S.Run.IsEnabled-and-not$S.Refresh.IsEnabled-and$S.Cancel.IsEnabled-and$S.Status.Text.StartsWith('Disconnected.')) 'post-DOWN review did not preserve observer ownership and explicit Save'
$Selected=$S.Table.SelectedItem;ReceiveOrderedCandidates $S $SavedValue 'poll';Assert-Candidate ($S.Table.SelectedItem.ID-ceq$Selected.ID) 'review polling silently changed the selected candidate'
$S.ProfileName.Text='Saved path for later';$ReviewView=$S.View;$S.View=@{}+$ReviewView;$S.View.expires_at=$Now-1;$script:SavedRequest=$null;&$Click;$S.View=$ReviewView
Assert-Candidate ($SavedRequest.Path-ceq'/api/multihop/saved-candidates/save-profile'-and$SavedRequest.Body.request_id-ceq$S.RequestID-and$SavedRequest.Body.view_token-ceq$Catalog.view_token-and$SavedRequest.Body.proposed_path.Count-eq3) 'saved purpose callback changed the exact future profile or request'
$SavedValue.reviewing=$false;ReceiveOrderedCandidates $S $SavedValue 'poll';SetOrderedCandidateControls $S
Assert-Candidate ($S.Rows.Count-eq0-and-not$S.Save.IsEnabled) 'closed review retained adoptable rows'
$SavedValue.reviewing=$true;$SavedValue.cleanup_pending=$true;ReceiveOrderedCandidates $S $SavedValue 'poll';SetOrderedCandidateControls $S
Assert-Candidate ($S.Rows.Count-eq0-and-not$S.Save.IsEnabled-and$S.CancelWanted-and$S.PendingDrain) 'pending cleanup exposed a future-profile choice'
$SavedValue.cleanup_pending=$false;$S.CancelWanted=$false;ReceiveOrderedCandidates $S $SavedValue 'poll';$S.Table.SelectedItem=$S.Rows[0]
$S.Rows[0].Receipt.measured_at=$Now-120001;$S.Rows[0].Receipt.expires_at=$Now-1;SetOrderedCandidateControls $S
Assert-Candidate (-not$S.Save.IsEnabled) 'saved observer polling renewed the original measurement deadline'
$SavedValue.results=@((New-CandidateRow));ReceiveOrderedCandidates $S $SavedValue 'poll';$S.Table.SelectedItem=$S.Rows[0]
$S.CloseWanted=$true;$S.CancelWanted=$true;ReceiveOrderedCandidates $S $SavedValue 'poll';SetOrderedCandidateControls $S
Assert-Candidate ($S.Rows.Count-eq0-and$null-eq$S.Receipt-and-not$S.Save.IsEnabled-and$S.PendingDrain) 'closing temporary review revived scored results'
$S.Next=[DateTime]::UtcNow.AddSeconds(-1);$script:SavedRequest=$null;TickOrderedCandidates $S
Assert-Candidate ($SavedRequest.Path-ceq'/api/multihop/saved-candidates/cancel'-and$SavedRequest.Body.request_id-ceq$S.RequestID-and$SavedRequest.Body.view_token-ceq$Catalog.view_token) 'saved review cancellation lost its exact request or view'
$Cancelled=@{request_id=$S.RequestID;view_token=$Catalog.view_token;drained=$true;native_down=$false}
$Cancelled=Add-SavedCandidateEnvelope $Cancelled
$Rejected=$false;try{ReceiveOrderedCandidates $S $Cancelled 'cancel'}catch{$Rejected=$true};Assert-Candidate ($Rejected-and$S.PendingDrain) 'drained response without native DOWN released saved review'
$Cancelled.native_down=$true;$Cancelled.request_id=('e'*32);$Rejected=$false;try{ReceiveOrderedCandidates $S $Cancelled 'cancel'}catch{$Rejected=$true};Assert-Candidate ($Rejected-and$S.PendingDrain) 'foreign saved cancellation retired original owner'
$Early=@{request_id=$S.RequestID;view_token=$Catalog.view_token;drained=$true;native_down=$false;admission_cancelled=$true;started=$true;active_path_changed=$false}
$Early=Add-SavedCandidateEnvelope $Early
$Rejected=$false;try{ReceiveOrderedCandidates $S $Early 'cancel'}catch{$Rejected=$true};Assert-Candidate ($Rejected-and$S.PendingDrain) 'already-started cancellation bypassed native DOWN'
$Early.Remove('started');$Rejected=$false;try{ReceiveOrderedCandidates $S $Early 'cancel'}catch{$Rejected=$true};Assert-Candidate ($Rejected-and$S.PendingDrain) 'missing started receipt was treated as proven absence'
$Early.started=$false;$Early.view_token=('f'*64);$Rejected=$false;try{ReceiveOrderedCandidates $S $Early 'cancel'}catch{$Rejected=$true};Assert-Candidate ($Rejected-and$S.PendingDrain) 'never-started receipt from another view retired original request'
$Early.view_token=$Catalog.view_token;$Rejected=$false;try{ReceiveOrderedCandidates $S $Early 'cancel'}catch{$Rejected=$true};Assert-Candidate ($Rejected-and$S.PendingDrain) 'never-started cancellation erased previously observed admission'
$Cancelled.request_id=$S.RequestID;ReceiveOrderedCandidates $S $Cancelled 'cancel';Assert-Candidate (-not$S.PendingDrain) 'joined original saved cancellation retained temporary ownership'
$S.RequestID=('9'*32);$S.SavedAdmitted=$false;$S.PendingDrain=$true;$Early.request_id=$S.RequestID
ReceiveOrderedCandidates $S $Early 'cancel';Assert-Candidate (-not$S.PendingDrain-and$S.Status.Text-ceq'Cancelled before the temporary path started.'-and$null-eq$S.Receipt) 'exact never-started cancellation claimed native shutdown or retained ownership'
$S.CloseWanted=$false;$S.CancelWanted=$false;$S.SavedProfileID=''
$SavedReply=@{request_id=$S.RequestID;view_token=$Catalog.view_token;drained=$false;native_down=$true;saved_profile_id='original-profile';profile_name='Saved path for later';active_path_changed=$false;failure='Original observer changed after append'}
$SavedReply=Add-SavedCandidateEnvelope $SavedReply
ReceiveOrderedCandidates $S $SavedReply 'save';SetOrderedCandidateControls $S
Assert-Candidate ($S.SavedProfileID-ceq'original-profile'-and$S.PendingDrain-and$S.CancelWanted-and-not$S.Save.IsEnabled-and$S.Rows.Count-eq0-and$S.Status.Text.Contains('Saved path for later')-and$S.Status.Text.Contains('invalidated')) 'committed file with pending cleanup was hidden or offered a duplicate Save'
$SavedReply.drained=$true;$SavedReply.native_down=$false;ReceiveOrderedCandidates $S $SavedReply 'cancel'
Assert-Candidate ($S.PendingDrain-and$S.SavedProfileID-ceq'original-profile'-and-not$S.Status.Text.Contains('path is disconnected')) 'committed-file response falsely claimed native DOWN'
$SavedReply.native_down=$true;ReceiveOrderedCandidates $S $SavedReply 'cancel';SetOrderedCandidateControls $S
Assert-Candidate (-not$S.PendingDrain-and-not$S.Save.IsEnabled-and$S.Status.Text.Contains('Use Profiles')) 'final cleanup lost the saved write or automatically applied it'
$SavedReply.saved_profile_id='replacement-profile';$Rejected=$false;try{ReceiveOrderedCandidates $S $SavedReply 'poll'}catch{$Rejected=$true};Assert-Candidate $Rejected 'retry changed the original committed profile identity'
# Prefix-only uses its own immutable purpose and never borrows full-path proof.
$S.SavedPrefix=$true;$S.SavedPath=$true;$S.SavedProfileID='';$S.SavedAdmitted=$false;$S.PendingDrain=$false;$S.CancelWanted=$false;$S.CloseWanted=$false;$S.Table.SelectedItem=$null;$S.RequestID=('7'*32)
$PrefixCatalog=@{}+$Catalog;$PrefixCatalog.scope='saved-prefix-local';$PrefixCatalog.proof_scope='selected-prefix';$PrefixCatalog.application_open=$false;$PrefixCatalog.dns_open=$false
Assert-Candidate ((OrderedCandidateCatalogPath $S)-ceq'/api/multihop/saved-candidates/catalog?prefix_position=0&scope=saved-prefix-local') 'prefix capture omitted its explicit purpose'
$Rejected=$false;try{ReceiveOrderedCandidates $S $Catalog 'catalog'}catch{$Rejected=$true};Assert-Candidate $Rejected 'complete-path catalog substituted for prefix capture'
foreach($Field in @('application_open','dns_open','proof_scope')){$Bad=@{}+$PrefixCatalog;$Bad.Remove($Field);$Rejected=$false;try{ReceiveOrderedCandidates $S $Bad 'catalog'}catch{$Rejected=$true};Assert-Candidate $Rejected ('missing closed prefix catalog field accepted: '+$Field)}
ReceiveOrderedCandidates $S $PrefixCatalog 'catalog';SetOrderedCandidateControls $S
Assert-Candidate ($S.Run.IsEnabled-and$S.Status.Text.Contains('only the selected saved prefix')) 'prefix catalog was described as full-path proof'
$S.Table|Add-Member -MemberType NoteProperty -Name SelectedItems -Value @($S.Rows[0]) -Force
$script:SavedRequest=$null;&$RunClick
Assert-Candidate ($SavedRequest.Body.scope-ceq'saved-prefix-local'-and$SavedRequest.Body.request_id-ceq$S.RequestID-and$SavedRequest.Body.samples-eq50) 'prefix Test lost exact request purpose or samples'
$PrefixValue=Add-SavedCandidateEnvelope @{request_id=$S.RequestID;view_token=$PrefixCatalog.view_token;running=$false;drained=$false;accepted=$true;native_down=$false;reviewing=$true;cleanup_pending=$false;results=@((New-CandidateRow))}
$PrefixValue.scope='saved-prefix-local';$PrefixValue.proof_scope='selected-prefix';$PrefixValue.application_open=$false;$PrefixValue.dns_open=$false
ReceiveOrderedCandidates $S $PrefixValue 'poll';SetOrderedCandidateControls $S;Assert-Candidate (-not$S.Save.IsEnabled-and$S.Rows.Count-eq0) 'prefix result was exposed before native DOWN'
$PrefixValue.native_down=$true;ReceiveOrderedCandidates $S $PrefixValue 'poll';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
Assert-Candidate ($S.Save.IsEnabled-and$S.PendingDrain) 'prefix DOWN review lost explicit Save or its retained observer'
foreach($Phase in @('poll','save','cancel')){foreach($Fault in @(@{key='scope';value='saved-complete-local'},@{key='proof_scope';value='complete-path'},@{key='application_open';value=$true},@{key='dns_open';value='false'})){$Bad=@{}+$PrefixValue;$Bad[$Fault.key]=$Fault.value;$Rejected=$false;try{ReceiveOrderedCandidates $S $Bad $Phase}catch{$Rejected=$true};Assert-Candidate ($Rejected-and$S.PendingDrain-and-not$S.SavedProfileID) ('prefix receipt broadened its purpose: '+$Phase+'/'+$Fault.key)}}
$S.ProfileName.Text='Named prefix choice';$script:SavedRequest=$null;&$Click
Assert-Candidate ($SavedRequest.Body.scope-ceq'saved-prefix-local'-and$SavedRequest.Body.proposed_path.Count-eq3-and$SavedRequest.Body.view_token-ceq$PrefixCatalog.view_token) 'prefix Save lost its complete future profile or captured purpose'
$CancelBody=OrderedCandidateCancelBody $S;Assert-Candidate ($CancelBody.scope-ceq'saved-prefix-local'-and$CancelBody.request_id-ceq$S.RequestID-and$CancelBody.view_token-ceq$PrefixCatalog.view_token) 'prefix Cancel changed its original purpose or owner'
foreach($Combo in @(@('server','server'),@('auto','local'),@('auto','server'))){
 $Requested,$Winner=$Combo
 $Original=@(@{id='entry';mode='wg'},@{id='imported';mode='shadowsocks'},@{id='packet';mode='awg2-fast'},@{id='final';mode='shadowsocks'})
 $Proposed=@($Original[0],$Original[1],$Original[2],@{id='custom-original';mode='shadowsocks'},$Original[3])
 $S.Draft=@{execution=$Requested;nodes=$Original;expected_selected_node_id='final';expected_profile_tokens=@{entry='a';imported='b';packet='c';final='d'}}
 $S.Position=2;$S.CloseWanted=$false;$S.CancelWanted=$false;$S.PendingDrain=$false;$S.SelectedWinner='';$S.SelectedEpoch=0;$S.SavedAdmitted=$false;$S.SavedProfileID=''
 $S.Table.SelectedItem=$null;$S.Table|Add-Member -Force NoteProperty SelectedItems ([Collections.ArrayList]::new())
 $S.Dialog=[pscustomobject]@{Tag=$null}
 $Offer=@{}+$Catalog;$Offer.scope='draft-complete-selected';$Offer.origin='editor-draft';$Offer.requested_execution=$Requested;$Offer.prefix_position=2
 $Offer.prefixes=@(@{id='packet';name='Packet';position=2;mode='awg2-fast'});$Offer.candidates=@(@{id='custom-original';name='Candidate';proposed_path=$Proposed})
 Assert-Candidate ((OrderedCandidateCatalogPath $S)-ceq'/api/multihop/draft-candidates/catalog?prefix_position=2&scope=draft-complete-selected&server_response=true') 'selected draft catalog went to the Local prefix owner'
 foreach($Fault in @(@{key='scope';value='saved-prefix-local'},@{key='requested_execution';value='local'},@{key='selected_execution';value=$Winner},@{key='prefixes';value=@(@{position=2;id='other';mode='wg'})})){
  $Bad=@{}+$Offer;$Bad[$Fault.key]=$Fault.value;$Rejected=$false;try{ReceiveOrderedCandidates $S $Bad 'catalog'}catch{$Rejected=$true};Assert-Candidate $Rejected ('foreign selected catalog: '+$Fault.key)
 }
 ReceiveOrderedCandidates $S $Offer 'catalog'
 $S.Prefix.SelectedValue=2;$script:SavedRequest=$null;&$RunClick
 Assert-Candidate ($SavedRequest.Path-ceq'/api/multihop/draft-candidates'-and$SavedRequest.Body.scope-ceq'draft-complete-selected'-and$SavedRequest.Body.samples-eq50) 'selected run changed scope or sample count'
 $Measured=@{}+$PrefixValue;$Measured.scope='draft-complete-selected';$Measured.origin='editor-draft';$Measured.requested_execution=$Requested;$Measured.request_id=$S.RequestID;$Measured.prefix_position=2;$Measured.view_token=$Offer.view_token
 $Rejected=$false;try{ReceiveOrderedCandidates $S $Measured 'run'}catch{$Rejected=$true};Assert-Candidate $Rejected 'unselected draft result became reviewable'
 $Measured.selected_execution=$Winner;$Measured.selection_epoch=19L
 ReceiveOrderedCandidates $S $Measured 'run';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
 Assert-Candidate ($S.Save.IsEnabled-and$S.SelectedWinner-ceq$Winner-and$S.Status.Text.Contains($Winner)) 'selected measured winner missing before choosing'
 foreach($Fault in @(@{key='selected_execution';value=$(if($Winner-ceq'local'){'server'}else{'local'})},@{key='selection_epoch';value=20},@{key='selection_epoch';value=$true},@{key='admission_cancelled';value=$true},@{key='requested_execution';value='local'})){
  $Bad=@{}+$Measured;$Bad[$Fault.key]=$Fault.value;$Rejected=$false;try{ReceiveOrderedCandidates $S $Bad 'poll'}catch{$Rejected=$true};Assert-Candidate $Rejected ('foreign measured winner: '+$Fault.key)
 }
 $script:SavedRequest=$null;&$Click
 Assert-Candidate ($SavedRequest.Path-ceq'/api/multihop/draft-candidates/choose'-and$SavedRequest.Body.scope-ceq'draft-complete-selected'-and$SavedRequest.Body.proposed_path[-1].id-ceq'final') 'selected choose lost suffix or wrote a profile'
 $Chosen=@{}+$Measured;$Chosen.drained=$true;$Chosen.native_down=$true;$Chosen.accepted=$false;$Chosen.reviewing=$false;$Chosen.chosen=$true;$Chosen.saved_profile_id='';$Chosen.candidate_id='custom-original';$Chosen.proposed_path=$Proposed
 ReceiveOrderedCandidates $S $Chosen 'save'
 Assert-Candidate ($S.Dialog.Tag.selected_execution-ceq$Winner-and$S.Dialog.Tag.selection_epoch-eq19-and$S.CloseWanted-and-not$S.PendingDrain) 'selected choice failed original editor handoff'
}
# A response receipt is independently typed at the catalog, envelope, row and
# benchmark. Its owner, prefix and 50 samples must agree for every UI purpose.
$metric='routed-candidate-response'
$privatePrefix=@{id='imported';name='Imported B';mode='shadowsocks';position=1;measurement=$metric}
$paired=@{id='candidate-C';name='Paired C';kind='router-vpn';proposal_action='save-final-profile';proposed_path=@($Path[0],$privatePrefix,@{id='candidate-C';mode='shadowsocks'})}
$selectedDraft=@{execution='auto';nodes=@($Path[0],$privatePrefix,$Path[-1])}
$selectedOffer=@{measurement=$metric;requested_execution='auto';required_selected_execution='local';scope='draft-complete-selected';prefixes=@($privatePrefix);candidates=@($paired)}
$selectedState=@{Position=1;Draft=$selectedDraft;View=$selectedOffer}
Assert-Candidate ((OrderedCandidateViewMetric $selectedState $selectedOffer) -ceq $metric -and (OrderedCandidateFinalProfileChoice $selectedState $paired) -and (TestOrderedCandidateDraftExecution $selectedState $selectedOffer $true)) 'Compare Local source must offer separately named exact final replacement'
$selectedReview=@{}+$selectedOffer;$selectedReview.selected_execution='local';$selectedReview.selection_epoch=19L
Assert-Candidate (TestOrderedCandidateDraftExecution $selectedState $selectedReview $false) 'Compare Local private receipt lost original winner'
foreach($fault in @(@{key='selected_execution';value='server'},@{key='required_selected_execution';value='server'},@{key='selection_epoch';value=0})){
 $bad=@{}+$selectedReview;$bad[$fault.key]=$fault.value
 Assert-Candidate (-not (TestOrderedCandidateDraftExecution $selectedState $bad $false)) ('foreign selected private winner accepted '+$fault.key)
}
foreach($purpose in @('connected','saved-complete-local','saved-prefix-local','editor-draft')){
 $S.SavedPath=$purpose -cne 'connected';$S.SavedPrefix=$purpose -cin @('saved-prefix-local','editor-draft')
 $S.Draft=if($purpose -ceq 'editor-draft'){@{execution='local';nodes=@($Path[0],$privatePrefix,$Path[-1])}}else{$null}
 $S.Position=1;$S.CloseWanted=$false;$S.CancelWanted=$false;$S.SavedAdmitted=$false;$S.SavedProfileID='';$S.PendingDrain=$false
 $offer=@{schema=1;samples=50;measurement=$metric;view_token='8'*64;expires_at=$Now+120000;prefix_position=1;prefixes=@($privatePrefix);candidates=@($paired)}
 if($S.SavedPath){$offer.scope=OrderedCandidateScope $S}
 if($S.SavedPrefix){$offer.proof_scope='selected-prefix';$offer.application_open=$false;$offer.dns_open=$false}
 if($null -ne $S.Draft){$offer.origin='editor-draft'}
 foreach($badOffer in @(@{key='prefixes';v=@(@{id='imported';position=1;mode='wg';measurement=$metric})},@{key='prefixes';v=@(@{id='imported';position=1;mode='shadowsocks'})},@{key='requested_execution';v='server'},@{key='selected_execution';v='server'},@{key='candidates';v=@(@{id='unproved';kind='external'})})){
  $bad=@{}+$offer;$bad[$badOffer.key]=$badOffer.v;$rejected=$false;try{ReceiveOrderedCandidates $S $bad 'catalog'}catch{$rejected=$true}
  Assert-Candidate $rejected ('private catalog accepted incompatible '+$purpose+'/'+$badOffer.key)
 }
 ReceiveOrderedCandidates $S $offer 'catalog'
 $private=New-CandidateRow;$private.candidate_id='candidate-C';$private.results[0].node_id='candidate-C'
 $private.measurement=$metric;$private.results[0].kind='private-agent-response';$private.results[0].benchmark.measurement=$metric
 $value=@{schema=1;measurement=$metric;request_id=$S.RequestID;view_token=$offer.view_token;prefix_position=1;drained=$true;accepted=$true;results=@($private,(New-CandidateRow));failure='';native_down=$true;reviewing=$true;active_path_changed=$false}
 foreach($field in @('scope','proof_scope','application_open','dns_open','origin')){if($offer.ContainsKey($field)){$value[$field]=$offer[$field]}}
 ReceiveOrderedCandidates $S $value 'poll';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
 Assert-Candidate ($S.Rows.Count -eq 1 -and $S.Rows[0].ID -ceq $paired.id -and $S.Rows[0].Timing.Contains('50/50 private responses') -and $S.Save.IsEnabled) ('matching private receipt lost, or mixed ranking: '+$purpose)
 if($purpose -ceq 'editor-draft'){
  $S.Dialog=[pscustomobject]@{Tag=$null}
  $S.ProfileName.Text='';$script:SavedRequest=$null;&$Click
  Assert-Candidate ($null -eq $SavedRequest) 'draft final save accepted an empty name'
  foreach($fault in @('missing-action','short','changed-prefix','foreign-final')){
   $wrong=@{}+$paired;$wrong.proposed_path=@($paired.proposed_path)
   switch($fault){'missing-action'{$wrong.Remove('proposal_action')};'short'{$wrong.proposed_path=@($wrong.proposed_path[0],$wrong.proposed_path[2])};'changed-prefix'{$wrong.proposed_path[0]=@{id='foreign';mode='wg'}};'foreign-final'{$wrong.id='foreign'}}
   Assert-Candidate (-not (OrderedCandidateFinalProfileChoice $S $wrong)) ('draft final choice accepted '+$fault)
  }
  $S.ProfileName.Text='Named final C';$script:SavedRequest=$null;&$Click
  Assert-Candidate ($SavedRequest.Path -ceq '/api/multihop/draft-candidates/save-profile' -and $SavedRequest.Body.name -ceq 'Named final C' -and $SavedRequest.Body.proposed_path[-1].id -ceq 'candidate-C' -and $SavedRequest.Body.scope -ceq 'saved-prefix-local') 'final profile went to insertion or lost name/route/scope'
  $reply=@{}+$value;$reply.saved_profile_id='new-profile';$reply.candidate_id='candidate-C';$reply.proposal_action='save-final-profile';$reply.profile_name='Named final C'
  foreach($f in @(@{key='proposal_action';v='replace-final'},@{key='chosen';v=$true},@{key='candidate_id';v='other'})){
   $bad=@{}+$reply;$bad[$f.key]=$f.v;$refused=$false;try{ReceiveOrderedCandidates $S $bad 'save'}catch{$refused=$true}
   Assert-Candidate ($refused -and -not $S.SavedProfileID) ('wrong named save confirmed: '+$f.key)
  }
  ReceiveOrderedCandidates $S $reply 'save'
  Assert-Candidate ($S.SavedProfileID -ceq 'new-profile' -and $null -eq $S.Dialog.Tag -and $S.Draft.nodes[-1].id -ceq 'final') 'named save replaced the Home/editor final'
  $oldDraft=$S.Draft
  $suffix=@{id='original-suffix';mode='shadowsocks'}
  $S.Draft=@{execution='local';nodes=@($oldDraft.nodes[0],$oldDraft.nodes[1],$suffix,$oldDraft.nodes[-1])}
  $intermediate=@{}+$paired
  $intermediate.proposal_action='save-intermediate-profile'
  $intermediate.proposed_path=@($S.Draft.nodes[0],$S.Draft.nodes[1],$paired.proposed_path[-1],$suffix,$oldDraft.nodes[-1])
  Assert-Candidate (OrderedCandidateFinalProfileChoice $S $intermediate) 'measured intermediate lost full original suffix'
  $intermediate.proposed_path=@($S.Draft.nodes[0],$S.Draft.nodes[1],$paired.proposed_path[-1],$oldDraft.nodes[-1],$suffix)
  Assert-Candidate (-not (OrderedCandidateFinalProfileChoice $S $intermediate)) 'intermediate accepted reordered suffix'
  foreach($size in @(8,9,95,96)){
   $extra=@(4..($size-1)|ForEach-Object{@{id="deep-$_";mode='shadowsocks'}})
   $base=@($oldDraft.nodes[0],$oldDraft.nodes[1],$suffix)+$extra+@($oldDraft.nodes[-1])
   $S.Draft=@{execution='local';nodes=$base}
   $intermediate.proposed_path=@($base[0],$base[1],$paired.proposed_path[-1])+@($base[2..($base.Count-1)])
   Assert-Candidate ((OrderedCandidateFinalProfileChoice $S $intermediate) -eq ($size -lt 96)) 'deep insertion lost original suffix or physical depth'
  }
  $S.Draft=$oldDraft
  $S.SavedProfileID='';$S.SaveFinalProfile=$false
 }
 $bad=@{}+$value;$bad.measurement='routed-tcp-connect';$rejected=$false;try{ReceiveOrderedCandidates $S $bad 'poll'}catch{$rejected=$true}
 Assert-Candidate $rejected ('outer receipt changed measurement: '+$purpose)
 $private.results[0].kind='tcp-connect';Assert-Candidate ($null -eq (OrderedCandidateScore $private $Now $metric)) 'TCP result relabelled as private response'
 $private.results[0].kind='private-agent-response';$private.results[0].benchmark.measurement='routed-tcp-connect'
 Assert-Candidate ($null -eq (OrderedCandidateScore $private $Now $metric)) 'TCP benchmark relabelled as private response'
 $private.results[0].benchmark.measurement=$metric;$private.results[0].benchmark.distribution.samples=49
 Assert-Candidate ($null -eq (OrderedCandidateScore $private $Now $metric)) 'short private benchmark became selectable'
 $private.results[0].benchmark.distribution.samples=50
 Assert-Candidate ($null -eq (OrderedCandidateScore $private ($Now+120000) $metric)) 'expired private receipt could be saved'
 $S.CancelWanted=$true;ReceiveOrderedCandidates $S $value 'poll';SetOrderedCandidateControls $S
 Assert-Candidate ($S.Rows.Count -eq 0 -and -not $S.Save.IsEnabled) ('late private result survived cancel: '+$purpose)
}
foreach($depth in @(9,16,96)){
 $nodes=@(for($i=0;$i -lt $depth;$i++){@{id=('member-'+$i);mode=$(if($i){'shadowsocks'}else{'wg'})}})
 $position=$depth-2;$row=@{}+$nodes[$position];$row.position=$position;$row.measurement=$metric
 $S.Draft=@{execution='local';nodes=$nodes};$S.SavedPrefix=$true;$S.Position=$position;$S.View=@{measurement=$metric;prefixes=@($row)}
 $proposal=@($nodes|Select-Object -SkipLast 1)+@(@{id='new-final';mode='shadowsocks'})
 $choice=@{id='new-final';kind='router-vpn';proposal_action='save-final-profile';proposed_path=$proposal}
 Assert-Candidate (OrderedCandidateFinalProfileChoice $S $choice) 'original deep draft lost its explicit measured final'
 $proposal[$position]=@{id='replaced-late-prefix';mode='shadowsocks'}
 Assert-Candidate (-not(OrderedCandidateFinalProfileChoice $S $choice)) 'late replacement borrowed another measured route'
}
foreach($layout in @(@(4,2,-1),@(9,7,2),@(16,14,-1),@(96,94,94),@(4,1,-1),@(16,9,-1),@(9,6,-1),@(95,92,-1))){
 $depth,$position,$privatePosition=$layout
 $entryMode=if($depth -eq 9){'awg2-fast'}elseif($depth -eq 16){'awg2-strong'}else{'wg'}
 $insert=$position -lt $depth-2
 $action=if($insert){'save-intermediate-profile'}else{'save-final-profile'}
 $crossedAction=if($insert){'save-final-profile'}else{'save-intermediate-profile'}
 $nodes=@(for($i=0;$i -lt $depth;$i++){@{id=('member-'+$i);mode=$(if($i){'shadowsocks'}else{$entryMode})}})
 $source=@(for($i=0;$i -lt $depth;$i++){@{}+$nodes[$i]+@{kind=$(if($i -eq 0 -or $i -eq $privatePosition -or $i -eq $depth-1){'router-vpn'}else{'external'})}})
 $proposal=@($nodes[0..$position])+@(@{id='candidate-C';mode='shadowsocks'})
 if($insert){$proposal+=@($nodes[($position+1)..($depth-1)])}
 $choice=@{id='candidate-C';name='Measured candidate C';kind='router-vpn';proposal_action=$action;proposed_path=$proposal}
 $row=@{}+$nodes[$position]+@{position=$position;measurement=$metric;name='Original private hop'}
 foreach($temporary in @($false,$true)){
  $S.Position=$position;$S.SavedPrefix=$temporary;$S.SavedPath=$temporary;$S.Draft=if($temporary){@{execution='auto';nodes=$nodes}}else{$null}
  $S.CancelWanted=$false;$S.CloseWanted=$false;$S.PendingDrain=$false;$S.SavedAdmitted=$false;$S.Dialog.Tag=$null
  $offer=@{schema=1;samples=50;view_token='7'*64;expires_at=$Now+120000;prefix_position=$position;measurement=$metric;requested_execution='auto';required_selected_execution='local';response_source_nodes=$source;prefixes=@($row);candidates=@($choice)}
  if($temporary){$offer.scope='draft-complete-selected';$offer.origin='editor-draft'}else{$offer.selected_execution='local';$offer.selection_epoch=37L}
  foreach($requested in @('server','auto')){
   $savedDraft=$S.Draft
   $typed=@{}+$offer;$typed.requested_execution=$requested;$typed.response_executions=@(if($requested -ceq 'server'){'server'}else{'local';'server'})
   $typed.selected_execution='server';$typed.required_selected_execution='server';$typed.selection_epoch=42L
   if($temporary){$S.Draft=@{execution=$requested;nodes=$nodes}}
   Assert-Candidate (TestOrderedCandidateLocalResponse $S $typed) 'typed Server lost its original source or actual winner'
   $stale=@{}+$typed;$stale.selection_epoch=0L
   Assert-Candidate (-not(TestOrderedCandidateLocalResponse $S $stale)) 'typed Server accepted stale selection epoch'
   $stale=@{}+$typed;$stale.response_executions=@('local')
   Assert-Candidate (-not(TestOrderedCandidateLocalResponse $S $stale)) 'typed Server borrowed a Local-only lease'
   if($temporary){
    $typed.Remove('selected_execution');$typed.Remove('selection_epoch')
    if($requested -ceq 'auto'){$typed.Remove('required_selected_execution')}
    Assert-Candidate (TestOrderedCandidateLocalResponse $S $typed) 'pending typed source invented a prior winner'
   }
   $S.Draft=$savedDraft
  }
  if(-not $temporary -and $position -eq 1){
   $missing=@{}+$offer;$missing.Remove('response_source_nodes')
   $entry=@{id=$nodes[0].id;position=0;mode=$entryMode;name='Entry'}
   $missing.prefixes=@($entry,$row)
   $refused=$false;try{ReceiveOrderedCandidates $S $missing 'catalog'}catch{$refused=$true}
   Assert-Candidate $refused 'A connected intermediate at the first import lost its source map'
   $legacyChoice=@{}+$choice;$legacyChoice.Remove('proposal_action')
   $missing.candidates=@($legacyChoice)
   $refused=$false;try{ReceiveOrderedCandidates $S $missing 'catalog'}catch{$refused=$true}
   Assert-Candidate $refused 'An unmarked long proposal borrowed the three-node connected catalog'
   $legacyChoice.proposed_path=@($proposal[0..2])
   ReceiveOrderedCandidates $S $missing 'catalog'
   Assert-Candidate ($S.View.candidates[0].proposed_path.Count -eq 3) 'The three-node connected Compare response was lost'
   $legacyChoice.proposal_action=$action
   $refused=$false;try{ReceiveOrderedCandidates $S $missing 'catalog'}catch{$refused=$true}
   Assert-Candidate $refused 'A marked Save borrowed a three-node connected catalog'
   $legacyChoice.Remove('proposal_action')
   $missing.prefixes+=@(@{id='extra';position=2;mode='shadowsocks'})
   $refused=$false;try{ReceiveOrderedCandidates $S $missing 'catalog'}catch{$refused=$true}
   Assert-Candidate $refused 'An additional stop borrowed a three-node connected catalog'
  }
  if($depth -gt 4){
   $bad=@{}+$offer;$two=@($source.Clone())
   foreach($i in @(2,[Math]::Max(3,$position))){$two[$i]=@{}+$two[$i];$two[$i].kind='router-vpn'}
   $bad.response_source_nodes=$two;$refused=$false;try{ReceiveOrderedCandidates $S $bad 'catalog'}catch{$refused=$true}
   Assert-Candidate (-not $refused) 'Two retained private interiors lost a selected response'
  }
  $bad=@{}+$offer;$bad.candidates=@(@{}+$choice);$bad.candidates[0].proposal_action=$crossedAction
  $refused=$false;try{ReceiveOrderedCandidates $S $bad 'catalog'}catch{$refused=$true}
  Assert-Candidate $refused 'A different named Save action acquired this selected response'
  if($insert){
   $bad=@{}+$offer;$bad.response_source_nodes=@($source.Clone());$bad.response_source_nodes[2]=@{}+$source[2];$bad.response_source_nodes[2].kind='router-vpn'
   $refused=$false;try{ReceiveOrderedCandidates $S $bad 'catalog'}catch{$refused=$true};Assert-Candidate (-not $refused) 'Intermediate Save lost an existing private stream'
   $bad=@{}+$offer;$wrong=@{}+$choice;$wrong.proposed_path=@($proposal.Clone());$wrong.proposed_path[-1]=@{id='crossed-final';mode='shadowsocks'};$bad.candidates=@($wrong)
   $refused=$false;try{ReceiveOrderedCandidates $S $bad 'catalog'}catch{$refused=$true};Assert-Candidate $refused 'Intermediate Save dropped the original final'
   $bad=@{}+$offer;$reused=@{}+$choice;$reused.id=$nodes[-1].id;$reused.proposed_path=@($proposal.Clone());$reused.proposed_path[$position+1]=@{}+$nodes[-1];$bad.candidates=@($reused)
   $refused=$false;try{ReceiveOrderedCandidates $S $bad 'catalog'}catch{$refused=$true};Assert-Candidate $refused 'The retained original final was offered as an intermediate candidate'
  }
  foreach($badIndex in @(0,1,($depth-1))){
   $bad=@{}+$offer;$crossed=@($source.Clone());$crossed[$badIndex]=@{}+$crossed[$badIndex];$crossed[$badIndex].kind=if($crossed[$badIndex].kind -ceq 'external'){'router-vpn'}else{'external'}
   $bad.response_source_nodes=$crossed;$refused=$false;try{ReceiveOrderedCandidates $S $bad 'catalog'}catch{$refused=$true}
   Assert-Candidate $refused 'A changed saved role acquired a selected private response'
  }
  if(-not $temporary -and $depth -eq 95){
   $extra=@{id='extra';mode='shadowsocks'};$bad=@{}+$offer
   $extraSource=@{}+$extra+@{kind='external'}
   $bad.response_source_nodes=@($source[0..($depth-2)])+@($extraSource,$source[-1])
   $larger=@{}+$choice;$larger.proposed_path=@($proposal[0..($depth-1)])+@($extra,$proposal[-1]);$bad.candidates=@($larger)
   $refused=$false;try{ReceiveOrderedCandidates $S $bad 'catalog'}catch{$refused=$true};Assert-Candidate $refused '96 original nodes offered a 97th measured hop'
  }
  ReceiveOrderedCandidates $S $offer 'catalog'
  $value=@{}+$offer;$value.request_id=$S.RequestID;$value.results=@($private);$value.selected_execution='local';$value.selection_epoch=37L
  $value.native_down=$true;$value.accepted=$true;$value.active_path_changed=$false;$value.reviewing=$temporary;$value.drained=-not $temporary;$value.failure=''
  $private.results[0].benchmark.measurement=$metric;$private.results[0].benchmark.distribution.samples=50
  if(-not $temporary -and $depth -eq 4){
   $typed=@{}+$offer;$typed.response_executions=@('local','server');$typed.selected_execution='server';$typed.required_selected_execution='server'
   $missingChoice=@{}+$choice;$missingChoice.id='not-provisioned';$missingChoice.name='Unregistered'
   $missingChoice.proposed_path=@($proposal.Clone());$missingChoice.proposed_path[$position+1]=@{id=$missingChoice.id;mode='shadowsocks'}
   $typed.candidates=@($missingChoice,$choice)
   ReceiveOrderedCandidates $S $typed 'catalog'
   $terminal=@{}+$value;$terminal.response_executions=@('local','server');$terminal.selected_execution='server';$terminal.required_selected_execution='server'
   $missing=@{}+$private;$missing.candidate_id=$missingChoice.id
   $missingResult=@{}+$private.results[0];$missingResult.node_id=$missingChoice.id;$missingResult.candidate_disposition='not-registered';$missingResult.ready=$false;$missingResult.Remove('benchmark')
   $missing.results=@($missingResult);$terminal.results=@($missing,$private)
   ReceiveOrderedCandidates $S $terminal 'run'
   Assert-Candidate ($S.Rows.Count -eq 1 -and $S.Rows[0].ID -ceq $choice.id) 'unregistered candidate displaced its measured Server peer'
   $missingResult.ready=$true;$missingResult.benchmark=$private.results[0].benchmark
   ReceiveOrderedCandidates $S $terminal 'poll'
   Assert-Candidate ($S.Rows.Count -eq 1 -and $S.Rows[0].ID -ceq $choice.id) 'unregistered candidate acquired a contradictory benchmark'
   foreach($fault in @('owners','epoch','winner')){
    $cross=@{}+$terminal
    if($fault -ceq 'owners'){$cross.Remove('response_executions')}
    if($fault -ceq 'epoch'){$cross.selection_epoch=38L}
    if($fault -ceq 'winner'){$cross.selected_execution='local';$cross.required_selected_execution='local'}
    $refused=$false;try{ReceiveOrderedCandidates $S $cross 'status'}catch{$refused=$true}
    Assert-Candidate $refused ('actual Server receipt crossed its '+$fault)
   }
   ReceiveOrderedCandidates $S $offer 'catalog'
  }
  $crossed=@($source.Clone());$crossed[1]=@{}+$source[1];$crossed[1].id='foreign-import'
  $changedPosition=if($privatePosition -ge 0){$privatePosition}else{$position}
  $alternate=@($source.Clone());$alternate[$changedPosition]=@{}+$alternate[$changedPosition];$alternate[$changedPosition].kind=if($privatePosition -ge 0){'external'}else{'router-vpn'}
  $rekeyed=@($source.Clone());$rekeyed[0]=@{}+$source[0];$rekeyed[0].mode=if($entryMode -ceq 'awg2-strong'){'awg2-fast'}else{'awg2-strong'}
  foreach($field in @(@{key='response_source_nodes';v=$rekeyed},@{key='response_source_nodes';v=$alternate},@{key='response_source_nodes';v=$crossed},@{key='response_source_nodes';v=$null},@{key='selected_execution';v='server'},@{key='view_token';v='a'*64})){
   $bad=@{}+$value;$bad[$field.key]=$field.v;$refused=$false;try{ReceiveOrderedCandidates $S $bad 'poll'}catch{$refused=$true}
   Assert-Candidate $refused ('Changed selected result reached review '+$field.key)
  }
  ReceiveOrderedCandidates $S $value 'poll';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
  Assert-Candidate $S.Save.IsEnabled 'Original private response did not enable measured profile Save'
  $S.ProfileName.Text='Measured paired exit';&$Click
  $expectedPath=if($temporary){'/api/multihop/draft-candidates/save-profile'}else{'/api/multihop/prefix-candidates/save-profile'}
  Assert-Candidate ($SavedRequest.Path -ceq $expectedPath -and $SavedRequest.Body.name -ceq 'Measured paired exit' -and ($SavedRequest.Body.proposed_path.id -join ',') -ceq ($proposal.id -join ',')) 'Selected Compare did not save the full named final replacement'
  $saved=@{}+$value;$saved.saved_profile_id='future-profile';$saved.saved=$true;$saved.ok=$true;$saved.candidate_id='candidate-C';$saved.proposal_action=$action;$saved.proposed_path=$proposal
  $saved.profile_name='Measured paired exit';$saved.accepted=$false;$saved.reviewing=$false;$saved.drained=$true
  foreach($change in @(@{key='candidate_id';v='other'},@{key='proposal_action';v=$crossedAction},@{key='prefix_position';v=0},@{key='proposed_path';v=$nodes},@{key='response_source_nodes';v=$crossed},@{key='selection_epoch';v=38L})){
   $bad=@{}+$saved;$bad[$change.key]=$change.v;$refused=$false;try{ReceiveOrderedCandidates $S $bad 'save'}catch{$refused=$true}
   Assert-Candidate $refused ('Wrong named save confirmed '+$change.key)
  }
  ReceiveOrderedCandidates $S $saved 'save'
  Assert-Candidate ($S.Status.Text.Contains('Measured paired exit') -and -not $S.PendingDrain -and $null -eq $S.Dialog.Tag) 'Named selected profile changed the editor or lost write confirmation'
  if(-not $temporary -and $depth -eq 16){
   $body=OrderedCandidateCancelBody $S
   Assert-Candidate ($body.Count -eq 2 -and $body.view_token -ceq $offer.view_token -and $body.request_id -ceq $S.RequestID) 'Mapped connected Cancel omitted the original view'
   $reply=@{}+$value;$reply.results=@();$reply.reviewing=$false;$reply.running=$false;$reply.accepted=$false;$reply.drained=$true
   $reply.ok=$true;$reply.cancelled=$true;$reply.cleanup_pending=$false
   $reply.started=$false;$reply.admission_cancelled=$true;$S.PendingDrain=$true;$refused=$false
   try{ReceiveOrderedCandidates $S $reply 'cancel'}catch{$refused=$true}
   Assert-Candidate ($refused -and $S.PendingDrain) 'Late connected tombstone retired admitted work'
   $reply.started=$true;$reply.admission_cancelled=$false
   foreach($change in @(@{key='request_id';v='other'},@{key='view_token';v='foreign'},@{key='selection_epoch';v=38},@{key='accepted';v=$true},@{key='results';v=@($private)},@{key='running';v=$true},@{key='reviewing';v=$true},@{key='drained';v=$false})){
    $bad=@{}+$reply;$bad[$change.key]=$change.v;$refused=$false;try{ReceiveOrderedCandidates $S $bad 'cancel'}catch{$refused=$true}
    Assert-Candidate ($refused -and $S.PendingDrain) ('Connected Cancel retired foreign work '+$change.key)
   }
   ReceiveOrderedCandidates $S $reply 'cancel';Assert-Candidate (-not $S.PendingDrain) 'Connected cancellation retained joined work'
   $S.SavedAdmitted=$false;$S.PendingDrain=$true;$reply.started=$false;$reply.admission_cancelled=$true
   ReceiveOrderedCandidates $S $reply 'cancel';Assert-Candidate (-not $S.PendingDrain) 'Original connected admission tombstone did not retire'
  }
  if($temporary){
   $S.UseDraft=[pscustomobject]@{IsEnabled=$false;Visibility='Collapsed'}
   $draftPath=@($nodes[0..$position])+@(@{id='candidate-C';mode='shadowsocks'})+@($nodes[($position+1)..($depth-1)])
   $useChoice=@{}+$choice;$useChoice.draft_path=$draftPath;$useChoice.draft_action='insert-measured-hop'
   $draftOnly=$depth -eq 9 -and $insert
   if($draftOnly){$useChoice.Remove('proposed_path');$useChoice.Remove('proposal_action')}
   $useOffer=@{}+$offer;$useOffer.candidates=@($useChoice)
   ReceiveOrderedCandidates $S $useOffer 'catalog'
   ReceiveOrderedCandidates $S $value 'poll';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
   $eligible=$depth -lt 96
   Assert-Candidate ($S.UseDraft.IsEnabled -eq $eligible -and $S.Save.IsEnabled -ne $draftOnly -and (($S.UseDraft.Visibility -ceq 'Visible') -eq $eligible)) 'Use escaped the captured path capacity or private roles'
   if($eligible){
    $S.Preview=[pscustomobject]@{Text=''};&$PreviewChoice
    Assert-Candidate ($S.Preview.Text.Contains('Use in draft') -and $S.Preview.Text.Contains($nodes[-1].id) -and
       $S.Preview.Text.Contains('Named profile') -eq (-not $insert)) 'The two path previews confused insertion and final replacement'
    $S.ProfileName.Text='';$script:SavedRequest=$null;&$UseClick
    Assert-Candidate ($SavedRequest.Path -ceq '/api/multihop/draft-candidates/choose' -and $SavedRequest.Phase -ceq 'choose' -and -not $SavedRequest.Body.ContainsKey('name') -and
       ($SavedRequest.Body.proposed_path.id -join ',') -ceq ($draftPath.id -join ',')) 'Use posted a named Save or dropped original suffix'
    $used=@{}+$value;$used.draft_action='insert-measured-hop';$used.proposed_path=$draftPath;$used.candidate_id='candidate-C'
    $used.chosen=$true;$used.drained=$true;$used.accepted=$false;$used.reviewing=$false;$used.saved_profile_id='';$used.saved=$false;$used.running=$false;$used.cleanup_pending=$false;$used.cancelled=$false
    foreach($fault in @(@{key='draft_action';v='save-final-profile'},@{key='proposed_path';v=$nodes},@{key='selection_epoch';v=38L},@{key='native_down';v=$false},@{key='saved_profile_id';v='unexpected'},@{key='prefix_position';v=0},@{key='candidate_id';v='other'},@{key='view_token';v='foreign'},@{key='request_id';v='foreign'},@{key='response_source_nodes';v=$crossed})){
     $bad=@{}+$used;$bad[$fault.key]=$fault.v;$refused=$false;try{ReceiveOrderedCandidates $S $bad 'choose'}catch{$refused=$true}
     Assert-Candidate ($refused -and $null -eq $S.Dialog.Tag) ('Foreign draft insertion confirmed: '+$fault.key)
    }
    foreach($closing in @('CancelWanted','CloseWanted')){
     $S[$closing]=$true;$refused=$false;try{ReceiveOrderedCandidates $S $used 'choose'}catch{$refused=$true}
     Assert-Candidate ($refused -and $null -eq $S.Dialog.Tag) ('Late Choose after '+$closing+' changed the draft');$S[$closing]=$false
    }
    ReceiveOrderedCandidates $S $used 'choose'
    Assert-Candidate ($S.CloseWanted -and -not $S.PendingDrain -and $null -ne $S.Dialog.Tag -and -not $S.SavedProfileID) 'Use failed to return the unsaved insertion to its owner'
    $S.CloseWanted=$false;$S.Dialog.Tag=$null
   }
  }
  if($temporary -and $depth -eq 16){
   ReceiveOrderedCandidates $S $offer 'catalog'
   $failure=@{}+$saved;$failure.selected_execution='server';$failure.saved=$false;$failure.saved_profile_id='';$failure.running=$false
   $failure.cancelled=$true;$failure.failure='The Server winner cannot measure this private response.';$failure.results=@($private)
   $refused=$false;try{ReceiveOrderedCandidates $S $failure 'cancel'}catch{$refused=$true}
   Assert-Candidate $refused 'Server failure exposed measured scores'
   $failure.results=@();$S.PendingDrain=$true;ReceiveOrderedCandidates $S $failure 'cancel';SetOrderedCandidateControls $S
   Assert-Candidate (-not $S.PendingDrain -and -not $S.Save.IsEnabled -and -not $S.SavedProfileID) 'Failed Server trial retained ownership after original native DOWN'
  }
 }
}
# Use the same shipping catalog, measurement result, Save and Use handlers as the dialog.
$publicMetric='routed-public-candidate-response'
function Assert-PublicRefused($state,$value,$phase,$why){
 $refused=$false
 try {ReceiveOrderedCandidates $state $value $phase} catch {$refused=$true}
 Assert-Candidate $refused $why
}
foreach($layout in @(@(3,1,'wg'),@(4,1,'wg'),@(4,2,'wg'),@(9,1,'wg'),@(9,7,'wg'),@(96,1,'wg'),@(96,94,'wg'),@(9,7,'awg2-fast'),@(96,94,'awg2-strong'))){
 $depth,$position,$entryMode=$layout
 $nodes=@(for($i=0;$i -lt $depth;$i++){@{id="public-member-$i";mode=$(if($i){'shadowsocks'}else{$entryMode})}})
 $source=@(for($i=0;$i -lt $depth;$i++){@{}+$nodes[$i]+@{kind=$(if($i){'external'}else{'router-vpn'})}})
 $candidate='measured-public-import'
 $path=@($nodes[0..$position])+@(@{id=$candidate;mode='shadowsocks'})+@($nodes[($position+1)..($depth-1)])
 foreach($purpose in @('connected','saved','saved-prefix','draft')){
  $Now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $S.Position=$position;$S.Draft=$null;$S.View=$null;$S.SavedPath=$purpose -cne 'connected';$S.SavedPrefix=$purpose -cin @('saved-prefix','draft')
  $S.RequestID='d'*32;$S.SavedAdmitted=$false;$S.CancelWanted=$false;$S.CloseWanted=$false;$S.PendingDrain=$false;$S.Dialog.Tag=$null
  $S.Table.SelectedItems.Clear()
  if($purpose -ceq 'draft'){$S.Draft=@{execution='local';external_final=$true;nodes=$nodes}}
  $choice=@{id=$candidate;kind='external';name='Measured public import'}
  if($depth -eq 96){$choice.save_reason='At physical traversal limit.'}
  else{
   $choice.proposal_action='save-intermediate-profile';$choice.proposed_path=$path
   if($purpose -ceq 'draft'){$choice.draft_action='insert-measured-hop';$choice.draft_path=$path}
  }
  $offer=@{schema=1;samples=50;measurement=$publicMetric;view_token='c'*64;expires_at=$Now+120000;prefix_position=$position;requested_execution='local';external_final=$true;public_response_source_nodes=$source
   prefixes=@(@{}+$nodes[$position]+@{position=$position;name='Original public prefix';measurement=$publicMetric});candidates=@($choice)}
  if($S.SavedPath){$offer.scope=OrderedCandidateScope $S}
  if($S.SavedPrefix){$offer.proof_scope='selected-prefix';$offer.application_open=$false;$offer.dns_open=$false}
  if($purpose -ceq 'draft'){$offer.origin='editor-draft'}
  $context="$purpose/$depth/$position"
  if($depth -eq 4){
   foreach($fault in @('server','epoch','owner','wrong-entry','private-final','missing-map','duplicate','reused-final','private-choice','wrong-path','proposal-role')){
    $bad=@{}+$offer
    switch($fault){
     'server' {$bad.requested_execution='server'}
     'epoch' {$bad.selection_epoch=1L}
     'owner' {$bad.response_source_nodes=$source}
     'wrong-entry' {$bad.public_response_source_nodes=@($source.Clone());$bad.public_response_source_nodes[0]=@{}+$source[0];$bad.public_response_source_nodes[0].mode='openvpn'}
     'private-final' {$bad.public_response_source_nodes=@($source.Clone());$bad.public_response_source_nodes[-1]=@{}+$source[-1];$bad.public_response_source_nodes[-1].kind='router-vpn'}
     'missing-map' {$bad.Remove('public_response_source_nodes')}
     'duplicate' {$bad.candidates=@($choice,$choice)}
     'reused-final' {$bad.candidates=@(@{}+$choice);$bad.candidates[0].id=$nodes[-1].id}
     'private-choice' {$bad.candidates=@(@{}+$choice);$bad.candidates[0].kind='router-vpn'}
     'wrong-path' {$bad.candidates=@(@{}+$choice);$bad.candidates[0].proposed_path=@($path.Clone());$bad.candidates[0].proposed_path[-1]=@{id='changed-public-exit';mode='shadowsocks'}}
     'proposal-role' {$bad.candidates=@(@{}+$choice);$bad.candidates[0].proposal_action='save-final-profile'}
    }
    Assert-PublicRefused $S $bad 'catalog' "public catalog $context accepted $fault"
   }
  }
  if($purpose -ceq 'draft'){
   $switched=@{}+$offer;$switched.public_response_source_nodes=@($source.Clone());$switched.public_response_source_nodes[0]=@{}+$source[0]
   $switched.public_response_source_nodes[0].mode=if($entryMode -ceq 'awg2-fast'){'awg2-strong'}else{'awg2-fast'}
   Assert-PublicRefused $S $switched 'catalog' "public draft $context accepted a different paired transport"
  }
  ReceiveOrderedCandidates $S $offer 'catalog'
  Assert-Candidate ($S.Rows.Count -eq 1 -and $S.Rows[0].ID -ceq $candidate) "public catalog $context lost sole independent import"
  if($purpose -ceq 'connected'){Assert-Candidate ($S.Status.Text -ceq 'Measure 50 HTTPS responses after TLS through each candidate and verify its expected public exit IP.') "public catalog $context described a different measurement"}
  if($purpose -ceq 'draft'){Assert-Candidate ($S.AutoRun -and $S.Table.SelectedItems.Count -eq 1) "draft auto-run omitted publicly measurable $context"}
  else{[void]$S.Table.SelectedItems.Add($S.Rows[0])}
  $script:SavedRequest=$null;&$RunClick
  Assert-Candidate ($SavedRequest.Phase -ceq 'run' -and $SavedRequest.Body.prefix_position -eq $position -and $SavedRequest.Body.samples -eq 50 -and ($SavedRequest.Body.candidate_ids -join ',') -ceq $candidate) "public Run dispatched a different prefix $context"
  $receipt=New-CandidateRow;$receipt.measurement=$publicMetric;$receipt.candidate_id=$candidate
  $result=$receipt.results[0];$result.kind='public-exit-response';$result.node_id=$candidate
  $result.benchmark.measurement=$publicMetric;$result.benchmark.endpoint='https://1.1.1.1/cdn-cgi/trace'
  $value=@{schema=1;measurement=$publicMetric;request_id=$S.RequestID;view_token=$offer.view_token;prefix_position=$position;accepted=$true;native_down=$true;drained= -not $S.SavedPath;active_path_changed=$false;reviewing=$S.SavedPath;failure='';results=@($receipt)}
  foreach($key in @('scope','origin','proof_scope','application_open','dns_open')){if($offer.ContainsKey($key)){$value[$key]=$offer[$key]}}
  if($purpose -ceq 'draft'){$value.requested_execution='local'}
  if($depth -eq 4){
   foreach($fault in @('kind','metric','endpoint','samples')){
    $broken=@{}+$receipt;$broken.results=@(@{}+$result);$b=@{}+$result.benchmark;$broken.results[0].benchmark=$b
    switch($fault){'kind'{$broken.results[0].kind='private-agent-response'} 'metric'{$b.measurement='routed-candidate-response'} 'endpoint'{$b.endpoint='https://1.0.0.1/cdn-cgi/trace'} 'samples'{$b.distribution=@{}+$b.distribution;$b.distribution.samples=49}}
    $wrong=@{}+$value;$wrong.results=@($broken)
    ReceiveOrderedCandidates $S $wrong 'run'
    Assert-Candidate ($S.Rows.Count -eq 0) "public ranking $context accepted $fault"
   }
   foreach($fault in @('selected_execution','selection_epoch','requested_execution','external_final','public_response_source_nodes')){
    $wrong=@{}+$value
    switch($fault){'selected_execution'{$wrong[$fault]='server'} 'selection_epoch'{$wrong[$fault]=1} 'requested_execution'{$wrong[$fault]='auto'} 'external_final'{$wrong[$fault]=$false} 'public_response_source_nodes'{$wrong.external_final=$true;$wrong.requested_execution='local';$wrong[$fault]=@($source.Clone());$wrong[$fault][-1]=@{}+$source[-1];$wrong[$fault][-1].id='foreign-final'}}
    Assert-PublicRefused $S $wrong 'poll' "public review $context accepted $fault"
   }
  }
  ReceiveOrderedCandidates $S $value 'run';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
  Assert-Candidate ($S.Rows.Count -eq 1 -and $S.Rows[0].Timing.Contains('50/50 HTTPS exit responses')) "public $context lost verified timing"
  if($depth -eq 96){
   Assert-Candidate (-not $S.Save.IsEnabled -and -not $S.UseDraft.IsEnabled) "public $context offered a 97th hop"
   $bad=@{}+$offer;$bad.candidates=@(@{}+$choice);$bad.candidates[0].proposal_action='save-intermediate-profile';$bad.candidates[0].proposed_path=$path
   Assert-PublicRefused $S $bad 'catalog' "public $context allowed a 97th hop payload"
   continue
  }
  Assert-Candidate $S.Save.IsEnabled "public $context lost explicit named profile Save"
  $S.ProfileName.Text='Public original';$script:SavedRequest=$null;&$Click
  Assert-Candidate ($SavedRequest.Phase -ceq 'save' -and $SavedRequest.Body.name -ceq 'Public original' -and ($SavedRequest.Body.proposed_path.id -join ',') -ceq ($path.id -join ',')) "public $context Save dropped suffix or final"
  $saved=@{}+$value;$saved.ok=$true;$saved.saved=$true;$saved.saved_profile_id='measured-public-profile';$saved.profile_name='Public original';$saved.proposal_action='save-intermediate-profile';$saved.candidate_id=$candidate;$saved.proposed_path=$path;$saved.accepted=$false;$saved.reviewing=$false;$saved.drained=$true
  foreach($fault in @('candidate_id','request_id','proposed_path','proposal_action')){
   $bad=@{}+$saved
   if($fault -ceq 'proposed_path'){$bad[$fault]=$nodes}else{$bad[$fault]='foreign'}
   Assert-PublicRefused $S $bad 'save' "public named Save $context accepted $fault"
  }
  ReceiveOrderedCandidates $S $saved 'save'
  Assert-Candidate ($S.Status.Text.Contains('Public original') -and $null -eq $S.Dialog.Tag) "public named Save $context changed the draft"
  if($purpose -cin @('saved','saved-prefix')){
   foreach($phase in @('poll','cancel')){
    $S.SavedProfileID='';$S.Status.Text=''
    foreach($field in @('proposed_path','candidate_id','proposal_action')){
     $changed=@{}+$saved
     if($field -ceq 'proposed_path'){
      $changed.proposed_path=@($path.Clone());$changed.proposed_path[-1]=@{id='foreign-public-exit';mode='shadowsocks'}
     }else{$changed[$field]='foreign'}
     Assert-PublicRefused $S $changed $phase "public $context lost Save response accepted a changed $field on $phase"
     Assert-Candidate (-not $S.SavedProfileID) "public $context acknowledged a foreign save on $phase"
    }
    ReceiveOrderedCandidates $S $saved $phase
    Assert-Candidate ($S.SavedProfileID -ceq $saved.saved_profile_id -and $S.Status.Text.Contains('Public original')) "public $context lost its original save on $phase"
   }
  }
  if($purpose -ceq 'draft'){
   $S.Table.SelectedItems.Clear();ReceiveOrderedCandidates $S $offer 'catalog';ReceiveOrderedCandidates $S $value 'poll';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
   Assert-Candidate $S.UseDraft.IsEnabled "public $context lost Use in draft"
   $script:SavedRequest=$null;&$UseClick
   Assert-Candidate ($SavedRequest.Phase -ceq 'choose' -and ($SavedRequest.Body.proposed_path.id -join ',') -ceq ($path.id -join ',')) "public $context Use changed its retained final"
   $used=@{}+$value;$used.proposed_path=$path;$used.candidate_id=$candidate;$used.draft_action='insert-measured-hop';$used.saved_profile_id='';$used.chosen=$true;$used.drained=$true
   foreach($field in @('accepted','running','reviewing','cleanup_pending','cancelled')){$used[$field]=$false}
   foreach($fault in @('native_down','proposed_path','candidate_id')){
    $bad=@{}+$used;if($fault -ceq 'native_down'){$bad[$fault]=$false}elseif($fault -ceq 'proposed_path'){$bad[$fault]=$nodes}else{$bad[$fault]='another'}
    Assert-PublicRefused $S $bad 'choose' "public $context Use accepted $fault"
   }
   ReceiveOrderedCandidates $S $used 'choose'
   Assert-Candidate ($S.CloseWanted -and -not $S.PendingDrain -and ($S.Dialog.Tag.proposed_path.id -join ',') -ceq ($path.id -join ',')) "public $context did not hand off exact joined insertion"
  }
 }
}
Write-Output "Composed Windows ordered candidates: PASS ($Count checks; actual functions and save callback, no WPF or VPN connection)"
