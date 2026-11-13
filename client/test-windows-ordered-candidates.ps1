param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
# Execute the actual launcher composition and existing asynchronous ownership
# witness, then extract this new dialog's shipping functions and callbacks.
. (Join-Path $Root 'client/test-windows-performance.ps1') -Root $Root
$Ast=[ScriptBlock]::Create($ProductSource).Ast
foreach($Name in @('ExternalComparisonValue','ExternalComparisonToken','OrderedCandidateScore','OrderedCandidateBase','OrderedCandidateScope','OrderedCandidateCatalogPath','OrderedCandidateScopedBody','OrderedCandidateNumber','OrderedCandidateSavedEnvelope','OrderedCandidateBeforeStart','OrderedCandidateCancelBody','OrderedCandidateReady','SetOrderedCandidateControls','ReceiveOrderedCandidates','TickOrderedCandidates')){
 $F=@($Ast.FindAll({param($n)$n-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$Name},$true));if($F.Count-ne1){throw "Missing shipping candidate function $Name"};. ([ScriptBlock]::Create($F[0].Extent.Text))
}
$Count=0
function Assert-Candidate($OK,[string]$Why){$script:Count++;if(-not$OK){throw ('ORDERED-CANDIDATE-CHECK: '+$Why)}}
$Now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
function New-CandidateRow {return @{measurement='routed-tcp-connect';complete=$true;drained=$true;stage='complete';candidate_id='custom-original';measured_at=$Now;expires_at=$Now+120000;results=@(@{node_id='custom-original';kind='tcp-connect';role='candidate';ready=$true;benchmark=@{measurement='routed-tcp-connect';attempts=50;failed=0;trimmed_mean_ms=2.0;distribution=@{samples=50;min_ms=1.0;max_ms=3.0}}})}}
$R=New-CandidateRow;Assert-Candidate ((OrderedCandidateScore $R $Now)-eq2) 'complete exact TCP row rejected'
Assert-Candidate ($null-eq(OrderedCandidateScore $R ($Now+120000))) 'status polling renewed expired receipt'
foreach($Field in @('attempts','failed')){$R=New-CandidateRow;$R.results[0].benchmark[$Field]=if($Field-ceq'attempts'){49}else{1};Assert-Candidate ($null-eq(OrderedCandidateScore $R $Now)) ('incomplete '+$Field+' became sortable')}
$R=New-CandidateRow;$R.results[0].benchmark.trimmed_mean_ms=[double]::NaN;Assert-Candidate ($null-eq(OrderedCandidateScore $R $Now)) 'nonfinite score became sortable'
$R=New-CandidateRow;$R.results[0].node_id='foreign';Assert-Candidate ($null-eq(OrderedCandidateScore $R $Now)) 'foreign candidate row became sortable'
$R=New-CandidateRow;$R.measurement='icmp';Assert-Candidate ($null-eq(OrderedCandidateScore $R $Now)) 'ICMP masqueraded as routed TCP'
$S=@{Closed=$false;CancelWanted=$false;CloseWanted=$false;Next=[DateTime]::UtcNow.AddSeconds(1);Position=0;View=$null;Receipt=$null;Rows=@();Table=[pscustomobject]@{ItemsSource=$null;SelectedItem=$null};Prefix=[pscustomobject]@{ItemsSource=$null;SelectedValue=$null;IsEnabled=$false};Status=[pscustomobject]@{Text=''};RequestID=('b'*32);PendingDrain=$true;Task=$null;Refresh=[pscustomobject]@{IsEnabled=$false};Run=[pscustomobject]@{IsEnabled=$false};Save=[pscustomobject]@{IsEnabled=$false};Cancel=[pscustomobject]@{IsEnabled=$false}}
$Path=@(@{id='entry';mode='wg'},@{id='custom-original';mode='shadowsocks'},@{id='final';mode='shadowsocks'})
$Catalog=@{view_token=('a'*64);prefix_position=0;expires_at=$Now+120000;prefixes=@(@{position=0;name='Original entry';mode='wg'});candidates=@(@{id='custom-original';name='Original custom';proposed_path=$Path;save_reason=''})}
ReceiveOrderedCandidates $S $Catalog 'catalog';Assert-Candidate ($S.View.view_token-ceq('a'*64)-and$S.Rows.Count-eq1) 'actual catalog capture lost original candidate'
$Value=@{request_id=$S.RequestID;view_token=$Catalog.view_token;prefix_position=0;drained=$true;accepted=$true;results=@((New-CandidateRow));failure=''}
ReceiveOrderedCandidates $S $Value 'run';$S.Table.SelectedItem=$S.Rows[0];SetOrderedCandidateControls $S
Assert-Candidate ($S.Save.IsEnabled-and-not$S.PendingDrain-and$S.Rows[0].ID-ceq'custom-original') 'joined current receipt did not enable explicit profile save'
function StartOrderedCandidateRequest($State,$Phase,$Path,$Body){$script:SavedRequest=@{Phase=$Phase;Path=$Path;Body=$Body}}
$S.Next=[DateTime]::UtcNow.AddSeconds(-1);$script:SavedRequest=$null;TickOrderedCandidates $S
Assert-Candidate ($SavedRequest.Phase-ceq'poll'-and$SavedRequest.Path-ceq('/api/multihop/prefix-candidates?request_id='+$S.RequestID)) 'actual timer did not observe the original completed owner'
$Lost=@{request_id=$S.RequestID;view_token=$Catalog.view_token;prefix_position=0;drained=$true;accepted=$false;results=@();failure='Original reader changed'}
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
$RunEvent=@($Dialog[0].FindAll({param($n)$n-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Expression.Extent.Text-ceq'$S.Run'-and$n.Member.Extent.Text-ceq'Add_Click'},$true));Assert-Candidate ($RunEvent.Count-eq1) 'actual test callback missing'
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
Write-Output "Composed Windows ordered candidates: PASS ($Count checks; actual functions and save callback, no WPF or VPN connection)"
