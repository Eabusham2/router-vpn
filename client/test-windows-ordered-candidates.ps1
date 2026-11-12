param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
# Execute the actual launcher composition and existing asynchronous ownership
# witness, then extract this new dialog's shipping functions and callbacks.
. (Join-Path $Root 'client/test-windows-performance.ps1') -Root $Root
$Ast=[ScriptBlock]::Create($ProductSource).Ast
foreach($Name in @('ExternalComparisonValue','ExternalComparisonToken','OrderedCandidateScore','SetOrderedCandidateControls','ReceiveOrderedCandidates','TickOrderedCandidates')){
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
Write-Output "Composed Windows ordered candidates: PASS ($Count checks; actual functions and save callback, no WPF or VPN connection)"
