param([Parameter(Mandatory=$true)][string]$ProductSource)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Net.Http
$Ast=[ScriptBlock]::Create($ProductSource).Ast
$Names=@('BeginUnifiedCandidateEntryChoice','MarkUnifiedCandidateEntryChoice','CommitUnifiedCandidateEntryChoice','UnifiedMultihopValue','TestUnifiedCandidateCurrent','TestUnifiedCandidateFresh','ReadUnifiedCandidateReceipt','TestUnifiedCandidateValidation','UpdateUnifiedCandidateButtons','NewUnifiedCandidateRequest','StartUnifiedCandidates','FinishUnifiedCandidateCancel','StopUnifiedCandidates','SelectUnifiedCandidate','PollUnifiedCandidates')
$Original=@{}
foreach($Name in $Names){
    $Functions=@($Ast.FindAll({param($N)$N-is[System.Management.Automation.Language.FunctionDefinitionAst] -and $N.Name-eq$Name},$true))
    if($Functions.Count-ne1){throw "Missing shipping candidate function: $Name"}
    $Original[$Name]=$Functions[0].Extent.Text
    . ([ScriptBlock]::Create($Original[$Name]))
}
$script:Checks=0
function Check([bool]$Value,[string]$Message){$script:Checks++;if(-not$Value){throw $Message}}
function Log([string]$Text){}
function New-State{
    $Client=[pscustomobject]@{Jobs=(New-Object System.Collections.ArrayList)}
    $Client|Add-Member ScriptMethod SendAsync {param($Request,$Token)
        $Source=[System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]]::new()
        $Job=[pscustomobject]@{Path=$Request.RequestUri.AbsolutePath;Body=($Request.Content.ReadAsStringAsync().GetAwaiter().GetResult()|ConvertFrom-Json);Source=$Source;Token=$Token}
        [void]$this.Jobs.Add($Job);return $Source.Task
    }
    $Dialog=[pscustomobject]@{CloseCalls=0};$Dialog|Add-Member ScriptMethod Close {$this.CloseCalls++}
    $S=@{Closed=$false;AllowClose=$false;EntryID='entry';EntryName='Selected entry';Names=[ordered]@{slow='Slow exit';best='Best exit';failed='Failed exit'};RequestID='';Receipt=$null;Expires=[DateTimeOffset]::MinValue;Rows=@();Eligible=@{};FastestID='';PendingExit='';Operation='';Action='';LastError='';Cancelled=$false;CancelAck=$false;Client=$Client;Task=$null;Request=$null;Cts=$null;CancelTask=$null;CancelRequest=$null;CancelCts=$null;List=[pscustomobject]@{SelectedItem=$null;ItemsSource=$null};Status=[pscustomobject]@{Text=''};Dialog=$Dialog}
    foreach($N in @('Select','Fastest','Retest','Cancel')){$S[$N]=[pscustomobject]@{IsEnabled=$false}}
    $script:MultihopEntryCombo=[pscustomobject]@{SelectedValue='entry'};$script:MultihopExitCombo=[pscustomobject]@{SelectedValue='slow'};$script:UnifiedCandidates=$S
    return $S
}
function Receipt($S){return @{schema=1;request_id=$S.RequestID;entry_id=$S.EntryID;entry_mode='wg';entry_base='wg';drained=$true;measured_at=[DateTimeOffset]::UtcNow.ToString('o');expires_at=[DateTimeOffset]::UtcNow.AddSeconds(120).ToString('o');results=@(@{id='slow';samples=5;failed=0;median_ms=20.5},@{id='best';samples=5;failed=0;median_ms=7.25},@{id='failed';samples=4;failed=1;median_ms=1});errors=@(@{id='failed';error='candidate TCP timeout'});fastest_id='best'}}
function Complete($Job,$Value,[int]$Status=200){
    $Response=[System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$Status)
    $Response.Content=[System.Net.Http.StringContent]::new(($Value|ConvertTo-Json -Depth 12 -Compress))
    $Job.Source.SetResult($Response)
}
function Measure-CandidatesTest($S){StartUnifiedCandidates $S;Complete $S.Client.Jobs[0] (Receipt $S);PollUnifiedCandidates $S}
function Ack($S){Complete $S.Client.Jobs[$S.Client.Jobs.Count-1] @{ok=$true;request_id=$S.RequestID;drained=$true};PollUnifiedCandidates $S}

$S=New-State;Measure-CandidatesTest $S
Check ($S.Client.Jobs[0].Path-eq'/api/multihop/candidates') 'Wrong candidate endpoint'
Check ($S.RequestID-cmatch'^[0-9a-f]{32}$' -and $S.Client.Jobs[0].Body.request_id-ceq$S.RequestID) 'Nonce not captured before request'
Check ($S.Client.Jobs[0].Body.samples-eq5 -and $S.Client.Jobs[0].Body.base-eq'wg' -and @($S.Client.Jobs[0].Body.candidate_ids).Count-eq3 -and $S.Client.Jobs[0].Body.candidate_ids-notcontains'entry') 'Candidate request identities or sample count changed'
Check ($S.Rows.Count-eq3 -and $S.Eligible.Count-eq2) 'Partial failures dropped or eligible candidates lost'
$Failed=@($S.Rows|Where-Object id -eq 'failed')[0]
Check (-not$Failed.eligible -and $null-eq$Failed.median_ms -and $Failed.response-like'*unavailable*candidate TCP timeout*') 'Failure was displayed as a numeric routed RTT'
# This fixture is executed directly by Windows PowerShell 5.1, which reads a
# BOM-less file as the system code page. The product source is explicitly UTF-8.
# Construct the exact Unicode expectations without code-page-dependent bytes.
$ViaLabel='*via Selected entry '+[char]0x00B7+' TCP response 7*'
Check ($S.Rows[1].response-like$ViaLabel -and $MultihopExitCombo.SelectedValue-eq'slow') 'Measurement selected an exit or lost its via-entry label'
SelectUnifiedCandidate $S 'best'
Check ($S.Client.Jobs[1].Path-eq'/api/multihop/candidates/validate' -and $MultihopExitCombo.SelectedValue-eq'slow') 'Selection skipped validation'
Complete $S.Client.Jobs[1] @{ok=$true;measured=$true;request_id=$S.RequestID;entry_id='entry';exit_id='best';entry_base='wg';entry_mode='wg'};PollUnifiedCandidates $S
Check ($MultihopExitCombo.SelectedValue-eq'best' -and $S.Dialog.CloseCalls-eq0 -and $S.Cancelled) 'Validated selection did not await owned cleanup'
Complete $S.Client.Jobs[2] @{ok=$true;request_id=$S.RequestID;drained=$false};PollUnifiedCandidates $S
Check ($S.Dialog.CloseCalls-eq0 -and -not$S.Retest.IsEnabled -and $S.Cancel.IsEnabled) 'Failed cleanup released or restarted candidate operation'
StopUnifiedCandidates $S 'close';Ack $S
Check ($S.Dialog.CloseCalls-eq1 -and -not$S.RequestID) 'Acknowledged cancellation did not release dialog'
Check (@($S.Client.Jobs|Where-Object{$_.Path-notmatch'^/api/multihop/candidates(?:/validate|/cancel)?$'}).Count-eq0) 'Candidate selection called a connection or direct-cache endpoint'

foreach($Case in @('request','entry','base','mode','missing','drained','typed-drained','expiry','measurement-time','duplicate','unknown','fastest')){
    $S=New-State;StartUnifiedCandidates $S;$R=Receipt $S
    switch($Case){
        request {$R.request_id='00000000000000000000000000000000'}
        entry {$R.entry_id='other'}
        base {$R.entry_base='awg'}
        mode {$R.entry_mode='awg2-fast'}
        missing {$R.results=@($R.results|Where-Object id -ne 'slow')}
        drained {$R.drained=$false}
        typed-drained {$R.drained='true'}
        expiry {$R.expires_at=[DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('o')}
        measurement-time {$R.measured_at=[DateTimeOffset]::UtcNow.AddMinutes(5).ToString('o')}
        duplicate {$R.results+=,$R.results[0]}
        unknown {$R.results[0].id='not-captured'}
        fastest {$R.fastest_id='failed'}
    }
    $Rejected=$false;try{ReadUnifiedCandidateReceipt $S $R}catch{$Rejected=$true}
    Check $Rejected ("Accepted invalid routed receipt: $Case")
    StopUnifiedCandidates $S 'cancel';Complete $S.Client.Jobs[0] @{error='cancelled'} 409;Ack $S
}
$S=New-State;StartUnifiedCandidates $S;$R=Receipt $S;$R.results=$null;$R.fastest_id='';$R.errors=@($S.Names.Keys|ForEach-Object{@{id=$_;error='unavailable routed TCP response'}})
ReadUnifiedCandidateReceipt $S $R
Check ($S.Rows.Count-eq3 -and $S.Eligible.Count-eq0 -and -not$S.FastestID) 'All-failed null results fabricated or lost candidate rows'
StopUnifiedCandidates $S 'cancel';Complete $S.Client.Jobs[0] @{error='cancelled'} 409;Ack $S

foreach($Bad in @([double]::NaN,[double]::PositiveInfinity,-1,0)){
    $S=New-State;StartUnifiedCandidates $S;$R=Receipt $S;$R.results[1].median_ms=$Bad;$R.fastest_id=''
    ReadUnifiedCandidateReceipt $S $R
    Check (-not$S.Eligible.ContainsKey('best') -and $null-eq$S.Rows[1].median_ms) 'Invalid median became a routed score'
    StopUnifiedCandidates $S 'cancel';Complete $S.Client.Jobs[0] @{error='cancelled'} 409;Ack $S
}
foreach($Count in @(0,1,2,3.5,[double]::PositiveInfinity)){
    $S=New-State;StartUnifiedCandidates $S;$R=Receipt $S;$R.results[1].samples=$Count;$R.fastest_id='';ReadUnifiedCandidateReceipt $S $R
    Check (-not$S.Eligible.ContainsKey('best')) 'Fewer than 3 samples became eligible'
    StopUnifiedCandidates $S 'cancel';Complete $S.Client.Jobs[0] @{error='cancelled'} 409;Ack $S
}
function Reject-Selection([string]$Case){
    $S=New-State;Measure-CandidatesTest $S;SelectUnifiedCandidate $S 'best'
    $V=@{ok=$true;measured=$true;request_id=$S.RequestID;entry_id='entry';exit_id='best';entry_base='wg';entry_mode='wg'};$Status=200
    switch($Case){
        request {$V.request_id='00000000000000000000000000000000'}
        entry {$V.entry_id='other'}
        base {$V.entry_base='awg'}
        mode {$V.entry_mode='awg2-fast'}
        exit {$V.exit_id='slow'}
        measured {$V.measured=$false}
        typed-measured {$V.measured='true'}
        expiry {$S.Expires=[DateTimeOffset]::UtcNow.AddSeconds(-1)}
        conflict {$Status=409}
    }
    Complete $S.Client.Jobs[1] $V $Status;PollUnifiedCandidates $S
    Check ($MultihopExitCombo.SelectedValue-eq'slow' -and $S.Cancelled) ("Stale validation changed the selected exit: $Case")
    Ack $S
}
foreach($Case in @('request','entry','exit','base','mode','measured','typed-measured','expiry','conflict')){Reject-Selection $Case}

$S=New-State;StartUnifiedCandidates $S;$OldID=$S.RequestID;$Late=Receipt $S
StopUnifiedCandidates $S 'retest'
Check ($S.Client.Jobs[1].Body.request_id-eq$OldID -and $S.Client.Jobs[0].Token.IsCancellationRequested) 'Pending cancellation lost the original nonce or sender'
Ack $S
Check ($S.Client.Jobs.Count-eq2 -and $S.RequestID-eq$OldID -and -not$S.Retest.IsEnabled) 'Retest began before old HTTP sender completed'
Complete $S.Client.Jobs[0] $Late;PollUnifiedCandidates $S
Check ($S.Client.Jobs.Count-eq3 -and $S.RequestID-ne$OldID -and $null-eq$S.Receipt -and $MultihopExitCombo.SelectedValue-eq'slow') 'Late cancelled receipt was adopted or Retest reused its nonce'
Complete $S.Client.Jobs[2] (Receipt $S);PollUnifiedCandidates $S
StopUnifiedCandidates $S 'close';Ack $S

$S=New-State;StartUnifiedCandidates $S;$Late=Receipt $S;$MultihopEntryCombo.SelectedValue='other';PollUnifiedCandidates $S
Check ($S.Cancelled -and $S.Action-eq'close') 'Entry replacement did not invalidate pending operation'
Complete $S.Client.Jobs[0] $Late;Ack $S
Check ($S.Dialog.CloseCalls-eq1 -and $MultihopExitCombo.SelectedValue-eq'slow') 'Old entry response survived reselection'

# Executable mutation control: removing the receipt validation branch must make
# the actual completion callback adopt a stale ID and fail this same test.
$Mutation=$Original['PollUnifiedCandidates'].Replace('if(-not(TestUnifiedCandidateValidation $State $Value))','if($false)')
Check ($Mutation-cne$Original['PollUnifiedCandidates']) 'Validation mutation seam missing'
. ([ScriptBlock]::Create($Mutation))
$Caught=$false;try{Reject-Selection 'request'}catch{$Caught=$true}
. ([ScriptBlock]::Create($Original['PollUnifiedCandidates']))
Check $Caught 'Negative control failed to expose stale receipt adoption'

$script:Busy=$false;$script:TestBusy=$false;$script:UnifiedEntryChoice=$null;$script:PickerOpens=0
function UnifiedAsyncBusy{return $script:TestBusy}
function ShowUnifiedCandidates{$script:PickerOpens++}
$MultihopEntryCombo.SelectedValue='entry';MarkUnifiedCandidateEntryChoice;CommitUnifiedCandidateEntryChoice
Check ($script:PickerOpens-eq0) 'Startup/programmatic selection opened measurement'
BeginUnifiedCandidateEntryChoice;MarkUnifiedCandidateEntryChoice;CommitUnifiedCandidateEntryChoice
Check ($script:PickerOpens-eq0) 'Unchanged entry popup opened measurement'
BeginUnifiedCandidateEntryChoice;$MultihopEntryCombo.SelectedValue='explicit-entry';MarkUnifiedCandidateEntryChoice;CommitUnifiedCandidateEntryChoice
Check ($script:PickerOpens-eq1) 'Explicit changed entry did not measure candidates'
BeginUnifiedCandidateEntryChoice;$script:Busy=$true;$MultihopEntryCombo.SelectedValue='refresh-entry';MarkUnifiedCandidateEntryChoice;$script:Busy=$false;CommitUnifiedCandidateEntryChoice
Check ($script:PickerOpens-eq1) 'Programmatic refresh was treated as an entry-picker commit'
$script:TestBusy=$true;BeginUnifiedCandidateEntryChoice;$MultihopEntryCombo.SelectedValue='busy-entry';MarkUnifiedCandidateEntryChoice;CommitUnifiedCandidateEntryChoice
Check ($script:PickerOpens-eq1) 'Entry picker opened a competing operation'

foreach($Marker in @('UnifiedCandidatesButton','ShowUnifiedCandidates','UseProxy=$false','AllowAutoRedirect=$false','MaxResponseContentBufferSize=2097152',"StopUnifiedCandidates `$script:UnifiedCandidates 'close'",('Measure exits via entry'+[char]0x2026))){Check ($ProductSource.Contains($Marker)) ("Candidate shipping UI or lifecycle seam missing: $Marker")}
Write-Host "Windows routed candidate UI/receipt/cancellation tests: PASS ($script:Checks checks; stale-selection mutation rejected)"
