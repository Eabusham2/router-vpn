param([string]$Source=(Join-Path $PSScriptRoot 'RouterVPN-Windows-DNSMeasurement.ps1'),[switch]$Live,[string]$Scenario='success',[string]$BaseUrl='http://127.0.0.1:8788')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
Add-Type -AssemblyName System.Net.Http
$Text=Get-Content -LiteralPath $Source -Raw -Encoding UTF8
$Tokens=$null;$Errors=$null
[void][Management.Automation.Language.Parser]::ParseInput($Text,[ref]$Tokens,[ref]$Errors)
if($Errors.Count){throw ($Errors.Message -join '; ')}
. ([ScriptBlock]::Create($Text))
$script:Checks=0
function Check([bool]$Condition,[string]$Message){if(-not$Condition){throw ('CONTROL '+$Message)};$script:Checks++}
function Reject([scriptblock]$Action,[string]$Message){$Caught=$false;try{&$Action}catch{$Caught=$true};Check $Caught $Message}
function FakeClient {
    $Client=[pscustomobject]@{Jobs=[Collections.Generic.List[object]]::new();Disposed=$false}
    $Client|Add-Member ScriptMethod SendAsync {
        param($Request,$Token)
        $Promise=[Threading.Tasks.TaskCompletionSource[Net.Http.HttpResponseMessage]]::new()
        $Body=if($null-ne$Request.Content){$Request.Content.ReadAsStringAsync().GetAwaiter().GetResult()}else{''}
        [void]$this.Jobs.Add([pscustomobject]@{Promise=$Promise;Path=$Request.RequestUri.PathAndQuery;Method=[string]$Request.Method;Body=$Body;Token=$Token})
        return $Promise.Task
    }
    $Client|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
    return $Client
}
function Status([string]$Request='', [string]$Stage='idle', [bool]$Complete=$true, [bool]$Drained=$true) {
    return @{profile_id='external-a';profile_token='source-a';session_id=('a'*32);request_id=$Request;expires_in_ms=0;status=@{schema=1;node_id='external-a';session_id=('a'*32);request_id=$Request;public_transport='https';stage=$Stage;complete=$Complete;drained=$Drained;results=@()}}
}
function State {
    $S=New-RouterVPNDNSState 'http://127.0.0.1:8788' 'external-a';$S.Client=FakeClient
    Receive-RouterVPNDNSStatus $S (Status) -Initial
    return $S
}
function Reply($Job,[int]$Code,$Value) {
    $Response=[Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]$Code)
    $Response.Content=[Net.Http.StringContent]::new(($Value|ConvertTo-Json -Depth 12 -Compress),[Text.Encoding]::UTF8,'application/json')
    $Job.Promise.SetResult($Response)
}
function LastJob($S,[string]$Path) {
    $Jobs=@($S.Client.Jobs|Where-Object{$_.Path-ceq$Path-and-not$_.Promise.Task.IsCompleted});Check ($Jobs.Count-eq1) ('one pending '+$Path);return $Jobs[0]
}
function ResultStatus($S) {
    $V=Status $S.Request 'complete';$V.expires_in_ms=120000;$V.status.public_transport=$S.Transport
    $Rows=[Collections.Generic.List[object]]::new()
    [void]$Rows.Add(@{id='selected';name='Saved resolver';kind='selected';address='192.0.2.53';port=8443;transport='https';server_name='home.example';path='/private-query';route='entry';route_label='Selected Home via entry';samples=3;failed=0;ready=$true;median_ms=0.01})
    $IDs=@('cf4a','cf4b','cf6a','cf6b','g4a','g4b','g6a','g6b','q4a','q4b','q6a','q6b')
    for($I=0;$I-lt12;$I++){
        $Ready=$I-lt2;$Row=@{id=$IDs[$I];name=('Public '+$IDs[$I]);kind='public';address='1.1.1.1';port=443;transport='https';server_name='cloudflare-dns.com';path='/dns-query';route='exit';route_label='Captured public exit';samples=$(if($Ready){3}else{0});failed=$(if($Ready){0}else{3});ready=$Ready}
        $Row.transport=$S.Transport
        if($S.Transport-ceq'tcp'){$Row.port=53;$Row.server_name='';$Row.path=''}elseif($S.Transport-ceq'tls'){$Row.port=853;$Row.path=''}
        if($Ready){$Row.median_ms=$(if($I-eq0){7.5}else{2.25})}else{$Row.failure='Unreachable through captured exit'}
        [void]$Rows.Add($Row)
    }
    $V.status.results=$Rows.ToArray();return $V
}
function Finished {
    $S=State;$S.Request='b'*32;$S.Drained=$false
    Receive-RouterVPNDNSStatus $S (ResultStatus $S)
    return $S
}
function Draft($S) {
    $Source=$S.Selection.source
    $Mode=if($Source.transport-ceq'tls'){'dot'}elseif($Source.transport-ceq'https'){'doh'}else{'custom'}
    return @{session_id=$S.Session;request_id=$S.Request;expires_in_ms=90000;draft=@{profile_id=$S.Profile;profile_token=$S.Token;measurement_id=$S.Request;result_id=$S.Selection.id;mode=$Mode;protocol=$Source.transport;host=$Source.address;port=$Source.port;server_name=$Source.server_name;path=$Source.path;password='never-copy';entry=@{password='never-copy'}}}
}
function Staged {
    $S=Finished;$S.Selection=$S.Rows[0];Receive-RouterVPNDNSDraft $S (Draft $S);return $S
}

if($Live){
    $Visual=$env:OS-eq'Windows_NT';$Owner=$null
    if($Visual){
        Add-Type -AssemblyName PresentationFramework
        $Owner=[Windows.Window]::new();$Owner.Title='DNS fixture owner';$Owner.Show()
        $PublicTransport=if($Scenario-cin@('tcp','tls')){$Scenario}else{'https'}
        Show-RouterVPNDNSMeasurement -BaseUrl $BaseUrl -Owner $Owner -DisplayedProfileID 'external-a' -PublicTransport $PublicTransport
        $S=$global:RouterVPNDNSView
        Check ($S.Window.IsVisible-and$Owner.IsEnabled) 'modeless panel keeps main controls reachable'
    }else{
        $S=New-RouterVPNDNSState $BaseUrl 'external-a';$S.Client=New-RouterVPNDNSClient;$S.AutoStart=$true
        if($Scenario-cin@('tcp','tls')){$S.Transport=$Scenario}
        [void](New-RouterVPNDNSRequest $S 'info' '/api/dns/measurement')
    }
    $Until=[DateTime]::UtcNow.AddSeconds(18);$Pulses=0
    $Pump={
        Update-RouterVPNDNSView $S
        if($Visual){[Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::Background)}
        Start-Sleep -Milliseconds 5
    }
    while(-not$S.Request-and[DateTime]::UtcNow-lt$Until){&$Pump;$Pulses++}
    Check ($S.Ready-and$S.Request-cmatch'^[0-9a-f]{32}$'-and-not$S.Closed) 'live capture starts exact owned request'
    if($Scenario-cin@('early-close','owner-close','draining','unavailable','replacement')){
        if($Scenario-cin@('draining','unavailable')){while(-not$S.StartDone-and[DateTime]::UtcNow-lt$Until){&$Pump}}
        if($Scenario-ceq'replacement'){while(-not$S.Invalid-and[DateTime]::UtcNow-lt$Until){&$Pump};Check $S.Invalid 'replacement receipt was not rejected'}
        if($Visual){if($Scenario-ceq'owner-close'){$Owner.Close()}else{$S.Window.Close()}}else{[void](Request-RouterVPNDNSClose $S)}
        Check (-not$S.Closed) 'close must await an actual native drain receipt'
        if($Visual){Check $Owner.IsVisible 'owner remained visible during native cleanup'}
        while(-not$S.Closed-and[DateTime]::UtcNow-lt$Until){&$Pump;$Pulses++}
        Check ($S.Closed-and$S.Drained-and$S.Jobs.Count-eq0) 'live close drained exact workers and HTTP tasks'
        Check ($S.Rows.Count-eq0-and$null-eq$S.Draft) 'closed cancellation retained no usable result'
        if($Visual-and$Scenario-ceq'owner-close'){Check (-not$Owner.IsVisible) 'owner closes only after native drain'}
    }else{
        while((-not$S.Drained-or$S.Jobs.Count-ne0)-and[DateTime]::UtcNow-lt$Until){&$Pump;$Pulses++}
        Check ($S.Stage-ceq'complete'-and$S.Rows.Count-eq12-and$S.Selected.Contains('Selected resolver:')) 'live rows keep selected policy separate'
        Check ($S.Rows[0].id-ceq'cf4b'-and$S.Rows[0].eligible) 'live fastest ignores faster selected resolver'
        if($Visual){$S.Window.FindName('Fastest').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))}else{[void](Select-RouterVPNDNSResult $S 'fastest')}
        while($null-eq$S.Draft-and[DateTime]::UtcNow-lt$Until){&$Pump}
        Check ($null-ne$S.Draft-and$S.Draft.result_id-ceq'cf4b'-and$S.Draft.measurement_id-ceq$S.Request) 'live measured draft retains its result and nonce'
        [void](Save-RouterVPNDNSDraft $S)
        while($S.Jobs.Count-ne0-and[DateTime]::UtcNow-lt$Until){&$Pump}
        Check (-not$S.Saved-and$null-ne$S.Draft) 'live connected Save is refused without losing draft'
        [void](Save-RouterVPNDNSDraft $S)
        while(-not$S.Saved-and[DateTime]::UtcNow-lt$Until){&$Pump}
        Check ($S.Saved-and$S.Jobs.Count-eq0) 'live disconnected explicit Save was confirmed'
        if($Visual){Check $Owner.IsEnabled 'live results keep main Disconnect available';$S.Window.Close()}else{[void](Request-RouterVPNDNSClose $S);Update-RouterVPNDNSView $S}
        Check $S.Closed 'completed modeless view closes without reentrant Closing'
    }
    Check ($Pulses-gt1) 'live HTTP work left dispatcher responsive'
    if($Visual-and$Owner.IsVisible){$Owner.Close()}
    Write-Host "PASS: $script:Checks real DNS loopback $Scenario checks (WPF=$Visual)";return
}

foreach($Address in @('https://127.0.0.1:8788','http://example.com:8788','http://127.0.0.1:8788/other','http://user@127.0.0.1:8788','http://127.0.0.1:8788/?request_id=bad')){Reject {New-RouterVPNDNSState $Address 'external-a'} 'remote or changed controller accepted'}
$S=State;Check ($S.Ready-and$S.Drained-and$S.Rows.Count-eq0) 'empty initial results capture is valid'
foreach($Field in @('profile_id','profile_token','session_id')){
    $V=Status;$V[$Field]=if($Field-ceq'session_id'){'c'*32}else{'replacement'}
    if($Field-ceq'profile_id'){$V.status.node_id=$V.profile_id};if($Field-ceq'session_id'){$V.status.session_id=$V.session_id}
    Reject {Receive-RouterVPNDNSStatus $S $V -Initial} ('captured '+$Field+' accepted replacement')
}
Check (Start-RouterVPNDNSMeasurement $S 'https') 'owned Start refused'
$ID=$S.Request;$Start=LastJob $S '/api/dns/measurement';$Body=$Start.Body|ConvertFrom-Json
Check ($ID-cmatch'^[0-9a-f]{32}$'-and$Body.request_id-ceq$ID-and$Body.profile_id-ceq$S.Profile-and$Body.profile_token-ceq$S.Token-and$Body.session_id-ceq$S.Session-and$Body.public_transport-ceq'https') 'Start captured all identities and transport'
Update-RouterVPNDNSView $S;Check ($S.Jobs.Count-eq1-and-not$S.StartDone) 'poll cannot race an unaccepted queued Start'
Check (-not(Start-RouterVPNDNSMeasurement $S 'tls')) 'overlapping Start accepted'
Check (-not(Request-RouterVPNDNSClose $S)) 'early close guessed native drain'
$Cancel=LastJob $S '/api/dns/measurement/cancel';$Body=$Cancel.Body|ConvertFrom-Json
Check ($Body.request_id-ceq$ID-and$Body.profile_token-ceq$S.Token-and$Body.session_id-ceq$S.Session) 'cancel lost captured identities'
Check $Start.Token.IsCancellationRequested 'early close left pending HTTP Start alive'
Reply $Cancel 409 @{error='not available'};Update-RouterVPNDNSView $S
Check (-not$S.Drained-and-not$S.Closed) 'HTTP409 must never be drain proof'
$Start.Promise.SetCanceled();Update-RouterVPNDNSView $S
Check (-not$S.Drained-and-not$S.Closed-and$S.StartDone) 'HTTP cancellation must never be native drain proof'
$Poll=LastJob $S ('/api/dns/measurement?request_id='+$ID)
Reply $Poll 200 (Status $ID 'draining' $true $false);Update-RouterVPNDNSView $S
Check (-not$S.Drained-and-not$S.Closed) 'complete-but-undrained close accepted'
$S.NextPoll=[DateTime]::MinValue;$S.NextCancel=[DateTime]::MaxValue;Update-RouterVPNDNSView $S
$Poll=LastJob $S ('/api/dns/measurement?request_id='+$ID)
Reply $Poll 200 (Status $ID 'cancelled');$Client=$S.Client;Update-RouterVPNDNSView $S
Check ($S.Drained-and$S.Closed-and$Client.Disposed-and$S.Jobs.Count-eq0) 'exact cancellation drain must close owned resources'

$S=State;$S.Request='b'*32;$S.Drained=$false
foreach($Field in @('request_id','node_id','session_id','complete','drained','schema','stage','results')){
    $V=Status $S.Request 'cancelled'
    switch($Field){'request_id'{$V.status.request_id='c'*32};'node_id'{$V.status.node_id='replacement'};'session_id'{$V.status.session_id='c'*32};'complete'{$V.status.complete='true'};'drained'{$V.status.drained=1};'schema'{$V.status.schema=2};'stage'{$V.status.stage='unknown'};'results'{$V.status.results=$null}}
    Reject {Receive-RouterVPNDNSStatus $S $V} ('invalid inner '+$Field+' accepted')
    Check (-not$S.Drained) ('invalid inner '+$Field+' changed drain state')
}
$V=Status $S.Request 'cancelled';$V.request_id='c'*32;$V.status.request_id=$V.request_id
Reject {Receive-RouterVPNDNSStatus $S $V} 'foreign request adopted';Check (-not$S.Drained) 'foreign request marked drained'
$V=Status $S.Request 'cancelled';$V.expires_in_ms=-1
Reject {Receive-RouterVPNDNSStatus $S $V} 'invalid expiry accepted';Check (-not$S.Drained) 'invalid expiry marked drained'
$V=Status $S.Request 'draining' $false $true
Reject {Receive-RouterVPNDNSStatus $S $V} 'drain before completion accepted'

$S=Finished;Check ($S.Drained-and$S.Rows.Count-eq12-and$S.Selected.Contains('0.01 ms')) 'complete measured catalog not rendered'
Check ($S.Rows[0].id-ceq'cf4b'-and$S.Rows[1].id-ceq'cf4a') 'public scores sorted incorrectly'
Check (@($S.Rows|Where-Object{-not$_.eligible-and$_.latency-ceq'No valid score'}).Count-eq10) 'failed candidates fabricated a zero score'
Reject {Select-RouterVPNDNSResult $S 'selected'} 'selected-policy timing became public choice'
Reject {Select-RouterVPNDNSResult $S 'g4a'} 'failed DNS candidate became selectable'
foreach($Case in @('zero','nan','infinity','negative','samples','failed','ready','missing-row','duplicate','transport')){
    $T=State;$T.Request='b'*32;$T.Drained=$false;$V=ResultStatus $T
    switch($Case){'zero'{$V.status.results[1].median_ms=0};'nan'{$V.status.results[1].median_ms=[double]::NaN};'infinity'{$V.status.results[1].median_ms=[double]::PositiveInfinity};'negative'{$V.status.results[1].median_ms=-1};'samples'{$V.status.results[1].samples=2};'failed'{$V.status.results[1].failed=1};'ready'{$V.status.results[1].ready='true'};'missing-row'{$V.status.results=@($V.status.results|Select-Object -Skip 1)};'duplicate'{$V.status.results[2].id=$V.status.results[1].id};'transport'{$V.status.public_transport='tls'}}
    Reject {Receive-RouterVPNDNSStatus $T $V} ('invalid result '+$Case+' accepted')
    Check (-not$T.Drained-and$T.Rows.Count-eq0) ('invalid result '+$Case+' mutated accepted state')
}
Check (Select-RouterVPNDNSResult $S 'fastest') 'valid fastest refused'
$Choice=LastJob $S '/api/dns/measurement/select';$Body=$Choice.Body|ConvertFrom-Json
Check ($Body.result_id-ceq'fastest'-and$Body.request_id-ceq$S.Request-and$S.Selection.id-ceq'cf4b') 'Fastest request lost its public winner'
Reply $Choice 200 (Draft $S);Update-RouterVPNDNSView $S
Check ($null-ne$S.Draft-and$S.Draft.Count-eq10-and-not$S.Draft.ContainsKey('password')-and-not$S.Draft.ContainsKey('entry')) 'draft copied private or unrelated fields'
Check ($S.Draft.measurement_id-ceq$S.Request-and$S.Draft.result_id-ceq'cf4b') 'draft lost measurement identity'
foreach($Field in @('profile_id','profile_token','measurement_id','result_id','mode','protocol','host','port','server_name','path')){
    $T=Finished;$T.Selection=$T.Rows[0];$V=Draft $T;$V.draft[$Field]=if($Field-ceq'port'){853}else{'replacement'}
    Reject {Receive-RouterVPNDNSDraft $T $V} ('draft '+$Field+' accepted changed identity or endpoint')
    Check ($null-eq$T.Draft) ('draft '+$Field+' persisted after rejection')
}
$T=Finished;$T.Selection=$T.Rows[0];$V=Draft $T;$V.expires_in_ms=120001
Reject {Receive-RouterVPNDNSDraft $T $V} 'unbounded draft expiry accepted'
$V=Draft $T;$V.expires_in_ms=500
Reject {Receive-RouterVPNDNSDraft $T $V -RequestedAt ([DateTime]::UtcNow.AddSeconds(-2))} 'expiry extended by transport delay'
$T.ResultsExpires=[DateTime]::UtcNow.AddMilliseconds(-1)
Check (-not(Select-RouterVPNDNSResult $T 'fastest')) 'expired result remained selectable'
foreach($Transport in @('tcp','tls','https')){
    $T=State;$T.Request='b'*32;$T.Drained=$false;$T.Transport=$Transport;Receive-RouterVPNDNSStatus $T (ResultStatus $T)
    $T.Selection=$T.Rows[0];Receive-RouterVPNDNSDraft $T (Draft $T)
    Check ($T.Draft.protocol-ceq$Transport-and$T.Draft.port-eq$T.Selection.source.port-and$T.Draft.server_name-ceq$T.Selection.source.server_name-and$T.Draft.path-ceq$T.Selection.source.path) ('measured '+$Transport+' endpoint changed')
}

Check (Save-RouterVPNDNSDraft $S) 'explicit Save did not check disconnection'
$StatusJob=LastJob $S '/api/status';Reply $StatusJob 200 @{connected=$true;phase='off'};Update-RouterVPNDNSView $S
Check (-not$S.Saved-and$S.Jobs.Count-eq0-and$null-ne$S.Draft) 'connected Save sent policy mutation'
Check (Save-RouterVPNDNSDraft $S) 'disconnected Save refused'
$StatusJob=LastJob $S '/api/status';Reply $StatusJob 200 @{connected=$false;phase='disconnected'};Update-RouterVPNDNSView $S
$Save=LastJob $S '/api/dns/policy';$Body=$Save.Body|ConvertFrom-Json
Check ($Body.measurement_id-ceq$S.Request-and$Body.result_id-ceq'cf4b'-and$Body.profile_token-ceq$S.Token-and$Body.host-ceq'1.1.1.1'-and$Body.protocol-ceq'https'-and$Body.port-eq443-and$Body.path-ceq'/dns-query') 'explicit Save changed exact measured draft'
$Ack=@{};foreach($K in $S.Draft.Keys){$Ack[$K]=$S.Draft[$K]};$Ack.profile_token='new-saved-source';Reply $Save 200 $Ack;Update-RouterVPNDNSView $S
Check ($S.Saved-and$null-eq$S.Draft-and$S.Status.Contains('next connection')) 'successful Save falsely claimed active DNS proof'
foreach($Phase in @('connecting','starting','disconnecting','stopping','measuring','external-node:proving','auto:trying:hysteria2','reasserting','unknown','')){
    $T=Staged;[void](Save-RouterVPNDNSDraft $T);Reply (LastJob $T '/api/status') 200 @{connected=$false;phase=$Phase};Update-RouterVPNDNSView $T
    Check ($T.Jobs.Count-eq0-and-not$T.Saved) ('Save accepted active phase '+$Phase)
}
$T=Staged;$T.DraftExpires=[DateTime]::UtcNow.AddSeconds(-1)
Check (-not(Save-RouterVPNDNSDraft $T)-and$null-eq$T.Draft-and$T.Jobs.Count-eq0) 'expired measured draft was saved'
$T=Staged;[void](Save-RouterVPNDNSDraft $T);$T.DraftExpires=[DateTime]::UtcNow.AddSeconds(-1)
Reply (LastJob $T '/api/status') 200 @{connected=$false;phase='disconnected'};Update-RouterVPNDNSView $T
Check ($T.Jobs.Count-eq0-and$null-eq$T.Draft) 'draft expiry raced Save check'

$T=Staged;$T.Drained=$false;Cancel-RouterVPNDNSMeasurement $T
Check ($T.Rows.Count-eq0-and-not$T.Selected-and$null-eq$T.Draft) 'cancellation kept a usable selection'
$V=ResultStatus $T;Receive-RouterVPNDNSStatus $T $V
Check ($T.Drained-and$T.Rows.Count-eq0-and$null-eq$T.Draft) 'late complete result after cancellation was adopted'
Receive-RouterVPNDNSStatus $T (Status $T.Request 'draining' $true $false)
Check $T.Drained 'stale poll regressed proved drain'
$T=State;[void](New-RouterVPNDNSRequest $T 'info' '/api/dns/measurement');$Info=LastJob $T '/api/dns/measurement';$T.Generation++
Reply $Info 200 @{profile_id='replacement'};Update-RouterVPNDNSView $T
Check ($T.Profile-ceq'external-a'-and-not$T.Invalid-and$T.Jobs.Count-eq0) 'stale HTTP completion mutated replacement generation'
Check (Request-RouterVPNDNSClose $T) 'idle close refused';$Client=$T.Client;Update-RouterVPNDNSView $T
Check ($T.Closed-and$Client.Disposed) 'idle view leaked HTTP client'

Write-Host "PASS: $script:Checks captured Windows DNS state, measured draft, cancellation and ownership checks"
