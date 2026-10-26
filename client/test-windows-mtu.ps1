param([string]$Source=(Join-Path $PSScriptRoot 'RouterVPN-Windows-MTU.ps1'),[switch]$Live,[string]$Scenario='accepted')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
Add-Type -AssemblyName System.Net.Http
. ([ScriptBlock]::Create((Get-Content -LiteralPath $Source -Raw -Encoding UTF8)))
$script:Checks=0
function Check([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message};$script:Checks++}
function Reject([scriptblock]$Action,[string]$Message){$Failed=$false;try{&$Action}catch{$Failed=$true};Check $Failed $Message}
function FakeClient {
    $Client=[pscustomobject]@{Jobs=(New-Object 'System.Collections.Generic.List[object]');Disposed=$false}
    $Client|Add-Member ScriptMethod SendAsync {
        param($Request,$Token)
        $Promise=New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]'
        $Body=if($null-ne$Request.Content){$Request.Content.ReadAsStringAsync().GetAwaiter().GetResult()}else{''}
        $this.Jobs.Add([pscustomobject]@{Promise=$Promise;Path=$Request.RequestUri.PathAndQuery;Method=[string]$Request.Method;Body=$Body;Token=$Token})
        return $Promise.Task
    }
    $Client|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
    return $Client
}
function State {
    $S=New-RouterVPNMTUState 'http://127.0.0.1:8788';$S.Client=FakeClient;return $S
}
function Reply($Job,[int]$Code,$Value){
    $R=New-Object System.Net.Http.HttpResponseMessage ([System.Net.HttpStatusCode]$Code)
    $R.Content=New-Object System.Net.Http.StringContent (($Value|ConvertTo-Json -Depth 12 -Compress),[Text.Encoding]::UTF8,'application/json')
    $Job.Promise.SetResult($R)
}
function Status([string]$ID='', [bool]$Running=$false, [bool]$Complete=$false, [bool]$Restored=$false){
    return @{session_id='captured-session';profile_id='router-a';requested=$false;waiting_commit=$false;status=@{
        request_id=$ID;phase='measuring';running=$Running;complete=$Complete;measured=$false;restored=$Restored;
        original_mtu=1420;effective_mtu=1420;source='saved-auto-throughput';failure='';candidates=@()}}
}
function Idle($S){[void](Receive-RouterVPNMTUStatus $S (Status));Check ($S.Session-ceq'captured-session') 'Initial status did not capture its session'}
function CompleteAll($S){
    $Client=$S.Client
    [void](Close-RouterVPNMTUView $S)
    foreach($J in $Client.Jobs){if(-not$J.Promise.Task.IsCompleted){$J.Promise.SetCanceled()}}
    Update-RouterVPNMTUView $S
    Check $S.Closed 'View did not drain its owned tasks'
}

if($Live){
    $Visual=$env:OS-eq'Windows_NT';$Owner=$null
    if($Visual){
        Add-Type -AssemblyName PresentationFramework
        $Owner=New-Object System.Windows.Window;$Owner.Show()
        Show-RouterVPNMTUDialog -BaseUrl 'http://127.0.0.1:8788' -Owner $Owner
        $S=$global:RouterVPNMTUView
        Check ($S.Window.IsVisible-and$Owner.IsEnabled) 'Actual MTU panel blocked the main window'
    }else{$S=New-RouterVPNMTUState 'http://127.0.0.1:8788';$S.Client=New-RouterVPNMTUClient}
    $Until=[DateTime]::UtcNow.AddSeconds(8);$Pulses=0
    $Pump={
        Update-RouterVPNMTUView $S
        if($Visual){[Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::Background)}
        Start-Sleep -Milliseconds 5
    }
    while(-not$S.Session-and-not$S.Retired-and[DateTime]::UtcNow-lt$Until){&$Pump}
    Check ($S.Session-and-not$S.Retired) 'Real loopback status did not capture a connection'
    if($Scenario-eq'configured'){
        Check (-not$S.OptimizationAllowed-and$S.Detail.Contains('Effective interface MTU: 9000')) 'Configured live capacity was not retained'
        if($Visual){
            Check (-not$S.Window.FindName('Retest').IsEnabled) 'WPF enabled Retest against configured policy'
            $S.Window.FindName('Retest').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
        }else{Check (-not(Start-RouterVPNMTURetest $S)) 'Configured live policy accepted Retest'}
        Check (-not$S.Own-and-not$S.Request) 'Configured policy emitted a real mutation'
        if($Visual){Check $Owner.IsEnabled 'Configured MTU panel blocked main controls';$S.Window.Close()}
        [void](Close-RouterVPNMTUView $S)
        while(-not$S.Closed-and[DateTime]::UtcNow-lt$Until){&$Pump}
        Check $S.Closed 'Configured observer did not drain on close'
        if($Visual){$Owner.Close()}
        Write-Host "PASS: $script:Checks real Windows configured-capacity checks (WPF=$Visual)"
        return
    }
    if($Visual){$S.Window.FindName('Retest').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))}
    else{[void](Start-RouterVPNMTURetest $S)}
    Check ($S.Own-and$S.Request-and-not$S.RunDone) 'Actual Retest callback blocked on its POST'
    if($Scenario-ne'early'){
        while(-not$S.Seen-and-not$S.Retired-and[DateTime]::UtcNow-lt$Until){&$Pump;$Pulses++}
        Check $S.Seen 'Real loopback request was not accepted'
    }
    if($Scenario-ne'replaced'){
        if($Visual){$S.Window.FindName('CancelTest').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))}
        else{Cancel-RouterVPNMTUTest $S}
    }
    while((-not$S.Terminal-or-not$S.RunDone)-and[DateTime]::UtcNow-lt$Until){&$Pump;$Pulses++}
    if($Scenario-ne'early'){Check ($Pulses-gt0) 'UI dispatch was not exercised while HTTP work was pending'}
    if($Scenario-eq'replaced'){Check ($S.Retired-and$S.Terminal) 'Real replaced session did not retire its captured observer'}
    elseif($Scenario-eq'early'){Check ($S.Terminal-and$S.RunDone-and-not$S.Seen) 'Real unaccepted POST did not drain after cancellation'}
    else{Check ($S.Terminal-and$S.RunDone-and-not$S.Retired-and$S.Status-ceq'Previous MTU restored.') 'Real Cancel failed to retain exact restoration after POST409'}
    if($Visual){Check $Owner.IsEnabled 'MTU measurement blocked main connection controls';$S.Window.Close()}
    [void](Close-RouterVPNMTUView $S)
    while(-not$S.Closed-and[DateTime]::UtcNow-lt$Until){&$Pump}
    Check $S.Closed 'Real HTTP tasks did not drain on close'
    if($Visual){$Owner.Close()}
    Write-Host "PASS: $script:Checks real Windows MTU loopback $Scenario checks (WPF=$Visual)"
    return
}

Reject {New-RouterVPNMTUState 'https://127.0.0.1:8788'} 'TLS controller substitution accepted'
Reject {New-RouterVPNMTUState 'http://example.com:8788'} 'Remote controller accepted'
Reject {New-RouterVPNMTUState 'http://127.0.0.1:8788/else'} 'Controller path accepted'
foreach($Allowed in @($false,$true)){
    $S=State;$Value=Status;$Value.optimization_allowed=$Allowed
    $Value.status.effective_mtu=9000;$Value.status.source='configured-unmeasured'
    [void](Receive-RouterVPNMTUStatus $S $Value)
    Check ($S.OptimizationAllowed-eq$Allowed) 'Captured optimization capability was lost'
    $Before=$S.Client.Jobs.Count
    Check ((Start-RouterVPNMTURetest $S)-eq$Allowed) 'Configured policy did not govern the actual Retest callback'
    if(-not$Allowed){Check ($S.Client.Jobs.Count-eq$Before-and-not$S.Own-and$S.Status.Contains('configured MTU')-and$S.Detail.Contains('Effective interface MTU: 9000')) 'Configured Jumbo emitted a mutation or lost readback'}
    CompleteAll $S
}
foreach($Bad in @($null,'false',0,1)){
    $S=State;$Value=Status;$Value.optimization_allowed=$Bad
    Reject {Receive-RouterVPNMTUStatus $S $Value} 'Malformed optimization capability was accepted'
    Check (-not$S.Session-and-not$S.OptimizationAllowed) 'Malformed capability adopted a connection'
    CompleteAll $S
}
$S=State;Idle $S
Check ($S.Detail.Contains('historical; not measured on this path')) 'Saved MTU displayed as fresh readback'
Check (-not$S.Detail.Contains('Effective interface MTU')) 'Historical source claimed live MTU'
Check (-not$S.Terminal) 'Idle source claimed measurement completion'
Check (Start-RouterVPNMTURetest $S) 'requested=false incorrectly disabled Retest'
$ID=$S.Request;$Run=$S.Client.Jobs[0];$Body=$Run.Body|ConvertFrom-Json
Check ($ID-cmatch'^[0-9a-f]{32}$') 'Retest did not generate a bounded request ID'
Check ($Body.request_id-ceq$ID-and$Body.session_id-ceq$S.Session-and$Body.profile_id-ceq$S.Profile) 'Retest omitted its captured identity'
Check ($Run.Method-eq'POST'-and$Run.Path-ceq'/api/mtu/retest') 'Retest used the wrong operation'
Check (-not$S.RunDone-and-not$Run.Promise.Task.IsCompleted) 'Retest blocked instead of returning a live task'
Update-RouterVPNMTUView $S;$Poll=$S.Client.Jobs[1]
Check ($Poll.Path-ceq('/api/mtu/status?request_id='+$ID+'&session_id=captured-session')) 'Poll did not bind both identities'
Reply $Poll 404 @{error='not registered'};Update-RouterVPNMTUView $S
Check (-not$S.Retired-and-not$S.Terminal) 'Pre-registration 404 retired an owned pending POST'
Cancel-RouterVPNMTUTest $S;$Cancel=$S.Client.Jobs[$S.Client.Jobs.Count-1];$Body=$Cancel.Body|ConvertFrom-Json
Check $Run.Token.IsCancellationRequested 'Pre-registration Cancel left a delayed POST alive'
Check ($Cancel.Path-ceq'/api/mtu/cancel'-and$Body.request_id-ceq$ID-and$Body.session_id-ceq$S.Session) 'Cancel did not target exactly its own request'
Reply $Cancel 404 @{error='not registered'};Update-RouterVPNMTUView $S
Check (-not$S.Terminal) 'Cancel 404 claimed that the POST drained'
$Run.Promise.SetCanceled();Update-RouterVPNMTUView $S
$Poll=$S.Client.Jobs[$S.Client.Jobs.Count-1];Reply $Poll 404 @{error='not registered'};Update-RouterVPNMTUView $S
if(-not$S.Terminal){$Poll=$S.Client.Jobs[$S.Client.Jobs.Count-1];Reply $Poll 404 @{error='not registered'};Update-RouterVPNMTUView $S}
Check ($S.Terminal-and$S.RunDone-and-not$S.Seen) 'Cancelled unaccepted request did not finish after its POST drained'
CompleteAll $S

$S=State;Idle $S;[void](Start-RouterVPNMTURetest $S);$ID=$S.Request;$Run=$S.Client.Jobs[0]
Update-RouterVPNMTUView $S;$Poll=$S.Client.Jobs[1];Reply $Poll 200 (Status $ID $true);Update-RouterVPNMTUView $S
Check $S.Seen 'Accepted status did not bind the request'
Cancel-RouterVPNMTUTest $S;$Cancel=$S.Client.Jobs[$S.Client.Jobs.Count-1]
Check (-not$Run.Token.IsCancellationRequested) 'Accepted cancellation discarded the POST before rollback acknowledgement'
Reply $Cancel 200 @{request_id=$ID;phase='canceling'};Update-RouterVPNMTUView $S
Check ($S.CancelAck-and-not$S.Terminal) 'Pending cancel acknowledgement claimed completed rollback'
Check (-not(Start-RouterVPNMTURetest $S)) 'Another Retest started during cancellation'
$Poll=$S.Client.Jobs[$S.Client.Jobs.Count-1];$Waiting=Status $ID $false $true $true;$Waiting.waiting_commit=$true
Reply $Poll 200 $Waiting;Update-RouterVPNMTUView $S
Check (-not$S.Terminal) 'Waiting commit was treated as complete'
$S.Next=[DateTime]::MinValue;Update-RouterVPNMTUView $S;$Poll=$S.Client.Jobs[$S.Client.Jobs.Count-1]
$Done=Status $ID $false $true $true;$Done.status.source='restored-captured-interface';Reply $Poll 200 $Done;Update-RouterVPNMTUView $S
Check (-not$S.Terminal-and$S.Status-cne'Previous MTU restored.') 'Pre-POST completion GET prematurely displayed restoration'
Check (-not(Start-RouterVPNMTURetest $S)) 'Terminal status allowed a still-undrained POST to be replaced'
$S.Next=[DateTime]::MinValue;Update-RouterVPNMTUView $S;$BeforeDrain=$S.Client.Jobs[$S.Client.Jobs.Count-1]
Reply $Run 409 @{error='cancelled after rollback'};Update-RouterVPNMTUView $S
Check ($S.RunDone-and-not$S.Retired-and-not$S.Terminal-and$BeforeDrain.Token.IsCancellationRequested) 'POST completion trusted or retained a pre-completion GET'
Reply $BeforeDrain 200 $Done;Update-RouterVPNMTUView $S
Check (-not$S.Terminal) 'Delayed pre-POST GET attested final restoration'
$Final=$S.Client.Jobs[$S.Client.Jobs.Count-1];Reply $Final 200 $Done;Update-RouterVPNMTUView $S
Check ($S.Terminal-and$S.Status-ceq'Previous MTU restored.') 'Fresh post-completion exact GET did not confirm restoration'
Check (Start-RouterVPNMTURetest $S) 'Drained terminal operation did not allow another Retest'
Check ($S.Request-cne$ID) 'New Retest reused an old request ID'
CompleteAll $S

$S=State;Update-RouterVPNMTUView $S;$Initial=$S.Client.Jobs[0];Reply $Initial 200 (Status);Update-RouterVPNMTUView $S
$S.Next=[DateTime]::MinValue;Update-RouterVPNMTUView $S;$SessionPoll=$S.Client.Jobs[1]
Check ($SessionPoll.Path-ceq'/api/mtu/status?session_id=captured-session') 'Idle Auto observer lost its captured session'
$AutoID='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';Reply $SessionPoll 200 (Status $AutoID $true);Update-RouterVPNMTUView $S
Check ($S.Seen-and-not$S.Own-and$S.Request-ceq$AutoID) 'Auto request ownership was confused with a manual POST'
$Waiting=Status $AutoID $false $true $true;$Waiting.waiting_commit=$true
[void](Receive-RouterVPNMTUStatus $S $Waiting)
Check (-not$S.Terminal) 'Auto completion skipped its pending durable commit'
Cancel-RouterVPNMTUTest $S;$Cancel=$S.Client.Jobs[$S.Client.Jobs.Count-1];Reply $Cancel 409 @{error='already completed'};Update-RouterVPNMTUView $S
Check (-not$S.Retired) 'Cancel conflict incorrectly erased a possible completed receipt'
$Poll=$S.Client.Jobs[$S.Client.Jobs.Count-1];$Done=Status $AutoID $false $true $true;Reply $Poll 200 $Done;Update-RouterVPNMTUView $S
Check ($S.Terminal-and$S.Status-ceq'Previous MTU restored.') 'Exact final status after Cancel conflict was discarded'
CompleteAll $S

 $S=State;Idle $S;$ID='abababababababababababababababab';[void](Receive-RouterVPNMTUStatus $S (Status $ID $true))
Update-RouterVPNMTUView $S;$BeforeCancel=$S.Client.Jobs[0];Cancel-RouterVPNMTUTest $S;$Cancel=$S.Client.Jobs[1]
Reply $BeforeCancel 200 (Status $ID $false $true $true);Update-RouterVPNMTUView $S
Check (-not$S.Terminal) 'In-flight Cancel accepted an earlier terminal status'
$S.Next=[DateTime]::MinValue;Update-RouterVPNMTUView $S;$DuringCancel=$S.Client.Jobs[$S.Client.Jobs.Count-1]
Reply $Cancel 200 @{request_id=$ID;phase='canceling'};Update-RouterVPNMTUView $S
Check ($DuringCancel.Token.IsCancellationRequested-and-not$S.Terminal) 'Cancel completion did not revoke an older poll'
Reply $DuringCancel 200 (Status $ID $false $true $true);Update-RouterVPNMTUView $S
Check (-not$S.Terminal) 'Pre-Cancel poll attested post-Cancel restoration'
$Fresh=$S.Client.Jobs[$S.Client.Jobs.Count-1];Reply $Fresh 200 (Status $ID $false $true $true);Update-RouterVPNMTUView $S
Check ($S.Terminal-and$S.Status-ceq'Previous MTU restored.') 'Fresh post-Cancel status was not adopted'
CompleteAll $S

foreach($Code in @(404,409)){
    $S=State;Idle $S;$ID='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';[void](Receive-RouterVPNMTUStatus $S (Status $ID $true));Update-RouterVPNMTUView $S
    $Poll=$S.Client.Jobs[0];Reply $Poll $Code @{error='gone'};Update-RouterVPNMTUView $S
    Check ($S.Retired-and$S.Request-ceq$ID) 'A missing/replaced observed request was silently followed'
    Check ($S.Client.Jobs.Count-eq1) 'Retired observer polled another owner'
    CompleteAll $S
}
foreach($Field in @('session_id','profile_id')){
    $S=State;Idle $S;$Next=Status;$Next[$Field]='replacement';[void](Receive-RouterVPNMTUStatus $S $Next)
    Check $S.Retired ('Changed '+$Field+' was adopted');CompleteAll $S
}
$S=State;Idle $S;$ID='cccccccccccccccccccccccccccccccc';[void](Receive-RouterVPNMTUStatus $S (Status $ID $true))
[void](Receive-RouterVPNMTUStatus $S (Status 'dddddddddddddddddddddddddddddddd' $true))
Check ($S.Retired-and$S.Request-ceq$ID) 'Replacement request overwrote captured ownership';CompleteAll $S
foreach($Field in @('running','complete','measured','restored')){
    $S=State;$Bad=Status;$Bad.status[$Field]='false';Reject {Receive-RouterVPNMTUStatus $S $Bad} ('Nonboolean '+$Field+' accepted');CompleteAll $S
}
$S=State;Update-RouterVPNMTUView $S;$Old=$S.Client.Jobs[0];Idle $S;[void](Start-RouterVPNMTURetest $S);$ID=$S.Request
Check $Old.Token.IsCancellationRequested 'Old poll did not cancel before manual Retest'
$Foreign=Status 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' $true;$Foreign.session_id='replacement';Reply $Old 200 $Foreign;Update-RouterVPNMTUView $S
Check (-not$S.Retired-and$S.Request-ceq$ID-and$S.Session-ceq'captured-session') 'A previous generation callback mutated current view'
CompleteAll $S

$S=State;Update-RouterVPNMTUView $S;$Poll=$S.Client.Jobs[0];$Client=$S.Client
Check (Request-RouterVPNMTUClose $S) 'Idle Auto observer was forced to cancel the connection test'
Check (-not(Close-RouterVPNMTUView $S)) 'View claimed drain before pending task completed'
Check ($S.Detaching-and-not$S.Closed-and$Poll.Token.IsCancellationRequested) 'Closing Auto observer did not cancel its own poll'
Check ($Client.Jobs.Count-eq1-and-not$Client.Disposed) 'Observer close cancelled Auto or disposed a still-used client'
Reply $Poll 200 (Status 'ffffffffffffffffffffffffffffffff' $true);Update-RouterVPNMTUView $S
Check ($S.Closed-and$Client.Disposed-and$S.Request-ceq'') 'Late response survived close or adopted a new request'

$S=State;Idle $S;[void](Start-RouterVPNMTURetest $S);$Run=$S.Client.Jobs[0]
Check (-not(Request-RouterVPNMTUClose $S)) 'Close abandoned an active manual Retest'
Check ($S.Closing-and$S.Cancelled-and$Run.Token.IsCancellationRequested) 'Manual Close did not cancel its own pending request'
Check (-not(Start-RouterVPNMTURetest $S)) 'Closing view started a new test'
CompleteAll $S

$S=State;Idle $S;$Measured=Status 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' $false $true
$Measured.status.measured=$true;$Measured.status.source='measured-public-system-tun-transfer';$Measured.status.effective_mtu=1360
$Measured.status.candidates=@(@{mtu=1360;working=$true;median_rtt_ms=10.2;latency_kind='routed HTTP response';download=@{mbps=42.3};upload=@{mbps=18.1}})
[void](Receive-RouterVPNMTUStatus $S $Measured)
Check ($S.Status-ceq'Measured MTU: 1360'-and$S.Detail.Contains('42.3 Mbps')-and$S.Detail.Contains('routed HTTP response')) 'Real candidate fields were omitted or relabelled'
Check (-not$S.Detail.Contains('ICMP')) 'HTTP response time was relabelled as ICMP'
CompleteAll $S

Write-Host "PASS: $script:Checks shipping Windows MTU ownership, progress, cancellation and drain checks"
