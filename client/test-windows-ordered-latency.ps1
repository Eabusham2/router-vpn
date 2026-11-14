param([string]$Source=(Join-Path $PSScriptRoot 'RouterVPN-Windows-SpeedLab.ps1'),[switch]$Live,[string]$Scenario='success',[string]$BaseUrl='http://127.0.0.1:8788')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
Import-Module (Join-Path $PSScriptRoot 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
Add-Type -AssemblyName System.Net.Http
$SourceText=[IO.File]::ReadAllText($Source,[Text.Encoding]::UTF8);$Tokens=$null;$Errors=$null
[void][Management.Automation.Language.Parser]::ParseInput($SourceText,[ref]$Tokens,[ref]$Errors)
if($Errors.Count){throw ($Errors.Message -join '; ')}
. ([ScriptBlock]::Create($SourceText))
$script:Checks=0
function Check([bool]$Condition,[string]$Message){if(-not$Condition){throw ('ORDERED CONTROL '+$Message)};$script:Checks++}
function Reject([scriptblock]$Action,[string]$Message){$Failed=$false;try{&$Action}catch{$Failed=$true};Check $Failed $Message}
function CopyValue($Value){return ($Value|ConvertTo-Json -Depth 15 -Compress|ConvertFrom-Json)}
function Capture {return @{session_id='session-1794630000000-7';profile_id='home-a';profile_token=('a'*64);source_sha256=('b'*64);config_sha256=('c'*64);generation_sha256=('d'*64)}}
function Nodes {return @(0..2|ForEach-Object{@{node_id=('node-'+$_);position=$_;role=@('entry','intermediate','exit')[$_];label=('Hop '+($_+1));kind=$(if($_-eq1){'public-path'}else{'private-node'});measurement=$(if($_-eq1){'routed-https-response-after-tls'}else{'routed-private-response-including-connection'})}})}
function Receipt([string]$Request=('e'*32),[int]$Position=0){
    $C=Capture;$N=(Nodes)[$Position];$Now=[long](([DateTime]::UtcNow-[DateTime]::SpecifyKind([DateTime]'1970-01-01',[DateTimeKind]::Utc)).TotalMilliseconds)-100
    return @{schema=1;position=$Position;source_sha256=$C.source_sha256;config_sha256=$C.config_sha256;generation_sha256=$C.generation_sha256;node_id=$N.node_id;request_id=$Request;measured_at=$Now;result=@{node_id=$N.node_id;role=$N.role;kind=$N.kind;label=$(if($Position-eq1){'Cumulative path through custom node 2 of 3 '+[char]0x2192+' Cloudflare edge'}else{'Cumulative path through node '+($Position+1)+' of 3'});ready=$true;benchmark=@{schema=1;measurement=$N.measurement;endpoint=$(if($Position-eq1){'https://speed.cloudflare.com/__down?bytes=1'}else{''});attempts=50;failed=0;trimmed_mean_ms=12.0;distribution=@{samples=50;min_ms=10.0;median_ms=11.0;average_ms=12.0;p90_ms=15.0;max_ms=20.0;jitter_ms=0.5}}}}
}
function Status([string]$Request='', [int]$Position=0,[string]$Stage='idle',[bool]$Complete=$true,[bool]$Drained=$true){
    return @{schema=1;capture=(Capture);nodes=(Nodes);history=@((Receipt));request_id=$Request;node_id=$(if($Request){'node-'+$Position}else{''});position=$Position;status=@{request_id=$Request;stage=$Stage;complete=$Complete;drained=$Drained;failure='';results=@()}}
}
function FakeClient {
    $Client=[pscustomobject]@{Jobs=[Collections.Generic.List[object]]::new();Disposed=$false}
    $Client|Add-Member ScriptMethod SendAsync {
        param($Request,$Token)
        $Promise=[Threading.Tasks.TaskCompletionSource[Net.Http.HttpResponseMessage]]::new()
        $Body=if($null-ne$Request.Content){$Request.Content.ReadAsStringAsync().GetAwaiter().GetResult()}else{''}
        [void]$this.Jobs.Add([pscustomobject]@{Promise=$Promise;Path=$Request.RequestUri.PathAndQuery;Method=[string]$Request.Method;Body=$Body;Token=$Token});return $Promise.Task
    }
    $Client|Add-Member ScriptMethod Dispose {$this.Disposed=$true};return $Client
}
function State {$S=New-RouterVPNOrderedState $BaseUrl 'home-a';$S.Client=FakeClient;Receive-RouterVPNOrderedStatus $S (Status) -Initial;return $S}
function Pending($S,[string]$Suffix){$Jobs=@($S.Client.Jobs|Where-Object{$_.Path-ceq('/api/speed-lab/ordered-latency'+$Suffix)-and-not$_.Promise.Task.IsCompleted});Check ($Jobs.Count-eq1) ('one pending '+$Suffix);return $Jobs[0]}
function Reply($Job,[int]$Code,$Value){$Response=[Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]$Code);$Response.Content=[Net.Http.StringContent]::new(($Value|ConvertTo-Json -Depth 15 -Compress),[Text.Encoding]::UTF8,'application/json');$Job.Promise.SetResult($Response)}

if($Live){
    $Visual=$env:OS-eq'Windows_NT';$Owner=$null
    if($Visual){
        Add-Type -AssemblyName PresentationFramework
        $Owner=[Windows.Window]::new();$Owner.Title='Ordered hop fixture';$Owner.Show()
        Show-RouterVPNOrderedLatency -BaseUrl $BaseUrl -Owner $Owner -DisplayedProfileID 'home-a';$S=$global:RouterVPNOrderedView
        Check ($Owner.IsEnabled-and$S.Window.IsVisible) 'modeless hop controls keep main window reachable'
    }else{$S=New-RouterVPNOrderedState $BaseUrl 'home-a';$S.Client=New-RouterVPNControllerClient -TimeoutMilliseconds 6000 -ResponseLimit 1048576;New-RouterVPNOrderedRequest $S 'info'}
    $Until=[DateTime]::UtcNow.AddSeconds(20)
    $Pump={Update-RouterVPNOrderedView $S;if($Visual){[Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::Background)};Start-Sleep -Milliseconds 5}
    while($null-eq$S.Capture-and-not$S.Invalid-and[DateTime]::UtcNow-lt$Until){&$Pump}
    Check ($null-ne$S.Capture-and-not$S.Invalid-and$S.Nodes.Count-eq3) 'live exact ordered capture'
    $Prior=[string](Get-RouterVPNOrderedValue $S.History[0] 'request_id')
    $Position=if($Scenario-ceq'public'){1}elseif($Scenario-ceq'exit'){2}else{0}
    if($Visual){$S.Window.FindName('Hop').SelectedIndex=$Position;$S.Window.FindName('Retest').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))}else{[void](Start-RouterVPNOrderedLatency $S $Position)}
    Check ($S.Request-cmatch'^[0-9a-f]{32}$'-and-not$S.Drained) 'live Retest captures request before HTTP completion'
    if($Scenario-cin@('early','cancel','owner-close')){
        if($Scenario-cne'early'){while((Test-RouterVPNOrderedJob $S 'start')-and[DateTime]::UtcNow-lt$Until){&$Pump}}
        if($Visual){if($Scenario-ceq'owner-close'){$Owner.Close()}else{$S.Window.Close()}}else{[void](Request-RouterVPNOrderedClose $S)}
        Check (-not$S.Closed) 'pending native cleanup blocks close'
        while(-not$S.Closed-and[DateTime]::UtcNow-lt$Until){&$Pump}
        Check ($S.Closed-and$S.Drained-and$S.Jobs.Count-eq0) 'close joins original native and HTTP owners'
        Check ([string](Get-RouterVPNOrderedValue $S.History[0] 'request_id')-ceq$Prior) 'cancellation preserves earlier saved history'
        if($Visual-and$Scenario-ceq'owner-close'){Check (-not$Owner.IsVisible) 'parent closes only after captured cleanup'}
    }else{
        while((-not$S.Drained-or$S.Jobs.Count-ne0)-and[DateTime]::UtcNow-lt$Until){&$Pump}
        Check ($S.Drained-and$S.Jobs.Count-eq0) 'live test waits for native drain and all HTTP tasks'
        $Saved=@($S.History|Where-Object{[string](Get-RouterVPNOrderedValue $_ 'request_id')-ceq$S.Request})
        if($Scenario-cin@('success','public','exit')){Check ($Saved.Count-eq1) 'live durable fifty receipt adopted';Assert-RouterVPNOrderedReceipt $Saved[0] $S.Capture $S.Node -Current}
        else{Check ($Saved.Count-eq0-and[string](Get-RouterVPNOrderedValue $S.History[0] 'request_id')-ceq$Prior) 'failed or foreign result preserves saved history'}
        if($Visual){$S.Window.Close();&$Pump}else{Check (Request-RouterVPNOrderedClose $S) 'settled close';[void](Close-RouterVPNOrderedView $S)}
        Check $S.Closed 'settled view releases owned transport'
    }
    if($Visual-and$Owner.IsVisible){$Owner.Close()}
    Write-Output "PASS $script:Checks ordered hop HTTP checks ($Scenario; WPF=$Visual)";exit 0
}

foreach($Position in 0..2){
    $N=(Nodes)[$Position];Assert-RouterVPNOrderedNode $N $Position;Assert-RouterVPNOrderedReceipt (Receipt ('e'*32) $Position) (Capture) $N -Current;$script:Checks+=2
    foreach($Case in @('samples','attempts','failed','meaning','endpoint','generation','node','position','future','negative','unordered','budget','jitter','label','idle','download','upload','response')){
        $R=CopyValue (Receipt ('e'*32) $Position)
        switch($Case){
            'samples'{$R.result.benchmark.distribution.samples=49}
            'attempts'{$R.result.benchmark.attempts=49}
            'failed'{$R.result.benchmark.failed=1}
            'meaning'{$R.result.benchmark.measurement='icmp-rtt'}
            'endpoint'{$R.result.benchmark.endpoint='https://unselected.invalid/'}
            'generation'{$R.generation_sha256='f'*64}
            'node'{$R.node_id='other'}
            'position'{$R.position=($Position+1)%3}
            'future'{$R.measured_at+=[long]5000}
            'negative'{$R.result.benchmark.distribution.min_ms=-1}
            'unordered'{$R.result.benchmark.distribution.median_ms=30}
            'budget'{$R.result.benchmark.distribution.max_ms=$(if($Position-eq1){5001}else{2001})}
            'jitter'{$R.result.benchmark.distribution.jitter_ms=11}
            'label'{$R.result.label='wrong metric'}
            default{$R.result|Add-Member NoteProperty $Case @{} -Force}
        }
        Reject {Assert-RouterVPNOrderedReceipt $R (Capture) $N -Current} ("receipt $Position $Case")
    }
}
$EmptyState=New-RouterVPNOrderedState $BaseUrl 'home-a';$Empty=Status;[void]$Empty.Remove('history');Receive-RouterVPNOrderedStatus $EmptyState $Empty -Initial
Check ($EmptyState.History-is[array]-and$EmptyState.History.Count-eq0) 'first measurement accepts omitted empty backend history'
$Bad=Capture;$Bad.session_id='a'*32;Reject {Assert-RouterVPNOrderedCapture $Bad} 'tracker format cannot become a native hex session'
$S=State;Check (Start-RouterVPNOrderedLatency $S 0) 'captured Start';$Start=Pending $S '';$ID=$S.Request
$Body=$Start.Body|ConvertFrom-Json;Check ($Body.request_id-ceq$ID-and$Body.node_id-ceq'node-0'-and$Body.capture.session_id-ceq$S.Capture.session_id) 'Start body owns exact captured route'
$V=Status $ID 0 'draining' $true $false;$V.status.failure='joining';Reply $Start 202 $V;Update-RouterVPNOrderedView $S
Check (-not$S.Drained) 'completion without native drain remains owned'
$Poll=Pending $S ('?request_id='+$ID);$V=Status $ID 0 'cancelled';$V.capture.generation_sha256='f'*64;$V.status.failure='cancelled';Reply $Poll 200 $V;Update-RouterVPNOrderedView $S
Check (-not$S.Drained-and$S.Cancelled) 'foreign capture cannot release original'
$Cancel=Pending $S '/cancel';$V=Status $ID 0 'cancelled';$V.status.failure='cancelled';Reply $Cancel 200 $V;Update-RouterVPNOrderedView $S
Check ($S.Drained-and$S.History[0].request_id-ceq('e'*32)) 'cancel preserves earlier history'
Check (Request-RouterVPNOrderedClose $S) 'settled model close';[void](Close-RouterVPNOrderedView $S)

$S=State;[void](Start-RouterVPNOrderedLatency $S 1);$Start=Pending $S '';$ID=$S.Request
Check (-not(Request-RouterVPNOrderedClose $S)) 'queued Start blocks close'
$Cancel=Pending $S '/cancel';$V=Status $ID 1 'cancelled';$V.status.failure='cancelled';Reply $Cancel 200 $V;Update-RouterVPNOrderedView $S
Check ($S.Drained-and-not$S.Closed-and-not(Request-RouterVPNOrderedClose $S)) 'native cancel still joins queued HTTP Start'
Reply $Start 202 (Status $ID 1 'starting' $false $false);Update-RouterVPNOrderedView $S
Check ($S.Closed-and$S.Drained-and$S.Jobs.Count-eq0) 'late Start cannot revive cancelled owner'

$S=State;[void](Start-RouterVPNOrderedLatency $S 2);$Start=Pending $S '';$ID=$S.Request;Cancel-RouterVPNOrderedLatency $S;$Cancel=Pending $S '/cancel'
$V=Status $ID 2 'complete';$V.receipt=Receipt $ID 2;Reply $Start 200 $V;Update-RouterVPNOrderedView $S
Check ($S.Drained-and$S.Status.Contains('before cancellation')-and@($S.History|Where-Object{$_.request_id-ceq$ID}).Count-eq1) 'durable success before cancellation remains visible'
$V=Status $ID 2 'cancelled';$V.status.failure='cancelled';Reply $Cancel 200 $V;Update-RouterVPNOrderedView $S
Check (@($S.History|Where-Object{$_.request_id-ceq$ID}).Count-eq1) 'late cancel preserves committed receipt'
Check (Request-RouterVPNOrderedClose $S) 'durable owner closes';[void](Close-RouterVPNOrderedView $S)

$S=State;$SelectionGuard=@{Current=$true};$S.SelectionCurrent={return $SelectionGuard.Current}.GetNewClosure()
[void](Start-RouterVPNOrderedLatency $S 0);$Start=Pending $S '';$ID=$S.Request;$SelectionGuard.Current=$false
Reply $Start 202 (Status $ID 0 'starting' $false $false);Update-RouterVPNOrderedView $S
Check ($S.Invalid-and-not$S.Drained-and-not(Start-RouterVPNOrderedLatency $S 0)) 'replacement is latched before completed callbacks and blocks retest'
$Cancel=Pending $S '/cancel';$Poll=Pending $S ('?request_id='+$ID)
$V=Status $ID 0 'complete';$V.receipt=Receipt $ID;$V.receipt.generation_sha256='f'*64;Reply $Poll 200 $V;Update-RouterVPNOrderedView $S
Check (-not$S.Drained) 'invalidated view still rejects foreign cleanup receipt'
$V=Status $ID 0 'complete';$V.receipt=Receipt $ID;Reply $Cancel 200 $V;Update-RouterVPNOrderedView $S
Check ($S.Drained-and$S.Jobs.Count-eq0) 'exact committed original drains invalidated view'
Check ($S.History.Count-eq1-and$S.History[0].request_id-cne$ID) 'replacement cannot adopt original committed history'
Check (-not(Start-RouterVPNOrderedLatency $S 0)-and(Request-RouterVPNOrderedClose $S)) 'invalidated view closes without retesting old capture'
[void](Close-RouterVPNOrderedView $S)

function PairedNodes([int]$Count) {return @(0..($Count-1)|ForEach-Object{@{node_id=('node-'+$_);position=$_;role=$(if($_-eq0){'entry'}elseif($_-eq($Count-1)){'exit'}else{'intermediate'});label=('Private hop '+($_+1));kind='private-node';measurement='routed-private-response-including-connection'}})}
function PairedReceipt([int]$Count,[int]$Position,[string]$Request=('e'*32)) {
    $R=Receipt $Request 0;$N=(PairedNodes $Count)[$Position];$R.position=$Position;$R.node_id=$N.node_id
    $R.result.node_id=$N.node_id;$R.result.role=$N.role;$R.result.kind='private-node';$R.result.label='Cumulative path through node '+($Position+1)+' of '+$Count
    return $R
}
foreach($Count in 2..8){
    $Rows=PairedNodes $Count;$S=New-RouterVPNOrderedState $BaseUrl 'home-a';$S.Client=FakeClient
    $V=Status;$V.nodes=$Rows;$V.history=@((PairedReceipt $Count 0));try{Receive-RouterVPNOrderedStatus $S $V -Initial}catch{Check $false ("whole private inventory $Count was rejected: "+$_.Exception.Message)}
    Check ($S.Nodes.Count-eq$Count-and-not$S.Invalid) "whole private inventory $Count"
    foreach($Position in 0..($Count-1)){
        $N=$Rows[$Position];Assert-RouterVPNOrderedNode $N $Position $Count
        $R=PairedReceipt $Count $Position;Assert-RouterVPNOrderedReceipt $R (Capture) $N -Current -Count $Count;$script:Checks+=2
        $R.result.benchmark.distribution.max_ms=2001
        Reject {Assert-RouterVPNOrderedReceipt $R (Capture) $N -Current -Count $Count} "private budget including middle $Count/$Position"
        $R=PairedReceipt $Count $Position;$R.result.label='Cumulative path through node '+($Position+1)+' of '+$(if($Count-eq8){7}else{8})
        Reject {Assert-RouterVPNOrderedReceipt $R (Capture) $N -Current -Count $Count} "foreign path length $Count/$Position"
    }
    $Position=$Count-1;Check (Start-RouterVPNOrderedLatency $S $Position) "last private hop starts $Count"
    $Start=Pending $S '';$ID=$S.Request;$V=Status $ID $Position 'complete';$V.receipt=PairedReceipt $Count $Position $ID
    Reply $Start 200 $V;Update-RouterVPNOrderedView $S
    Check ($S.Drained-and@($S.History|Where-Object{$_.request_id-ceq$ID-and$_.position-eq$Position}).Count-eq1) "last private hop saved through shipping callback $Count"
    Check (Request-RouterVPNOrderedClose $S) "whole private path joined $Count";[void](Close-RouterVPNOrderedView $S)
}
foreach($Count in @(1,9)){
    $S=New-RouterVPNOrderedState $BaseUrl 'home-a';$V=Status;$V.nodes=PairedNodes $Count;$V.history=@()
    Reject {Receive-RouterVPNOrderedStatus $S $V -Initial} 'unbounded inventory refused'
}

Write-Output "PASS $script:Checks ordered hop shipping model checks"
