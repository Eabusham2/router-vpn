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
function SelectedCapture([string]$Execution,$Rows){
    $C=Capture;$Selected=@{schema=1;source_sha256=$C.source_sha256;config_sha256=$C.config_sha256;generation_sha256=$C.generation_sha256;selected_execution=$Execution;
        nodes=@(foreach($N in $Rows){@{node_id=$N.node_id;position=$N.position;role=$N.role;kind=$N.kind}})}
    $C.selected_capture=($Selected|ConvertTo-Json -Depth 10 -Compress);return $C
}
function Nodes {return @(0..2|ForEach-Object{@{node_id=('node-'+$_);position=$_;role=@('entry','intermediate','exit')[$_];label=$(if($_-eq1){'Cumulative path through custom node 2 of 3 '+[char]0x2192+' Cloudflare edge'}else{'Cumulative path through node '+($_+1)+' of 3'});kind=$(if($_-eq1){'public-path'}else{'private-node'});measurement=$(if($_-eq1){'routed-https-response-after-tls'}else{'routed-private-response-including-connection'})}})}
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
    $Count=if($Scenario-ceq'connect8'){8}else{3}
    Check ($null-ne$S.Capture-and-not$S.Invalid-and$S.Nodes.Count-eq$Count) 'live exact ordered capture'
    if($Visual){&$Pump;Check ($S.Window.FindName('Hop').Items.Count-eq$Count) 'actual WPF chooser retains every captured hop'}
    $Prior=[string](Get-RouterVPNOrderedValue $S.History[0] 'request_id')
    $Position=if($Scenario-ceq'connect8'){6}elseif($Scenario-ceq'public'){1}elseif($Scenario-ceq'exit'){2}else{0}
    if($Visual){$S.Window.FindName('Hop').SelectedIndex=$Position;$S.Window.FindName('Retest').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))}else{[void](Start-RouterVPNOrderedLatency $S $Position)}
    if($Visual-and$Scenario-ceq'connect8'){&$Pump;Check ($S.Window.FindName('Detail').Text.StartsWith('HTTPS response after TLS')) 'actual WPF public penultimate timing label'}
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
        if($Scenario-cin@('success','public','exit','connect8')){Check ($Saved.Count-eq1) 'live durable fifty receipt adopted';Assert-RouterVPNOrderedReceipt $Saved[0] $S.Capture $S.Node -Current -Count $Count}
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
$CustomState=New-RouterVPNOrderedState $BaseUrl 'home-a';$CustomState.Client=FakeClient
$CustomInfo=Status;$CustomNodes=$CustomInfo.nodes;$Entry=$CustomNodes[0]
$Entry.kind='public-path';$Entry.measurement=$CustomNodes[1].measurement;$Entry.label='Cumulative path through custom node 1 of 3 '+[char]0x2192+' Cloudflare edge'
$Saved=Receipt ('e'*32) 1;$Saved.node_id=$Entry.node_id;$Saved.position=0
foreach($Key in @('node_id','role','label')){$Saved.result[$Key]=$Entry[$Key]}
$CustomInfo.history=@($Saved)
Reject {Assert-RouterVPNOrderedNode $Entry 0 3} 'unbound public entry rejected'
$Wrong=CopyValue $CustomInfo;$Wrong.nodes[1].kind='private-node';$Wrong.nodes[1].label='Cumulative path through node 2 of 3';$Wrong.nodes[1].measurement='routed-private-response-including-connection'
Reject {Receive-RouterVPNOrderedStatus $CustomState $Wrong -Initial} 'public entry requires original public middle'
Receive-RouterVPNOrderedStatus $CustomState $CustomInfo -Initial
Check ($CustomState.History.Count-eq1-and$CustomState.Nodes[0].kind-ceq'public-path') 'custom entry saved receipt displayed'
Check (Start-RouterVPNOrderedLatency $CustomState 0) 'custom public entry retest'
$Saved=CopyValue $Saved;$Saved.request_id=$CustomState.Request
$Terminal=Status $CustomState.Request 0 'complete' $true $true;$Terminal.receipt=$Saved
Receive-RouterVPNOrderedStatus $CustomState $Terminal
Check ($CustomState.Drained-and$CustomState.History[0].request_id-ceq$CustomState.Request) 'custom public entry retest committed'

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

function PairedNodes([int]$Count) {return @(0..($Count-1)|ForEach-Object{@{node_id=('node-'+$_);position=$_;role=$(if($_-eq0){'entry'}elseif($_-eq($Count-1)){'exit'}else{'intermediate'});label=('Cumulative path through node '+($_+1)+' of '+$Count);kind='private-node';measurement='routed-private-response-including-connection'}})}
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
foreach($Count in @(9,16)){
    $Rows=PairedNodes $Count;$Position=$Count-2
    $S=New-RouterVPNOrderedState $BaseUrl 'home-a';$S.Client=FakeClient
    $V=Status;$V.nodes=$Rows;$V.capture.extended_local_nodes=$Count;$V.history=@((PairedReceipt $Count $Position))
    Receive-RouterVPNOrderedStatus $S $V -Initial
    Check ($S.Nodes.Count -eq $Count -and $S.History.Count -eq 1) 'Deep original private history lost its late hop'
    $R=PairedReceipt $Count $Position
    Reject {Assert-RouterVPNOrderedReceipt $R $V.capture (CopyValue $Rows[$Position]) -Current -Count $Count -OriginalNodes $Rows} 'A copied private row lacks its original inventory'
    $Mixed=@($Rows);$Mixed[1]=(Nodes)[1]
    Reject {Assert-RouterVPNOrderedReceipt $R $V.capture $Rows[$Position] -Current -Count $Count -OriginalNodes $Mixed} 'A mixed long path yielded private history'
    Check (Start-RouterVPNOrderedLatency $S $Position) 'Deep private hop starts'
    $Start=Pending $S '';$ID=$S.Request;$Reply=Status $ID $Position 'complete';$Reply.capture=$S.Capture;$Reply.receipt=PairedReceipt $Count $Position $ID
    Reply $Start 200 $Reply;Update-RouterVPNOrderedView $S
    Check ($S.Drained -and @($S.History|Where-Object{$_.request_id -ceq $ID -and $_.position -eq $Position}).Count -eq 1) 'Deep private callback lost original history'
    [void](Close-RouterVPNOrderedView $S)
}
foreach($Count in @(9,16,96)){
    $packets=2;$Rows=PairedNodes $Count
    for($i=$packets;$i -lt $Count-1;$i++){$N=(Nodes)[1];$N.position=$i;$N.node_id='node-'+$i;$N.label='Cumulative path through custom node '+($i+1)+' of '+$Count+' '+[char]0x2192+' Cloudflare edge';$Rows[$i]=$N}
    $S=New-RouterVPNOrderedState $BaseUrl 'home-a';$S.Client=FakeClient;$V=Status;$V.nodes=$Rows;$V.capture.extended_local_nodes=$Count;$V.capture.paired_prefix_nodes=$packets;$V.history=@()
    Receive-RouterVPNOrderedStatus $S $V -Initial;Check ($S.Nodes.Count -eq $Count) 'Original mixed latency inventory truncated'
    $R=PairedReceipt $Count 1;Assert-RouterVPNOrderedReceipt $R $V.capture $Rows[1] -Current -Count $Count -OriginalNodes $Rows
    Reject {Assert-RouterVPNOrderedReceipt $R $V.capture (CopyValue $Rows[1]) -Current -Count $Count -OriginalNodes $Rows} 'A copied mixed position retains no independent original authority'
    foreach($fault in @('removed','shift','foreign','type')){
        $bad=CopyValue $V.capture
        if($fault -ceq 'removed'){$bad.PSObject.Properties.Remove('paired_prefix_nodes')};if($fault -ceq 'shift'){$bad.paired_prefix_nodes=3};if($fault -ceq 'foreign'){$bad|Add-Member NoteProperty extended_original_nodes $Count};if($fault -ceq 'type'){$bad.paired_prefix_nodes='2'}
        Reject {Assert-RouterVPNOrderedCapture $bad;Assert-RouterVPNOrderedReceipt $R $bad $Rows[1] -Current -Count $Count -OriginalNodes $Rows} ('Mixed latency lost source marker '+$fault)
    }
    Check (Start-RouterVPNOrderedLatency $S 1) 'Mixed private packet benchmark refused';$Start=Pending $S '';Check ($Start.Body.Contains('"paired_prefix_nodes":2')) 'Mixed original benchmark POST omitted original marker'
    [void](Close-RouterVPNOrderedView $S)
}
foreach($Count in @(1,9)){
    $S=New-RouterVPNOrderedState $BaseUrl 'home-a';$V=Status;$V.nodes=PairedNodes $Count;$V.history=@()
    Reject {Receive-RouterVPNOrderedStatus $S $V -Initial} 'unbounded inventory refused'
}


# CONNECT counts3–8 retain their original public penultimate row and fifty receipt.
foreach($Count in 3..8){
    $Position=$Count-2;$Rows=PairedNodes $Count;$N=(Nodes)[1]
    $N.position=$Position;$N.node_id='node-'+$Position;$N.label='Cumulative path through custom node '+($Position+1)+' of '+$Count+' '+[char]0x2192+' Cloudflare edge';$Rows[$Position]=$N
    $R=Receipt ('e'*32) 1;$R.position=$Position;$R.node_id=$N.node_id;$R.result.node_id=$N.node_id;$R.result.label=$N.label
    $S=New-RouterVPNOrderedState $BaseUrl 'home-a';$S.Client=FakeClient;$V=Status;$V.nodes=$Rows;$V.history=@($R)
    try{Receive-RouterVPNOrderedStatus $S $V -Initial}catch{Check $false ('CONNECT bounded inventory rejected: '+$_.Exception.Message)};Check ($S.Nodes.Count-eq$Count-and-not$S.Invalid) 'CONNECT bounded inventory'
    Assert-RouterVPNOrderedReceipt $R (Capture) $N -Current -Count $Count;Assert-RouterVPNOrderedReceipt $R (Capture) $N -Count $Count;$script:Checks+=2
    foreach($Other in 0..($Count-1)){
        if($Other-eq$Position){continue};$Bad=CopyValue $N;$Bad.position=$Other;$Bad.role=if($Other-eq0){'entry'}elseif($Other-eq($Count-1)){'exit'}else{'intermediate'};$Bad.label='Cumulative path through custom node '+($Other+1)+' of '+$Count+' '+[char]0x2192+' Cloudflare edge'
        if($Other-eq0-or$Other-eq($Count-1)){Reject {Assert-RouterVPNOrderedNode $Bad $Other $Count} 'public row cannot become an endpoint'}else{Reject {Assert-RouterVPNOrderedReceipt $R (Capture) $Bad -Current -Count $Count} 'original CONNECT receipt cannot move to another interior'}
    }
    Check (Start-RouterVPNOrderedLatency $S $Position) 'CONNECT original public hop starts'
    $Start=Pending $S '';$ID=$S.Request;$R.request_id=$ID;$V=Status $ID $Position 'complete';$V.receipt=$R
    Reply $Start 200 $V;Update-RouterVPNOrderedView $S
    Check ($S.Drained-and@($S.History|Where-Object{$_.request_id-ceq$ID-and$_.position-eq$Position}).Count-eq1) 'CONNECT callback commits original fifty receipt'
    Check (Request-RouterVPNOrderedClose $S) 'CONNECT complete owner joins';[void](Close-RouterVPNOrderedView $S)
}

# Ordinary Local observations retain every independent public interior. The
# source/controller owns its graph; history cannot relabel selected execution.
foreach($Count in (@(3..8)+@(9,16))){
    $Rows=PairedNodes $Count;$History=@()
    foreach($Position in 1..($Count-2)){
        $N=(Nodes)[1];$N.position=$Position;$N.node_id='node-'+$Position;$N.label='Cumulative path through custom node '+($Position+1)+' of '+$Count+' '+[char]0x2192+' Cloudflare edge';$Rows[$Position]=$N
        $R=Receipt ('{0:x32}' -f ($Position+901)) 1;$R.position=$Position;$R.node_id=$N.node_id;$R.result.node_id=$N.node_id;$R.result.label=$N.label;$History+=$R
    }
    $S=New-RouterVPNOrderedState $BaseUrl 'home-a';$S.Client=FakeClient;$V=Status;$V.nodes=$Rows;$V.history=$History;if($Count-gt8){$V.capture.extended_local_nodes=$Count}
    try{Receive-RouterVPNOrderedStatus $S $V -Initial}catch{Check $false ('independent imported interior receipt was refused: '+$_.Exception.Message)}
    Check ($S.Nodes.Count-eq$Count-and$S.History.Count-eq($Count-2)-and-not$S.Invalid) 'independent imported interior receipt was refused'
    foreach($Position in 1..($Count-2)){
        $N=$Rows[$Position];$R=$History[$Position-1]
        Assert-RouterVPNOrderedReceipt $R $V.capture $N -Current -Count $Count;Assert-RouterVPNOrderedReceipt $R $V.capture $N -Count $Count;$script:Checks+=2
        $Bad=CopyValue $R;$Bad.result.benchmark.distribution.samples=49
        Reject {Assert-RouterVPNOrderedReceipt $Bad $V.capture $N -Current -Count $Count} 'independent public history requires fifty samples'
        $Bad=CopyValue $R;$Bad.source_sha256='f'*64
        Reject {Assert-RouterVPNOrderedReceipt $Bad $V.capture $N -Current -Count $Count} 'independent public history retains original source'
        if($Position-ne($Count-2)){foreach($Execution in @('local','server')){
            $BadNode=CopyValue $N;$BadNode.label=$BadNode.label.Replace('Cumulative path',('Cumulative '+$Execution+' path'))
            Reject {Assert-RouterVPNOrderedNode $BadNode $Position $Count} 'independent history cannot borrow selected execution'
        }}
        Check (Start-RouterVPNOrderedLatency $S $Position) 'independent original public hop starts'
        $Start=Pending $S '';$ID=$S.Request;$Current=CopyValue $R;$Current.request_id=$ID;$V=Status $ID $Position 'complete';$V.capture=$S.Capture;$V.receipt=$Current
        Reply $Start 200 $V;Update-RouterVPNOrderedView $S
        Check ($S.Drained-and@($S.History|Where-Object{$_.request_id-ceq$ID-and$_.position-eq$Position}).Count-eq1) 'independent callback commits exact original receipt'
    }
    Check (Request-RouterVPNOrderedClose $S) 'independent public owner joins';[void](Close-RouterVPNOrderedView $S)
}

# The seven-field native inventory binds every public position to its own source.
foreach($Execution in @('local','server')){foreach($layout in @(@{count=4;slots=@(1)},@{count=5;slots=@(1,3)},@{count=8;slots=@(1,4,6)},@{count=9;slots=@(1..7)},@{count=16;slots=@(1..14)})){
    $Count=$layout.count;$Rows=PairedNodes $Count;$History=@()
    foreach($position in $layout.slots){
        $N=(Nodes)[1];$N.position=$position;$N.node_id='node-'+$position
        $N.label='Cumulative path through custom node '+($position+1)+' of '+$Count+' '+[char]0x2192+' Cloudflare edge';$Rows[$position]=$N
        $R=Receipt ('{0:x32}' -f ($position+801)) 1;$R.position=$position;$R.node_id=$N.node_id
        $R.result.node_id=$N.node_id;$R.result.label=$N.label.Replace('Cumulative path',('Cumulative '+$Execution+' path'));$History+=$R
    }
    foreach($N in $Rows){$N.label=$N.label.Replace('Cumulative path',('Cumulative '+$Execution+' path'))}
    $captured=SelectedCapture $Execution $Rows;$legacy=CopyValue $captured
    if($Count-gt8){$captured.extended_original_nodes=$Count}
    $native=$captured.selected_capture|ConvertFrom-Json
    $members=@(foreach($position in $layout.slots){@{position=$position;tag=('test-public-'+$position);source_sha256=('{0:x64}' -f $position)}})
    $native|Add-Member NoteProperty multiple_imported @{schema=6;original_source_sha256='7'*64;public=$members}
    $captured.selected_capture=$native|ConvertTo-Json -Depth 10 -Compress
    $S=New-RouterVPNOrderedState $BaseUrl 'home-a';$S.Client=FakeClient;$V=Status;$V.nodes=$Rows;$V.history=$History;$V.capture=$captured
    try{Receive-RouterVPNOrderedStatus $S $V -Initial}catch{Check $false 'Multiple imported selected response lost its public inventory or durable label'}
    Check ($S.History.Count-eq$layout.slots.Count-and$S.Nodes.Count-eq$Count) 'multiple-import selected capture lost original public history'
    foreach($R in $History){
        try{Assert-RouterVPNOrderedReceipt $R $captured $Rows[$R.position] -Current -Count $Count}
        catch{Check $false 'Multiple imported selected history lost its original public receipt'}
    }
    Reject {Assert-RouterVPNOrderedCapture $legacy} 'legacy selected capture borrowed multiple-import public positions'
    if($Count-gt8){
        $foreign=CopyValue $captured;$foreign.extended_original_nodes=$Count-1
        Reject {Assert-RouterVPNOrderedCapture $foreign} 'long selected capture cannot borrow another row count'
        $borrowed=CopyValue $captured;$borrowed|Add-Member NoteProperty extended_local_nodes $Count
        Reject {Assert-RouterVPNOrderedCapture $borrowed} 'long selected capture cannot borrow a Local-only owner'
    }
    $native.multiple_imported.public[0].position=0;$captured.selected_capture=$native|ConvertTo-Json -Depth 10 -Compress
    Reject {Assert-RouterVPNOrderedCapture $captured} 'multiple-import selected capture accepted a substituted public position'
    [void](Close-RouterVPNOrderedView $S)
}}

# Canonical selected paths execute through the original callback and receipt guards.
foreach($Execution in @('local','server')){
    foreach($Layout in @('imported',2,3,4,5,6,7,8)){
        $Imported=$Layout-ceq'imported';$Count=if($Imported){3}else{[int]$Layout}
        $Rows=if($Imported){Nodes}else{PairedNodes $Count}
        foreach($N in $Rows){$N.label=$N.label.Replace('Cumulative path',('Cumulative '+$Execution+' path'))}
        $OriginalCapture=SelectedCapture $Execution $Rows
        $Records=@(foreach($Position in 0..($Count-1)){
            $R=if($Imported){Receipt ('e'*32) $Position}else{PairedReceipt $Count $Position}
            $R.result.label=$Rows[$Position].label;$R
        })
        foreach($Position in 0..($Count-1)){
            $N=$Rows[$Position];$R=$Records[$Position]
            try{Assert-RouterVPNOrderedNode $N $Position $Count;Assert-RouterVPNOrderedReceipt $R $OriginalCapture $N -Current -Count $Count;Assert-RouterVPNOrderedReceipt $R $OriginalCapture $N -Count $Count;$script:Checks+=3}catch{Check $false "canonical selected receipt $Execution/$Layout/$Position"}
            foreach($Other in @('ordinary','local','server')|Where-Object{$_-cne$Execution}){
                $Bad=CopyValue $R;$Prefix=if($Other-ceq'ordinary'){'Cumulative path'}else{'Cumulative '+$Other+' path'}
                $Bad.result.label=$Bad.result.label.Replace(('Cumulative '+$Execution+' path'),$Prefix)
                Reject {Assert-RouterVPNOrderedReceipt $Bad $OriginalCapture $N -Current -Count $Count} 'current receipt cannot borrow another selected label'
                Reject {Assert-RouterVPNOrderedReceipt $Bad $OriginalCapture $N -Count $Count} 'history cannot borrow another selected label'
            }
            $BadNode=CopyValue $N;$BadNode.label=$N.label.Replace(('Cumulative '+$Execution+' path'),'Cumulative auto path')
            Reject {Assert-RouterVPNOrderedNode $BadNode $Position $Count} 'only canonical selected labels are admitted'
        }
        $S=New-RouterVPNOrderedState $BaseUrl 'home-a';$S.Client=FakeClient
        $V=Status;$V.capture=$OriginalCapture;$V.nodes=$Rows;$V.history=@($Records[0]);$Bad=CopyValue $V
        $Uncaptured=CopyValue $V;$Uncaptured.capture=Capture
        Reject {Receive-RouterVPNOrderedStatus $S $Uncaptured -Initial} 'selected inventory requires actual facade capture'
        foreach($Key in @('source_sha256','config_sha256','generation_sha256')){
            $Changed=CopyValue $OriginalCapture;$Changed.$Key='f'*64
            Reject {Assert-RouterVPNOrderedCapture $Changed} 'selected facade binds original digest'
        }
        $Bad.nodes[1].label=$Bad.nodes[1].label.Replace(('Cumulative '+$Execution+' path'),'Cumulative path')
        Reject {Receive-RouterVPNOrderedStatus $S $Bad -Initial} 'mixed selected inventory cannot be captured'
        $Bad=CopyValue $V;$Bad.history[0].result.label=$Bad.history[0].result.label.Replace(('Cumulative '+$Execution+' path'),'Cumulative path')
        Reject {Receive-RouterVPNOrderedStatus $S $Bad -Initial} 'foreign selected history cannot be captured'
        try{Receive-RouterVPNOrderedStatus $S $V -Initial}catch{Check $false "selected callback capture $Execution/$Layout"}
        $Position=$Count-1;Check (Start-RouterVPNOrderedLatency $S $Position) 'selected path starts original request'
        $Sent=New-RouterVPNOrderedBody $S;Check ($Sent.capture.selected_capture-ceq$OriginalCapture.selected_capture) 'selected request retains opaque native capture'
        $Start=Pending $S '';$ID=$S.Request;$V=Status $ID $Position 'complete';$V.capture=$OriginalCapture;$V.receipt=CopyValue $Records[$Position];$V.receipt.request_id=$ID
        $Wrong=CopyValue $V;$Wrong.capture=Capture
        Reject {Receive-RouterVPNOrderedStatus $S $Wrong} 'selected callback cannot omit original facade'
        Reply $Start 200 $V;Update-RouterVPNOrderedView $S
        Check ($S.Drained-and@($S.History|Where-Object{$_.request_id-ceq$ID-and$_.result.label-ceq$Rows[$Position].label}).Count-eq1) 'selected callback retains exact durable label'
        Check (Request-RouterVPNOrderedClose $S) 'selected path joins original workers';[void](Close-RouterVPNOrderedView $S)
    }
}

Write-Output "PASS $script:Checks ordered hop shipping model checks"
