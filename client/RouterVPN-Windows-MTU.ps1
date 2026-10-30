if(-not(Get-Command New-RouterVPNControllerClient -ErrorAction SilentlyContinue)){
    Import-Module (Join-Path $PSScriptRoot 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
}

# One MTU view owns its requests. Polls and cancellation never follow a new
# connection or a replacement measurement, even when an old HTTP task finishes.
function global:Get-RouterVPNMTUValue {
    param($Value,[string]$Name,$Default=$null)
    if($null-eq$Value){return $Default}
    if($Value-is[System.Collections.IDictionary]){if($Value.Contains($Name)){return $Value[$Name]};return $Default}
    $Property=$Value.PSObject.Properties[$Name]
    if($null-eq$Property){return $Default};return $Property.Value
}

function global:New-RouterVPNMTUState {
    param([string]$BaseUrl)
    Assert-RouterVPNControllerBaseUrl $BaseUrl
    return @{BaseUrl=$BaseUrl.TrimEnd('/');Generation=[long]1;Completion=[long]0;Session='';Profile='';Request='';Seen=$false;Own=$false;
        Cancelled=$false;CancelAck=$false;Terminal=$false;Retired=$false;Closing=$false;Detaching=$false;Closed=$false;RunDone=$true;OptimizationAllowed=$false;
        Run=$null;Poll=$null;Cancel=$null;Client=$null;Window=$null;Timer=$null;Next=[DateTime]::MinValue;
        Deadline=[DateTime]::MaxValue;PostError='';Status='Checking MTU on the connected path...';Detail='';Last=$null}
}

function global:Stop-RouterVPNMTUOwner {
    param($State,[string]$Reason)
    $State.Retired=$true;$State.Terminal=$true;$State.Status=$Reason
    if($null-ne$State.Run){$State.Run.Cts.Cancel()}
    if($null-ne$State.Poll){$State.Poll.Cts.Cancel()}
}

function global:Format-RouterVPNMTUCandidates {
    param($Status)
    $Lines=New-Object 'System.Collections.Generic.List[string]'
    $Original=Get-RouterVPNMTUValue $Status 'original_mtu' 0
    $Effective=Get-RouterVPNMTUValue $Status 'effective_mtu' 0
    $Source=[string](Get-RouterVPNMTUValue $Status 'source' '')
    if($Source.StartsWith('saved-')){
        if($Effective-is[ValueType]-and$Effective-isnot[bool]-and[int]$Effective-gt0){$Lines.Add("Saved MTU: $Effective (historical; not measured on this path)")}
    }else{
        if($Original-is[ValueType]-and$Original-isnot[bool]-and[int]$Original-gt0){$Lines.Add("Previous interface MTU: $Original")}
        if($Effective-is[ValueType]-and$Effective-isnot[bool]-and[int]$Effective-gt0){$Lines.Add("Effective interface MTU: $Effective")}
    }
    if($Source){$Lines.Add('Measurement source: '+$Source)}
    $Candidates=Get-RouterVPNMTUValue $Status 'candidates'
    if($null-ne$Candidates){foreach($Candidate in @($Candidates)|Select-Object -First 64){
        $MTU=Get-RouterVPNMTUValue $Candidate 'mtu' 0
        if($MTU-isnot[ValueType]-or$MTU-is[bool]-or[int]$MTU-le0){continue}
        $Working=Get-RouterVPNMTUValue $Candidate 'working' $false
        $Line="MTU $MTU : "+$(if($Working-is[bool]-and$Working){'working'}else{'not proved'})
        $Latency=Get-RouterVPNMTUValue $Candidate 'median_rtt_ms' 0
        $Kind=[string](Get-RouterVPNMTUValue $Candidate 'latency_kind' '')
        if($Latency-is[ValueType]-and$Latency-isnot[bool]-and[double]$Latency-gt0-and$Kind){$Line+=' | '+$Kind+' '+([double]$Latency).ToString('0.0',[Globalization.CultureInfo]::InvariantCulture)+' ms'}
        foreach($Direction in @('download','upload')){
            $Transfer=Get-RouterVPNMTUValue $Candidate $Direction
            $Rate=Get-RouterVPNMTUValue $Transfer 'mbps' 0
            if($Rate-is[ValueType]-and$Rate-isnot[bool]-and[double]$Rate-gt0){$Line+=' | '+$Direction+' '+([double]$Rate).ToString('0.0',[Globalization.CultureInfo]::InvariantCulture)+' Mbps'}
        }
        $Failure=[string](Get-RouterVPNMTUValue $Candidate 'failure' '')
        if($Failure){$Line+=' | '+$Failure.Substring(0,[Math]::Min(256,$Failure.Length))}
        $Lines.Add($Line)
    }}
    return [string]::Join([Environment]::NewLine,$Lines)
}

function global:Receive-RouterVPNMTUStatus {
    param($State,$Value,[bool]$AfterRun=$true)
    if($State.Closed-or$State.Retired){return $false}
    $Session=Get-RouterVPNMTUValue $Value 'session_id';$Profile=Get-RouterVPNMTUValue $Value 'profile_id'
    $Status=Get-RouterVPNMTUValue $Value 'status';$Waiting=Get-RouterVPNMTUValue $Value 'waiting_commit'
    $Requested=Get-RouterVPNMTUValue $Value 'requested'
    $OptimizationAllowed=Get-RouterVPNMTUValue $Value 'optimization_allowed' $true
    if($OptimizationAllowed-isnot[bool]){throw 'Invalid captured MTU optimization capability.'}
    $ID=Get-RouterVPNMTUValue $Status 'request_id'
    if($Session-isnot[string]-or-not$Session-or$Session.Length-gt128-or$Profile-isnot[string]-or-not$Profile-or$Profile.Length-gt256-or$ID-isnot[string]-or($ID-and$ID-cnotmatch'^[0-9a-f]{32}$')-or$Waiting-isnot[bool]-or$Requested-isnot[bool]){throw 'Invalid captured MTU status.'}
    foreach($Name in @('running','complete','measured','restored')){if((Get-RouterVPNMTUValue $Status $Name)-isnot[bool]){throw 'Invalid MTU progress state.'}}
    if($State.Session-and($State.Session-cne$Session-or$State.Profile-cne$Profile)){Stop-RouterVPNMTUOwner $State 'The connection changed. This MTU view has retired; reopen it for the new connection.';return $false}
    if(-not$State.Session){$State.Session=$Session;$State.Profile=$Profile}
    if($State.Request-and$State.Request-cne$ID){Stop-RouterVPNMTUOwner $State 'This MTU request was replaced. Its result was discarded.';return $false}
    if(-not$State.Request-and$ID){$State.Request=$ID;$State.Deadline=[DateTime]::UtcNow.AddSeconds(180)}
    if($ID){$State.Seen=$true}
    $State.OptimizationAllowed=$OptimizationAllowed
    $State.Last=$Status;$State.Detail=Format-RouterVPNMTUCandidates $Status
    $Running=[bool](Get-RouterVPNMTUValue $Status 'running');$Complete=[bool](Get-RouterVPNMTUValue $Status 'complete')
    $Candidate=$ID-and$Complete-and-not$Running-and-not$Waiting
    $State.Terminal=$Candidate-and$null-eq$State.Cancel-and(-not$State.Own-or($State.RunDone-and$AfterRun))
    $Failure=[string](Get-RouterVPNMTUValue $Status 'failure' '')
    $Effective=Get-RouterVPNMTUValue $Status 'effective_mtu' 0
    if($State.Terminal){
        if((Get-RouterVPNMTUValue $Status 'restored')){$State.Status='Previous MTU restored.'}
        elseif((Get-RouterVPNMTUValue $Status 'measured')-and$Effective-is[ValueType]-and$Effective-isnot[bool]-and[int]$Effective-ge576-and[int]$Effective-le9000){$State.Status="Measured MTU: $Effective";if($State.Cancelled){$State.Status+=' (the test finished before cancellation)'}}
        elseif($Failure){$State.Status='MTU test failed: '+$Failure.Substring(0,[Math]::Min(512,$Failure.Length))}
        else{$State.Status='The test ended without a new MTU measurement.'}
    }elseif($Candidate){$State.Status='The controller is finishing this test. Waiting for its final captured status.';$State.Detail=''}
    elseif($State.Cancelled){$State.Status='Cancelling; waiting for the captured test to finish its restoration.'}
    elseif($Waiting){$State.Status='Saving the verified MTU...'}
    elseif($Running){$Phase=[string](Get-RouterVPNMTUValue $Status 'phase' '');$State.Status=if($Phase){'MTU test: '+$Phase}else{'Measuring the captured path...'}}
    elseif($ID){$State.Status='Waiting for the captured MTU test...'}
    elseif(-not$State.OptimizationAllowed){$State.Status='This connection keeps its configured MTU. Retest is disabled by its Fixed, Default, or Jumbo policy.'}
    else{$State.Status='No MTU test is running. Retest measures this connected path.'}
    return $true
}

function global:New-RouterVPNMTUClient {
    Add-Type -AssemblyName System.Net.Http
    $Client=New-RouterVPNControllerClient -TimeoutMilliseconds 900000 -ResponseLimit 262144
    return $Client
}

function global:New-RouterVPNMTURequest {
    param($State,[string]$Path,$Body=$null,[int]$Timeout=6)
    if($State.Closed-or$null-eq$State.Client){throw 'MTU view is closed.'}
    if($Path-cnotmatch'^/api/mtu/(status(?:\?(?:request_id=[0-9a-f]{32}&)?session_id=[^&\r\n]+)?|retest|cancel)$'){throw 'Invalid MTU request path.'}
    $Method=if($null-eq$Body){[System.Net.Http.HttpMethod]::Get}else{[System.Net.Http.HttpMethod]::Post}
    $Request=[System.Net.Http.HttpRequestMessage]::new($Method,$State.BaseUrl+$Path)
    Set-RouterVPNControllerRequestTimeout $Request ([int]($Timeout*1000))
    $Cts=[System.Threading.CancellationTokenSource]::new();$Cts.CancelAfter([TimeSpan]::FromSeconds($Timeout))
    try{
        if($null-ne$Body){$Request.Content=[System.Net.Http.StringContent]::new(($Body|ConvertTo-Json -Depth 6 -Compress),[Text.Encoding]::UTF8,'application/json')}
        $Task=$State.Client.SendAsync($Request,$Cts.Token)
        return @{Generation=$State.Generation;Completion=$State.Completion;AfterRun=$State.RunDone;Request=$Request;Cts=$Cts;Task=$Task}
    }catch{$Cts.Cancel();$Request.Dispose();$Cts.Dispose();throw}
}

function global:Complete-RouterVPNMTURequest {
    param($Job)
    if($null-eq$Job-or-not$Job.Task.IsCompleted){return $null}
    $Response=$null
    try{
        $Response=$Job.Task.GetAwaiter().GetResult()
        $Text=$Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if($Text.Length-gt262144){throw 'MTU response exceeded its size limit.'}
        $Value=$null;if($Text){try{$Value=$Text|ConvertFrom-Json}catch{}}
        return @{Code=[int]$Response.StatusCode;Value=$Value;Error=$(if($Response.IsSuccessStatusCode){''}else{$Text.Substring(0,[Math]::Min(1024,$Text.Length))})}
    }catch{return @{Code=0;Value=$null;Error=$_.Exception.Message}}
    finally{if($null-ne$Response){$Response.Dispose()};$Job.Request.Dispose();$Job.Cts.Dispose()}
}

function global:Start-RouterVPNMTURetest {
    param($State)
    if($State.Closed-or$State.Detaching-or$State.Closing-or$State.Retired-or-not$State.OptimizationAllowed-or-not$State.Session-or-not$State.RunDone-or$null-ne$State.Run-or$null-ne$State.Cancel-or($State.Request-and-not$State.Terminal)){return $false}
    if(Get-Command UnifiedAsyncBusy -ErrorAction SilentlyContinue){if(UnifiedAsyncBusy){$State.Status='Another Router VPN action is running. Wait for it to finish.';return $false}}
    if($null-ne$State.Poll){$State.Poll.Cts.Cancel()}
    $State.Generation++;$State.Request=[Guid]::NewGuid().ToString('N');$State.Seen=$false;$State.Own=$true
    $State.Terminal=$false;$State.Cancelled=$false;$State.CancelAck=$false;$State.RunDone=$false;$State.PostError=''
    $State.Deadline=[DateTime]::UtcNow.AddSeconds(180);$State.Next=[DateTime]::MinValue
    $State.Status='Submitting Retest for this connection...';$State.Detail='';$State.Last=$null
    try{$State.Run=New-RouterVPNMTURequest $State '/api/mtu/retest' @{request_id=$State.Request;session_id=$State.Session;profile_id=$State.Profile} 150;return $true}
    catch{$State.RunDone=$true;Stop-RouterVPNMTUOwner $State ('Retest did not start: '+$_.Exception.Message);return $false}
}

function global:Cancel-RouterVPNMTUTest {
    param($State)
    if($State.Closed-or$State.Detaching-or$State.Retired-or-not$State.Request-or$State.Terminal-or$State.CancelAck-or$null-ne$State.Cancel){return}
    $State.Cancelled=$true;$State.Status='Cancelling; waiting for the captured test to finish its restoration.'
    # Before registration, stop this POST as well as sending the exact ID. A
    # delayed request must not start new work after the view has been cancelled.
    if($State.Own-and-not$State.Seen-and$null-ne$State.Run){$State.Run.Cts.Cancel()}
    try{$State.Cancel=New-RouterVPNMTURequest $State '/api/mtu/cancel' @{request_id=$State.Request;session_id=$State.Session} 6}
    catch{if($State.Own-and$null-ne$State.Run){$State.Run.Cts.Cancel()};$State.Status='Cancellation was not confirmed. Waiting for the captured status; Cancel can be retried.'}
}

function global:Update-RouterVPNMTUView {
    param($State)
    if($State.Closed){return}
    foreach($Name in @('Run','Cancel','Poll')){
        $Job=$State[$Name]
        if($null-eq$Job-or-not$Job.Task.IsCompleted){continue}
        $State[$Name]=$null;$Reply=Complete-RouterVPNMTURequest $Job
        if($Job.Generation-ne$State.Generation-or$State.Closed-or$State.Detaching){continue}
        if($Name-eq'Run'){
            $State.RunDone=$true;$State.Completion++;$State.Terminal=$State.Retired
            if($Reply.Code-lt200-or$Reply.Code-ge300){$State.PostError=$Reply.Error}
            if($null-ne$State.Poll-and-not$State.Poll.AfterRun){$State.Poll.Cts.Cancel()}
            # Only the filtered status can attest measurement or restoration.
            $State.Next=[DateTime]::MinValue
        }elseif($Name-eq'Cancel'){
            $State.Completion++;$State.Terminal=$State.Retired
            if($null-ne$State.Poll){$State.Poll.Cts.Cancel()}
            if($Reply.Code-eq200-and[string](Get-RouterVPNMTUValue $Reply.Value 'request_id' '')-ceq$State.Request-and[string](Get-RouterVPNMTUValue $Reply.Value 'phase' '')-ceq'canceling'){$State.CancelAck=$true}
            elseif($Reply.Code-eq409){$State.Status='Cancellation raced a completed or changed operation. Checking only the captured request.'}
            elseif($Reply.Code-ne404-or$State.Seen){if($State.Own-and$null-ne$State.Run){$State.Run.Cts.Cancel()};$State.Status='Cancellation was not confirmed. Waiting for captured status; Cancel can be retried.'}
            $State.Next=[DateTime]::MinValue
        }elseif(-not$State.Retired){
            if($Job.Completion-ne$State.Completion-or($State.Own-and$State.RunDone-and-not$Job.AfterRun)){$State.Next=[DateTime]::MinValue;continue}
            if($Reply.Code-eq200){try{[void](Receive-RouterVPNMTUStatus $State $Reply.Value $Job.AfterRun)}catch{Stop-RouterVPNMTUOwner $State $_.Exception.Message}}
            elseif($Reply.Code-eq404-and$State.Own-and-not$State.Seen){
                if(-not$State.RunDone){$State.Status=if($State.Cancelled){'Cancelling the unaccepted Retest request...'}else{'Waiting for the controller to accept this Retest...'}}
                elseif($State.Cancelled){$State.Terminal=$true;$State.Status='Retest cancelled before it was accepted.'}
                else{Stop-RouterVPNMTUOwner $State ('Retest was not accepted. '+$State.PostError)}
            }elseif($Reply.Code-eq404-or$Reply.Code-eq409){Stop-RouterVPNMTUOwner $State 'The connection or MTU request changed. This view has retired; reopen it for the current path.'}
            else{$State.Status='MTU progress could not be confirmed. Retrying the same captured request.'}
        }
    }
    if($State.Detaching){[void](Close-RouterVPNMTUView $State);return}
    if(-not$State.Retired-and-not$State.Terminal-and[DateTime]::UtcNow-gt$State.Deadline){Stop-RouterVPNMTUOwner $State 'MTU status did not finish within its deadline. No successful measurement or restoration is claimed.'}
    if(-not$State.Retired-and-not$State.Terminal-and$null-eq$State.Poll-and[DateTime]::UtcNow-ge$State.Next){
        $Path='/api/mtu/status'
        if($State.Request){$Path+='?request_id='+$State.Request+'&session_id='+[Uri]::EscapeDataString($State.Session)}
        elseif($State.Session){$Path+='?session_id='+[Uri]::EscapeDataString($State.Session)}
        try{$State.Poll=New-RouterVPNMTURequest $State $Path;$State.Next=[DateTime]::UtcNow.AddMilliseconds(500)}catch{$State.Status='MTU progress could not be requested.';$State.Next=[DateTime]::UtcNow.AddSeconds(2)}
    }
    if($null-ne$State.Window){
        $State.Window.FindName('MtuStatus').Text=$State.Status;$State.Window.FindName('MtuDetails').Text=$State.Detail
        $Ready=-not$State.Retired-and$State.OptimizationAllowed-and$State.Session-and$State.RunDone-and$null-eq$State.Run-and$null-eq$State.Cancel-and(-not$State.Request-or$State.Terminal)
        $State.Window.FindName('Retest').IsEnabled=[bool]($Ready-and-not$State.Closing)
        $State.Window.FindName('CancelTest').IsEnabled=[bool](-not$State.Retired-and$State.Request-and-not$State.Terminal-and-not$State.CancelAck-and$null-eq$State.Cancel)
        if($State.Closing-and($State.Terminal-or$State.Retired)-and$State.RunDone-and$null-eq$State.Run-and$null-eq$State.Cancel){$State.Window.Close()}
    }
}

function global:Close-RouterVPNMTUView {
    param($State)
    if($State.Closed){return $true}
    if(-not$State.Detaching){$State.Detaching=$true;$State.Generation++}
    foreach($Name in @('Run','Poll','Cancel')){if($null-ne$State[$Name]){$State[$Name].Cts.Cancel()}}
    $Pending=$false
    foreach($Name in @('Run','Poll','Cancel')){
        $Job=$State[$Name]
        if($null-ne$Job){
            if($Job.Task.IsCompleted){$State[$Name]=$null;[void](Complete-RouterVPNMTURequest $Job)}
            else{$Pending=$true}
        }
    }
    # The UI timer drains only this view's cancelled tasks. No worker owns WPF
    # objects, and a late successful response is disposed before the client.
    if($Pending){return $false}
    $State.Closed=$true
    if($null-ne$State.Timer){$State.Timer.Stop()}
    if($null-ne$State.Client){$State.Client.Dispose();$State.Client=$null}
    return $true
}

function global:Request-RouterVPNMTUClose {
    param($State)
    if(-not$State.Closed-and($State.Own-or$State.Cancelled)-and-not$State.Retired-and(-not$State.Terminal-or-not$State.RunDone-or$null-ne$State.Cancel)){
        $State.Closing=$true;Cancel-RouterVPNMTUTest $State;return $false
    }
    return $true
}

function global:Show-RouterVPNMTUDialog {
    param([string]$BaseUrl,[System.Windows.Window]$Owner)
    if($null-ne(Get-Variable RouterVPNMTUView -Scope Global -ErrorAction SilentlyContinue)){
        $Old=$global:RouterVPNMTUView
        if($null-ne$Old-and-not$Old.Closed-and$null-ne$Old.Window){$Old.Window.Activate()|Out-Null;return}
    }
    $State=New-RouterVPNMTUState $BaseUrl
    $State.Client=New-RouterVPNMTUClient
    [xml]$Xaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN MTU" Width="690" Height="460" MinWidth="540" MinHeight="330" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF">
<Grid Margin="20"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
<TextBlock Text="MTU on the connected path" FontSize="23" FontWeight="Bold"/>
<TextBlock Grid.Row="1" Margin="0,8,0,12" Foreground="#A8B6D5" TextWrapping="Wrap" Text="A running Auto measurement appears here. Retest starts a fresh measurement for this connection. Cancel waits for the captured test to finish or restore the previous MTU."/>
<TextBlock Name="MtuStatus" Grid.Row="2" TextWrapping="Wrap" Margin="0,0,0,10"/>
<TextBox Name="MtuDetails" Grid.Row="3" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Background="#101A2B" Foreground="#E8ECF8" Padding="10"/>
<StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0"><Button Name="Retest" Content="Retest MTU" Padding="12,6" Margin="4" IsEnabled="False"/><Button Name="CancelTest" Content="Cancel test" Padding="12,6" Margin="4" IsEnabled="False"/><Button Name="Close" Content="Close" Padding="12,6" Margin="4"/></StackPanel>
</Grid></Window>
'@
    $Reader=[Xml.XmlNodeReader]::new($Xaml);$Window=[Windows.Markup.XamlReader]::Load($Reader);$Reader.Dispose()
    $State.Window=$Window;if($null-ne$Owner){$Window.Owner=$Owner}
    $State.Timer=[Windows.Threading.DispatcherTimer]::new();$State.Timer.Interval=[TimeSpan]::FromMilliseconds(50)
    $Tick={Update-RouterVPNMTUView $State}.GetNewClosure();$State.Timer.Add_Tick($Tick)
    $Window.FindName('Retest').Add_Click({[void](Start-RouterVPNMTURetest $State);Update-RouterVPNMTUView $State}.GetNewClosure())
    $Window.FindName('CancelTest').Add_Click({Cancel-RouterVPNMTUTest $State;Update-RouterVPNMTUView $State}.GetNewClosure())
    $Window.FindName('Close').Add_Click({$State.Window.Close()}.GetNewClosure())
    $Window.Add_Closing({param($Sender,$Event)
        if(-not(Request-RouterVPNMTUClose $State)){
            $Event.Cancel=$true;Update-RouterVPNMTUView $State
        }
    }.GetNewClosure())
    $Window.Add_Closed({$State.Window=$null;[void](Close-RouterVPNMTUView $State)}.GetNewClosure())
    $global:RouterVPNMTUView=$State;$State.Timer.Start();$Window.Show();Update-RouterVPNMTUView $State
}
