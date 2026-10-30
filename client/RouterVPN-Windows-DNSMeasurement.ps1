if(-not(Get-Command New-RouterVPNControllerClient -ErrorAction SilentlyContinue)){
    Import-Module (Join-Path $PSScriptRoot 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
}

# One modeless view owns one captured DNS request. Closing never interprets an
# HTTP error, a disconnected path or a cancelled HTTP task as native drain proof.
function global:Get-RouterVPNDNSValue {
    param($Value,[string]$Name,$Default=$null)
    if($null-eq$Value){return $Default}
    if($Value-is[System.Collections.IDictionary]){if($Value.Contains($Name)){return ,$Value[$Name]};return $Default}
    $Property=$Value.PSObject.Properties[$Name];if($null-eq$Property){return $Default};return ,$Property.Value
}
function global:Test-RouterVPNDNSNumber {
    param($Value,[double]$Minimum=0,[double]$Maximum=2147483647,[switch]$Integer)
    if($Value-isnot[ValueType]-or$Value-is[bool]){return $false}
    $N=[double]$Value
    return -not[double]::IsNaN($N)-and-not[double]::IsInfinity($N)-and$N-ge$Minimum-and$N-le$Maximum-and(-not$Integer-or[Math]::Floor($N)-eq$N)
}
function global:New-RouterVPNDNSState {
    param([string]$BaseUrl,[string]$DisplayedProfileID)
    Assert-RouterVPNControllerBaseUrl $BaseUrl
    if([string]::IsNullOrEmpty($DisplayedProfileID)-or$DisplayedProfileID.Length-gt128){throw 'Select the external node displayed by this window.'}
    return @{BaseUrl=$BaseUrl.TrimEnd('/');Displayed=$DisplayedProfileID;Profile='';Token='';Session='';Request='';Generation=[long]0;
        Ready=$false;Drained=$true;StartDone=$true;Cancelled=$false;Closing=$false;Closed=$false;AllowClose=$false;Invalid=$false;Saved=$false;
        Transport='https';Stage='idle';Rows=@();Selected='';Selection=$null;Draft=$null;DraftExpires=[DateTime]::MinValue;ResultsExpires=[DateTime]::MinValue;ExpiresInMS=0;
        NextPoll=[DateTime]::MinValue;NextCancel=[DateTime]::MinValue;Deadline=[DateTime]::MaxValue;AutoStart=$false;
        Jobs=[Collections.Generic.List[object]]::new();Client=$null;Window=$null;Timer=$null;Owner=$null;OwnerClosing=$null;CloseOwner=$false;
        Status='Loading the selected native path...';Detail='';Revision=[long]0;Rendered=[long]-1}
}
function global:New-RouterVPNDNSClient {
    Add-Type -AssemblyName System.Net.Http
    $Client=New-RouterVPNControllerClient -TimeoutMilliseconds 6000 -ResponseLimit 262144
    return $Client
}
function global:New-RouterVPNDNSRequest {
    param($State,[string]$Kind,[string]$Path,$Body=$null)
    if($State.Closed-or$null-eq$State.Client){throw 'The DNS view is closed.'}
    if($Path-cnotmatch'^/api/(dns/measurement(?:\?request_id=[0-9a-f]{32}|/cancel|/select)?|dns/policy|status)$'){throw 'Invalid captured DNS route.'}
    $Method=if($null-eq$Body){[Net.Http.HttpMethod]::Get}else{[Net.Http.HttpMethod]::Post}
    $Request=[Net.Http.HttpRequestMessage]::new($Method,$State.BaseUrl+$Path);$Cts=[Threading.CancellationTokenSource]::new();$Cts.CancelAfter([TimeSpan]::FromSeconds(6))
    try{
        if($null-ne$Body){$Request.Content=[Net.Http.StringContent]::new(($Body|ConvertTo-Json -Depth 6 -Compress),[Text.Encoding]::UTF8,'application/json')}
        $Started=[DateTime]::UtcNow;$Task=$State.Client.SendAsync($Request,$Cts.Token)
        $Job=@{Kind=$Kind;Generation=$State.Generation;Captured=$State.Request;Started=$Started;Request=$Request;Cts=$Cts;Task=$Task}
        [void]$State.Jobs.Add($Job);return $Job
    }catch{$Request.Dispose();$Cts.Dispose();throw}
}
function global:Complete-RouterVPNDNSRequest {
    param($Job)
    $Response=$null
    try{
        $Response=$Job.Task.GetAwaiter().GetResult();$Text=$Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if($Text.Length-gt262144){throw 'DNS response exceeded its size limit.'}
        $Value=$null;if($Text){try{$Value=$Text|ConvertFrom-Json}catch{}}
        return @{Code=[int]$Response.StatusCode;Value=$Value;Error=$(if($Response.IsSuccessStatusCode){''}else{$Text.Substring(0,[Math]::Min(512,$Text.Length))})}
    }catch{return @{Code=0;Value=$null;Error=$_.Exception.Message}}
    finally{if($null-ne$Response){$Response.Dispose()};$Job.Request.Dispose();$Job.Cts.Dispose()}
}
function global:Test-RouterVPNDNSJob {
    param($State,[string]$Kind)
    foreach($Job in $State.Jobs){if($Job.Kind-ceq$Kind){return $true}};return $false
}
function global:New-RouterVPNDNSOwnerBody {
    param($State)
    if(-not$State.Profile-or-not$State.Token-or$State.Session-cnotmatch'^[0-9a-f]{32}$'-or$State.Request-cnotmatch'^[0-9a-f]{32}$'){throw 'The DNS request has no exact captured owner.'}
    return @{profile_id=$State.Profile;profile_token=$State.Token;session_id=$State.Session;request_id=$State.Request}
}
function global:Convert-RouterVPNDNSRows {
    param($Status)
    $Rows=Get-RouterVPNDNSValue $Status 'results';if($Rows-isnot[array]){throw 'DNS status omitted its measured rows.'}
    $All=@($Rows);if($All.Count-gt13){throw 'DNS comparison exceeded its bounded resolver catalog.'}
    $IDs=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$Output=[Collections.Generic.List[object]]::new();$Selected=''
    foreach($Row in $All){
        $ID=Get-RouterVPNDNSValue $Row 'id';$Kind=Get-RouterVPNDNSValue $Row 'kind';$Name=Get-RouterVPNDNSValue $Row 'name';$Address=Get-RouterVPNDNSValue $Row 'address';$Transport=Get-RouterVPNDNSValue $Row 'transport';$Route=Get-RouterVPNDNSValue $Row 'route_label'
        if($ID-isnot[string]-or$ID-cnotmatch'^[a-zA-Z0-9._-]{1,64}$'-or-not$IDs.Add($ID)-or$Kind-cnotin@('selected','public')){throw 'DNS comparison returned an invalid or duplicate row owner.'}
        foreach($Text in @($Name,$Address,$Route)){if($Text-isnot[string]-or-not$Text-or$Text.Length-gt512-or$Text-match'[\r\n\x00]'){throw 'DNS row text is missing or malformed.'}}
        if($Transport-cnotin@('udp','tcp','tls','https','h3')){throw 'DNS row transport is unknown.'}
        $Port=Get-RouterVPNDNSValue $Row 'port';$Samples=Get-RouterVPNDNSValue $Row 'samples';$Failed=Get-RouterVPNDNSValue $Row 'failed';$Ready=Get-RouterVPNDNSValue $Row 'ready';$Median=Get-RouterVPNDNSValue $Row 'median_ms'
        if(-not(Test-RouterVPNDNSNumber $Port 1 65535 -Integer)-or-not(Test-RouterVPNDNSNumber $Samples 0 3 -Integer)-or-not(Test-RouterVPNDNSNumber $Failed 0 3 -Integer)-or$Ready-isnot[bool]){throw 'DNS row measurement shape is invalid.'}
        if([string](Get-RouterVPNDNSValue $Status 'stage' '')-ceq'complete'-and$Samples+$Failed-ne3){throw 'Completed DNS row lost its three attempts.'}
        $Valid=$Ready-and$Samples-eq3-and$Failed-eq0-and(Test-RouterVPNDNSNumber $Median 0 75000)-and[double]$Median-gt0
        if($Ready-and-not$Valid){throw 'A ready DNS row has no three-sample measurement.'}
        $Latency=if($Valid){([double]$Median).ToString('0.00',[Globalization.CultureInfo]::InvariantCulture)+' ms'}else{'No valid score'}
        $Failure=[string](Get-RouterVPNDNSValue $Row 'failure' '');if($Failure.Length-gt256){$Failure=$Failure.Substring(0,256)}
        $Label=if($Valid){'3 successful samples'}elseif($Failure){$Failure}else{'Not ready'}
        if($Kind-ceq'selected'){
            if($ID-cne'selected'-or$Selected){throw 'The selected DNS measurement is not unique.'}
            $Selected="Selected resolver: $Name | $Address`:$Port | $Transport | $Latency | $Route | $Label";continue
        }
        if($ID-ceq'selected'-or$Transport-cnotin@('tcp','tls','https')){throw 'The public DNS row is not eligible for comparison.'}
        $Endpoint=if($Address.Contains(':')){"[$Address]:$Port"}else{"$Address`:$Port"}
        [void]$Output.Add([pscustomobject]@{id=$ID;name=$Name;endpoint=$Endpoint;transport=$Transport;route=$Route;latency=$Latency;samples="$Samples / 3";status=$Label;eligible=[bool]$Valid;median=$(if($Valid){[double]$Median}else{[double]::PositiveInfinity});source=$Row})
    }
    return @{Rows=@($Output.ToArray()|Sort-Object @{Expression={if($_.eligible){0}else{1}}},median,id);Selected=$Selected}
}
function global:Receive-RouterVPNDNSStatus {
    param($State,$Value,[switch]$Initial,[DateTime]$RequestedAt=[DateTime]::UtcNow)
    $Profile=Get-RouterVPNDNSValue $Value 'profile_id';$Token=Get-RouterVPNDNSValue $Value 'profile_token';$Session=Get-RouterVPNDNSValue $Value 'session_id';$Request=Get-RouterVPNDNSValue $Value 'request_id';$Status=Get-RouterVPNDNSValue $Value 'status'
    if($Profile-isnot[string]-or$Profile-cne$State.Displayed-or$Token-isnot[string]-or-not$Token-or$Token.Length-gt512-or$Session-isnot[string]-or$Session-cnotmatch'^[0-9a-f]{32}$'-or$Request-isnot[string]){throw 'DNS response belongs to another displayed node or invalid native session.'}
    if($State.Profile-and($Profile-cne$State.Profile-or$Token-cne$State.Token-or$Session-cne$State.Session)){throw 'DNS source or native session changed. This view keeps only its original request.'}
    $Schema=Get-RouterVPNDNSValue $Status 'schema';$Complete=Get-RouterVPNDNSValue $Status 'complete';$Drained=Get-RouterVPNDNSValue $Status 'drained';$Stage=Get-RouterVPNDNSValue $Status 'stage';$Inner=Get-RouterVPNDNSValue $Status 'request_id'
    if(-not(Test-RouterVPNDNSNumber $Schema 1 1 -Integer)-or$Complete-isnot[bool]-or$Drained-isnot[bool]-or$Stage-cnotin@('idle','preparing','starting','measuring','verifying','complete','cancelled','invalidated','failed','draining')-or[string](Get-RouterVPNDNSValue $Status 'node_id' '')-cne$Profile-or[string](Get-RouterVPNDNSValue $Status 'session_id' '')-cne$Session-or$Inner-isnot[string]-or$Inner-cne$Request){throw 'DNS progress lost its exact captured identity or drain state.'}
    if($Initial){if($State.Request-or$Request-or$Stage-cne'idle'-or-not$Complete-or-not$Drained){throw 'Initial DNS capture is not idle.'}}
    elseif(-not$State.Request-or$Request-cne$State.Request){throw 'DNS progress belongs to another request.'}
    if($Drained-and-not$Complete){throw 'Native DNS drain was reported before completion.'}
    if($Stage-ceq'complete'-and[string](Get-RouterVPNDNSValue $Status 'public_transport' '')-cne$State.Transport){throw 'DNS results changed the captured comparison transport.'}
    $Parsed=Convert-RouterVPNDNSRows $Status
    if($Stage-ceq'complete'-and($Parsed.Rows.Count-ne12-or-not$Parsed.Selected)){throw 'Completed DNS comparison omitted part of its resolver catalog.'}
    $Remaining=Get-RouterVPNDNSValue $Value 'expires_in_ms' 0
    if(-not(Test-RouterVPNDNSNumber $Remaining 0 120000 -Integer)){throw 'DNS result expiry is invalid.'}
    if($Initial){$State.Profile=$Profile;$State.Token=$Token;$State.Session=$Session;$State.Ready=$true;$State.Drained=$true;$State.Status='Captured path ready. Retest uses real DNS questions through this native connection.';return}
    $State.Stage=$Stage;$State.Drained=$State.Drained-or($Complete-and$Drained)
    $State.ExpiresInMS=[long]$Remaining
    $State.ResultsExpires=$RequestedAt.AddMilliseconds([long]$Remaining)
    if(-not$State.Cancelled-and-not$State.Invalid-and-not$State.Closing){
        $State.Rows=$Parsed.Rows;$State.Selected=$Parsed.Selected;$State.Revision++
        if($Stage-ceq'complete'-and$Complete-and$Drained){$State.Status='Measurement complete. Choose a successful public resolver or Fastest, then disconnect and explicitly Save.'}
        elseif($Stage-cin@('failed','invalidated','cancelled')){$State.Invalid=$true;$State.Rows=@();$State.Draft=$null;$State.Status='DNS measurement ended without a usable result. Reopen for the current connected path.'}
        else{$State.Status='DNS measurement: '+$Stage}
    }elseif($State.Drained){$State.Status='The captured DNS workers have drained.'}
    else{$State.Status='Cancelling the captured DNS request; waiting for actual native drain.'}
}
function global:Start-RouterVPNDNSMeasurement {
    param($State,[string]$Transport='https')
    if($State.Closed-or$State.Closing-or$State.Invalid-or$State.Saved-or-not$State.Ready-or-not$State.Drained-or$State.Jobs.Count-ne0){return $false}
    if($Transport-cnotin@('tcp','tls','https')){throw 'Choose TCP, DoT or DoH for public resolver comparison.'}
    $State.Generation++;$State.Request=[Guid]::NewGuid().ToString('N');$State.Transport=$Transport;$State.Drained=$false;$State.StartDone=$false;$State.Cancelled=$false
    $State.Rows=@();$State.Selected='';$State.Selection=$null;$State.Draft=$null;$State.ResultsExpires=[DateTime]::MinValue;$State.ExpiresInMS=0;$State.NextCancel=[DateTime]::MinValue;$State.Revision++;$State.Deadline=[DateTime]::UtcNow.AddSeconds(120);$State.Status='Starting DNS measurement on the captured native path...'
    $Body=New-RouterVPNDNSOwnerBody $State;$Body.public_transport=$Transport
    try{[void](New-RouterVPNDNSRequest $State 'start' '/api/dns/measurement' $Body);return $true}
    catch{$State.StartDone=$true;Cancel-RouterVPNDNSMeasurement $State;$State.Status='Start could not be confirmed. Cancelling the same captured request.';return $false}
}
function global:Cancel-RouterVPNDNSMeasurement {
    param($State)
    if($State.Closed-or-not$State.Request){return}
    if(-not$State.Cancelled){$State.Cancelled=$true;$State.Draft=$null;$State.Rows=@();$State.Selected='';$State.Selection=$null;$State.Revision++}
    foreach($Job in $State.Jobs){if($Job.Kind-cin@('start','select','save-check','save')){$Job.Cts.Cancel()}}
    if($State.Drained){return}
    if(-not(Test-RouterVPNDNSJob $State 'cancel')-and[DateTime]::UtcNow-ge$State.NextCancel){
        try{[void](New-RouterVPNDNSRequest $State 'cancel' '/api/dns/measurement/cancel' (New-RouterVPNDNSOwnerBody $State))}catch{}
        $State.NextCancel=[DateTime]::UtcNow.AddSeconds(1)
    }
    $State.Status='Cancelling the captured DNS request; waiting for actual native drain.'
}
function global:Select-RouterVPNDNSResult {
    param($State,[string]$ResultID)
    if($State.Closed-or$State.Closing-or$State.Invalid-or$State.Cancelled-or-not$State.Drained-or$State.Stage-cne'complete'-or[DateTime]::UtcNow-ge$State.ResultsExpires-or$State.Jobs.Count-ne0){return $false}
    $Candidates=@($State.Rows|Where-Object{$_.eligible});if(-not$Candidates.Count){throw 'No public resolver has three successful samples.'}
    $Chosen=if($ResultID-ceq'fastest'){$Candidates[0]}else{@($Candidates|Where-Object{$_.id-ceq$ResultID})|Select-Object -First 1}
    if($null-eq$Chosen){throw 'Choose a successful public resolver; selected-policy timing is separate.'}
    $Body=New-RouterVPNDNSOwnerBody $State;$Body.result_id=$ResultID;$State.Selection=$Chosen
    [void](New-RouterVPNDNSRequest $State 'select' '/api/dns/measurement/select' $Body);$State.Status='Capturing the exact measured resolver for explicit Save...';return $true
}
function global:Receive-RouterVPNDNSDraft {
    param($State,$Value,[DateTime]$RequestedAt=[DateTime]::UtcNow)
    if($State.Cancelled-or$State.Closing-or$State.Invalid){return}
    if([string](Get-RouterVPNDNSValue $Value 'session_id' '')-cne$State.Session-or[string](Get-RouterVPNDNSValue $Value 'request_id' '')-cne$State.Request){throw 'Measured DNS draft belongs to another native session.'}
    $Draft=Get-RouterVPNDNSValue $Value 'draft';$Left=Get-RouterVPNDNSValue $Value 'expires_in_ms'
    if(-not(Test-RouterVPNDNSNumber $Left 1 120000 -Integer)-or$null-eq$State.Selection){throw 'The measured DNS selection has expired.'}
    $Source=$State.Selection.source;$Body=@{}
    foreach($Pair in @(@('profile_id',$State.Profile),@('profile_token',$State.Token),@('measurement_id',$State.Request),@('result_id',$State.Selection.id),@('protocol',[string](Get-RouterVPNDNSValue $Source 'transport' '')),@('host',[string](Get-RouterVPNDNSValue $Source 'address' '')),@('server_name',[string](Get-RouterVPNDNSValue $Source 'server_name' '')),@('path',[string](Get-RouterVPNDNSValue $Source 'path' '')))){
        $Actual=Get-RouterVPNDNSValue $Draft $Pair[0] '';if($Actual-isnot[string]-or$Actual-cne$Pair[1]){throw 'Measured DNS draft changed its captured source or exact endpoint.'};$Body[$Pair[0]]=$Actual
    }
    $Port=Get-RouterVPNDNSValue $Draft 'port';if(-not(Test-RouterVPNDNSNumber $Port 1 65535 -Integer)-or$Port-ne(Get-RouterVPNDNSValue $Source 'port')){throw 'Measured DNS draft changed its transport port.'};$Body.port=[int]$Port
    $Mode=Get-RouterVPNDNSValue $Draft 'mode';$Expected=if($Body.protocol-ceq'tls'){'dot'}elseif($Body.protocol-ceq'https'){'doh'}else{'custom'}
    if($Mode-isnot[string]-or$Mode-cne$Expected){throw 'Measured DNS draft changed its resolver mode.'};$Body.mode=$Mode
    $Expiry=$RequestedAt.AddMilliseconds([long]$Left)
    if([DateTime]::UtcNow-ge$Expiry){throw 'The measured DNS selection expired in transit.'}
    $State.Draft=$Body;$State.DraftExpires=$Expiry
    $State.Status='Measured selection staged. Disconnect using the main window, then Save within the remaining time. Active DNS has not changed.'
}
function global:Save-RouterVPNDNSDraft {
    param($State)
    if($State.Closed-or$State.Closing-or$State.Invalid-or$State.Cancelled-or$null-eq$State.Draft-or$State.Jobs.Count-ne0){return $false}
    if([DateTime]::UtcNow-ge$State.DraftExpires){$State.Draft=$null;$State.Status='Measured selection expired. Reconnect and Retest before choosing again.';return $false}
    [void](New-RouterVPNDNSRequest $State 'save-check' '/api/status');return $true
}
function global:Request-RouterVPNDNSClose {
    param($State)
    if($State.Closed-or$State.AllowClose){return $true}
    $State.Closing=$true;$State.Draft=$null
    if($State.Request-and-not$State.Drained){Cancel-RouterVPNDNSMeasurement $State}
    else{foreach($Job in $State.Jobs){$Job.Cts.Cancel()}}
    return $State.Drained-and$State.Jobs.Count-eq0
}
function global:Close-RouterVPNDNSView {
    param($State)
    if($State.Closed){return $true};if(-not$State.Drained-or$State.Jobs.Count-ne0){return $false}
    $State.Closed=$true;$State.Draft=$null;$State.Rows=@();$State.Selection=$null
    if($null-ne$State.Timer){$State.Timer.Stop();$State.Timer=$null};if($null-ne$State.Client){$State.Client.Dispose();$State.Client=$null}
    $Owner=$State.Owner;$Closing=$State.OwnerClosing;$State.Owner=$null;$State.OwnerClosing=$null
    if($null-ne$Owner-and$null-ne$Closing){$Owner.Remove_Closing($Closing)}
    if($State.CloseOwner-and$null-ne$Owner){$State.CloseOwner=$false;$Owner.Close()}
    return $true
}
function global:Update-RouterVPNDNSView {
    param($State)
    if($State.Closed){return}
    foreach($Job in @($State.Jobs.ToArray())){
        if(-not$Job.Task.IsCompleted){continue};[void]$State.Jobs.Remove($Job);$Reply=Complete-RouterVPNDNSRequest $Job
        if($Job.Generation-ne$State.Generation-or$Job.Captured-cne$State.Request){continue}
        try{
            if($Job.Kind-ceq'start'){
                $State.StartDone=$true;$State.NextPoll=[DateTime]::MinValue
                if($Reply.Code-lt200-or$Reply.Code-ge300){Cancel-RouterVPNDNSMeasurement $State}
            }elseif($Job.Kind-ceq'info'){
                if($Reply.Code-ne200){throw ('Cannot capture this connected external path. '+$Reply.Error)}
                Receive-RouterVPNDNSStatus $State $Reply.Value -Initial -RequestedAt $Job.Started
                if($State.AutoStart-and-not$State.Closing){$State.AutoStart=$false;[void](Start-RouterVPNDNSMeasurement $State $State.Transport)}
            }elseif($Job.Kind-cin@('poll','cancel')){
                if($Reply.Code-ge200-and$Reply.Code-lt300){Receive-RouterVPNDNSStatus $State $Reply.Value -RequestedAt $Job.Started}
                else{if($Reply.Code-eq409){$State.Invalid=$true;Cancel-RouterVPNDNSMeasurement $State};$State.Status='Captured DNS status is unavailable. Retrying its cancellation/drain check; no result is adopted.'}
            }elseif($Job.Kind-ceq'select'){
                if($Reply.Code-ne200){throw ('Measured selection was not accepted. '+$Reply.Error)};Receive-RouterVPNDNSDraft $State $Reply.Value -RequestedAt $Job.Started
            }elseif($Job.Kind-ceq'save-check'){
                if($State.Closing-or$State.Cancelled-or$null-eq$State.Draft){continue}
                if($Reply.Code-ne200-or(Get-RouterVPNDNSValue $Reply.Value 'connected')-isnot[bool]){throw 'Cannot verify disconnection before Save.'}
                $Phase=Get-RouterVPNDNSValue $Reply.Value 'phase'
                if((Get-RouterVPNDNSValue $Reply.Value 'connected')-or$Phase-isnot[string]-or$Phase-cnotin@('off','failed','disconnected')){throw 'Disconnect in the main window before saving the measured resolver.'}
                if([DateTime]::UtcNow-ge$State.DraftExpires){$State.Draft=$null;throw 'The measured resolver draft expired before Save.'}
                [void](New-RouterVPNDNSRequest $State 'save' '/api/dns/policy' $State.Draft)
            }elseif($Job.Kind-ceq'save'){
                if($Reply.Code-ne200){throw ('DNS Save was not confirmed. '+$Reply.Error)}
                if($null-eq$State.Draft-or[string](Get-RouterVPNDNSValue $Reply.Value 'profile_id' '')-cne$State.Profile){throw 'DNS Save acknowledgement lost the captured node.'}
                foreach($Name in @('mode','protocol','host','port','server_name','path')){if([string](Get-RouterVPNDNSValue $Reply.Value $Name '')-cne[string]$State.Draft[$Name]){throw 'DNS Save acknowledgement changed the selected measured endpoint.'}}
                $State.Saved=$true;$State.Draft=$null;$State.Status='DNS policy saved for the next connection. Reconnect and verify the selected native DNS proof.'
            }
        }catch{
            $State.Status=$_.Exception.Message
            if($Job.Kind-cin@('info','poll','cancel')){$State.Invalid=$true;$State.Draft=$null;$State.Selection=$null;$State.Rows=@();$State.Selected='';$State.Revision++;if($State.Request-and-not$State.Drained){Cancel-RouterVPNDNSMeasurement $State}}
        }
    }
    if($State.Request-and-not$State.Drained){
        if([DateTime]::UtcNow-ge$State.Deadline){$State.Deadline=[DateTime]::MaxValue;$State.Invalid=$true;Cancel-RouterVPNDNSMeasurement $State}
        if($State.Cancelled-or$State.Closing-or$State.Invalid){Cancel-RouterVPNDNSMeasurement $State}
        if($State.StartDone-and-not(Test-RouterVPNDNSJob $State 'poll')-and[DateTime]::UtcNow-ge$State.NextPoll){
            try{[void](New-RouterVPNDNSRequest $State 'poll' ('/api/dns/measurement?request_id='+$State.Request))}catch{}
            $State.NextPoll=[DateTime]::UtcNow.AddMilliseconds(500)
        }
    }
    if($null-ne$State.Draft-and[DateTime]::UtcNow-ge$State.DraftExpires){$State.Draft=$null;$State.Status='Measured resolver draft expired. Reconnect and Retest to choose a fresh result.'}
    if($State.Stage-ceq'complete'-and$State.ExpiresInMS-gt0-and[DateTime]::UtcNow-ge$State.ResultsExpires-and$null-eq$State.Draft-and-not$State.Cancelled-and-not$State.Invalid-and-not$State.Closing-and-not$State.Saved){$State.ExpiresInMS=0;$State.Status='These measured results expired. Retest the connected path before staging a resolver.'}
    if($null-ne$State.Window){
        $W=$State.Window;$W.FindName('DnsProgress').Text=$State.Status;$W.FindName('SelectedResolver').Text=$State.Selected
        if($State.Rendered-ne$State.Revision){$List=$W.FindName('Resolvers');$Old=[string]$List.SelectedValue;$List.ItemsSource=$State.Rows;if($Old){$List.SelectedValue=$Old};$State.Rendered=$State.Revision}
        $Idle=$State.Jobs.Count-eq0-and-not$State.Closing-and-not$State.Invalid-and-not$State.Saved
        $W.FindName('Retest').IsEnabled=[bool]($Idle-and$State.Ready-and$State.Drained);$W.FindName('Transport').IsEnabled=[bool]($Idle-and$State.Drained)
        $CanChoose=$Idle-and-not$State.Cancelled-and$State.Drained-and$State.Stage-ceq'complete'-and[DateTime]::UtcNow-lt$State.ResultsExpires
        $W.FindName('Choose').IsEnabled=[bool]$CanChoose;$W.FindName('Fastest').IsEnabled=[bool]$CanChoose
        $W.FindName('CancelTest').IsEnabled=[bool]($State.Request-and-not$State.Drained-and-not$State.Closing)
        $W.FindName('Save').IsEnabled=[bool]($Idle-and$null-ne$State.Draft)
        $W.FindName('Draft').Text=if($null-ne$State.Draft){$D=$State.Draft;$Seconds=[Math]::Max(0,[Math]::Ceiling(($State.DraftExpires-[DateTime]::UtcNow).TotalSeconds));"Staged: $($D.mode) $($D.host):$($D.port) | $($D.server_name)$($D.path) | expires in $Seconds seconds. Save requires disconnection."}else{'No measured resolver is staged. Manual DNS editing remains in Settings.'}
    }
    if($State.Closing-and$State.Drained-and$State.Jobs.Count-eq0){$State.AllowClose=$true;if($null-ne$State.Window){$State.Window.Close()}else{[void](Close-RouterVPNDNSView $State)}}
}
function global:Show-RouterVPNDNSMeasurement {
    param([string]$BaseUrl,$Owner,[string]$DisplayedProfileID,[ValidateSet('tcp','tls','https')][string]$PublicTransport='https')
    if($null-ne(Get-Variable RouterVPNDNSView -Scope Global -ErrorAction SilentlyContinue)){$Old=$global:RouterVPNDNSView;if($null-ne$Old-and-not$Old.Closed){if($null-ne$Old.Window){[void]$Old.Window.Activate()};if($Old.Displayed-cne$DisplayedProfileID){throw 'The open DNS view still owns another captured node. Close it after cleanup before testing this node.'};return}}
    $State=New-RouterVPNDNSState $BaseUrl $DisplayedProfileID;$State.Client=New-RouterVPNDNSClient;$State.Owner=$Owner;$State.AutoStart=$true;$State.Transport=$PublicTransport
    [xml]$Xaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN DNS measurements" Width="1000" Height="650" MinWidth="720" MinHeight="480" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF">
<Grid Margin="20"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
<TextBlock Text="DNS on the connected external path" FontSize="23" FontWeight="Bold"/>
<TextBlock Grid.Row="1" TextWrapping="Wrap" Foreground="#A8B6D5" Margin="0,8,0,12" Text="Three fresh DNS questions measure each resolver through this captured native connection. The selected resolver keeps its saved transport and route. Public comparisons use the transport below; failed rows receive no score. Disconnect remains available in the main window."/>
<TextBlock Name="SelectedResolver" Grid.Row="2" TextWrapping="Wrap" Margin="0,0,0,10"/>
<ListView Name="Resolvers" Grid.Row="3" SelectedValuePath="id" Background="#101A2B" Foreground="#E8ECF8"><ListView.View><GridView><GridViewColumn Header="Public resolver" DisplayMemberBinding="{Binding name}" Width="140"/><GridViewColumn Header="Endpoint" DisplayMemberBinding="{Binding endpoint}" Width="185"/><GridViewColumn Header="Transport" DisplayMemberBinding="{Binding transport}" Width="75"/><GridViewColumn Header="Median DNS RTT" DisplayMemberBinding="{Binding latency}" Width="115"/><GridViewColumn Header="Samples" DisplayMemberBinding="{Binding samples}" Width="70"/><GridViewColumn Header="Route" DisplayMemberBinding="{Binding route}" Width="135"/><GridViewColumn Header="Result" DisplayMemberBinding="{Binding status}" Width="155"/></GridView></ListView.View></ListView>
<TextBlock Name="DnsProgress" Grid.Row="4" TextWrapping="Wrap" Margin="0,12,0,6"/>
<TextBlock Name="Draft" Grid.Row="5" TextWrapping="Wrap" Foreground="#A8B6D5" Margin="0,6,0,8"/>
<WrapPanel Grid.Row="6" HorizontalAlignment="Right"><ComboBox Name="Transport" Width="110" Margin="4" SelectedIndex="2"><ComboBoxItem Content="TCP" Tag="tcp"/><ComboBoxItem Content="DoT" Tag="tls"/><ComboBoxItem Content="DoH" Tag="https"/></ComboBox><Button Name="Retest" Content="Retest" Padding="10,7" Margin="4"/><Button Name="CancelTest" Content="Cancel test" Padding="10,7" Margin="4"/><Button Name="Choose" Content="Stage selected" Padding="10,7" Margin="4"/><Button Name="Fastest" Content="Stage fastest" Padding="10,7" Margin="4"/><Button Name="Save" Content="Save after Disconnect" Padding="10,7" Margin="4"/><Button Name="Close" Content="Close" Padding="10,7" Margin="4"/></WrapPanel>
</Grid></Window>
'@
    $Reader=[Xml.XmlNodeReader]::new($Xaml);$W=[Windows.Markup.XamlReader]::Load($Reader);$Reader.Dispose();$State.Window=$W;$W.Title='Router VPN DNS - '+$DisplayedProfileID;if($null-ne$Owner){$W.Owner=$Owner}
    $W.FindName('Transport').SelectedIndex=@('tcp','tls','https').IndexOf($PublicTransport)
    $State.Timer=[Windows.Threading.DispatcherTimer]::new();$State.Timer.Interval=[TimeSpan]::FromMilliseconds(50)
    $State.Timer.Add_Tick({Update-RouterVPNDNSView $State}.GetNewClosure())
    $W.FindName('Retest').Add_Click({try{[void](Start-RouterVPNDNSMeasurement $State ([string]$State.Window.FindName('Transport').SelectedItem.Tag))}catch{$State.Status=$_.Exception.Message};Update-RouterVPNDNSView $State}.GetNewClosure())
    $W.FindName('CancelTest').Add_Click({Cancel-RouterVPNDNSMeasurement $State;Update-RouterVPNDNSView $State}.GetNewClosure())
    $W.FindName('Choose').Add_Click({try{[void](Select-RouterVPNDNSResult $State ([string]$State.Window.FindName('Resolvers').SelectedValue))}catch{$State.Status=$_.Exception.Message};Update-RouterVPNDNSView $State}.GetNewClosure())
    $W.FindName('Fastest').Add_Click({try{[void](Select-RouterVPNDNSResult $State 'fastest')}catch{$State.Status=$_.Exception.Message};Update-RouterVPNDNSView $State}.GetNewClosure())
    $W.FindName('Save').Add_Click({try{[void](Save-RouterVPNDNSDraft $State)}catch{$State.Status=$_.Exception.Message};Update-RouterVPNDNSView $State}.GetNewClosure())
    $W.FindName('Close').Add_Click({$State.Window.Close()}.GetNewClosure())
    $W.Add_Closing({param($Sender,$Event)if(-not(Request-RouterVPNDNSClose $State)){$Event.Cancel=$true}}.GetNewClosure())
    $W.Add_Closed({$State.Window=$null;[void](Close-RouterVPNDNSView $State)}.GetNewClosure())
    if($null-ne$Owner){$State.OwnerClosing=[ComponentModel.CancelEventHandler]({param($Sender,$Event)if(-not$State.Closed){if(-not(Request-RouterVPNDNSClose $State)){$State.CloseOwner=$true;$Event.Cancel=$true}else{$State.CloseOwner=$false;$State.AllowClose=$true}}}.GetNewClosure());$Owner.Add_Closing($State.OwnerClosing)}
    $global:RouterVPNDNSView=$State;[void](New-RouterVPNDNSRequest $State 'info' '/api/dns/measurement');$State.Timer.Start();$W.Show();Update-RouterVPNDNSView $State
}
