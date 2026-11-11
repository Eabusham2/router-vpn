function Add-RouterVPNTelemetryWindowsShell {
    param([Parameter(Mandatory=$true)][string]$ProductSource)
    Set-StrictMode -Version Latest

    $killOld='<CheckBox Name="UnifiedKillSwitch" Grid.Column="1" Content="Kill switch" IsEnabled="False" VerticalAlignment="Center" Margin="14,0,0,0"/>'
    $killNew='<StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" Margin="10,0,0,0"><ComboBox Name="UnifiedFastestNode" Width="150" DisplayMemberPath="display" SelectedValuePath="id" ToolTip="Select the fastest measured node or a specific Router VPN node"/><TextBlock Name="UnifiedLiveLatency" Text="-- ms" FontFamily="Consolas" FontWeight="SemiBold" Foreground="#A8B6D5" VerticalAlignment="Center" Margin="8,0"/><CheckBox Name="UnifiedKillSwitch" Content="Kill switch" IsEnabled="False" VerticalAlignment="Center" Margin="4,0"/><Button Name="UnifiedForwardButton" Content="Forward ?" Margin="6,0,0,0" Padding="8,4" ToolTip="Real active-home forwarding master"/></StackPanel>'
    if(-not $ProductSource.Contains($killOld)){throw 'Windows telemetry connect-row contract drifted.'}
    $ProductSource=$ProductSource.Replace($killOld,$killNew)

    $multiOld='<ComboBox Name="UnifiedExitMode" Grid.Column="5" Margin="6,0,0,0"><ComboBoxItem Content="Shadowsocks" Tag="shadowsocks"/><ComboBoxItem Content="Hysteria2" Tag="hysteria2"/><ComboBoxItem Content="REALITY Vision" Tag="reality-vision"/><ComboBoxItem Content="PQ REALITY Vision" Tag="reality-pq-vision"/><ComboBoxItem Content="REALITY XHTTP" Tag="reality-xhttp"/><ComboBoxItem Content="Naive H2" Tag="naive-h2"/><ComboBoxItem Content="Naive H3" Tag="naive-h3"/><ComboBoxItem Content="WireGuard" Tag="wg"/><ComboBoxItem Content="AWG Fast" Tag="awg2-fast"/><ComboBoxItem Content="AWG Strong" Tag="awg2-strong"/><ComboBoxItem Content="SS/V2Ray" Tag="ss-v2ray"/><ComboBoxItem Content="Split" Tag="split"/><ComboBoxItem Content="MAX" Tag="max"/><ComboBoxItem Content="WG + PQ" Tag="wg-pq"/><ComboBoxItem Content="AWG + PQ" Tag="awg2-pq"/><ComboBoxItem Content="Complete MAX TLS / WG" Tag="max-tls-wg"/><ComboBoxItem Content="Complete MAX TLS / AWG" Tag="max-tls-awg"/><ComboBoxItem Content="Complete MAX QUIC / WG" Tag="max-quic-wg"/><ComboBoxItem Content="Complete MAX QUIC / AWG" Tag="max-quic-awg"/></ComboBox></Grid>'
    $multiNew=$multiOld+'<TextBlock Name="UnifiedMultihopLatency" Text="" FontFamily="Consolas" FontSize="11" Foreground="#A8B6D5" Margin="76,0,0,4"/>'
    if(-not $ProductSource.Contains($multiOld)){throw 'Windows telemetry multihop-row contract drifted.'}
    $ProductSource=$ProductSource.Replace($multiOld,$multiNew)

    $settingsOld='<StackPanel Grid.Column="2" Orientation="Horizontal"><Button Name="UnifiedSettingsButton" Content="Open settings" Padding="10,5"/><Button Name="UnifiedMtuButton" Content="Retest MTU" Margin="6,0,0,0" Padding="10,5"/></StackPanel>'
    $settingsNew='<StackPanel Grid.Column="2" Orientation="Horizontal"><Button Name="UnifiedSettingsButton" Content="Open settings" Padding="10,5"/><Button Name="UnifiedPerformanceButton" Content="Performance" Margin="6,0,0,0" Padding="10,5"/><Button Name="UnifiedMtuButton" Content="Retest MTU" Margin="6,0,0,0" Padding="10,5"/></StackPanel>'
    if(-not $ProductSource.Contains($settingsOld)){throw 'Windows telemetry settings-row contract drifted.'}
    $ProductSource=$ProductSource.Replace($settingsOld,$settingsNew)

    # Replace the legacy rectangular lat/lon renderer with an offline VPN globe.
    # Only coordinates explicitly stored in linked node data are plotted.
    $globe=@'
$script:UnifiedRoute=$null
$script:UnifiedRoutePacket=$null
$script:UnifiedMapPhase=0.0
$script:UnifiedRoutePathMs=0.0
function GlobeXY([double]$Lat,[double]$Lon,[double]$Width,[double]$Height){
 $cx=$Width/2;$cy=$Height/2;$rx=[Math]::Max(40.0,$Width/2-18);$ry=[Math]::Max(40.0,$Height/2-16)
 $latRad=$Lat*[Math]::PI/180.0
 $x=$cx+($Lon/180.0)*$rx*0.92*[Math]::Cos($latRad*0.55)
 $y=$cy-($Lat/90.0)*$ry*0.86
 return @($x,$y)
}
function AddGlobeLine($x1,$y1,$x2,$y2,[string]$Color,[double]$Thickness=1){
 $Line=New-Object Windows.Shapes.Line;$Line.X1=$x1;$Line.Y1=$y1;$Line.X2=$x2;$Line.Y2=$y2;$Line.Stroke=$Color;$Line.StrokeThickness=$Thickness;$Line.StrokeStartLineCap='Round';$Line.StrokeEndLineCap='Round';[void]$MapCanvas.Children.Add($Line);return $Line
}
function SelectUnifiedMapNode([string]$ID){try{Assert-RouterVPNMutationIdle 'selecting a node from the VPN globe';[void](Api '/api/profile/select' 'POST' @{id=$ID} 10);RefreshProduct;RefreshUnifiedTelemetry}catch{Log ('Map node select failed: '+$_.Exception.Message)}}
function DrawMap($Profiles,[string]$Selected){
 $MapCanvas.Children.Clear();$script:UnifiedRoute=$null;$script:UnifiedRoutePacket=$null
 $Width=[Math]::Max(420.0,[double]$MapCanvas.ActualWidth);$Height=[Math]::Max(190.0,[double]$MapCanvas.ActualHeight);$cx=$Width/2;$cy=$Height/2;$rx=[Math]::Max(40.0,$Width/2-15);$ry=[Math]::Max(40.0,$Height/2-14)
 $Ocean=New-Object Windows.Shapes.Ellipse;$Ocean.Width=$rx*2;$Ocean.Height=$ry*2;$Ocean.Fill='#102743';$Ocean.Stroke='#2D527E';$Ocean.StrokeThickness=2;[Windows.Controls.Canvas]::SetLeft($Ocean,$cx-$rx);[Windows.Controls.Canvas]::SetTop($Ocean,$cy-$ry);[void]$MapCanvas.Children.Add($Ocean)
 foreach($Lat in @(-60,-30,0,30,60)){$xyLat=GlobeXY $Lat 0 $Width $Height;$y=[double]$xyLat[1];$half=$rx*[Math]::Cos(($Lat*[Math]::PI/180.0)*0.78)*0.92;$LatColor=if($Lat -eq 0){'#436B98'}else{'#294866'};$LatThickness=if($Lat -eq 0){1.4}else{0.8};[void](AddGlobeLine ($cx-$half) $y ($cx+$half) $y $LatColor $LatThickness)}
 foreach($Lon in @(-120,-60,0,60,120)){$Arc=New-Object Windows.Shapes.Ellipse;$factor=[Math]::Max(.10,[Math]::Abs([Math]::Cos(($Lon*[Math]::PI/180.0))));$Arc.Width=[Math]::Max(8.0,$rx*2*$factor);$Arc.Height=$ry*2;$Arc.Stroke=if($Lon -eq 0){'#436B98'}else{'#294866'};$Arc.StrokeThickness=if($Lon -eq 0){1.3}else{0.8};$Arc.Fill='Transparent';[Windows.Controls.Canvas]::SetLeft($Arc,$cx-$Arc.Width/2);[Windows.Controls.Canvas]::SetTop($Arc,$cy-$ry);[void]$MapCanvas.Children.Add($Arc)}
 $Title=New-Object Windows.Controls.TextBlock;$Title.Text='ROUTER VPN GLOBE';$Title.Foreground='#8EA6C8';$Title.FontSize=11;$Title.FontWeight='SemiBold';[Windows.Controls.Canvas]::SetLeft($Title,18);[Windows.Controls.Canvas]::SetTop($Title,12);[void]$MapCanvas.Children.Add($Title)
 $Entry='';$Exit='';try{$MH=Api '/api/multihop/status' -Timeout 2;if([bool]$MH.connected){$Entry=[string]$MH.entry_id;$Exit=[string]$MH.exit_id}}catch{}
 $Points=@{};$Count=0
 foreach($Profile in @($Profiles)){
  try{$Lat=[Convert]::ToDouble($Profile.latitude,[Globalization.CultureInfo]::InvariantCulture);$Lon=[Convert]::ToDouble($Profile.longitude,[Globalization.CultureInfo]::InvariantCulture)}catch{continue}
  if($Lat -lt -90 -or $Lat -gt 90 -or $Lon -lt -180 -or $Lon -gt 180 -or ($Lat -eq 0 -and $Lon -eq 0)){continue}
  $xy=GlobeXY $Lat $Lon $Width $Height;$X=[double]$xy[0];$Y=[double]$xy[1];$ID=[string]$Profile.id;$Points[$ID]=@($X,$Y)
  $Kind=([string]$Profile.node_kind).ToLowerInvariant();$Role=if($ID -eq $Entry){'entry'}elseif($ID -eq $Exit){'exit'}elseif($ID -eq $Selected){'selected'}elseif($Kind -eq 'external'){'external'}else{'normal'}
  $Color=switch($Role){'entry'{'#3791FF'}'exit'{'#FF9A32'}'selected'{'#916CFF'}'external'{'#F25BAC'}default{'#48C7D6'}};$Size=if(@('entry','exit','selected') -contains $Role){16}else{12}
  $Dot=New-Object Windows.Shapes.Ellipse;$Dot.Width=$Size;$Dot.Height=$Size;$Dot.Fill=$Color;$Dot.Stroke='#EAF3FF';$Dot.StrokeThickness=1;$Dot.Tag=$ID;$Dot.Cursor='Hand';$Dot.ToolTip="$($Profile.name) • real stored coordinate $Lat,$Lon";[Windows.Controls.Canvas]::SetLeft($Dot,$X-$Size/2);[Windows.Controls.Canvas]::SetTop($Dot,$Y-$Size/2);$Dot.Add_MouseLeftButtonUp({param($sender,$event)SelectUnifiedMapNode ([string]$sender.Tag)});[void]$MapCanvas.Children.Add($Dot)
  $Ms=if([double]$Profile.latency_trimmed_mean_ms -gt 0){[double]$Profile.latency_trimmed_mean_ms}elseif([double]$Profile.latency_median_ms -gt 0){[double]$Profile.latency_median_ms}else{0};$Label=New-Object Windows.Controls.TextBlock;$Https=UnifiedLiveHTTPSForID $ID;$Label.Text=if($Https-gt0){'{0}  {1:N1} ms HTTPS'-f [string]$Profile.name,$Https}elseif($Ms -gt 0){'{0}  {1:N1} ms'-f [string]$Profile.name,$Ms}else{[string]$Profile.name};if($Https-gt0){$Label.Uid='live-https-node';$Label.DataContext=$Profile};$Label.Foreground='#E8F2FF';$Label.FontSize=11;$Label.Tag=$ID;$Label.Cursor='Hand';$Label.Add_MouseLeftButtonUp({param($sender,$event)SelectUnifiedMapNode ([string]$sender.Tag)});[Windows.Controls.Canvas]::SetLeft($Label,$X+$Size/2+4);[Windows.Controls.Canvas]::SetTop($Label,$Y-8);[void]$MapCanvas.Children.Add($Label);$Count++
 }
 if($Entry -and $Exit -and $Points.ContainsKey($Entry) -and $Points.ContainsKey($Exit)){$a=$Points[$Entry];$b=$Points[$Exit];$Route=AddGlobeLine $a[0] $a[1] $b[0] $b[1] '#59A7FF' 4;$Route.Opacity=.88;$Packet=New-Object Windows.Shapes.Ellipse;$Packet.Width=8;$Packet.Height=8;$Packet.Fill='White';$Packet.Stroke='#8FD3FF';$Packet.StrokeThickness=2;[void]$MapCanvas.Children.Add($Packet);$script:UnifiedRoute=[pscustomobject]@{x1=[double]$a[0];y1=[double]$a[1];x2=[double]$b[0];y2=[double]$b[1]};$script:UnifiedRoutePacket=$Packet;$PathLabel=New-Object Windows.Controls.TextBlock;$PathLabel.Text=if($script:UnifiedRoutePathMs -gt 0){'PATH {0:N1} ms'-f $script:UnifiedRoutePathMs}else{'LIVE MULTIHOP'};$PathLabel.Foreground='#CBE7FF';$PathLabel.FontSize=10;$PathLabel.FontFamily='Consolas';$PathLabel.Background='#AA0D1B31';$PathLabel.Padding='5,2';[Windows.Controls.Canvas]::SetLeft($PathLabel,(($a[0]+$b[0])/2)-28);[Windows.Controls.Canvas]::SetTop($PathLabel,(($a[1]+$b[1])/2)-22);[void]$MapCanvas.Children.Add($PathLabel)}
 if($Count -eq 0){$Empty=New-Object Windows.Controls.TextBlock;$Empty.Text='No real node coordinates in linked profiles';$Empty.Foreground='#AEBBD5';[Windows.Controls.Canvas]::SetLeft($Empty,20);[Windows.Controls.Canvas]::SetTop($Empty,40);[void]$MapCanvas.Children.Add($Empty)}
 $Privacy=New-Object Windows.Controls.TextBlock;$Privacy.Text='Only real stored coordinates • device location is never fabricated';$Privacy.Foreground='#7186A6';$Privacy.FontSize=9;[Windows.Controls.Canvas]::SetLeft($Privacy,18);[Windows.Controls.Canvas]::SetTop($Privacy,$Height-25);[void]$MapCanvas.Children.Add($Privacy)
}
function TickUnifiedMapAnimation{ExpireUnifiedLiveHTTPS;if($null -eq $script:UnifiedRoutePacket -or $null -eq $script:UnifiedRoute){return};$script:UnifiedMapPhase=($script:UnifiedMapPhase+.018)%1.0;$r=$script:UnifiedRoute;$x=$r.x1+($r.x2-$r.x1)*$script:UnifiedMapPhase;$y=$r.y1+($r.y2-$r.y1)*$script:UnifiedMapPhase;[Windows.Controls.Canvas]::SetLeft($script:UnifiedRoutePacket,$x-4);[Windows.Controls.Canvas]::SetTop($script:UnifiedRoutePacket,$y-4)}
'@
    $drawPattern='(?s)function DrawMap\(\$Profiles,\[string\]\$Selected\)\{.*?\}\r?\nfunction SessionEvents'
    if(-not [regex]::IsMatch($ProductSource,$drawPattern)){throw 'Windows globe renderer contract drifted.'}
    $ProductSource=[regex]::Replace($ProductSource,$drawPattern,[System.Text.RegularExpressions.MatchEvaluator]{ param($m) $globe+"`nfunction SessionEvents" },1)

    $startup='$BaseCombo.SelectedIndex=0'
    if(-not $ProductSource.Contains($startup)){throw 'Windows telemetry startup seam drifted.'}
    $telemetry=@'
$script:UnifiedLiveHTTPS=$null
function UnifiedLiveNumber($Object,[string]$Key){$V=ExternalComparisonValue $Object $Key;if($null-eq$V-or$V-is[bool]-or$V-is[string]){return [double]::NaN};try{return [double]$V}catch{return [double]::NaN}}
function ReadUnifiedLiveHTTPS($Value,[long]$Started,[long]$Now=[System.Diagnostics.Stopwatch]::GetTimestamp(),[long]$Wall=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()){
 if([string](ExternalComparisonValue $Value 'measurement')-cne'routed-https-response-after-tls'-or(ExternalComparisonValue $Value 'connected')-isnot[bool]-or-not(ExternalComparisonValue $Value 'connected')){return $null}
 $R=ExternalComparisonValue $Value 'response';$D=ExternalComparisonValue $R 'distribution'
 if($null-eq$R-or$null-eq$D-or@($R.PSObject.Properties).Count-ne5-or@($D.PSObject.Properties).Count-ne7-or(UnifiedLiveNumber $R 'schema')-ne1-or(UnifiedLiveNumber $R 'attempts')-ne3-or(UnifiedLiveNumber $D 'samples')-ne3-or[string](ExternalComparisonValue $R 'measurement')-cne'routed-https-response-after-tls'-or[string](ExternalComparisonValue $R 'endpoint')-cne'https://speed.cloudflare.com/__down?bytes=1'){return $null}
 $Binding=@{};foreach($Key in @('profile_id','profile_token','session_id','request_id','source_sha256','config_sha256','network_sha256')){$Text=ExternalComparisonValue $Value $Key;if($Text-isnot[string]-or-not$Text){return $null};$Length=if($Key-in@('session_id','request_id')){32}else{64};if($Key-ne'profile_id'-and-not(ExternalComparisonToken $Text $Length)){return $null};$Binding[$Key]=$Text}
 foreach($Key in @('median_ms','benchmark','idle','download','upload')){if(($Value-is[System.Collections.IDictionary]-and$Value.Contains($Key))-or($Value-isnot[System.Collections.IDictionary]-and$null-ne$Value.PSObject.Properties[$Key])){return $null}}
 $Numbers=@();foreach($Key in @('min_ms','median_ms','average_ms','p90_ms','max_ms','jitter_ms')){$N=UnifiedLiveNumber $D $Key;if([double]::IsNaN($N)-or[double]::IsInfinity($N)){return $null};$Numbers+=,$N}
 $Min,$Ms,$Avg,$P90,$Max,$Jitter=$Numbers;$At=UnifiedLiveNumber $Value 'measured_at';$Left=UnifiedLiveNumber $Value 'expires_in_ms'
 if([double]::IsNaN($At)-or[double]::IsNaN($Left)-or[double]::IsInfinity($At)-or[double]::IsInfinity($Left)-or$Min-le0-or$Min-gt$Ms-or$Ms-gt$P90-or$P90-gt$Max-or$Max-gt10000-or$Avg-lt$Min-or$Avg-gt$Max-or$Jitter-lt0-or$Jitter-gt($Max-$Min)-or$Left-le0-or$Left-gt10000-or$Wall-lt$At-or($Wall-$At)-ge10000-or$Now-lt$Started){return $null}
 $Frequency=[double][System.Diagnostics.Stopwatch]::Frequency;$Remaining=[Math]::Min($Left/1000-($Now-$Started)/$Frequency,(10000-($Wall-$At))/1000);if($Remaining-le0){return $null}
 return [pscustomobject]@{Binding=$Binding;Median=$Ms;Values=$Numbers;Deadline=([long]($Now+$Remaining*$Frequency))}
}
function TestUnifiedLiveHTTPSMatch($A,$B){if($null-eq$A-or$null-eq$B){return $false};foreach($Key in $A.Binding.Keys){if($A.Binding[$Key]-cne$B.Binding[$Key]){return $false}};return ($A.Values-join'|')-ceq($B.Values-join'|')}
function ClearUnifiedLiveHTTPS{
 $script:UnifiedLiveHTTPS=$null;(Control 'UnifiedLiveLatency').Text='-- ms'
 foreach($Item in @($MapCanvas.Children)){if($Item-is[Windows.Controls.TextBlock]-and$Item.Uid-eq'live-https-node'){$Item.Text=[string]$Item.DataContext.name;$Item.Uid=''}}
}
function ExpireUnifiedLiveHTTPS{if($null-ne$script:UnifiedLiveHTTPS-and[System.Diagnostics.Stopwatch]::GetTimestamp()-ge$script:UnifiedLiveHTTPS.Deadline){ClearUnifiedLiveHTTPS}}
function UnifiedLiveHTTPSForID([string]$ID){$R=$script:UnifiedLiveHTTPS;if($null-ne$R-and$R.Binding.profile_id-ceq$ID-and[string]$RouterCombo.SelectedValue-ceq$ID-and[System.Diagnostics.Stopwatch]::GetTimestamp()-lt$R.Deadline-and-not(UnifiedAsyncBusy)){return $R.Median};return 0.0}
$script:UnifiedTelemetrySync=$false
$script:UnifiedForwardSync=$false
function ApplyUnifiedFastestStore($Store){
 $Values=New-Object System.Collections.ArrayList;[void]$Values.Add([pscustomobject]@{id='fastest';display='⚡ Fastest Router · 50 TCP samples'})
 [void]$Values.Add([pscustomobject]@{id='external-comparison';display='External paths · 50 responses…'})
 $Routers=@($Store.profiles|Where-Object{(([string]$_.node_kind).ToLowerInvariant() -ne 'external')}|Sort-Object @{Expression={if([double]$_.latency_trimmed_mean_ms -gt 0){[double]$_.latency_trimmed_mean_ms}else{[double]::PositiveInfinity}}},name)
 foreach($P in $Routers){$Ms=[double]$P.latency_trimmed_mean_ms;$Label=if($Ms -gt 0){'{0}  {1:N1} ms'-f [string]$P.name,$Ms}else{[string]$P.name};[void]$Values.Add([pscustomobject]@{id=[string]$P.id;display=$Label})}
 $Preferred=[string]$Store.selected_id;$Known=@($Values|Where-Object{[string]$_.id -eq $Preferred}).Count -gt 0;if(-not $Preferred -or -not $Known){$Preferred='fastest'}
 $script:UnifiedTelemetrySync=$true;(Control 'UnifiedFastestNode').ItemsSource=@($Values);(Control 'UnifiedFastestNode').SelectedValue=$Preferred;$script:UnifiedTelemetrySync=$false
}
$script:UnifiedTelemetryClient=New-RouterVPNControllerClient -TimeoutMilliseconds 12000 -ResponseLimit 2097152
$script:UnifiedTelemetryClient.Timeout=[System.Threading.Timeout]::InfiniteTimeSpan
$script:UnifiedTelemetryTasks=@{}
$script:UnifiedTelemetryRequests=@{}
$script:UnifiedTelemetryCts=$null
$script:UnifiedTelemetryDiscard=$false
$script:UnifiedTelemetryPending=$null
$script:UnifiedTelemetryOriginal=$null
$script:UnifiedTelemetryStarted=[long]0
$script:UnifiedTelemetryPoller=New-Object Windows.Threading.DispatcherTimer
$script:UnifiedTelemetryPoller.Interval=[TimeSpan]::FromMilliseconds(100)
function UnifiedTelemetryBusy{return $script:UnifiedTelemetryTasks.Count -gt 0}
function CancelUnifiedTelemetryRefreshAsync{
 ClearUnifiedLiveHTTPS;if(-not(UnifiedTelemetryBusy)){return $false};$script:UnifiedTelemetryDiscard=$true;try{$script:UnifiedTelemetryCts.Cancel()}catch{};return $true
}
function StartUnifiedTelemetryRefresh{
 ExpireUnifiedLiveHTTPS;if((UnifiedTelemetryBusy)-or(UnifiedAsyncBusy)-or@($Window.OwnedWindows|Where-Object{$_.IsVisible}).Count-gt0){return}
 $script:UnifiedTelemetryTasks=@{};$script:UnifiedTelemetryRequests=@{};$script:UnifiedTelemetryDiscard=$false;$script:UnifiedTelemetryPending=$null;$script:UnifiedTelemetryOriginal=$null;$script:UnifiedTelemetryStarted=[System.Diagnostics.Stopwatch]::GetTimestamp()
 $script:UnifiedTelemetryCts=[System.Threading.CancellationTokenSource]::new();$script:UnifiedTelemetryCts.CancelAfter([TimeSpan]::FromSeconds(12))
 $Specs=[ordered]@{status=@('GET','/api/status',$null);profiles=@('GET','/api/profiles',$null);live=@('GET','/api/connection/live-latency',$null);forward=@('GET','/api/forwarding/master',$null)}
 try{
  if((Control 'UnifiedMultihop').IsChecked){
   $Entry=[string]$MultihopEntryCombo.SelectedValue;$Exit=[string]$MultihopExitCombo.SelectedValue
   if($Entry-and$Exit-and$Entry-ne$Exit){$Specs.multihop=@('POST','/api/multihop/live-latency',@{entry_id=$Entry;exit_id=$Exit;samples=2})}
  }else{(Control 'UnifiedMultihopLatency').Text=''}
  foreach($Key in $Specs.Keys){
   $Verb=if($Specs[$Key][0]-eq'POST'){[System.Net.Http.HttpMethod]::Post}else{[System.Net.Http.HttpMethod]::Get}
   $Req=[System.Net.Http.HttpRequestMessage]::new($Verb,([string]$BaseUrl)+[string]$Specs[$Key][1])
   if($null-ne$Specs[$Key][2]){$Json=$Specs[$Key][2]|ConvertTo-Json -Depth 12 -Compress;$Req.Content=[System.Net.Http.StringContent]::new($Json,[System.Text.Encoding]::UTF8,'application/json')}
   $script:UnifiedTelemetryRequests[$Key]=$Req;$script:UnifiedTelemetryTasks[$Key]=$script:UnifiedTelemetryClient.SendAsync($Req,$script:UnifiedTelemetryCts.Token)
  }
  $script:UnifiedTelemetryPoller.Start()
 }catch{[void](CancelUnifiedTelemetryRefreshAsync)}
}
function CompleteUnifiedTelemetryRefresh{
 if(-not(UnifiedTelemetryBusy)){return};foreach($Task in $script:UnifiedTelemetryTasks.Values){if(-not$Task.IsCompleted){return}}
 $Discard=$script:UnifiedTelemetryDiscard;$Validating=$null-ne$script:UnifiedTelemetryPending;$Payload=if($Validating){$script:UnifiedTelemetryPending}else{@{}};$Responses=@();$Checked=$null;$LiveReceipt=$null;$NextRequestID="";$script:UnifiedTelemetryPoller.Stop()
 try{
  foreach($Key in @($script:UnifiedTelemetryTasks.Keys)){
   try{
    $Resp=$script:UnifiedTelemetryTasks[$Key].GetAwaiter().GetResult();$Responses+=$Resp;$Text=$Resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    if($Resp.IsSuccessStatusCode-and-not[string]::IsNullOrWhiteSpace($Text)){if($Key-eq'validation'){$Checked=$Text|ConvertFrom-Json}else{$Payload[$Key]=$Text|ConvertFrom-Json}}
   }catch{}
  }
  if(-not$Discard-and$null-ne$Payload.live-and$null-ne(ExternalComparisonValue $Payload.live 'measurement')){
   if($Validating){$LiveReceipt=ReadUnifiedLiveHTTPS $Checked $script:UnifiedTelemetryStarted;if(-not(TestUnifiedLiveHTTPSMatch $script:UnifiedTelemetryOriginal $LiveReceipt)){$LiveReceipt=$null;[void]$Payload.Remove('live')}else{$Payload.live=$Checked}}
   else{$First=ReadUnifiedLiveHTTPS $Payload.live $script:UnifiedTelemetryStarted;if($null-ne$First){$NextRequestID=$First.Binding.request_id;$script:UnifiedTelemetryPending=$Payload;$script:UnifiedTelemetryOriginal=$First}else{[void]$Payload.Remove('live')}}
  }
  if(-not$Discard-and-not$NextRequestID){
   if($Payload.profiles){ApplyUnifiedFastestStore $Payload.profiles}
   try{(Control 'UnifiedFastestNode').IsEnabled=($Payload.status-and-not$script:UnifiedProtectionPending-and-not(Test-RouterVPNMutationBusyFromStatus $Payload.status))}catch{(Control 'UnifiedFastestNode').IsEnabled=$false}
   if($null-ne$LiveReceipt-and[string]$RouterCombo.SelectedValue-ceq$LiveReceipt.Binding.profile_id-and$Window.IsVisible-and@($Window.OwnedWindows|Where-Object{$_.IsVisible}).Count-eq0-and[System.Diagnostics.Stopwatch]::GetTimestamp()-lt$LiveReceipt.Deadline-and-not(UnifiedAsyncBusy)){$script:UnifiedLiveHTTPS=$LiveReceipt;$script:UnifiedRoutePathMs=0.0;(Control 'UnifiedLiveLatency').Text=('{0:N1} ms HTTPS'-f$LiveReceipt.Median);(Control 'UnifiedLiveLatency').ToolTip='3 HTTPS responses through the current proved VPN and selected DNS, timed after DNS/TCP/TLS preparation. Expires after 10 seconds; separate from ICMP, private-node RTT and saved50.';(Control 'UnifiedLiveLatency').Foreground='#E8ECF8'}elseif($Payload.live-and$null-eq(ExternalComparisonValue $Payload.live 'measurement')){ClearUnifiedLiveHTTPS;$script:UnifiedRoutePathMs=[double]$Payload.live.median_ms;(Control 'UnifiedLiveLatency').Text=('{0:N1} ms'-f[double]$Payload.live.median_ms);(Control 'UnifiedLiveLatency').ToolTip='HTTP RTT through the current private Router-node path.';(Control 'UnifiedLiveLatency').Foreground='#E8ECF8'}else{ClearUnifiedLiveHTTPS;$script:UnifiedRoutePathMs=0.0;(Control 'UnifiedLiveLatency').Foreground='#A8B6D5'}
   if($Payload.multihop){$Bits=@();if($Payload.multihop.entry){$Bits+=('IN {0:N1}'-f[double]$Payload.multihop.entry.median_ms)};if($Payload.multihop.exit){$Bits+=('OUT {0:N1}'-f[double]$Payload.multihop.exit.median_ms)};if($Payload.multihop.current_path){$script:UnifiedRoutePathMs=[double]$Payload.multihop.current_path.median_ms;$Bits+=('PATH {0:N1} ms'-f[double]$Payload.multihop.current_path.median_ms)};(Control 'UnifiedMultihopLatency').Text=($Bits-join' • ')}
   if($Payload.forward){$script:UnifiedForwardSync=$true;(Control 'UnifiedForwardButton').Content=if([bool]$Payload.forward.enabled){'Forward ON'}else{'Forward OFF'};(Control 'UnifiedForwardButton').Tag=[bool]$Payload.forward.enabled;(Control 'UnifiedForwardButton').ToolTip='Real server forwarding master on '+[string]$Payload.forward.name;$script:UnifiedForwardSync=$false}else{$script:UnifiedForwardSync=$true;(Control 'UnifiedForwardButton').Content='Forward ?';(Control 'UnifiedForwardButton').Tag=$null;(Control 'UnifiedForwardButton').ToolTip='Connect a Router VPN home-node path to control the real server forwarding master';$script:UnifiedForwardSync=$false}
  }
 }finally{
  foreach($Resp in $Responses){try{$Resp.Dispose()}catch{}};foreach($Req in $script:UnifiedTelemetryRequests.Values){try{$Req.Dispose()}catch{}};try{$script:UnifiedTelemetryCts.Dispose()}catch{}
  $script:UnifiedTelemetryTasks=@{};$script:UnifiedTelemetryRequests=@{};$script:UnifiedTelemetryCts=$null;$script:UnifiedTelemetryDiscard=$false
 }
 if($NextRequestID-and-not$Discard){
  try{$script:UnifiedTelemetryCts=[System.Threading.CancellationTokenSource]::new();$script:UnifiedTelemetryCts.CancelAfter([TimeSpan]::FromSeconds(3));$Req=[System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get,([string]$BaseUrl)+'/api/connection/live-latency?request_id='+$NextRequestID);$script:UnifiedTelemetryRequests.validation=$Req;$script:UnifiedTelemetryTasks.validation=$script:UnifiedTelemetryClient.SendAsync($Req,$script:UnifiedTelemetryCts.Token);$script:UnifiedTelemetryPoller.Start()}catch{$script:UnifiedTelemetryPending=$null;$script:UnifiedTelemetryOriginal=$null;[void](CancelUnifiedTelemetryRefreshAsync)}
 }else{$script:UnifiedTelemetryPending=$null;$script:UnifiedTelemetryOriginal=$null}
}
$script:UnifiedTelemetryPoller.Add_Tick({CompleteUnifiedTelemetryRefresh})
function RefreshUnifiedFastestChoices{StartUnifiedTelemetryRefresh}
function RefreshUnifiedForwardingMaster{StartUnifiedTelemetryRefresh}
function ToggleUnifiedForwardingMaster{
 if($script:UnifiedForwardSync){return};if(UnifiedAsyncBusy){Log 'Forwarding change refused: another Router VPN action is running.';return}
 $Current=(Control 'UnifiedForwardButton').Tag;if($null-eq$Current){Log 'Forwarding state is not proved yet; refreshing status first.';RefreshUnifiedTelemetry;return}
 $Want=-not[bool]$Current;(Control 'UnifiedForwardButton').Content='Forward …'
 $Success={param($R)if([bool]$R.enabled-ne$Want){Log 'Forwarding master response did not verify requested state.';return};$script:UnifiedForwardSync=$true;(Control 'UnifiedForwardButton').Tag=[bool]$R.enabled;(Control 'UnifiedForwardButton').Content=if([bool]$R.enabled){'Forward ON'}else{'Forward OFF'};$script:UnifiedForwardSync=$false;$StateLabel=if($Want){'ON'}else{'OFF'};Log ('Forwarding master '+$StateLabel+' on '+[string]$R.name)}.GetNewClosure()
 [void](StartUnifiedApiAsync 'Updating forwarding…' '/api/forwarding/master' 'PUT' @{enabled=$Want} 10 $Success {param($E)Log ('Forwarding master failed: '+$E)} {RefreshUnifiedTelemetry})
}
function RefreshUnifiedTelemetry{StartUnifiedTelemetryRefresh}
function ExternalComparisonValue($Object,[string]$Name){
 if($null-eq$Object){return $null};if($Object -is [System.Collections.IDictionary]){return $Object[$Name]};$P=$Object.PSObject.Properties[$Name];if($null-eq$P){return $null};return $P.Value
}
function ExternalComparisonToken($Value,[int]$Length){$Text=[string]$Value;return $Text.Length-eq$Length-and$Text-cmatch'\A[0-9a-f]+\z'}
function ExternalComparisonMatches($Value,[string]$Request,[string]$Cohort){return (ExternalComparisonToken (ExternalComparisonValue $Value 'request_id') 32)-and(ExternalComparisonToken (ExternalComparisonValue $Value 'cohort_id') 64)-and([string](ExternalComparisonValue $Value 'request_id')-ceq$Request)-and([string](ExternalComparisonValue $Value 'cohort_id')-ceq$Cohort)}
function ExternalComparisonScore($Row){
 if([string](ExternalComparisonValue $Row 'status')-cne'complete'){return $null};$B=ExternalComparisonValue $Row 'benchmark';$D=ExternalComparisonValue $B 'distribution'
 if($null-eq$B-or$null-eq$D-or([int](ExternalComparisonValue $B 'schema'))-ne1-or([string](ExternalComparisonValue $B 'measurement'))-cne'routed-https-response-after-tls'-or([string](ExternalComparisonValue $B 'endpoint'))-cne'https://speed.cloudflare.com/__down?bytes=1'-or([int](ExternalComparisonValue $B 'attempts'))-ne50-or([int](ExternalComparisonValue $B 'failed'))-ne0-or([int](ExternalComparisonValue $D 'samples'))-ne50){return $null}
 try{$Score=[double](ExternalComparisonValue $B 'trimmed_mean_ms')}catch{return $null};if([double]::IsNaN($Score)-or[double]::IsInfinity($Score)-or$Score-le0){return $null};return $Score
}
function ExternalComparisonRows($Rows,[bool]$Historical){
 $Lines=New-Object System.Collections.Generic.List[string];$Heading=if($Historical){'Saved history — these values are not a current winner.'}else{'50 routed HTTPS responses · 10% trimmed mean'};$Lines.Add($Heading)
 foreach($Row in @($Rows)){
  if($null-eq$Row){continue};$Name=[string](ExternalComparisonValue $Row 'name');if(-not$Name){$Name=[string](ExternalComparisonValue $Row 'id')};$Entry=[string](ExternalComparisonValue $Row 'entry_name');if(-not$Entry){$Entry=[string](ExternalComparisonValue $Row 'entry_id')};$Route=if($Entry){'Via '+$Entry}else{'Direct saved path'};$Score=ExternalComparisonScore $Row
  if($null-ne$Score){$Lines.Add(('{0} · {1} · {2} · {3:N2} ms'-f$Name,$Route,[string](ExternalComparisonValue $Row 'execution'),$Score))}else{$State=[string](ExternalComparisonValue $Row 'failure');if(-not$State){$State=[string](ExternalComparisonValue $Row 'status')};$Lines.Add($Name+' · '+$Route+' · '+$State)}
 }
 return ($Lines-join"`n")
}
function ExternalComparisonState($Value){
 $Text=([string](ExternalComparisonValue $Value 'stage')).Replace('-',' ');$Progress=[string](ExternalComparisonValue $Value 'progress');if($Progress){$Text+=' · '+$Progress}
 if([bool](ExternalComparisonValue $Value 'complete')){if([bool](ExternalComparisonValue $Value 'committed')){if([string](ExternalComparisonValue $Value 'stage')-ceq'connected'){$Text+="`nThe freshly proved winner is connected and selected."}else{$Text+="`nThe winner selection was saved. Check the current connection status."}}elseif([bool](ExternalComparisonValue $Value 'restored')){$Text+="`nYour original connection state was restored."}else{$Text+="`nRestoration is unresolved; check the main connection status."};if(-not[bool](ExternalComparisonValue $Value 'drained')){$Text+="`nCleanup is pending. Retry Cancel."}}
 foreach($Key in @('failure','warning')){$Note=[string](ExternalComparisonValue $Value $Key);if($Note){$Text+="`n"+$Note}};return $Text
}
function SetExternalComparisonControls($S){$Idle=$null-eq$S.Task-and(-not$S.Started-or$S.Finished);$S.Compare.IsEnabled=$Idle;$S.Fastest.IsEnabled=$Idle;$S.Cancel.IsEnabled=$S.Started-and-not$S.Finished}
function StartExternalComparisonRequest($S,[string]$Phase,[string]$Path,$Body=$null){
 if($S.Closed-or$null-ne$S.Task){return}
 $S.Phase=$Phase;$S.Request=$null;$S.Cts=$null
 try{
  $Verb=if($null-eq$Body){[System.Net.Http.HttpMethod]::Get}else{[System.Net.Http.HttpMethod]::Post}
  $S.Request=[System.Net.Http.HttpRequestMessage]::new($Verb,([string]$BaseUrl).TrimEnd('/')+$Path);Set-RouterVPNControllerRequestTimeout $S.Request 10000
  if($null-ne$Body){$S.Request.Content=[System.Net.Http.StringContent]::new(($Body|ConvertTo-Json -Depth 6 -Compress),[System.Text.Encoding]::UTF8,'application/json')}
  $S.Cts=[System.Threading.CancellationTokenSource]::new();$S.Cts.CancelAfter([TimeSpan]::FromSeconds(10));$S.Task=$S.Client.SendAsync($S.Request,$S.Cts.Token)
 }catch{
  if($null-ne$S.Request){$S.Request.Dispose()};if($null-ne$S.Cts){$S.Cts.Dispose()};$S.Request=$null;$S.Cts=$null;$S.Task=$null
  $S.Status.Text='Comparison request failed: '+$_.Exception.Message;if($S.Started-and-not$S.Finished){$S.CancelWanted=$true;$S.CancelAccepted=$false};$S.Next=[DateTime]::UtcNow.AddSeconds(1)
 }
 SetExternalComparisonControls $S
}
function ReceiveExternalComparison($S,$Value,[string]$Phase){
 if($Phase-ceq'offer'){
  $Request=[string](ExternalComparisonValue $Value 'request_id');$Cohort=[string](ExternalComparisonValue $Value 'cohort_id');$Candidates=@((ExternalComparisonValue $Value 'candidates')|Where-Object{$null-ne$_})
  if(-not(ExternalComparisonToken $Request 32)-or-not(ExternalComparisonToken $Cohort 64)-or$Candidates.Count-lt1-or$Candidates.Count-gt128){$S.Status.Text='Saved external paths could not be captured. Refresh and try again.';$S.Choice=$null;return}
  $S.RequestID=$Request;$S.CohortID=$Cohort;$Lines=@();foreach($Row in $Candidates){$Entry=if([bool](ExternalComparisonValue $Row 'has_entry')){[string](ExternalComparisonValue $Row 'entry_id')}else{'Direct'};$Lines+=([string](ExternalComparisonValue $Row 'name')+' · '+$Entry+' · '+[string](ExternalComparisonValue $Row 'protocol'))};$S.Result.Text=$Lines-join"`n"
  $History=ExternalComparisonValue (ExternalComparisonValue $Value 'history') 'rows';if(@($History).Count-gt0){$S.Result.Text+="`n`n"+(ExternalComparisonRows $History $true)}
  $S.Status.Text=([string]$Candidates.Count)+' saved external paths. Compare, or explicitly compare and connect the winner.';$Warning=[string](ExternalComparisonValue $Value 'warning');if($Warning){$S.Status.Text+="`n"+$Warning}
  if($null-ne$S.Choice-and-not$S.CloseWanted){$S.Started=$true;$S.Finished=$false;StartExternalComparisonRequest $S 'start' '/api/speed-lab/external-comparison' @{request_id=$S.RequestID;cohort_id=$S.CohortID;connect_fastest=[bool]$S.Choice}}
  return
 }
 if(-not(ExternalComparisonMatches $Value $S.RequestID $S.CohortID)){$S.Status.Text='A response belongs to another comparison. Result discarded; cancelling only the captured request.';$S.CancelWanted=$true;$S.CancelAccepted=$false;return}
 if($Phase-ceq'cancel'){$S.CancelAccepted=$true}
 $S.Status.Text=ExternalComparisonState $Value;$S.Result.Text=ExternalComparisonRows (ExternalComparisonValue $Value 'rows') $false
 $S.Finished=[bool](ExternalComparisonValue $Value 'complete')-and[bool](ExternalComparisonValue $Value 'drained')
 if($S.Finished){$S.Choice=$null;RefreshProduct;RefreshUnifiedTelemetry}elseif([bool](ExternalComparisonValue $Value 'complete')){$S.CancelWanted=$true;$S.CancelAccepted=$false}
}
function TickExternalComparison($S){
 if($S.Closed){return}
 if($null-ne$S.Task-and$S.Task.IsCompleted){
  $Value=$null;$Failure='';$Phase=$S.Phase;$Resp=$null
  try{$Resp=$S.Task.GetAwaiter().GetResult();$Text=$Resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();if(-not$Resp.IsSuccessStatusCode){throw ('HTTP '+[int]$Resp.StatusCode+' '+$Text)};$Value=$Text|ConvertFrom-Json}catch{$Failure=$_.Exception.Message}
  finally{if($null-ne$Resp){$Resp.Dispose()};if($null-ne$S.Request){$S.Request.Dispose()};if($null-ne$S.Cts){$S.Cts.Dispose()};$S.Task=$null;$S.Request=$null;$S.Cts=$null}
  $S.Next=[DateTime]::UtcNow.AddMilliseconds(650)
  if($Failure){$S.Status.Text='Comparison request failed: '+$Failure;if($S.Started-and-not$S.Finished){$S.CancelWanted=$true;$S.CancelAccepted=$false;$S.Status.Text+="`nCancellation will be retried; cleanup is not confirmed."}else{$S.Choice=$null}}else{ReceiveExternalComparison $S $Value $Phase}
 }
 if($S.CloseWanted-and$null-eq$S.Task-and(-not$S.Started-or$S.Finished)){$S.AllowClose=$true;$S.Dialog.Close();return}
 if($null-eq$S.Task-and$S.Started-and-not$S.Finished-and[DateTime]::UtcNow-ge$S.Next){
  if($S.CancelWanted-and-not$S.CancelAccepted){StartExternalComparisonRequest $S 'cancel' '/api/speed-lab/external-comparison/cancel' @{request_id=$S.RequestID;cohort_id=$S.CohortID}}else{StartExternalComparisonRequest $S 'poll' ('/api/speed-lab/external-comparison?request_id='+$S.RequestID)}
 }
 SetExternalComparisonControls $S
}
function ShowExternalComparison{
 if($null-ne(Get-Variable RouterVPNExternalComparison -Scope Script -ErrorAction SilentlyContinue)-and$null-ne$script:RouterVPNExternalComparison-and-not$script:RouterVPNExternalComparison.Closed){[void]$script:RouterVPNExternalComparison.Dialog.Activate();return}
 [xml]$X=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Compare external paths" Width="850" Height="570" MinWidth="660" MinHeight="440" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF"><Grid Margin="18"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Find the fastest saved external path" FontSize="23" FontWeight="Bold"/><TextBlock Grid.Row="1" Margin="0,10" TextWrapping="Wrap" Foreground="#A8B6D5" Text="Each saved path keeps its own entry, DNS and protection. Every valid path sends 50 HTTPS responses through its proved exit to the same Cloudflare endpoint. Timing starts after TLS; lowest 10% trimmed mean wins. Router TCP reachability is separate. Compare restores your original connection between trials; connecting the winner requires the explicit second action."/><TextBlock Name="Status" Grid.Row="2" Margin="0,4,0,10" TextWrapping="Wrap" Text="Loading saved external paths…"/><TextBox Name="Result" Grid.Row="3" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Background="#101A2B" Foreground="#E8ECF8" Padding="10"/><WrapPanel Grid.Row="4" Margin="0,12,0,0"><Button Name="Compare" Content="Compare external paths" Margin="4" Padding="10,6"/><Button Name="Fastest" Content="Compare + connect fastest" Margin="4" Padding="10,6"/><Button Name="Cancel" Content="Cancel" Margin="4" Padding="10,6"/><Button Name="Close" Content="Close" Margin="4" Padding="10,6"/></WrapPanel></Grid></Window>
"@
 $Reader=New-Object System.Xml.XmlNodeReader $X;$D=[Windows.Markup.XamlReader]::Load($Reader);$D.Owner=$Window
 $S=@{Dialog=$D;Status=$D.FindName('Status');Result=$D.FindName('Result');Compare=$D.FindName('Compare');Fastest=$D.FindName('Fastest');Cancel=$D.FindName('Cancel');Client=(New-RouterVPNControllerClient -TimeoutMilliseconds 10000 -ResponseLimit 2097152);Task=$null;Request=$null;Cts=$null;Phase='';Choice=$null;RequestID='';CohortID='';Started=$false;Finished=$true;CancelWanted=$false;CancelAccepted=$false;CloseWanted=$false;AllowClose=$false;Closed=$false;Next=[DateTime]::UtcNow;Timer=(New-Object Windows.Threading.DispatcherTimer)}
 $S.Client.Timeout=[System.Threading.Timeout]::InfiniteTimeSpan;$script:RouterVPNExternalComparison=$S
 $Begin={param([bool]$Connect)if($null-ne$S.Task-or($S.Started-and-not$S.Finished)){return};try{Assert-RouterVPNMutationIdle 'comparing saved external paths'}catch{$S.Status.Text=$_.Exception.Message;return};$S.Choice=$Connect;$S.Started=$false;$S.Finished=$true;$S.CancelWanted=$false;$S.CancelAccepted=$false;$S.Status.Text='Capturing current saved paths…';StartExternalComparisonRequest $S 'offer' '/api/speed-lab/external-comparison'}.GetNewClosure()
 $S.Compare.Add_Click({&$Begin $false}.GetNewClosure());$S.Fastest.Add_Click({&$Begin $true}.GetNewClosure())
 $S.Cancel.Add_Click({$S.CancelWanted=$true;$S.CancelAccepted=$false;$S.Status.Text='Cancelling this comparison; waiting for workers and original-state restoration.';TickExternalComparison $S}.GetNewClosure())
 $D.FindName('Close').Add_Click({$S.Dialog.Close()}.GetNewClosure())
 $D.Add_Closing({param($sender,$e)if($S.AllowClose){return};if($null-ne$S.Task-or($S.Started-and-not$S.Finished)){$e.Cancel=$true;$S.CloseWanted=$true;$S.CancelWanted=$true;$S.CancelAccepted=$false;if(-not$S.Started-and$null-ne$S.Cts){$S.Cts.Cancel()};$S.Status.Text='Closing after this comparison drains and restoration finishes.'}}.GetNewClosure())
 $D.Add_Closed({$S.Closed=$true;$S.Timer.Stop();if($null-ne$S.Cts){$S.Cts.Cancel();$S.Cts.Dispose()};if($null-ne$S.Request){$S.Request.Dispose()};$S.Client.Dispose()}.GetNewClosure())
 $S.Timer.Interval=[TimeSpan]::FromMilliseconds(200);$S.Timer.Add_Tick({TickExternalComparison $S}.GetNewClosure());$S.Timer.Start();StartExternalComparisonRequest $S 'offer' '/api/speed-lab/external-comparison';$D.Show()
}

$script:UnifiedPerformancePanel=$null
function UnifiedPerformanceOwned($State,$Token){
 return -not$State.Closed-and[object]::ReferenceEquals($State.Current,$Token)-and[object]::ReferenceEquals($State.Task,$script:UnifiedAsyncTask)
}
function SetUnifiedPerformanceIdle($State){
 if($State.Closed){return};foreach($B in $State.Buttons){$B.IsEnabled=$true};$State.Cancel.IsEnabled=$false
}
function CancelUnifiedPerformance($State){
 $State.Pending=$null;$State.Timer.Stop()
 if($null-ne$State.Current-and$null-ne$State.Task-and[object]::ReferenceEquals($State.Task,$script:UnifiedAsyncTask)-and(UnifiedAsyncBusy)){
  [void](CancelUnifiedApiAsync $false)
  if(-not$State.Closed){$State.Result.Text='Cancelling this request; controller cleanup may still be pending.'}
 }elseif($null-eq$State.Current){SetUnifiedPerformanceIdle $State}
}
function CloseUnifiedPerformance($State){
 $State.Closed=$true;CancelUnifiedPerformance $State
 # The actual async owner retains the request and callbacks until completion.
 if($null-eq$State.Current-and[object]::ReferenceEquals($script:UnifiedPerformancePanel,$State)){$script:UnifiedPerformancePanel=$null}
}
function FinishUnifiedPerformanceRequest($State,$Token){
 if(-not[object]::ReferenceEquals($State.Current,$Token)){return}
 $State.Current=$null;$State.Task=$null
 if($State.Closed){$State.Pending=$null;if([object]::ReferenceEquals($script:UnifiedPerformancePanel,$State)){$script:UnifiedPerformancePanel=$null};return}
 if($null-ne$State.Pending){$State.Timer.Start()}else{SetUnifiedPerformanceIdle $State}
}
function StartUnifiedPerformanceRequest($State,[string]$Label,[string]$Path,$Body,[int]$Timeout,[int]$Depth,[bool]$RefreshAfter,[bool]$HopPreflight=$false){
 if($State.Closed-or$null-ne$State.Current-or$null-ne$State.Pending){return $false}
 if(UnifiedAsyncBusy){$State.Result.Text='Another Router VPN action is still running.';return $false}
 $Token=[object]::new();$State.Current=$Token;$State.Task=$null
 foreach($B in $State.Buttons){$B.IsEnabled=$false};$State.Cancel.IsEnabled=$true;$State.Result.Text=$Label
 $Success={param($R)
  if(-not(UnifiedPerformanceOwned $State $Token)){return}
  if($HopPreflight){
   $connected=$R.PSObject.Properties['connected'];$entry=$R.PSObject.Properties['entry_id'];$exit=$R.PSObject.Properties['exit_id']
   if($null-eq$connected-or$connected.Value-isnot[bool]-or-not$connected.Value-or$null-eq$entry-or$null-eq$exit-or$entry.Value-isnot[string]-or$exit.Value-isnot[string]-or[string]::IsNullOrWhiteSpace($entry.Value)-or[string]::IsNullOrWhiteSpace($exit.Value)-or$entry.Value-ceq$exit.Value){throw 'Connect an actual multihop graph with different entry and exit nodes first.'}
   # Capture this status response once. The controller revalidates the active
   # graph on POST and throughout measurement; GET/POST is not atomic.
   $State.Pending=@{entry_id=[string]$entry.Value;exit_id=[string]$exit.Value;bytes=4194304}
   $State.Result.Text='Active multihop captured; waiting for the status request to retire…'
  }else{$State.Result.Text=($R|ConvertTo-Json -Depth $Depth);if($RefreshAfter){RefreshProduct}}
 }.GetNewClosure()
 $Failure={param($E)if(UnifiedPerformanceOwned $State $Token){$State.Result.Text=$E}}.GetNewClosure()
 $Finally={FinishUnifiedPerformanceRequest $State $Token}.GetNewClosure()
 $Method=if($HopPreflight){'GET'}else{'POST'}
 $Started=StartUnifiedApiAsync $Label $Path $Method $Body $Timeout $Success $Failure $Finally
 if($Started-and[object]::ReferenceEquals($State.Current,$Token)){$State.Task=$script:UnifiedAsyncTask;if($State.Closed){CancelUnifiedPerformance $State}}
 if(-not$Started-and[object]::ReferenceEquals($State.Current,$Token)){$State.Current=$null;$State.Task=$null;SetUnifiedPerformanceIdle $State}
 return $Started
}
function ContinueUnifiedPerformanceHop($State){
 $State.Timer.Stop();$Body=$State.Pending;$State.Pending=$null
 if($State.Closed-or$null-eq$Body){return}
 if($null-ne$State.Current-or(UnifiedAsyncBusy)){$State.Result.Text='The captured hop request was superseded by another action. Run it again.';if($null-eq$State.Current){SetUnifiedPerformanceIdle $State};return}
 [void](StartUnifiedPerformanceRequest $State 'Testing routed hop speeds…' '/api/multihop/speed-test' $Body 70 10 $false)
}
function ShowUnifiedPerformance{
 if($null-ne$script:UnifiedPerformancePanel){if(-not$script:UnifiedPerformancePanel.Closed){[void]$script:UnifiedPerformancePanel.Dialog.Activate();return};if($null-ne$script:UnifiedPerformancePanel.Current){Log 'The previous Performance request is still retiring.';return}}
 [xml]$PX=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN Performance" Width="760" Height="470" MinWidth="600" MinHeight="380" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF"><Grid Margin="20"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Latency &amp; path performance" FontSize="23" FontWeight="Bold"/><TextBlock Grid.Row="1" Margin="0,8,0,12" Foreground="#A8B6D5" TextWrapping="Wrap" Text="Router-node RTT uses the current private tunnel; external live response uses three routed HTTPS responses, timed after TLS and expiring after 10 seconds. Real path speed transfers authenticated bounded data to the active exit. Routed hop speed independently transfers to the selected entry and exit private agents through the active multihop graph; unreachable hops report their real error. Auto MTU is a separate optimizer."/><TextBox Name="Result" Grid.Row="2" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Background="#101A2B" Foreground="#E8ECF8" Padding="10"/><WrapPanel Grid.Row="3" Margin="0,12,0,0"><Button Name="Live" Content="Live path response" Margin="4" Padding="11,6"/><Button Name="Durable" Content="50-sample selected node" Margin="4" Padding="11,6"/><Button Name="Speed" Content="Real path speed" Margin="4" Padding="11,6"/><Button Name="HopSpeed" Content="Routed hop speeds" Margin="4" Padding="11,6"/><Button Name="Mtu" Content="Throughput + Auto MTU" Margin="4" Padding="11,6"/><Button Name="External" Content="Compare external / connect fastest" Margin="4" Padding="11,6"/><Button Name="CancelTest" Content="Cancel test" Margin="4" Padding="11,6" IsEnabled="False"/><Button Name="Close" Content="Close" Margin="4" Padding="11,6"/></WrapPanel></Grid></Window>
"@
 $Reader=New-Object System.Xml.XmlNodeReader $PX;$D=[Windows.Markup.XamlReader]::Load($Reader);$D.Owner=$Window
 $State=[pscustomobject]@{Dialog=$D;Result=$D.FindName('Result');Cancel=$D.FindName('CancelTest');Buttons=@();Current=$null;Task=$null;Pending=$null;Closed=$false;Timer=(New-Object Windows.Threading.DispatcherTimer)}
 $State.Buttons=@($D.FindName('Live'),$D.FindName('Durable'),$D.FindName('Speed'),$D.FindName('HopSpeed'),$D.FindName('Mtu'),$D.FindName('External'))
 $script:UnifiedPerformancePanel=$State
 $State.Timer.Interval=[TimeSpan]::FromMilliseconds(50);$State.Timer.Add_Tick({ContinueUnifiedPerformanceHop $State}.GetNewClosure())
 $D.FindName('Live').Add_Click({[void](StartUnifiedPerformanceRequest $State 'Checking current path response…' '/api/connection/live-latency' @{samples=5} 12 6 $false)}.GetNewClosure())
 $D.FindName('Durable').Add_Click({try{$P=SelectedNode;[void](StartUnifiedPerformanceRequest $State 'Testing 50-sample node latency…' '/api/profile/latency' @{id=[string]$P.id;samples=50} 180 6 $true)}catch{if(-not$State.Closed){$State.Result.Text=$_.Exception.Message}}}.GetNewClosure())
 $D.FindName('Speed').Add_Click({[void](StartUnifiedPerformanceRequest $State 'Testing real path speed…' '/api/connection/speed-test' @{bytes=8388608} 45 8 $false)}.GetNewClosure())
 $D.FindName('HopSpeed').Add_Click({[void](StartUnifiedPerformanceRequest $State 'Checking the active multihop graph…' '/api/multihop/status' $null 5 10 $false $true)}.GetNewClosure())
 $D.FindName('Mtu').Add_Click({Show-RouterVPNMTUDialog -BaseUrl $BaseUrl -Owner $D}.GetNewClosure())
 $D.FindName('External').Add_Click({$D.Close();ShowExternalComparison}.GetNewClosure())
 $D.FindName('CancelTest').Add_Click({CancelUnifiedPerformance $State}.GetNewClosure())
 $D.FindName('Close').Add_Click({$D.Close()}.GetNewClosure())
 $D.Add_Closed({CloseUnifiedPerformance $State}.GetNewClosure())
 [void]$D.ShowDialog()
}
(Control 'UnifiedFastestNode').Add_SelectionChanged({
 if($script:UnifiedTelemetrySync){return};$ID=[string](Control 'UnifiedFastestNode').SelectedValue;if(-not$ID){return}
 try{
  Assert-RouterVPNMutationIdle 'selecting a Router VPN node'
  if(UnifiedAsyncBusy){throw 'Another Router VPN action is still running.'}
  if($ID-eq'external-comparison'){ShowExternalComparison;return}
  if($ID-eq'fastest'){
   [void](StartUnifiedApiAsync 'Selecting fastest node…' '/api/profile/fastest' 'POST' @{samples=50;select=$true} 185 {param($R)Log ('Selected the fastest Router VPN node from 50 complete TCP samples per candidate, ranked by trimmed mean. Press Connect when ready. '+[string]$R.note)} {param($E)Log ('Fastest selection failed: '+$E)} {RefreshProduct;RefreshUnifiedTelemetry})
  }else{
   $Success={param($R)Log ('Selected Router VPN node '+$ID)}.GetNewClosure()
   [void](StartUnifiedApiAsync 'Selecting node…' '/api/profile/select' 'POST' @{id=$ID} 10 $Success {param($E)Log ('Node selection failed: '+$E)} {RefreshProduct;RefreshUnifiedTelemetry})
  }
 }catch{Log ('Node selection failed: '+$_.Exception.Message);RefreshUnifiedTelemetry}
})
(Control 'UnifiedForwardButton').Add_Click({ToggleUnifiedForwardingMaster})
(Control 'UnifiedPerformanceButton').Add_Click({ShowUnifiedPerformance})
'@
    $ProductSource=$ProductSource.Replace($startup,$telemetry+"`n"+$startup)

    $tick='$Timer.Add_Tick({RefreshProduct})'
    if($ProductSource.Contains($tick)){$ProductSource=$ProductSource.Replace($tick,'$Timer.Add_Tick({RefreshProduct;RefreshUnifiedTelemetry})')}
    $initial="RefreshProduct`n`$Timer.Start()"
    if($ProductSource.Contains($initial)){$ProductSource=$ProductSource.Replace($initial,"RefreshProduct`nRefreshUnifiedTelemetry`n`$Timer.Start()")}

    $timerMarker='$Timer=New-Object Windows.Threading.DispatcherTimer'
    $timerInject=@'
$UnifiedMapAnimationTimer=New-Object Windows.Threading.DispatcherTimer
$UnifiedMapAnimationTimer.Interval=[TimeSpan]::FromMilliseconds(60)
$UnifiedMapAnimationTimer.Add_Tick({TickUnifiedMapAnimation})
$UnifiedMapAnimationTimer.Start()
'@
    if(-not $ProductSource.Contains($timerMarker)){throw 'Windows map animation timer seam drifted.'}
    $ProductSource=$ProductSource.Replace($timerMarker,$timerInject+"`n"+$timerMarker)
    $closeMarker='$Window.Add_Closed({$Timer.Stop()})'
    if($ProductSource.Contains($closeMarker)){$ProductSource=$ProductSource.Replace($closeMarker,'$Window.Add_Closed({$Timer.Stop();$UnifiedMapAnimationTimer.Stop();try{if(UnifiedTelemetryBusy){[void](CancelUnifiedTelemetryRefreshAsync)}}catch{};try{$script:UnifiedTelemetryPoller.Stop();$script:UnifiedTelemetryClient.Dispose()}catch{}})')}

    $ProductSource+="`n# Windows telemetry UX contract: stylized offline VPN globe, clickable real-coordinate nodes, entry/exit/external/selected role colors, measured node ms, live entry-to-exit route with animated packet and PATH ms, fastest/specific node selector that stays separate from Connect, live path RTT beside Connect/Disconnect, live multihop IN/OUT/PATH RTT, authenticated Real path speed, Routed hop speeds via /api/multihop/speed-test, separate MTU optimizer, Performance panel, and real /api/forwarding/master active-home toggle.`n"
    return $ProductSource
}
