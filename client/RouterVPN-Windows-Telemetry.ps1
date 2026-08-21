function Add-RouterVPNTelemetryWindowsShell {
    param([Parameter(Mandatory=$true)][string]$ProductSource)
    Set-StrictMode -Version Latest

    $killOld='<CheckBox Name="UnifiedKillSwitch" Grid.Column="1" Content="Kill switch" VerticalAlignment="Center" Margin="14,0,0,0"/>'
    $killNew='<StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" Margin="10,0,0,0"><ComboBox Name="UnifiedFastestNode" Width="150" DisplayMemberPath="display" SelectedValuePath="id" ToolTip="Connect fastest measured node or a specific Router VPN node"/><TextBlock Name="UnifiedLiveLatency" Text="-- ms" FontFamily="Consolas" FontWeight="SemiBold" Foreground="#A8B6D5" VerticalAlignment="Center" Margin="8,0"/><CheckBox Name="UnifiedKillSwitch" Content="Kill switch" VerticalAlignment="Center" Margin="4,0"/><Button Name="UnifiedForwardButton" Content="Forward ?" Margin="6,0,0,0" Padding="8,4" ToolTip="Real active-home forwarding master"/></StackPanel>'
    if(-not $ProductSource.Contains($killOld)){throw 'Windows telemetry connect-row contract drifted.'}
    $ProductSource=$ProductSource.Replace($killOld,$killNew)

    $multiOld='<ComboBox Name="UnifiedExitMode" Grid.Column="5" Margin="6,0,0,0"><ComboBoxItem Content="Shadowsocks" Tag="shadowsocks"/><ComboBoxItem Content="Hysteria2" Tag="hysteria2"/></ComboBox></Grid>'
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
function SelectUnifiedMapNode([string]$ID){try{[void](Api '/api/profile/select' 'POST' @{id=$ID} 10);RefreshProduct;RefreshUnifiedTelemetry}catch{Log ('Map node select failed: '+$_.Exception.Message)}}
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
  $Ms=if([double]$Profile.latency_trimmed_mean_ms -gt 0){[double]$Profile.latency_trimmed_mean_ms}elseif([double]$Profile.latency_median_ms -gt 0){[double]$Profile.latency_median_ms}else{0};$Label=New-Object Windows.Controls.TextBlock;$Label.Text=if($Ms -gt 0){'{0}  {1:N1} ms'-f [string]$Profile.name,$Ms}else{[string]$Profile.name};$Label.Foreground='#E8F2FF';$Label.FontSize=11;$Label.Tag=$ID;$Label.Cursor='Hand';$Label.Add_MouseLeftButtonUp({param($sender,$event)SelectUnifiedMapNode ([string]$sender.Tag)});[Windows.Controls.Canvas]::SetLeft($Label,$X+$Size/2+4);[Windows.Controls.Canvas]::SetTop($Label,$Y-8);[void]$MapCanvas.Children.Add($Label);$Count++
 }
 if($Entry -and $Exit -and $Points.ContainsKey($Entry) -and $Points.ContainsKey($Exit)){$a=$Points[$Entry];$b=$Points[$Exit];$Route=AddGlobeLine $a[0] $a[1] $b[0] $b[1] '#59A7FF' 4;$Route.Opacity=.88;$Packet=New-Object Windows.Shapes.Ellipse;$Packet.Width=8;$Packet.Height=8;$Packet.Fill='White';$Packet.Stroke='#8FD3FF';$Packet.StrokeThickness=2;[void]$MapCanvas.Children.Add($Packet);$script:UnifiedRoute=[pscustomobject]@{x1=[double]$a[0];y1=[double]$a[1];x2=[double]$b[0];y2=[double]$b[1]};$script:UnifiedRoutePacket=$Packet;$PathLabel=New-Object Windows.Controls.TextBlock;$PathLabel.Text=if($script:UnifiedRoutePathMs -gt 0){'PATH {0:N1} ms'-f $script:UnifiedRoutePathMs}else{'LIVE MULTIHOP'};$PathLabel.Foreground='#CBE7FF';$PathLabel.FontSize=10;$PathLabel.FontFamily='Consolas';$PathLabel.Background='#AA0D1B31';$PathLabel.Padding='5,2';[Windows.Controls.Canvas]::SetLeft($PathLabel,(($a[0]+$b[0])/2)-28);[Windows.Controls.Canvas]::SetTop($PathLabel,(($a[1]+$b[1])/2)-22);[void]$MapCanvas.Children.Add($PathLabel)}
 if($Count -eq 0){$Empty=New-Object Windows.Controls.TextBlock;$Empty.Text='No real node coordinates in linked profiles';$Empty.Foreground='#AEBBD5';[Windows.Controls.Canvas]::SetLeft($Empty,20);[Windows.Controls.Canvas]::SetTop($Empty,40);[void]$MapCanvas.Children.Add($Empty)}
 $Privacy=New-Object Windows.Controls.TextBlock;$Privacy.Text='Only real stored coordinates • device location is never fabricated';$Privacy.Foreground='#7186A6';$Privacy.FontSize=9;[Windows.Controls.Canvas]::SetLeft($Privacy,18);[Windows.Controls.Canvas]::SetTop($Privacy,$Height-25);[void]$MapCanvas.Children.Add($Privacy)
}
function TickUnifiedMapAnimation{if($null -eq $script:UnifiedRoutePacket -or $null -eq $script:UnifiedRoute){return};$script:UnifiedMapPhase=($script:UnifiedMapPhase+.018)%1.0;$r=$script:UnifiedRoute;$x=$r.x1+($r.x2-$r.x1)*$script:UnifiedMapPhase;$y=$r.y1+($r.y2-$r.y1)*$script:UnifiedMapPhase;[Windows.Controls.Canvas]::SetLeft($script:UnifiedRoutePacket,$x-4);[Windows.Controls.Canvas]::SetTop($script:UnifiedRoutePacket,$y-4)}
'@
    $drawPattern='(?s)function DrawMap\(\$Profiles,\[string\]\$Selected\)\{.*?\}\r?\nfunction SessionEvents'
    if(-not [regex]::IsMatch($ProductSource,$drawPattern)){throw 'Windows globe renderer contract drifted.'}
    $ProductSource=[regex]::Replace($ProductSource,$drawPattern,$globe+"`nfunction SessionEvents",1)

    $startup='$BaseCombo.SelectedIndex=0'
    if(-not $ProductSource.Contains($startup)){throw 'Windows telemetry startup seam drifted.'}
    $telemetry=@'
$script:UnifiedTelemetrySync=$false
$script:UnifiedForwardSync=$false
function RefreshUnifiedFastestChoices{
 try{$Store=Api '/api/profiles' -Timeout 4;$Values=New-Object System.Collections.ArrayList;[void]$Values.Add([pscustomobject]@{id='fastest';display='⚡ Fastest'});$Routers=@($Store.profiles|Where-Object{(([string]$_.node_kind).ToLowerInvariant() -ne 'external')}|Sort-Object @{Expression={if([double]$_.latency_trimmed_mean_ms -gt 0){[double]$_.latency_trimmed_mean_ms}else{[double]::PositiveInfinity}}},name);foreach($P in $Routers){$Ms=[double]$P.latency_trimmed_mean_ms;$Label=if($Ms -gt 0){'{0}  {1:N1} ms'-f [string]$P.name,$Ms}else{[string]$P.name};[void]$Values.Add([pscustomobject]@{id=[string]$P.id;display=$Label})};$script:UnifiedTelemetrySync=$true;(Control 'UnifiedFastestNode').ItemsSource=@($Values);(Control 'UnifiedFastestNode').SelectedValue='fastest';$script:UnifiedTelemetrySync=$false}catch{$script:UnifiedTelemetrySync=$false}
}
function RefreshUnifiedForwardingMaster{
 try{$R=Api '/api/forwarding/master' -Timeout 4;$script:UnifiedForwardSync=$true;(Control 'UnifiedForwardButton').Content=if([bool]$R.enabled){'Forward ON'}else{'Forward OFF'};(Control 'UnifiedForwardButton').Tag=[bool]$R.enabled;(Control 'UnifiedForwardButton').ToolTip='Real server forwarding master on '+[string]$R.name;$script:UnifiedForwardSync=$false}catch{$script:UnifiedForwardSync=$true;(Control 'UnifiedForwardButton').Content='Forward ?';(Control 'UnifiedForwardButton').Tag=$null;(Control 'UnifiedForwardButton').ToolTip='Connect a Router VPN home-node path to control the real server forwarding master';$script:UnifiedForwardSync=$false}
}
function ToggleUnifiedForwardingMaster{
 if($script:UnifiedForwardSync){return}
 try{$Current=(Control 'UnifiedForwardButton').Tag;if($null -eq $Current){$Now=Api '/api/forwarding/master' -Timeout 5;$Current=[bool]$Now.enabled};$Want=-not [bool]$Current;(Control 'UnifiedForwardButton').Content='Forward …';$R=Api '/api/forwarding/master' 'PUT' @{enabled=$Want} 10;if([bool]$R.enabled -ne $Want){throw 'Forwarding master state did not verify.'};$StateLabel=if($Want){'ON'}else{'OFF'};Log ('Forwarding master '+$StateLabel+' on '+[string]$R.name);RefreshUnifiedForwardingMaster}catch{Log ('Forwarding master failed: '+$_.Exception.Message);RefreshUnifiedForwardingMaster}
}
function RefreshUnifiedTelemetry{
 RefreshUnifiedFastestChoices
 try{$Live=Api '/api/connection/live-latency' -Timeout 4;$script:UnifiedRoutePathMs=[double]$Live.median_ms;(Control 'UnifiedLiveLatency').Text=('{0:N1} ms'-f [double]$Live.median_ms);(Control 'UnifiedLiveLatency').Foreground='#E8ECF8'}catch{$script:UnifiedRoutePathMs=0.0;(Control 'UnifiedLiveLatency').Text='-- ms';(Control 'UnifiedLiveLatency').Foreground='#A8B6D5'}
 try{if((Control 'UnifiedMultihop').IsChecked){$Entry=[string]$MultihopEntryCombo.SelectedValue;$Exit=[string]$MultihopExitCombo.SelectedValue;if($Entry -and $Exit -and $Entry -ne $Exit){$R=Api '/api/multihop/live-latency' 'POST' @{entry_id=$Entry;exit_id=$Exit;samples=2} 8;$Bits=@();if($R.entry){$Bits+=('IN {0:N1}'-f[double]$R.entry.median_ms)};if($R.exit){$Bits+=('OUT {0:N1}'-f[double]$R.exit.median_ms)};if($R.current_path){$script:UnifiedRoutePathMs=[double]$R.current_path.median_ms;$Bits+=('PATH {0:N1} ms'-f[double]$R.current_path.median_ms)};(Control 'UnifiedMultihopLatency').Text=($Bits -join ' • ')}}else{(Control 'UnifiedMultihopLatency').Text=''}}catch{(Control 'UnifiedMultihopLatency').Text=''}
 RefreshUnifiedForwardingMaster
}
function ShowUnifiedPerformance{
 [xml]$PX=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN Performance" Width="760" Height="470" MinWidth="600" MinHeight="380" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF"><Grid Margin="20"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Latency &amp; path performance" FontSize="23" FontWeight="Bold"/><TextBlock Grid.Row="1" Margin="0,8,0,12" Foreground="#A8B6D5" TextWrapping="Wrap" Text="Live RTT uses the current private tunnel. Real path speed transfers authenticated bounded data to the active exit. Routed hop speed independently transfers to the selected entry and exit private agents through the active multihop graph; unreachable hops report their real error. Auto MTU is a separate optimizer."/><TextBox Name="Result" Grid.Row="2" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Background="#101A2B" Foreground="#E8ECF8" Padding="10"/><WrapPanel Grid.Row="3" Margin="0,12,0,0"><Button Name="Live" Content="Live path RTT" Margin="4" Padding="11,6"/><Button Name="Durable" Content="50-sample selected node" Margin="4" Padding="11,6"/><Button Name="Speed" Content="Real path speed" Margin="4" Padding="11,6"/><Button Name="HopSpeed" Content="Routed hop speeds" Margin="4" Padding="11,6"/><Button Name="Mtu" Content="Throughput + Auto MTU" Margin="4" Padding="11,6"/><Button Name="Close" Content="Close" Margin="4" Padding="11,6"/></WrapPanel></Grid></Window>
"@
 $Reader=New-Object System.Xml.XmlNodeReader $PX;$D=[Windows.Markup.XamlReader]::Load($Reader);$D.Owner=$Window;$Result=$D.FindName('Result')
 $D.FindName('Live').Add_Click({try{$R=Api '/api/connection/live-latency' 'POST' @{samples=5} 12;$Result.Text=($R|ConvertTo-Json -Depth 6)}catch{$Result.Text=$_.Exception.Message}})
 $D.FindName('Durable').Add_Click({try{$P=SelectedNode;$R=Api '/api/profile/latency' 'POST' @{id=[string]$P.id;samples=50} 180;$Result.Text=($R|ConvertTo-Json -Depth 6);RefreshProduct}catch{$Result.Text=$_.Exception.Message}})
 $D.FindName('Speed').Add_Click({try{$R=Api '/api/connection/speed-test' 'POST' @{bytes=8388608} 45;$Result.Text=($R|ConvertTo-Json -Depth 8)}catch{$Result.Text=$_.Exception.Message}})
 $D.FindName('HopSpeed').Add_Click({try{$Entry=[string]$MultihopEntryCombo.SelectedValue;$Exit=[string]$MultihopExitCombo.SelectedValue;if(-not $Entry -or -not $Exit -or $Entry -eq $Exit){throw 'Choose different multihop entry and exit nodes first.'};$R=Api '/api/multihop/speed-test' 'POST' @{entry_id=$Entry;exit_id=$Exit;bytes=4194304} 70;$Result.Text=($R|ConvertTo-Json -Depth 10)}catch{$Result.Text=$_.Exception.Message}})
 $D.FindName('Mtu').Add_Click({try{$R=Api '/api/mtu/retest' 'POST' @{} 130;$Result.Text=($R|ConvertTo-Json -Depth 8);RefreshProduct}catch{$Result.Text=$_.Exception.Message}})
 $D.FindName('Close').Add_Click({$D.Close()});[void]$D.ShowDialog()
}
(Control 'UnifiedFastestNode').Add_SelectionChanged({if($script:UnifiedTelemetrySync){return};$ID=[string](Control 'UnifiedFastestNode').SelectedValue;if(-not $ID){return};try{if($ID -eq 'fastest'){[void](Api '/api/profile/fastest' 'POST' @{samples=5;select=$true} 40)}else{[void](Api '/api/profile/select' 'POST' @{id=$ID} 10)};RefreshProduct;RefreshUnifiedTelemetry;UnifiedConnect}catch{Log ('Fast connect failed: '+$_.Exception.Message)}finally{$script:UnifiedTelemetrySync=$true;(Control 'UnifiedFastestNode').SelectedValue='fastest';$script:UnifiedTelemetrySync=$false}})
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
    if($ProductSource.Contains($closeMarker)){$ProductSource=$ProductSource.Replace($closeMarker,'$Window.Add_Closed({$Timer.Stop();$UnifiedMapAnimationTimer.Stop()})')}

    $ProductSource+="`n# Windows telemetry UX contract: stylized offline VPN globe, clickable real-coordinate nodes, entry/exit/external/selected role colors, measured node ms, live entry-to-exit route with animated packet and PATH ms, fastest-node connect dropdown, live path RTT beside Connect/Disconnect, live multihop IN/OUT/PATH RTT, authenticated Real path speed, Routed hop speeds via /api/multihop/speed-test, separate MTU optimizer, Performance panel, and real /api/forwarding/master active-home toggle.`n"
    return $ProductSource
}
