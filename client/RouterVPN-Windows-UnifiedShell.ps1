$script:RouterVPNUnifiedModeKey = 'windows-selected-mode-v1.txt'
$script:RouterVPNUnifiedPresets = 'windows-custom-presets-v1.json'

function Add-RouterVPNUnifiedWindowsShell {
    param([Parameter(Mandatory=$true)][string]$ProductSource)
    Set-StrictMode -Version Latest

    $oldHeader = '<Grid Grid.Row="0" Margin="4,0,4,14">'
    if (-not $ProductSource.Contains($oldHeader)) { throw 'Windows unified shell: header contract drifted.' }
    $ProductSource = $ProductSource.Replace($oldHeader, '<Grid Grid.Row="0" Visibility="Collapsed" Margin="4,0,4,14">')

    $oldTabs = '<TabControl Grid.Row="1" Background="#0F172A" BorderBrush="#263452" Foreground="#E8ECF8">'
    if (-not $ProductSource.Contains($oldTabs)) { throw 'Windows unified shell: TabControl contract drifted.' }
    $shell = @'
<Grid Name="UnifiedShell" Grid.Row="1" Background="#08101E">
  <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <Border Grid.Row="0" Background="#0E182B" CornerRadius="18" BorderBrush="#263A5A" BorderThickness="1" Margin="0,0,0,8">
    <Grid>
      <Canvas Name="UnifiedMapCanvas" ClipToBounds="True"/>
      <Border HorizontalAlignment="Left" VerticalAlignment="Top" Margin="14" Padding="10,7" CornerRadius="14" Background="#DD17243A">
        <StackPanel Orientation="Horizontal"><TextBlock Text="Node" FontWeight="SemiBold" Margin="0,0,8,0" VerticalAlignment="Center"/><ComboBox Name="UnifiedNodeCombo" DisplayMemberPath="display_name" SelectedValuePath="id" MinWidth="260"/><Button Name="UnifiedNodesButton" Content="Add / manage nodes" Margin="8,0,0,0" Padding="10,5"/></StackPanel>
      </Border>
      <Border HorizontalAlignment="Right" VerticalAlignment="Top" Margin="14" Padding="10,7" CornerRadius="14" Background="#DD17243A">
        <StackPanel><StackPanel Orientation="Horizontal"><Ellipse Name="UnifiedStateDot" Width="9" Height="9" Fill="#6B7280" Margin="0,0,7,0"/><TextBlock Name="UnifiedStateText" Text="Checking…" FontWeight="SemiBold"/></StackPanel><TextBlock Name="UnifiedStatusDetail" Text="Selected-path proof pending" FontSize="11" Foreground="#A8B6D5" MaxWidth="420" TextWrapping="Wrap"/></StackPanel>
      </Border>
    </Grid>
  </Border>
  <Border Grid.Row="1" Background="#F0162238" BorderBrush="#354968" BorderThickness="1" CornerRadius="22" Padding="16,8,16,14">
    <ScrollViewer MaxHeight="390" VerticalScrollBarVisibility="Auto"><StackPanel>
      <TextBlock Text="━━━━" HorizontalAlignment="Center" Foreground="#657794" FontSize="15"/>
      <TextBlock Name="UnifiedProofText" Text="Connected requires exact selected-node path proof." Foreground="#DDE7FF" TextWrapping="Wrap" Margin="0,0,0,7"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,0,0,6"><Button Name="UnifiedProofButton" Content="Prove actual exit" Padding="10,5"/><Button Name="UnifiedEmergencyButton" Content="Emergency disconnect" Margin="6,0,0,0" Padding="10,5"/></StackPanel>
      <TextBlock Name="UnifiedLastError" Foreground="#FF9CA8" TextWrapping="Wrap" Margin="0,0,0,6"/>
      <Grid Margin="0,2,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><Button Name="UnifiedConnectButton" Content="Connect" FontSize="17" FontWeight="Bold" Padding="18,10" Background="#6857E5" Foreground="White"/><CheckBox Name="UnifiedKillSwitch" Grid.Column="1" Content="Kill switch" VerticalAlignment="Center" Margin="14,0,0,0"/></Grid>
      <Grid Margin="0,4"><Grid.ColumnDefinitions><ColumnDefinition Width="76"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="Multihop" FontWeight="SemiBold" VerticalAlignment="Center"/><CheckBox Name="UnifiedMultihop" Grid.Column="1" VerticalAlignment="Center" Margin="6,0"/><ComboBox Name="UnifiedEntryCombo" Grid.Column="2" DisplayMemberPath="name" SelectedValuePath="id" MinWidth="150"/><TextBlock Grid.Column="3" Text=" → " VerticalAlignment="Center"/><ComboBox Name="UnifiedExitCombo" Grid.Column="4" DisplayMemberPath="name" SelectedValuePath="id" MinWidth="150"/><ComboBox Name="UnifiedExitMode" Grid.Column="5" Margin="6,0,0,0"><ComboBoxItem Content="Shadowsocks" Tag="shadowsocks"/><ComboBoxItem Content="Hysteria2" Tag="hysteria2"/></ComboBox></Grid>
      <Grid Margin="0,4"><Grid.ColumnDefinitions><ColumnDefinition Width="76"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="Settings" FontWeight="SemiBold" VerticalAlignment="Center"/><TextBlock Name="UnifiedSettingsSummary" Grid.Column="1" Foreground="#A8B6D5" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/><StackPanel Grid.Column="2" Orientation="Horizontal"><Button Name="UnifiedSettingsButton" Content="Open settings" Padding="10,5"/><Button Name="UnifiedMtuButton" Content="Retest MTU" Margin="6,0,0,0" Padding="10,5"/></StackPanel></Grid>
      <Grid Margin="0,4"><Grid.ColumnDefinitions><ColumnDefinition Width="76"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="Mode" FontWeight="SemiBold" VerticalAlignment="Center"/><ComboBox Name="UnifiedModeCombo" Grid.Column="1" DisplayMemberPath="display" SelectedValuePath="id"/><Button Name="UnifiedPresetsButton" Grid.Column="2" Content="Presets / CUSTOM" Margin="6,0,0,0" Padding="10,5"/></Grid>
      <Grid Margin="0,4"><Grid.ColumnDefinitions><ColumnDefinition Width="76"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="DNS" FontWeight="SemiBold" VerticalAlignment="Center"/><ComboBox Name="UnifiedDnsCombo" Grid.Column="1"><ComboBoxItem Content="Home AdGuard" Tag="home"/><ComboBoxItem Content="Fastest measured" Tag="fastest"/><ComboBoxItem Content="Custom" Tag="custom"/><ComboBoxItem Content="DoT" Tag="dot"/><ComboBoxItem Content="DoH" Tag="doh"/><ComboBoxItem Content="DoH3" Tag="doh3"/><ComboBoxItem Content="Rescue" Tag="rescue"/></ComboBox><Button Name="UnifiedDnsDetailsButton" Grid.Column="2" Content="DNS details" Margin="6,0,0,0" Padding="10,5"/></Grid>
    </StackPanel></ScrollViewer>
  </Border>
</Grid>
<Button Name="UnifiedBackButton" Grid.Row="1" Content="← Back to map" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="12" Padding="12,6" Panel.ZIndex="50" Visibility="Collapsed"/>
<TabControl Name="LegacyDetailTabs" Visibility="Collapsed" Grid.Row="1" Background="#0F172A" BorderBrush="#263452" Foreground="#E8ECF8" Margin="0,48,0,0">
  <TabControl.Template><ControlTemplate TargetType="{x:Type TabControl}"><Border Background="#0F172A"><ContentPresenter ContentSource="SelectedContent"/></Border></ControlTemplate></TabControl.Template>
'@
    $ProductSource = $ProductSource.Replace($oldTabs, $shell)

    $oldFooter = '<TextBlock Grid.Row="2" Margin="4,12,4,0" Foreground="#7E90B6" Text="Native WPF; fixed local controller 127.0.0.1:8788; no browser or embedded web surface."/>'
    if ($ProductSource.Contains($oldFooter)) { $ProductSource = $ProductSource.Replace($oldFooter, '<TextBlock Grid.Row="2" Visibility="Collapsed" Text="Native WPF; fixed local controller 127.0.0.1:8788; no browser or embedded web surface."/>') }

    $bindingsOld = '$StateText=Control ''StateText'';$StateDot=Control ''StateDot'';$HeaderDetail=Control ''HeaderDetail'';$RouterCombo=Control ''RouterCombo'';$ModeCombo=Control ''ModeCombo'';$BaseCombo=Control ''BaseCombo'';$ConnectionDetail=Control ''ConnectionDetail'';$ProofText=Control ''ProofText'';$LastErrorText=Control ''LastErrorText'';$NodesGrid=Control ''NodesGrid'';$MapCanvas=Control ''MapCanvas'';'
    $bindingsNew = '$StateText=Control ''UnifiedStateText'';$StateDot=Control ''UnifiedStateDot'';$HeaderDetail=Control ''HeaderDetail'';$RouterCombo=Control ''UnifiedNodeCombo'';$ModeCombo=Control ''UnifiedModeCombo'';$BaseCombo=Control ''BaseCombo'';$ConnectionDetail=Control ''UnifiedStatusDetail'';$ProofText=Control ''UnifiedProofText'';$LastErrorText=Control ''UnifiedLastError'';$NodesGrid=Control ''NodesGrid'';$MapCanvas=Control ''UnifiedMapCanvas'';'
    if (-not $ProductSource.Contains($bindingsOld)) { throw 'Windows unified shell: control binding contract drifted.' }
    $ProductSource = $ProductSource.Replace($bindingsOld,$bindingsNew)

    $multiOld = '$MultihopEntryCombo=Control ''MultihopEntryCombo'';$MultihopExitCombo=Control ''MultihopExitCombo'';$MultihopExitModeCombo=Control ''MultihopExitModeCombo'';$MultihopSummary=Control ''MultihopSummary'''
    $multiNew = '$MultihopEntryCombo=Control ''UnifiedEntryCombo'';$MultihopExitCombo=Control ''UnifiedExitCombo'';$MultihopExitModeCombo=Control ''UnifiedExitMode'';$MultihopSummary=Control ''MultihopSummary'''
    if (-not $ProductSource.Contains($multiOld)) { throw 'Windows unified shell: multihop binding contract drifted.' }
    $ProductSource = $ProductSource.Replace($multiOld,$multiNew)

    $scriptMarker = '$script:EventSeq=[uint64]0;$script:Busy=$false;$script:NodeSort=''current'';$script:DnsPolicySummary=''Saved DNS policy not loaded yet.'''
    if (-not $ProductSource.Contains($scriptMarker)) { throw 'Windows unified shell: script-state marker drifted.' }
    $extraState = @'
$script:UnifiedModeStateFile=Join-Path $PSScriptRoot '.routervpn-state\windows-selected-mode-v1.txt'
$script:UnifiedPresetFile=Join-Path $PSScriptRoot '.routervpn-state\windows-custom-presets-v1.json'
$script:UnifiedModeChoices=@()
Add-Type -AssemblyName System.Net.Http
$script:UnifiedAsyncClient=[System.Net.Http.HttpClient]::new()
$script:UnifiedAsyncClient.Timeout=[System.Threading.Timeout]::InfiniteTimeSpan
$script:UnifiedAsyncTask=$null
$script:UnifiedAsyncRequest=$null
$script:UnifiedAsyncCts=$null
$script:UnifiedAsyncResponse=$null
$script:UnifiedAsyncSuccess=$null
$script:UnifiedAsyncFailure=$null
$script:UnifiedAsyncFinally=$null
$script:UnifiedAsyncLabel=''
$script:UnifiedAsyncCancelled=$false
$script:UnifiedAsyncDisconnectAfterCancel=$false
$script:UnifiedAsyncPoller=New-Object Windows.Threading.DispatcherTimer
$script:UnifiedAsyncPoller.Interval=[TimeSpan]::FromMilliseconds(100)
function UnifiedAsyncBusy { return $null-ne$script:UnifiedAsyncTask -and -not $script:UnifiedAsyncTask.IsCompleted }
function SetUnifiedAsyncUI([bool]$Busy,[string]$Label=''){
    foreach($N in @('UnifiedMtuButton','UnifiedSettingsButton','UnifiedPresetsButton','UnifiedNodesButton','UnifiedModeCombo','UnifiedMultihop','UnifiedEntryCombo','UnifiedExitCombo','UnifiedExitMode')){
        $C=Control $N;if($null-ne$C){$C.IsEnabled=-not$Busy}
    }
    $B=Control 'UnifiedConnectButton';if($null-ne$B){$B.IsEnabled=$true;if($Busy){$B.Content=if($Label-match'(?i)connect|auto|custom|multihop|external'){'Cancel / Disconnect'}else{$Label}}}
}
function StartUnifiedApiAsync([string]$Label,[string]$Path,[string]$Method='GET',$Body=$null,[int]$Timeout=180,[scriptblock]$OnSuccess=$null,[scriptblock]$OnFailure=$null,[scriptblock]$OnFinally=$null){
    if(UnifiedAsyncBusy){Log ("$Label refused: another Router VPN action is still running.");return $false}
    [void](CancelUnifiedRefreshAsync)
    try{
        $Verb=if($Method.ToUpperInvariant()-eq'POST'){[System.Net.Http.HttpMethod]::Post}else{[System.Net.Http.HttpMethod]::Get}
        $Uri=([string]$BaseUrl).TrimEnd('/')+$Path
        $Req=[System.Net.Http.HttpRequestMessage]::new($Verb,$Uri)
        if($null-ne$Body){
            $Json=$Body|ConvertTo-Json -Depth 24 -Compress
            $Req.Content=[System.Net.Http.StringContent]::new($Json,[System.Text.Encoding]::UTF8,'application/json')
        }
        $Cts=[System.Threading.CancellationTokenSource]::new()
        $Cts.CancelAfter([TimeSpan]::FromSeconds([Math]::Max(1,$Timeout)))
        $script:UnifiedAsyncRequest=$Req;$script:UnifiedAsyncCts=$Cts;$script:UnifiedAsyncSuccess=$OnSuccess;$script:UnifiedAsyncFailure=$OnFailure;$script:UnifiedAsyncFinally=$OnFinally
        $script:UnifiedAsyncLabel=$Label;$script:UnifiedAsyncCancelled=$false;$script:UnifiedAsyncDisconnectAfterCancel=$false
        $script:UnifiedAsyncTask=$script:UnifiedAsyncClient.SendAsync($Req,$Cts.Token)
        SetUnifiedAsyncUI $true $Label
        $script:UnifiedAsyncPoller.Start()
        return $true
    }catch{
        if($null-ne$OnFailure){&$OnFailure $_.Exception.Message}else{Log ("$Label failed: "+$_.Exception.Message)}
        if($null-ne$OnFinally){&$OnFinally}
        SetUnifiedAsyncUI $false
        return $false
    }
}
function CancelUnifiedApiAsync([bool]$DisconnectAfter=$false){
    if(-not(UnifiedAsyncBusy)){return $false}
    $script:UnifiedAsyncCancelled=$true
    $script:UnifiedAsyncDisconnectAfterCancel=$DisconnectAfter
    try{$script:UnifiedAsyncCts.Cancel()}catch{}
    return $true
}
function CompleteUnifiedApiAsync{
    if($null-eq$script:UnifiedAsyncTask -or -not$script:UnifiedAsyncTask.IsCompleted){return}
    $Task=$script:UnifiedAsyncTask;$Req=$script:UnifiedAsyncRequest;$Cts=$script:UnifiedAsyncCts;$Success=$script:UnifiedAsyncSuccess;$Failure=$script:UnifiedAsyncFailure;$Finally=$script:UnifiedAsyncFinally;$Label=$script:UnifiedAsyncLabel
    $Cancelled=$script:UnifiedAsyncCancelled;$DisconnectAfter=$script:UnifiedAsyncDisconnectAfterCancel
    $script:UnifiedAsyncPoller.Stop()
    $script:UnifiedAsyncTask=$null;$script:UnifiedAsyncRequest=$null;$script:UnifiedAsyncCts=$null;$script:UnifiedAsyncSuccess=$null;$script:UnifiedAsyncFailure=$null;$script:UnifiedAsyncFinally=$null;$script:UnifiedAsyncLabel=''
    try{
        $Resp=$Task.GetAwaiter().GetResult();$script:UnifiedAsyncResponse=$Resp
        $Text=$Resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if(-not$Resp.IsSuccessStatusCode){throw ("HTTP "+[int]$Resp.StatusCode+" "+$Text)}
        $Value=if([string]::IsNullOrWhiteSpace($Text)){$null}else{$Text|ConvertFrom-Json}
        if(-not$Cancelled -and $null-ne$Success){&$Success $Value}
    }catch{
        if(-not$Cancelled){if($null-ne$Failure){&$Failure $_.Exception.Message}else{Log ("$Label failed: "+$_.Exception.Message)}}
    }finally{
        try{if($null-ne$script:UnifiedAsyncResponse){$script:UnifiedAsyncResponse.Dispose()}}catch{};$script:UnifiedAsyncResponse=$null
        try{if($null-ne$Req){$Req.Dispose()}}catch{};try{if($null-ne$Cts){$Cts.Dispose()}}catch{}
        if($null-ne$Finally){&$Finally}
        SetUnifiedAsyncUI $false
        RefreshProduct
    }
    if($DisconnectAfter){
        [void](StartUnifiedApiAsync 'Disconnecting…' '/api/disconnect' 'POST' @{} 20 {param($R)Log 'Disconnected'} {param($E)Log ('Disconnect failed: '+$E)} $null)
    }
}
$script:UnifiedAsyncPoller.Add_Tick({CompleteUnifiedApiAsync})
$script:UnifiedRefreshClient=[System.Net.Http.HttpClient]::new()
$script:UnifiedRefreshClient.Timeout=[System.Threading.Timeout]::InfiniteTimeSpan
$script:UnifiedRefreshTasks=@{}
$script:UnifiedRefreshRequests=@{}
$script:UnifiedRefreshCts=$null
$script:UnifiedRefreshDiscard=$false
$script:UnifiedRefreshPoller=New-Object Windows.Threading.DispatcherTimer
$script:UnifiedRefreshPoller.Interval=[TimeSpan]::FromMilliseconds(100)
function UnifiedRefreshBusy { return $script:UnifiedRefreshTasks.Count -gt 0 }
function CancelUnifiedRefreshAsync {
    if(-not(UnifiedRefreshBusy)){return $false}
    $script:UnifiedRefreshDiscard=$true
    try{$script:UnifiedRefreshCts.Cancel()}catch{}
    return $true
}
function StartUnifiedRefreshAsync {
    if((UnifiedRefreshBusy) -or (UnifiedAsyncBusy)){return}
    $script:UnifiedRefreshTasks=@{};$script:UnifiedRefreshRequests=@{};$script:UnifiedRefreshDiscard=$false
    $script:UnifiedRefreshCts=[System.Threading.CancellationTokenSource]::new()
    $script:UnifiedRefreshCts.CancelAfter([TimeSpan]::FromSeconds(15))
    $Paths=[ordered]@{
        status='/api/status'
        nodes=('/api/nodes?sort='+[Uri]::EscapeDataString([string]$script:NodeSort))
        session='/api/session'
        modes='/api/logical-modes'
        multihop='/api/multihop/status'
        events=('/api/session/events?after='+[string]$script:EventSeq)
    }
    try{
        foreach($Key in $Paths.Keys){
            $Req=[System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get,([string]$BaseUrl)+[string]$Paths[$Key])
            $script:UnifiedRefreshRequests[$Key]=$Req
            $script:UnifiedRefreshTasks[$Key]=$script:UnifiedRefreshClient.SendAsync($Req,$script:UnifiedRefreshCts.Token)
        }
        $script:UnifiedRefreshPoller.Start()
    }catch{
        [void](CancelUnifiedRefreshAsync)
        $StateText.Text='Controller unavailable';$StateDot.Fill='#FF5D6C';$LastErrorText.Text=$_.Exception.Message
    }
}
function ApplyUnifiedRefreshSnapshot($Status,$Store,$Session,$ModesRaw,$MH,$Timeline){
    $script:Busy=$true
    try{
        $Connected=[bool]$Status.connected;$Phase=[string]$Status.phase
        $MutationBusy=Test-RouterVPNMutationBusyFromStatus $Status
        $Disconnecting=$Phase -match '(?i)(disconnecting|stopping)'
        $StateText.Text=if($Connected){'Connected'}elseif($Phase){$Phase}else{'Off'}
        $StateDot.Fill=if($Connected){'#35D07F'}elseif($Phase-eq'failed'){'#FF5D6C'}else{'#6B7280'}
        $Runtime=if($Status.runtime_mode){$Status.runtime_mode}else{$Status.mode}
        $ConnectionDetail.Text="Phase: $Phase Logical: $($Status.logical_mode) Runtime: $Runtime Base: $($Status.base) Router: $($Status.router_id)"
        $LastErrorText.Text=[string]$Status.last_error
        if($Connected){$ProofText.Text='Connected - selected-router private path proof passed.'}
        $DnsSaveButton.IsEnabled=-not$MutationBusy;$DnsButton.IsEnabled=$Connected
        foreach($Name in @('PairNodeButton','ImportNodeButton','DeleteNodeButton','SelectNodeButton','SelectLowestLatencyButton','ExternalDirectButton','ExternalViaEntryButton','MultihopConnectButton','AutoButton','ConnectButton')){
            $C=Control $Name;if($null-ne$C){$C.IsEnabled=-not$MutationBusy}
        }
        foreach($Widget in @($RouterCombo,$ModeCombo,$BaseCombo,$DnsModeCombo,$DnsProtocolCombo,$DnsPresetCombo,$DnsHostBox,$DnsPortBox,$DnsServerBox,$DnsPathBox,$MultihopEntryCombo,$MultihopExitCombo,$MultihopExitModeCombo)){
            if($null-ne$Widget){$Widget.IsEnabled=-not$MutationBusy}
        }

        $Profiles=@($Store.profiles);$OldNode=[string]$NodesGrid.SelectedValue
        $RouterCombo.ItemsSource=$Profiles;$NodesGrid.ItemsSource=$Profiles
        if($Store.selected_id){$RouterCombo.SelectedValue=[string]$Store.selected_id}
        if($OldNode){$NodesGrid.SelectedValue=$OldNode}
        DrawMap $Profiles ([string]$Store.selected_id)
        $Selected=@($Profiles|Where-Object{[string]$_.id-eq[string]$Store.selected_id}|Select-Object -First 1)
        if($Selected.Count){
            $Profile=$Selected[0]
            $Success=if($Profile.effective_mtu_success_ratio){[double]$Profile.effective_mtu_success_ratio*100}else{0}
            $Perf=if($Profile.effective_mtu_mbps){" Retest=$([Math]::Round([double]$Profile.effective_mtu_mbps,1))Mbps/$([Math]::Round([double]$Profile.effective_mtu_median_rtt_ms,2))ms/$([Math]::Round($Success,1))% success"}else{''}
            $AdvancedSummary.Text="LAN=$($Profile.home_lan_access) Kill switch=$($Profile.kill_switch_policy) MTU policy=$($Profile.mtu_policy) Effective MTU=$($Profile.effective_mtu) source=$($Profile.effective_mtu_source)$Perf tested=$($Profile.effective_mtu_tested_at) Multihop=$($Profile.multihop_enabled)"
            $SettingsSummary.Text="Node=$($Profile.name) Endpoint=$($Profile.endpoint) Location=$($Profile.location)"
            $UnifiedSettings=Control 'UnifiedSettingsSummary'
            if($null-ne$UnifiedSettings){
                $AutoReq=@();if([bool]$Profile.auto_require_encrypted){$AutoReq+='Encrypted'};if([bool]$Profile.auto_require_obfuscation){$AutoReq+='Obfuscation'}
                $AutoReqText=if($AutoReq.Count){$AutoReq -join '+'}else{'Off'}
                $UnifiedSettings.Text="IPv6=$($Profile.ipv6_mode) • MTU=$($Profile.mtu_policy)/$($Profile.effective_mtu) • LAN=$($Profile.home_lan_access) • AUTO requirements=$AutoReqText"
            }
            $UnifiedKill=Control 'UnifiedKillSwitch'
            if($null-ne$UnifiedKill){$UnifiedKill.IsChecked=([string]$Profile.kill_switch_policy -ne 'off')}
            $UnifiedDns=Control 'UnifiedDnsCombo'
            if($null-ne$UnifiedDns -and $Profile.dns_mode){SetComboTag $UnifiedDns ([string]$Profile.dns_mode)}
        }

        $Dns=$Session.dns_proof
        $DnsSummary.Text="$script:DnsPolicySummary\r\n\r\nRuntime proof: mode=$($Dns.mode) resolver=$($Dns.host) status=$($Dns.status) latency=$($Dns.latency_ms)ms reason=$($Dns.reason)"
        $Modes=DecorateModes @($ModesRaw);$ModesGrid.ItemsSource=$Modes;RefreshUnifiedModeChoices $Modes
        $HeaderDetail.Text="Native Windows product - $($Profiles.Count) linked node(s) - order $($script:NodeSort)"

        $Nodes=@($MH.nodes);$EntrySelected=[string]$MultihopEntryCombo.SelectedValue;$ExitSelected=[string]$MultihopExitCombo.SelectedValue
        $MultihopEntryCombo.ItemsSource=$Nodes;$MultihopExitCombo.ItemsSource=$Nodes
        if(-not$EntrySelected-and$MH.entry_id){$EntrySelected=[string]$MH.entry_id};if(-not$ExitSelected-and$MH.exit_id){$ExitSelected=[string]$MH.exit_id}
        if($EntrySelected){$MultihopEntryCombo.SelectedValue=$EntrySelected};if($ExitSelected){$MultihopExitCombo.SelectedValue=$ExitSelected}
        $MultihopSummary.Text="Supported=$($MH.platform_supported) Connected=$($MH.connected) Actual exit=$($MH.actual_exit_id) Runtime=$($MH.runtime_exit_mode) Entry bases=$(@($MH.supported_entry_bases)-join',') Exit modes=$(@($MH.supported_exit_modes)-join',')"

        foreach($Event in @($Timeline.events)){
            $Seq=[uint64]$Event.seq;if($Seq-le$script:EventSeq){continue}
            $Parts=@([string]$Event.phase);if($Event.runtime_mode){$Parts+=("runtime="+$Event.runtime_mode)};if($Event.base){$Parts+=("base="+$Event.base)};if($Event.message){$Parts+=$Event.message}
            Log ("Session #$Seq $($Event.type): $($Parts-join' | ')");$script:EventSeq=$Seq
        }
        if([uint64]$Timeline.last_event_seq-gt$script:EventSeq){$script:EventSeq=[uint64]$Timeline.last_event_seq}

        $UnifiedConnect=Control 'UnifiedConnectButton'
        if($null-ne$UnifiedConnect){
            $UnifiedConnect.Content=if($Disconnecting){'Disconnecting…'}elseif($Connected-or$MutationBusy){'Disconnect'}else{'Connect'}
            $UnifiedConnect.IsEnabled=-not$Disconnecting
        }
        foreach($Name in @('UnifiedKillSwitch','UnifiedMultihop','UnifiedModeCombo','UnifiedDnsCombo')){
            $C=Control $Name;if($null-ne$C){$C.IsEnabled=-not$MutationBusy}
        }
    }finally{$script:Busy=$false}
}
function CompleteUnifiedRefreshAsync {
    if(-not(UnifiedRefreshBusy)){return}
    foreach($Task in $script:UnifiedRefreshTasks.Values){if(-not$Task.IsCompleted){return}}
    $Discard=$script:UnifiedRefreshDiscard;$Payload=@{};$Responses=@()
    $script:UnifiedRefreshPoller.Stop()
    try{
        foreach($Key in @($script:UnifiedRefreshTasks.Keys)){
            $Resp=$script:UnifiedRefreshTasks[$Key].GetAwaiter().GetResult();$Responses+=$Resp
            $Text=$Resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if(-not$Resp.IsSuccessStatusCode){throw ("refresh "+$Key+" HTTP "+[int]$Resp.StatusCode+" "+$Text)}
            $Payload[$Key]=if([string]::IsNullOrWhiteSpace($Text)){$null}else{$Text|ConvertFrom-Json}
        }
        if(-not$Discard){ApplyUnifiedRefreshSnapshot $Payload.status $Payload.nodes $Payload.session $Payload.modes $Payload.multihop $Payload.events}
    }catch{
        if(-not$Discard){$StateText.Text='Controller unavailable';$StateDot.Fill='#FF5D6C';$LastErrorText.Text=$_.Exception.Message}
    }finally{
        foreach($Resp in $Responses){try{$Resp.Dispose()}catch{}}
        foreach($Req in $script:UnifiedRefreshRequests.Values){try{$Req.Dispose()}catch{}}
        try{$script:UnifiedRefreshCts.Dispose()}catch{}
        $script:UnifiedRefreshTasks=@{};$script:UnifiedRefreshRequests=@{};$script:UnifiedRefreshCts=$null;$script:UnifiedRefreshDiscard=$false
    }
}
$script:UnifiedRefreshPoller.Add_Tick({CompleteUnifiedRefreshAsync})
function GetUnifiedPresets{if(-not(Test-Path -LiteralPath $script:UnifiedPresetFile)){return @()};try{return @((Get-Content -LiteralPath $script:UnifiedPresetFile -Raw -Encoding UTF8|ConvertFrom-Json))}catch{return @()}}
function SaveUnifiedPresets($Values){[void](New-Item -ItemType Directory -Force -Path (Split-Path $script:UnifiedPresetFile));@($Values)|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $script:UnifiedPresetFile -Encoding UTF8}
function GetUnifiedModeID{if(Test-Path -LiteralPath $script:UnifiedModeStateFile){$v=(Get-Content -LiteralPath $script:UnifiedModeStateFile -Raw -Encoding UTF8).Trim();if($v){return $v}};return 'smart-auto'}
function SaveUnifiedModeID([string]$Value){[void](New-Item -ItemType Directory -Force -Path (Split-Path $script:UnifiedModeStateFile));Set-Content -LiteralPath $script:UnifiedModeStateFile -Value $Value -Encoding UTF8}
function RefreshUnifiedModeChoices($Modes){$Wanted=GetUnifiedModeID;$Values=New-Object System.Collections.ArrayList;[void]$Values.Add([pscustomobject]@{id='smart-auto';display='SMART AUTO — recommended';available=$true});[void]$Values.Add([pscustomobject]@{id='auto';display='AUTO — first proven path';available=$true});foreach($M in @($Modes)){$Reason=[string]$M.reason_text;$Label=if([bool]$M.available){[string]$M.name}else{"$($M.name) — unavailable: $Reason"};[void]$Values.Add([pscustomobject]@{id=[string]$M.id;display=$Label;available=[bool]$M.available})};foreach($P in @(GetUnifiedPresets)){[void]$Values.Add([pscustomobject]@{id=('custom:'+[string]$P.name);display=('CUSTOM • '+[string]$P.name);available=$true})};[void]$Values.Add([pscustomobject]@{id='custom:new';display='New CUSTOM preset…';available=$true});$script:UnifiedModeChoices=@($Values);$ModeCombo.ItemsSource=$script:UnifiedModeChoices;$ModeCombo.SelectedValue=$Wanted;if(-not$ModeCombo.SelectedItem){$ModeCombo.SelectedValue='smart-auto';SaveUnifiedModeID 'smart-auto'}}
function UnifiedSelectedProfile{try{$S=Api '/api/profiles' -Timeout 4;return @($S.profiles|Where-Object{[string]$_.id -eq [string]$S.selected_id}|Select-Object -First 1)}catch{return $null}}
function OpenUnifiedDetail([int]$Index){(Control 'UnifiedShell').Visibility='Collapsed';(Control 'LegacyDetailTabs').Visibility='Visible';(Control 'LegacyDetailTabs').SelectedIndex=$Index;(Control 'UnifiedBackButton').Visibility='Visible'}
function BackUnifiedMap{(Control 'LegacyDetailTabs').Visibility='Collapsed';(Control 'UnifiedBackButton').Visibility='Collapsed';(Control 'UnifiedShell').Visibility='Visible';RefreshProduct}
function UnifiedConnect{
    if(UnifiedAsyncBusy){
        [void](CancelUnifiedApiAsync $true)
        Log 'Cancelling active Router VPN action; disconnect will follow cleanup.'
        return
    }
    try{
        $Status=Api '/api/status' -Timeout 3;$Phase=[string]$Status.phase
        if([bool]$Status.connected -or $Phase -match '^(starting|checking)|trying|proving'){
            [void](StartUnifiedApiAsync 'Disconnecting…' '/api/disconnect' 'POST' @{} 20 {param($R)Log 'Disconnected'} {param($E)Log ('Disconnect failed: '+$E)} $null)
            return
        }
        $Path='';$Body=@{};$Timeout=180;$Label='Connecting…'
        if((Control 'UnifiedMultihop').IsChecked){
            $Entry=[string]$MultihopEntryCombo.SelectedValue;$Exit=[string]$MultihopExitCombo.SelectedValue
            if(-not$Entry-or-not$Exit-or$Entry-eq$Exit){throw 'Multihop requires different entry and exit nodes.'}
            $Path='/api/multihop/connect';$Body=@{entry_id=$Entry;exit_id=$Exit;base='wg';exit_mode=(MultihopExitModeChoice)};$Timeout=200;$Label='Connecting multihop…'
        }else{
            $P=UnifiedSelectedProfile
            if($P-and(([string]$P.node_kind).ToLowerInvariant()-eq'external')){
                $Path='/api/external-profile/connect';$Body=@{profile_id=[string]$P.id};$Timeout=180;$Label='Connecting external exit…'
            }else{
                $ID=[string]$ModeCombo.SelectedValue;if(-not$ID){$ID='smart-auto'}
                if($ID-eq'custom:new'){ShowUnifiedCustomBuilder;return}
                if($ID-eq'smart-auto'){$Path='/api/strategy/smart-auto';$Timeout=240;$Label='SMART AUTO…'}
                elseif($ID-eq'auto'){$Path='/api/strategy/auto';$Timeout=200;$Label='AUTO…'}
                elseif($ID.StartsWith('custom:')){
                    $Name=$ID.Substring(7);$Preset=@(GetUnifiedPresets|Where-Object{[string]$_.name-eq$Name}|Select-Object -First 1)
                    if(-not$Preset){throw 'Saved CUSTOM preset is missing.'}
                    $Path='/api/strategy/custom';$Body=@{layers=@($Preset.layers)};$Timeout=240;$Label='CUSTOM…'
                }else{
                    $Choice=@($script:UnifiedModeChoices|Where-Object{[string]$_.id-eq$ID}|Select-Object -First 1)
                    if($Choice-and-not[bool]$Choice.available){throw [string]$Choice.display}
                    $Path='/api/connect-logical';$Body=@{mode=$ID;base='auto'};$Timeout=180;$Label='Connecting…'
                }
            }
        }
        $Success={param($R)
            if($null-ne$R.runtime_mode){Log ('Connected winner: '+[string]$R.runtime_mode)}
            elseif($null-ne$R.profile){Log ('External connected: '+[string]$R.profile.name)}
            elseif($null-ne$R.entry_id){Log ("Multihop connected entry=$($R.entry_id) exit=$($R.exit_id)")}
            else{Log 'Connection proved.'}
        }.GetNewClosure()
        [void](StartUnifiedApiAsync $Label $Path 'POST' $Body $Timeout $Success {param($E)Log ('Connect failed: '+$E)} $null)
    }catch{Log ('Connect failed: '+$_.Exception.Message);RefreshProduct}
}
function ShowUnifiedCustomBuilder{
 try{$Raw=@(Api '/api/logical-modes' -Timeout 12);$Layers=New-Object 'System.Collections.Generic.HashSet[string]';foreach($M in $Raw){foreach($V in @($M.variants.PSObject.Properties)){if($V.Value -and $V.Value.mode){foreach($L in @($V.Value.mode.layers)){if($L){[void]$Layers.Add([string]$L)}}}}};$LayerList=@($Layers|Sort-Object);if(-not $LayerList){throw 'No mode layers are available.'}
 [xml]$X=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="CUSTOM preset builder" Width="650" Height="640" MinWidth="520" MinHeight="460" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF"><Grid Margin="18"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Build a validated CUSTOM mode" FontSize="24" FontWeight="Bold"/><TextBox Name="PresetName" Grid.Row="1" Margin="0,12,0,10" Padding="8" ToolTip="Preset name"/><ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto"><StackPanel Name="LayerStack"/></ScrollViewer><StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0"><Button Name="Delete" Content="Delete saved preset" Padding="10,6" Margin="4"/><Button Name="Cancel" Content="Cancel" Padding="10,6" Margin="4"/><Button Name="Save" Content="Save" Padding="12,6" Margin="4"/><Button Name="SaveConnect" Content="Save &amp; Connect" Padding="12,6" Margin="4"/></StackPanel></Grid></Window>
"@;$R=New-Object System.Xml.XmlNodeReader $X;$D=[Windows.Markup.XamlReader]::Load($R);$D.Owner=$Window;$Name=$D.FindName('PresetName');$Stack=$D.FindName('LayerStack');$Checks=@{};foreach($L in $LayerList){$C=New-Object Windows.Controls.CheckBox;$C.Content=$L;$C.Margin='2';$Checks[$L]=$C;[void]$Stack.Children.Add($C)};$Current=[string]$ModeCombo.SelectedValue;$EditingName='';$PreservedUnknown=@();if($Current.StartsWith('custom:')){$N=$Current.Substring(7);$Old=@(GetUnifiedPresets|Where-Object{[string]$_.name -eq $N}|Select-Object -First 1);if($Old){$EditingName=$N;$Name.Text=$N;foreach($L in @($Old.layers)){if($Checks.ContainsKey([string]$L)){$Checks[[string]$L].IsChecked=$true}else{$PreservedUnknown+=[string]$L}}}}
 $SaveAction={param([bool]$Connect);$N=$Name.Text.Trim();$Known=@($LayerList|Where-Object{$Checks[$_].IsChecked});$Selected=@($Known+$PreservedUnknown|Select-Object -Unique);if(-not $N -or $N.Length -gt 64 -or $Selected.Count -eq 0){[Windows.MessageBox]::Show('Enter a 1–64 character name and choose at least one exact layer.','CUSTOM')|Out-Null;return};$P=@(GetUnifiedPresets|Where-Object{[string]$_.name -ne $N -and ([string]$_.name -ne $EditingName -or -not $EditingName)});$P+=,[pscustomobject]@{name=$N;layers=$Selected};SaveUnifiedPresets $P;SaveUnifiedModeID ('custom:'+$N);$D.Tag=if($Connect){'connect'}else{'saved'};$D.Close()};$D.FindName('Save').Add_Click({&$SaveAction $false});$D.FindName('SaveConnect').Add_Click({&$SaveAction $true});$D.FindName('Cancel').Add_Click({$D.Close()});$D.FindName('Delete').Add_Click({$N=$Name.Text.Trim();if($N){SaveUnifiedPresets @(GetUnifiedPresets|Where-Object{[string]$_.name -ne $N});SaveUnifiedModeID 'smart-auto';$D.Tag='deleted';$D.Close()}});[void]$D.ShowDialog();RefreshProduct;if([string]$D.Tag -eq 'connect'){UnifiedConnect}
 }catch{Log ('CUSTOM builder failed: '+$_.Exception.Message)}}
'@
    $ProductSource = $ProductSource.Replace($scriptMarker, $scriptMarker + "`n" + $extraState)
    if (-not $ProductSource.Contains('function RefreshProduct{')) { throw 'Windows unified shell: product refresh seam drifted.' }
    $ProductSource = $ProductSource.Replace('function RefreshProduct{','function RefreshProductLegacy{')
    if (-not $ProductSource.Contains('function ShowPairNodeDialog{')) { throw 'Windows unified shell: refresh wrapper seam drifted.' }
    $ProductSource = $ProductSource.Replace('function ShowPairNodeDialog{',"function RefreshProduct{StartUnifiedRefreshAsync}`nfunction ShowPairNodeDialog{")

    $modeRefreshOld = '$ModesGrid.ItemsSource=$Modes;$ModeCombo.ItemsSource=@($Modes|Where-Object{$_.available});if(-not$ModeCombo.SelectedValue-and$ModeCombo.Items.Count-gt0){$ModeCombo.SelectedIndex=0};'
    if (-not $ProductSource.Contains($modeRefreshOld)) { throw 'Windows unified shell: mode refresh contract drifted.' }
    $ProductSource = $ProductSource.Replace($modeRefreshOld, '$ModesGrid.ItemsSource=$Modes;RefreshUnifiedModeChoices $Modes;')

    $headerOld = '$HeaderDetail.Text="Native Windows product - $($Profiles.Count) linked node(s) - order $($script:NodeSort)";'
    $headerNew = '$HeaderDetail.Text="Native Windows product - $($Profiles.Count) linked node(s) - order $($script:NodeSort)";$ConnectionDetail.Text="Phase: $($Status.phase) • Logical: $($Status.logical_mode) • Runtime: $Runtime • Base: $($Status.base)";(Control ''UnifiedConnectButton'').Content=if($Connected -or ([string]$Status.phase -match ''starting|checking|trying|proving'')){''Disconnect''}else{''Connect''};$UnifiedSettings=(Control ''UnifiedSettingsSummary'');if($Selected.Count){$AutoReq=@();if([bool]$Profile.auto_require_encrypted){$AutoReq+="Encrypted"};if([bool]$Profile.auto_require_obfuscation){$AutoReq+="Obfuscation"};$AutoReqText=if($AutoReq.Count){$AutoReq -join "+"}else{"Off"};$UnifiedSettings.Text="IPv6=$($Profile.ipv6_mode) • MTU=$($Profile.mtu_policy)/$($Profile.effective_mtu) • LAN=$($Profile.home_lan_access) • AUTO requirements=$AutoReqText"};'
    if (-not $ProductSource.Contains($headerOld)) { throw 'Windows unified shell: refresh header contract drifted.' }
    $ProductSource = $ProductSource.Replace($headerOld,$headerNew)

    $beforeShow = '$BaseCombo.SelectedIndex=0'
    if (-not $ProductSource.Contains($beforeShow)) { throw 'Windows unified shell: startup marker drifted.' }
    $handlers = @'
(Control 'UnifiedConnectButton').Add_Click({UnifiedConnect})
(Control 'UnifiedProofButton').Add_Click({try{$R=Api '/api/home-summary/prove-exit' 'POST' @{} 15;if([string]$R.actual_exit_status -ne 'proved' -or -not [string]$R.actual_exit_ip){throw 'Current-session public-exit proof did not return proved.'};$ProofText.Text="Actual public VPN exit: $($R.actual_exit_ip) • current session proved";Log ("Actual public VPN exit proved: "+[string]$R.actual_exit_ip)}catch{Log ('Exit proof failed: '+$_.Exception.Message)};RefreshProduct})
(Control 'UnifiedEmergencyButton').Add_Click({try{[void](Api '/api/emergency-stop' 'POST' @{} 20);Log 'Emergency disconnect completed'}catch{Log ('Emergency disconnect failed: '+$_.Exception.Message)};RefreshProduct})
(Control 'UnifiedNodesButton').Add_Click({OpenUnifiedDetail 1})
(Control 'UnifiedPresetsButton').Add_Click({OpenUnifiedDetail 2})
(Control 'UnifiedDnsDetailsButton').Add_Click({OpenUnifiedDetail 3})
(Control 'UnifiedSettingsButton').Add_Click({try{$Saved=Show-RouterVPNProfileSettingsDialog -BaseUrl $BaseUrl -Owner $Window;if($null -ne $Saved){Log 'Profile settings saved'}}catch{Log ('Settings failed: '+$_.Exception.Message)};RefreshProduct})
(Control 'UnifiedMtuButton').Add_Click({if(UnifiedAsyncBusy){Log 'MTU Retest refused: another Router VPN action is running.';return};[void](StartUnifiedApiAsync 'Retesting MTU…' '/api/mtu/retest' 'POST' @{} 130 {param($R)Log ("MTU Retest: effective=$($R.effective_mtu) source=$($R.effective_mtu_source)")} {param($E)Log ('MTU Retest failed: '+$E)} $null)})
(Control 'UnifiedBackButton').Add_Click({BackUnifiedMap})`n$Window.Add_Closed({try{if(UnifiedAsyncBusy){[void](CancelUnifiedApiAsync $false)}}catch{};try{if(UnifiedRefreshBusy){[void](CancelUnifiedRefreshAsync)}}catch{};try{$script:UnifiedAsyncPoller.Stop();$script:UnifiedRefreshPoller.Stop()}catch{};try{$script:UnifiedAsyncClient.Dispose();$script:UnifiedRefreshClient.Dispose()}catch{}})
(Control 'UnifiedModeCombo').Add_SelectionChanged({if($ModeCombo.SelectedValue){$ID=[string]$ModeCombo.SelectedValue;if($ID -eq 'custom:new'){ShowUnifiedCustomBuilder}else{SaveUnifiedModeID $ID}}})
(Control 'UnifiedKillSwitch').Add_Click({try{$On=[bool](Control 'UnifiedKillSwitch').IsChecked;[void](Api '/api/profile/settings' 'POST' @{kill_switch_policy=if($On){'on-connect'}else{'off'}} 12);Log (if($On){'Kill switch enabled'}else{'Kill switch disabled'})}catch{Log ('Kill switch update failed: '+$_.Exception.Message)};RefreshProduct})
(Control 'UnifiedDnsCombo').Add_SelectionChanged({if(-not $script:Busy){$Tag=ComboTag (Control 'UnifiedDnsCombo') 'home';if($Tag -in @('custom','dot','doh','doh3')){OpenUnifiedDetail 3}else{try{[void](Api '/api/dns/policy' 'POST' @{mode=$Tag} 10);Log ('DNS selected: '+$Tag)}catch{Log ('DNS update failed: '+$_.Exception.Message)};RefreshDnsPolicy;RefreshProduct}}})
'@
    $ProductSource = $ProductSource.Replace($beforeShow, $handlers + "`n" + $beforeShow)

    $ProductSource += "`n# Unified Windows UX contract: map-first bottom control sheet Connect Disconnect quick kill switch Prove actual exit current-session proof Emergency disconnect Multihop Settings Mode DNS SMART AUTO default AUTO all presets CUSTOM visual preset builder saved delete Router node Custom external real coordinates color-coded hop roles IPv6 On Auto MTU Require encrypted Require obfuscation.`n"
    return $ProductSource
}
