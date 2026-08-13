param(
    [string]$BaseUrl = 'http://127.0.0.1:8788',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')
if ($BaseUrl -ne 'http://127.0.0.1:8788') {
    throw 'Router VPN native Windows app only talks to the fixed local controller at http://127.0.0.1:8788.'
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

[xml]$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Router VPN" Height="720" Width="1040" MinHeight="620" MinWidth="900"
        WindowStartupLocation="CenterScreen" Background="#0B1020" Foreground="#F5F7FF">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Margin" Value="4"/><Setter Property="Padding" Value="14,8"/>
      <Setter Property="Background" Value="#3157E3"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Margin" Value="4"/><Setter Property="Padding" Value="8"/>
      <Setter Property="Background" Value="#161F36"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderBrush" Value="#33415F"/>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Margin" Value="4"/><Setter Property="Padding" Value="7"/>
      <Setter Property="Background" Value="#161F36"/><Setter Property="Foreground" Value="Black"/>
    </Style>
    <Style TargetType="GroupBox">
      <Setter Property="Margin" Value="8"/><Setter Property="Padding" Value="10"/>
      <Setter Property="BorderBrush" Value="#263452"/><Setter Property="Foreground" Value="#F5F7FF"/>
    </Style>
  </Window.Resources>
  <Grid Margin="18">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Grid Grid.Row="0" Margin="4,0,4,14">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <StackPanel>
        <TextBlock Text="Router VPN" FontSize="30" FontWeight="Bold"/>
        <TextBlock Name="HeaderDetail" Text="Local native app • proven controller runtime" Foreground="#93A4C7" Margin="0,4,0,0"/>
      </StackPanel>
      <Border Grid.Column="1" Background="#152038" CornerRadius="16" Padding="16,8" VerticalAlignment="Center">
        <StackPanel Orientation="Horizontal"><Ellipse Name="StateDot" Width="10" Height="10" Fill="#6B7280" Margin="0,0,8,0"/><TextBlock Name="StateText" Text="Checking…" FontWeight="SemiBold"/></StackPanel>
      </Border>
    </Grid>

    <TabControl Grid.Row="1" Name="Tabs" Background="#0F172A" BorderBrush="#263452" Foreground="#E8ECF8">
      <TabItem Header="Connect">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="12">
            <GroupBox Header="Connection">
              <StackPanel>
                <TextBlock Text="Router" Foreground="#93A4C7"/>
                <ComboBox Name="RouterCombo" DisplayMemberPath="name" SelectedValuePath="id"/>
                <TextBlock Text="Mode" Foreground="#93A4C7" Margin="0,8,0,0"/>
                <ComboBox Name="ModeCombo" DisplayMemberPath="name" SelectedValuePath="id"/>
                <TextBlock Text="Tunnel base" Foreground="#93A4C7" Margin="0,8,0,0"/>
                <ComboBox Name="BaseCombo"><ComboBoxItem Content="Auto" Tag="auto"/><ComboBoxItem Content="WireGuard" Tag="wg"/><ComboBoxItem Content="AmneziaWG" Tag="awg"/></ComboBox>
                <WrapPanel Margin="0,12,0,0">
                  <Button Name="AutoButton" Content="AUTO Connect"/>
                  <Button Name="ConnectButton" Content="Connect Selected"/>
                  <Button Name="DisconnectButton" Content="Disconnect" Background="#B83248"/>
                  <Button Name="RefreshButton" Content="Refresh" Background="#33415F"/>
                </WrapPanel>
                <TextBlock Name="ConnectionDetail" TextWrapping="Wrap" Margin="4,12,4,0" Foreground="#A8B6D5"/>
              </StackPanel>
            </GroupBox>
            <GroupBox Header="Connection proof">
              <StackPanel>
                <TextBlock Name="ProofText" Text="Connected is accepted only after the controller's selected-router private path proof succeeds." TextWrapping="Wrap"/>
                <TextBlock Name="LastErrorText" Foreground="#FF9CA8" TextWrapping="Wrap" Margin="0,8,0,0"/>
              </StackPanel>
            </GroupBox>
          </StackPanel>
        </ScrollViewer>
      </TabItem>

      <TabItem Header="Nodes">
        <Grid Margin="14">
          <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <DataGrid Name="NodesGrid" AutoGenerateColumns="False" IsReadOnly="True" Background="#111A2E" Foreground="White" BorderBrush="#263452" HeadersVisibility="Column">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Name" Binding="{Binding name}" Width="2*"/>
              <DataGridTextColumn Header="Endpoint" Binding="{Binding endpoint}" Width="2*"/>
              <DataGridTextColumn Header="DNS" Binding="{Binding dns_host}" Width="*"/>
              <DataGridTextColumn Header="Median ms" Binding="{Binding latency_median_ms}" Width="*"/>
              <DataGridTextColumn Header="Public exit" Binding="{Binding public_ip}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
          <WrapPanel Grid.Row="1" Margin="0,10,0,0">
            <Button Name="SelectNodeButton" Content="Select highlighted node"/>
            <Button Name="LatencyButton" Content="Run 50-sample latency" Background="#33415F"/>
          </WrapPanel>
        </Grid>
      </TabItem>

      <TabItem Header="Methods">
        <Grid Margin="14">
          <DataGrid Name="ModesGrid" AutoGenerateColumns="False" IsReadOnly="True" Background="#111A2E" Foreground="White" BorderBrush="#263452" HeadersVisibility="Column">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Mode" Binding="{Binding name}" Width="2*"/>
              <DataGridCheckBoxColumn Header="Available" Binding="{Binding available}" Width="90"/>
              <DataGridTextColumn Header="Ready bases" Binding="{Binding ready_bases_text}" Width="130"/>
              <DataGridTextColumn Header="Reason / readiness" Binding="{Binding reason}" Width="3*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>

      <TabItem Header="Diagnostics">
        <StackPanel Margin="18">
          <TextBlock Text="Live proof and recovery" FontSize="20" FontWeight="Bold"/>
          <TextBlock Text="These actions use the same local controller API as the tunnel runtime. No browser or embedded website is involved." Foreground="#93A4C7" TextWrapping="Wrap" Margin="0,6,0,14"/>
          <WrapPanel>
            <Button Name="PublicIpButton" Content="Prove public VPN exit"/>
            <Button Name="DnsButton" Content="Retest home-exit DNS"/>
            <Button Name="EmergencyButton" Content="Emergency stop" Background="#B83248"/>
          </WrapPanel>
          <TextBox Name="DiagnosticsBox" Height="300" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Margin="4,16,4,4"/>
        </StackPanel>
      </TabItem>
    </TabControl>

    <TextBlock Grid.Row="2" Name="Footer" Margin="4,12,4,0" Foreground="#7E90B6" Text="Router VPN native Windows shell • controller bound to 127.0.0.1 only"/>
  </Grid>
</Window>
'@

$Reader = New-Object System.Xml.XmlNodeReader $Xaml
$Window = [Windows.Markup.XamlReader]::Load($Reader)
if ($SelfTest) {
    foreach ($required in @('StateText','RouterCombo','ModeCombo','AutoButton','ConnectButton','DisconnectButton','NodesGrid','ModesGrid','PublicIpButton','EmergencyButton')) {
        if (-not $Window.FindName($required)) { throw "Native WPF self-test missing control: $required" }
    }
    $source = Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw
    foreach ($api in @('/api/status','/api/profiles','/api/logical-modes','/api/auto','/api/connect-logical','/api/disconnect','/api/profile/select','/api/profile/latency','/api/public-ip','/api/dns/retest','/api/emergency-stop')) {
        if ($source -notlike "*$api*") { throw "Native WPF self-test missing API contract: $api" }
    }
    if ($source -match '--app=|WebBrowser|WebView2|msedge\.exe|chrome\.exe') { throw 'Native WPF app must not embed or launch a browser app-window.' }
    Write-Host 'Router VPN native Windows WPF self-test: OK'
    exit 0
}

function Get-Control([string]$Name) { $Window.FindName($Name) }
$StateText = Get-Control 'StateText'; $StateDot = Get-Control 'StateDot'; $HeaderDetail = Get-Control 'HeaderDetail'
$RouterCombo = Get-Control 'RouterCombo'; $ModeCombo = Get-Control 'ModeCombo'; $BaseCombo = Get-Control 'BaseCombo'
$ConnectionDetail = Get-Control 'ConnectionDetail'; $LastErrorText = Get-Control 'LastErrorText'; $ProofText = Get-Control 'ProofText'
$NodesGrid = Get-Control 'NodesGrid'; $ModesGrid = Get-Control 'ModesGrid'; $DiagnosticsBox = Get-Control 'DiagnosticsBox'

function Invoke-RouterVPN {
    param([string]$Path, [string]$Method = 'GET', $Body = $null, [int]$TimeoutSec = 45)
    $uri = "$BaseUrl$Path"
    if ($Method -eq 'GET') {
        return Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec $TimeoutSec
    }
    $json = if ($null -eq $Body) { '{}' } else { $Body | ConvertTo-Json -Depth 12 -Compress }
    return Invoke-RestMethod -Uri $uri -Method $Method -ContentType 'application/json' -Body $json -TimeoutSec $TimeoutSec
}

function Write-Diagnostic([string]$Text) {
    $stamp = Get-Date -Format 'HH:mm:ss'
    $DiagnosticsBox.AppendText("[$stamp] $Text`r`n")
    $DiagnosticsBox.ScrollToEnd()
}

function Get-SelectedBase {
    $item = $BaseCombo.SelectedItem
    if ($item -and $item.Tag) { return [string]$item.Tag }
    return 'auto'
}

function Refresh-RouterVPN {
    try {
        $status = Invoke-RouterVPN '/api/status' -TimeoutSec 3
        $connected = [bool]$status.connected
        $StateText.Text = if ($connected) { 'Connected' } elseif ($status.phase) { [string]$status.phase } else { 'Off' }
        $StateDot.Fill = if ($connected) { '#35D07F' } elseif ($status.phase -eq 'failed') { '#FF5D6C' } elseif ($status.phase -match 'starting|checking|auto') { '#F2B84B' } else { '#6B7280' }
        $runtime = if ($status.runtime_mode) { $status.runtime_mode } else { $status.mode }
        $ConnectionDetail.Text = "Phase: $($status.phase)   Logical: $($status.logical_mode)   Runtime: $runtime   Base: $($status.base)   Router: $($status.router_id)"
        $LastErrorText.Text = [string]$status.last_error
        if ($connected) { $ProofText.Text = 'Connected • selected-router private path proof passed before the controller set Connected=true.' }

        $profiles = Invoke-RouterVPN '/api/profiles' -TimeoutSec 3
        $profileItems = @($profiles.profiles)
        $RouterCombo.ItemsSource = $profileItems
        $NodesGrid.ItemsSource = $profileItems
        if ($profiles.selected_id) { $RouterCombo.SelectedValue = [string]$profiles.selected_id }

        $modes = @(Invoke-RouterVPN '/api/logical-modes' -TimeoutSec 12)
        foreach ($m in $modes) { $m | Add-Member -NotePropertyName ready_bases_text -NotePropertyValue ((@($m.ready_bases) -join ', ').ToUpperInvariant()) -Force }
        $ModesGrid.ItemsSource = $modes
        $ModeCombo.ItemsSource = @($modes | Where-Object { $_.available })
        if (-not $ModeCombo.SelectedValue -and $ModeCombo.Items.Count -gt 0) { $ModeCombo.SelectedIndex = 0 }
        $HeaderDetail.Text = "Native Windows app • $($profileItems.Count) linked node(s) • $(@($modes | Where-Object available).Count)/$($modes.Count) modes ready"
    } catch {
        $StateText.Text = 'Controller unavailable'
        $StateDot.Fill = '#FF5D6C'
        $LastErrorText.Text = $_.Exception.Message
    }
}

(Get-Control 'RefreshButton').Add_Click({ Refresh-RouterVPN })
(Get-Control 'AutoButton').Add_Click({
    try {
        $StateText.Text = 'AUTO connecting…'; $StateDot.Fill = '#F2B84B'
        $r = Invoke-RouterVPN '/api/auto' 'POST' @{} 120
        Write-Diagnostic("AUTO selected runtime $($r.runtime_mode)")
    } catch { Write-Diagnostic("AUTO failed: $($_.Exception.Message)") }
    Refresh-RouterVPN
})
(Get-Control 'ConnectButton').Add_Click({
    try {
        $mode = [string]$ModeCombo.SelectedValue
        if (-not $mode) { throw 'Choose an available mode.' }
        $base = Get-SelectedBase
        $StateText.Text = 'Connecting…'; $StateDot.Fill = '#F2B84B'
        $r = Invoke-RouterVPN '/api/connect-logical' 'POST' @{mode=$mode;base=$base} 150
        Write-Diagnostic("Connected logical=$($r.logical_mode) runtime=$($r.runtime_mode) base=$($r.base) fallback=$($r.fallback_used)")
    } catch { Write-Diagnostic("Connect failed: $($_.Exception.Message)") }
    Refresh-RouterVPN
})
(Get-Control 'DisconnectButton').Add_Click({
    try { [void](Invoke-RouterVPN '/api/disconnect' 'POST' @{} 15); Write-Diagnostic 'Disconnected.' } catch { Write-Diagnostic("Disconnect failed: $($_.Exception.Message)") }
    Refresh-RouterVPN
})
(Get-Control 'SelectNodeButton').Add_Click({
    try {
        $row = $NodesGrid.SelectedItem
        if (-not $row -or -not $row.id) { throw 'Highlight a node first.' }
        [void](Invoke-RouterVPN '/api/profile/select' 'POST' @{id=[string]$row.id} 10)
        Write-Diagnostic("Selected node: $($row.name)")
    } catch { Write-Diagnostic("Select node failed: $($_.Exception.Message)") }
    Refresh-RouterVPN
})
(Get-Control 'LatencyButton').Add_Click({
    try {
        $row = $NodesGrid.SelectedItem
        if (-not $row -or -not $row.id) { throw 'Highlight a node first.' }
        $r = Invoke-RouterVPN '/api/profile/latency' 'POST' @{id=[string]$row.id;samples=50} 180
        Write-Diagnostic("Latency $($row.name): median=$($r.median_ms)ms trimmed=$($r.trimmed_mean_ms)ms p90=$($r.p90_ms)ms samples=$($r.samples) failed=$($r.failed)")
    } catch { Write-Diagnostic("Latency test failed: $($_.Exception.Message)") }
    Refresh-RouterVPN
})
(Get-Control 'PublicIpButton').Add_Click({
    try { $r = Invoke-RouterVPN '/api/public-ip' 'GET' $null 12; Write-Diagnostic("Public VPN exit: $($r.public_ip) • router=$($r.router_id) • multihop=$($r.multihop)") } catch { Write-Diagnostic("Public exit proof failed: $($_.Exception.Message)") }
    Refresh-RouterVPN
})
(Get-Control 'DnsButton').Add_Click({
    try { $r = Invoke-RouterVPN '/api/dns/retest' 'POST' @{} 60; Write-Diagnostic("DNS winner: $($r.winner.name) $($r.winner.address) $($r.winner.latency_ms)ms") } catch { Write-Diagnostic("DNS retest failed: $($_.Exception.Message)") }
    Refresh-RouterVPN
})
(Get-Control 'EmergencyButton').Add_Click({
    try { [void](Invoke-RouterVPN '/api/emergency-stop' 'POST' @{} 15); Write-Diagnostic 'Emergency stop completed.' } catch { Write-Diagnostic("Emergency stop failed: $($_.Exception.Message)") }
    Refresh-RouterVPN
})
$RouterCombo.Add_SelectionChanged({
    if ($RouterCombo.SelectedValue) {
        try { [void](Invoke-RouterVPN '/api/profile/select' 'POST' @{id=[string]$RouterCombo.SelectedValue} 10) } catch { Write-Diagnostic("Router switch failed: $($_.Exception.Message)") }
        Refresh-RouterVPN
    }
})

$BaseCombo.SelectedIndex = 0
$Timer = New-Object Windows.Threading.DispatcherTimer
$Timer.Interval = [TimeSpan]::FromSeconds(2)
$Timer.Add_Tick({ Refresh-RouterVPN })
$Window.Add_Closed({ $Timer.Stop() })
Refresh-RouterVPN
$Timer.Start()
[void]$Window.ShowDialog()
