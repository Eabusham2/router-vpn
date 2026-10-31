param(
    [string]$BaseUrl = 'http://127.0.0.1:8788',
    [int]$UiPid = 0,
    [long]$UiCreationTicks = 0,
    [switch]$SelfTest,
    [string]$ControllerPipe,
    [long]$ControllerParentHandle
)

$ErrorActionPreference = 'Stop'
# Read the loaded function directly without initializing a provider cmdlet;
# the captured module below owns first import.
if($null-eq${function:New-RouterVPNControllerClient}){
    Import-Module ([IO.Path]::Combine($PSScriptRoot,'RouterVPN-Windows-ControllerTransport.psm1')) -Global -ErrorAction Stop
}

$Handoff=@{}
foreach($Name in @('ControllerPipe','ControllerParentHandle')){if($PSBoundParameters.ContainsKey($Name)){$Handoff[$Name]=$PSBoundParameters[$Name]}}
$CapturedBase=Initialize-RouterVPNControllerTransport @Handoff
try{
if(-not$PSBoundParameters.ContainsKey('BaseUrl')){$BaseUrl=$CapturedBase}
$BaseUrl=$BaseUrl.TrimEnd('/')
if($BaseUrl-cne$CapturedBase){throw 'Router VPN requires the fixed local controller captured by this UI owner.'}
Assert-RouterVPNControllerBaseUrl $BaseUrl

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class RouterVPNWindowNative {
    [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
}
'@

$Root = Microsoft.PowerShell.Management\Split-Path -Parent $PSScriptRoot
$IconPath = Join-Path $Root 'RouterVPN.ico'
$PrivateState = Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1'
if (-not (Test-Path -LiteralPath $PrivateState -PathType Leaf)) { throw 'Router VPN private-state helper is missing.' }
. $PrivateState

if ($SelfTest) {
    if($CapturedBase-ceq'https://127.0.0.1:8788'){
        $CapturedStatus=Invoke-RouterVPNControllerRequest -Uri "$BaseUrl/api/status" -Method Get -TimeoutSec 10
        if($null-eq$CapturedStatus-or[string]::IsNullOrEmpty([string]$CapturedStatus.mode)){throw 'The owned Tray did not read its real controller status.'}
    }
    if (-not (Test-Path -LiteralPath $IconPath -PathType Leaf)) { throw "Router VPN tray icon missing: $IconPath" }
    $Source = Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw
    foreach ($Marker in @('System.Windows.Forms.NotifyIcon','Open Router VPN','Emergency Stop','Exit Router VPN','/api/emergency-stop','ShowWindowAsync','SetForegroundWindow','PostMessage','IsIconic','Get-RouterVPNProcessIdentity','start_time_utc_ticks','executable_path')) {
        if ($Source -notlike "*$Marker*") { throw "Router VPN tray self-test missing $Marker" }
    }
    Write-Host 'Router VPN Windows system-tray self-test: OK'
    exit 0
}

if ($UiPid -le 0) { throw 'Router VPN tray requires the native WPF process ID.' }
if (-not (Test-Path -LiteralPath $IconPath -PathType Leaf)) { throw "Router VPN tray icon missing: $IconPath" }

$InitialUiProcess = Get-Process -Id $UiPid -ErrorAction Stop
$UiIdentity = Get-RouterVPNProcessIdentity $InitialUiProcess
if($CapturedBase-ceq'https://127.0.0.1:8788'-and($UiCreationTicks-le0-or[Int64]$UiIdentity.start_time_utc_ticks-ne$UiCreationTicks)){
    throw 'The Tray requires the exact App process captured by its launcher.'
}
$UiStartTicks = [Int64]$UiIdentity.start_time_utc_ticks
$UiExecutable = [string]$UiIdentity.executable_path

function Get-UiProcess {
    $p = Get-Process -Id $UiPid -ErrorAction SilentlyContinue
    if (-not $p) { return $null }
    try { $identity = Get-RouterVPNProcessIdentity $p } catch { return $null }
    if ([Int64]$identity.start_time_utc_ticks -ne $UiStartTicks) { return $null }
    if (-not [string]::Equals([string]$identity.executable_path,$UiExecutable,[StringComparison]::OrdinalIgnoreCase)) { return $null }
    return $p
}
function Get-UiHandle {
    $p = Get-UiProcess
    if (-not $p) { return [IntPtr]::Zero }
    $p.Refresh()
    return [IntPtr]$p.MainWindowHandle
}
function Show-RouterVPNWindow {
    $h = Get-UiHandle
    if ($h -eq [IntPtr]::Zero) { return }
    [void][RouterVPNWindowNative]::ShowWindowAsync($h, 9)
    [void][RouterVPNWindowNative]::SetForegroundWindow($h)
}
function Emergency-StopRouterVPN {
    try {
        Invoke-RouterVPNControllerRequest -Uri "$BaseUrl/api/emergency-stop" -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 3 | Out-Null
        $Notify.BalloonTipTitle = 'Router VPN'
        $Notify.BalloonTipText = 'Emergency stop completed.'
        $Notify.ShowBalloonTip(1500)
    } catch {
        $Notify.BalloonTipTitle = 'Router VPN'
        $Notify.BalloonTipText = "Emergency stop failed: $($_.Exception.Message)"
        $Notify.ShowBalloonTip(2500)
    }
}
function Close-RouterVPNWindow {
    $h = Get-UiHandle
    if ($h -ne [IntPtr]::Zero) {
        return [RouterVPNWindowNative]::PostMessage($h, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    }
    return $false
}

$Notify = New-Object System.Windows.Forms.NotifyIcon
$TrayIcon = New-Object System.Drawing.Icon($IconPath)
$Notify.Icon = $TrayIcon
$Notify.Text = 'Router VPN'
$Menu = New-Object System.Windows.Forms.ContextMenuStrip
$OpenItem = New-Object System.Windows.Forms.ToolStripMenuItem 'Open Router VPN'
$EmergencyItem = New-Object System.Windows.Forms.ToolStripMenuItem 'Emergency Stop'
$ExitItem = New-Object System.Windows.Forms.ToolStripMenuItem 'Exit Router VPN'
[void]$Menu.Items.Add($OpenItem)
[void]$Menu.Items.Add($EmergencyItem)
[void]$Menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
[void]$Menu.Items.Add($ExitItem)
$Notify.ContextMenuStrip = $Menu
$Notify.Visible = $true

$OpenItem.Add_Click({ Show-RouterVPNWindow })
$Notify.Add_DoubleClick({ Show-RouterVPNWindow })
$EmergencyItem.Add_Click({ Emergency-StopRouterVPN })
$ExitItem.Add_Click({
    if (-not (Close-RouterVPNWindow) -and $CapturedBase-cne'https://127.0.0.1:8788') {
        $ownedUi = Get-UiProcess
        if ($ownedUi) { Stop-Process -InputObject $ownedUi -ErrorAction SilentlyContinue }
    }
    # Owned launchers join their retained App Job after this Tray exits. Never
    # reopen and terminate a public PID on that path.
    [System.Windows.Forms.Application]::ExitThread()
})

# Minimize-to-tray without touching VPN state: once the WPF window is iconic,
# remove it from the taskbar. The tray Open action restores the same native window.
$Timer = New-Object System.Windows.Forms.Timer
$Timer.Interval = 500
$Timer.Add_Tick({
    $p = Get-UiProcess
    if (-not $p) {
        [System.Windows.Forms.Application]::ExitThread()
        return
    }
    $h = Get-UiHandle
    if ($h -ne [IntPtr]::Zero -and [RouterVPNWindowNative]::IsIconic($h)) {
        [void][RouterVPNWindowNative]::ShowWindowAsync($h, 0)
    }
})
$Timer.Start()

try {
    [System.Windows.Forms.Application]::Run()
}
finally {
    $Timer.Stop(); $Timer.Dispose()
    $Notify.Visible = $false; $Notify.Dispose()
    $TrayIcon.Dispose(); $Menu.Dispose()
}

}finally{Close-RouterVPNControllerTransport}
