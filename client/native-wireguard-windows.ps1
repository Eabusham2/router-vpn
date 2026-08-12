param(
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down','status')][string]$Action
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
  [Console]::Error.WriteLine($Message)
  exit 1
}

function Find-WireGuard {
  $candidates = @(
    (Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'WireGuard\wireguard.exe')
  )
  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate }
  }
  $cmd = Get-Command wireguard.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}

function Is-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Profile-Path {
  $root = $env:HOMEVPN_ROOT
  $id = $env:HOMEVPN_PROFILE_ID
  if (-not $root) { Fail 'HOMEVPN_ROOT is not set.' }
  if (-not $id -or $id -notmatch '^[A-Za-z0-9_-]{1,80}$') { Fail 'A valid Router VPN profile is not selected.' }
  $generated = Join-Path $root 'generated'
  $profileRoot = Join-Path $generated $id
  $candidate = Join-Path (Join-Path $profileRoot 'wg') 'wg.conf'
  $fullGenerated = [IO.Path]::GetFullPath($generated).TrimEnd('\') + '\'
  $fullCandidate = [IO.Path]::GetFullPath($candidate)
  if (-not $fullCandidate.StartsWith($fullGenerated, [StringComparison]::OrdinalIgnoreCase)) { Fail 'Unsafe WireGuard profile path.' }
  if (-not (Test-Path -LiteralPath $fullCandidate -PathType Leaf)) { Fail "Raw WireGuard profile is missing: $fullCandidate" }
  return $fullCandidate
}

$wireguard = Find-WireGuard
if (-not $wireguard) {
  Fail 'Native Windows WireGuard is unavailable. Install the official WireGuard for Windows package; Router VPN will not fake native readiness through WSL.'
}

$root = [IO.Path]::GetFullPath([string]$env:HOMEVPN_ROOT)
$killSwitch = Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
if (-not (Test-Path -LiteralPath $killSwitch -PathType Leaf)) { Fail "Windows kill-switch helper is missing: $killSwitch" }
$config = Profile-Path
$tunnelName = [IO.Path]::GetFileNameWithoutExtension($config)
$serviceName = "WireGuardTunnel`$$tunnelName"

function Invoke-KillSwitch([string]$KillAction,[string]$EndpointValue='') {
  $args=@('-Action',$KillAction,'-Root',$root)
  if ($EndpointValue) { $args += @('-Endpoint',$EndpointValue) }
  if ($KillAction -eq 'prepare') { $args += @('-TunnelAlias',$tunnelName) }
  & $killSwitch @args
  if ($LASTEXITCODE -ne 0) { throw "Windows kill-switch action '$KillAction' failed." }
}

switch ($Action) {
  'check' {
    if (-not (Is-Administrator)) { Fail 'Native WireGuard needs Administrator rights to manage the Windows tunnel service. Run Router VPN as Administrator.' }
    try { Invoke-KillSwitch 'check' } catch { Fail $_.Exception.Message }
    Write-Output "Native WireGuard for Windows ready: $wireguard"
    exit 0
  }
  'up' {
    if (-not (Is-Administrator)) { Fail 'Native WireGuard needs Administrator rights to install the Windows tunnel service.' }
    $endpoint = [string]$env:HOMEVPN_ENDPOINT
    try {
      Invoke-KillSwitch 'prepare' $endpoint
      # Ensure a prior crash/stale service cannot collide with the same deterministic
      # raw-WireGuard tunnel name. Uninstall is idempotent for our purposes.
      & $wireguard /uninstalltunnelservice $tunnelName *> $null
      $process = Start-Process -FilePath $wireguard -ArgumentList @('/installtunnelservice', $config) -Wait -PassThru -NoNewWindow
      if ($process.ExitCode -ne 0) { throw "wireguard.exe /installtunnelservice failed with exit code $($process.ExitCode)." }
      $deadline = (Get-Date).AddSeconds(12)
      do {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
          Write-Output "Native WireGuard tunnel service is running: $serviceName"
          exit 0
        }
        Start-Sleep -Milliseconds 250
      } while ((Get-Date) -lt $deadline)
      throw "Native WireGuard service did not reach Running state: $serviceName"
    } catch {
      & $wireguard /uninstalltunnelservice $tunnelName *> $null
      try { Invoke-KillSwitch 'release' } catch { }
      Fail $_.Exception.Message
    }
  }
  'down' {
    if (-not (Is-Administrator)) { Fail 'Native WireGuard needs Administrator rights to remove the Windows tunnel service.' }
    $process = Start-Process -FilePath $wireguard -ArgumentList @('/uninstalltunnelservice', $tunnelName) -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
      $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
      if ($service) { Fail "wireguard.exe /uninstalltunnelservice failed with exit code $($process.ExitCode)." }
    }
    try { Invoke-KillSwitch 'release' } catch { Fail $_.Exception.Message }
    Write-Output "Native WireGuard tunnel stopped: $tunnelName"
  }
  'status' {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) { Write-Output 'DOWN'; exit 1 }
    Write-Output $service.Status
    if ($service.Status -eq 'Running') { exit 0 }
    exit 1
  }
}
