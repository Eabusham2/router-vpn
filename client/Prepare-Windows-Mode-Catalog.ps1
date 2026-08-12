param(
  [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath($Root)
$Source = Join-Path $Root 'modes.json'
$Output = Join-Path $Root 'modes.windows.json'
$ClientConfig = Join-Path $Root 'client.json'
$ModesDir = Join-Path $Root 'modes'
$NativeWG = Join-Path $Root 'client\native-wireguard-windows.ps1'

if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Missing $Source" }
if (-not (Test-Path -LiteralPath $ClientConfig -PathType Leaf)) { throw "Missing $ClientConfig" }

$modes = Get-Content -Raw -LiteralPath $Source | ConvertFrom-Json
$linuxModes = $null
try {
  $linuxModes = (& wsl.exe --exec wslpath -a -u $ModesDir 2>$null | Select-Object -First 1).Trim()
  if (-not $linuxModes) { $linuxModes = $null }
} catch { $linuxModes = $null }

foreach ($mode in $modes) {
  if ($mode.id -eq 'wg' -and (Test-Path -LiteralPath $NativeWG -PathType Leaf)) {
    $mode.command = @('powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',$NativeWG,'up')
    $mode.check_command = @('powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',$NativeWG,'check')
    $mode.stop_command = @('powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',$NativeWG,'down')
    continue
  }
  foreach ($property in @('command','check_command','stop_command')) {
    $value = $mode.$property
    if (-not $value -or $value.Count -eq 0) { continue }
    $first = [string]$value[0]
    if (-not $first.StartsWith('./')) { continue }
    if ($linuxModes) {
      $script = $linuxModes.TrimEnd('/') + '/' + [IO.Path]::GetFileName($first)
      $rest = @()
      if ($value.Count -gt 1) { $rest = @($value | Select-Object -Skip 1) }
      $mode.$property = @('wsl.exe','--exec','bash',$script) + $rest
    } else {
      $message = 'This layered Router VPN mode requires WSL2/default Linux until its native Windows adapter is implemented. Run Setup-Windows-Runtime.ps1.'
      $mode.$property = @('cmd.exe','/d','/c',"echo $message 1>&2 & exit /b 127")
    }
  }
}

$modes | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 -LiteralPath $Output

$config = Get-Content -Raw -LiteralPath $ClientConfig | ConvertFrom-Json
$config.modes_file = $Output
$config.scripts_dir = $ModesDir
$config.state_file = Join-Path $Root 'state.json'
$config.profiles_file = Join-Path $Root 'routers.json'
if (-not $config.health_url) { $config | Add-Member -NotePropertyName health_url -NotePropertyValue 'http://10.77.0.1:8787/health' -Force }
$config | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 -LiteralPath $ClientConfig

Write-Output "Prepared Windows mode catalog: raw WireGuard=native tunnel service; layered modes=$([bool]$linuxModes ? 'WSL2' : 'unavailable without WSL2')."
