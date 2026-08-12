param(
  [string]$Root = (Split-Path -Parent $PSScriptRoot),
  [string]$Source = '',
  [string]$Output = '',
  [string]$ClientConfig = '',
  [string]$ModesDir = '',
  [string]$HelpersRoot = ''
)

$ErrorActionPreference = 'Stop'
function Write-Utf8NoBom([string]$Path,[string]$Text) {
  [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}
$Root = [IO.Path]::GetFullPath($Root)
if (-not $Source) { $Source = Join-Path $Root 'modes.json' }
if (-not $Output) { $Output = Join-Path $Root 'modes.windows.json' }
if (-not $ClientConfig) { $ClientConfig = Join-Path $Root 'client.json' }
if (-not $ModesDir) { $ModesDir = Join-Path $Root 'modes' }
if (-not $HelpersRoot) { $HelpersRoot = Join-Path $Root 'client' }
$NativeWG = Join-Path $HelpersRoot 'native-wireguard-windows.ps1'
$NativeLayered = Join-Path $HelpersRoot 'native-windows-mode.ps1'
$NativeLayeredIds = @('hysteria2','shadowsocks','naive-h2','naive-h3','reality-vision','reality-pq-vision','split','max')

if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Missing $Source" }
if (-not (Test-Path -LiteralPath $ClientConfig -PathType Leaf)) { throw "Missing $ClientConfig" }

$modes = Get-Content -Raw -LiteralPath $Source | ConvertFrom-Json
foreach ($mode in $modes) {
  if ($mode.id -eq 'wg' -and (Test-Path -LiteralPath $NativeWG -PathType Leaf)) {
    $mode.command = @('powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',$NativeWG,'up')
    $mode.check_command = @('powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',$NativeWG,'check')
    $mode.stop_command = @('powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',$NativeWG,'down')
    continue
  }
  if (($NativeLayeredIds -contains [string]$mode.id) -and (Test-Path -LiteralPath $NativeLayered -PathType Leaf)) {
    $mode.command = @('powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',$NativeLayered,'-Mode',[string]$mode.id,'-Action','up')
    $mode.check_command = @('powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',$NativeLayered,'-Mode',[string]$mode.id,'-Action','check')
    $mode.stop_command = @('powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',$NativeLayered,'-Mode',[string]$mode.id,'-Action','down')
    continue
  }
  foreach ($property in @('command','check_command','stop_command')) {
    $value = $mode.$property
    if (-not $value -or $value.Count -eq 0) { continue }
    if (-not ([string]$value[0]).StartsWith('./')) { continue }
    $message = "Mode '$($mode.id)' has no native Windows adapter yet. Router VPN will not pretend this mode is ready through a compatibility layer."
    $mode.$property = @('cmd.exe','/d','/c',"echo $message 1>&2 & exit /b 127")
  }
}

Write-Utf8NoBom $Output (($modes | ConvertTo-Json -Depth 30) + "`n")
$config = Get-Content -Raw -LiteralPath $ClientConfig | ConvertFrom-Json
$config.modes_file = $Output
$config.scripts_dir = $ModesDir
$config.state_file = Join-Path $Root 'state.json'
$config.profiles_file = Join-Path $Root 'routers.json'
if (-not $config.health_url) { $config | Add-Member -NotePropertyName health_url -NotePropertyValue 'http://10.77.0.1:8787/health' -Force }
Write-Utf8NoBom $ClientConfig (($config | ConvertTo-Json -Depth 30) + "`n")
Write-Output 'Prepared Windows mode catalog: WireGuard=native tunnel service; compatible layered modes=native sing-box/Xray TUN; unsupported engines=truthfully unavailable.'
