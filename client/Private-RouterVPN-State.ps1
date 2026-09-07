# Shared read-only access to controller-owned Router VPN profile state.
# This file intentionally exposes no profile-store writer. Durable profile
# mutation belongs to the Go controller transaction layer. The only write
# primitive below is create-only and scoped to ephemeral process-ownership
# records; it never mutates routers.json or other controller-owned profile state.

function Assert-RouterVPNNoReparseAncestors([string]$Path) {
  $full = [IO.Path]::GetFullPath($Path)
  if (Test-Path -LiteralPath $full) {
    $cursor = $full
  } else {
    $cursor = Split-Path -Parent $full
  }

  while ($cursor) {
    if (Test-Path -LiteralPath $cursor) {
      $item = Get-Item -LiteralPath $cursor -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing reparse-point/junction Router VPN private path: $cursor"
      }
    }
    $parent = Split-Path -Parent $cursor
    if (-not $parent -or $parent -eq $cursor) {
      break
    }
    $cursor = $parent
  }
}

function Resolve-RouterVPNPrivateRoot([string]$RootText) {
  if ([string]::IsNullOrWhiteSpace($RootText)) {
    throw 'HOMEVPN_ROOT is required.'
  }
  $root = [IO.Path]::GetFullPath($RootText)
  Assert-RouterVPNNoReparseAncestors $root
  if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Router VPN private root is missing: $root"
  }
  $item = Get-Item -LiteralPath $root -Force
  if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "Router VPN private root is not a real directory: $root"
  }
  return $root
}

function Resolve-RouterVPNPrivateChild([string]$RootText, [string]$ChildPath) {
  $root = Resolve-RouterVPNPrivateRoot $RootText
  if ([IO.Path]::IsPathRooted($ChildPath)) {
    $full = [IO.Path]::GetFullPath($ChildPath)
  } else {
    $full = [IO.Path]::GetFullPath((Join-Path $root $ChildPath))
  }
  $prefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  if ($full -ne $root -and -not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing Router VPN path outside private root: $full"
  }
  Assert-RouterVPNNoReparseAncestors $full
  return $full
}

function Read-RouterVPNPrivateJson(
  [string]$Path,
  [string]$Label = 'Router VPN private JSON',
  [int]$Limit = 4194304
) {
  Assert-RouterVPNNoReparseAncestors $Path
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label is missing: $Path"
  }
  $before = Get-Item -LiteralPath $Path -Force
  if ($before.PSIsContainer -or (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "Unsafe reparse/non-file $Label path: $Path"
  }
  if ($before.Length -lt 0 -or $before.Length -gt $Limit) {
    throw "$Label exceeds safety limit: $Path"
  }

  # FileShare.Read intentionally excludes write/delete sharing while the bytes
  # are read, preventing replacement of the opened leaf during policy parsing.
  $stream = [IO.File]::Open(
    $Path,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read
  )
  try {
    if ($stream.Length -gt $Limit) {
      throw "$Label exceeds safety limit: $Path"
    }
    $reader = New-Object IO.StreamReader(
      $stream,
      (New-Object Text.UTF8Encoding($false)),
      $true,
      4096,
      $true
    )
    try {
      $text = $reader.ReadToEnd()
    } finally {
      $reader.Dispose()
    }

    $after = Get-Item -LiteralPath $Path -Force
    if (
      $after.PSIsContainer -or
      (($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
      $after.FullName -ne $before.FullName -or
      $after.Length -ne $stream.Length -or
      $after.LastWriteTimeUtc -ne $before.LastWriteTimeUtc
    ) {
      throw "$Label changed during read: $Path"
    }
  } finally {
    $stream.Dispose()
  }

  try {
    return $text | ConvertFrom-Json
  } catch {
    throw "Invalid $Label JSON: $Path"
  }
}

function Get-RouterVPNPrivateFileSHA256(
  [string]$Path,
  [string]$Label = 'Router VPN private file',
  [int]$Limit = 4194304
) {
  Assert-RouterVPNNoReparseAncestors $Path
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label is missing: $Path"
  }
  $before = Get-Item -LiteralPath $Path -Force
  if ($before.PSIsContainer -or (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "Unsafe reparse/non-file $Label path: $Path"
  }
  if ($before.Length -lt 0 -or $before.Length -gt $Limit) {
    throw "$Label exceeds safety limit: $Path"
  }

  # The open handle excludes write/delete sharing while SHA-256 consumes the
  # exact bytes. Recheck the pathname after hashing so a caller never accepts a
  # digest for a leaf that changed identity between scan and use.
  $stream = [IO.File]::Open(
    $Path,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read
  )
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    if ($stream.Length -gt $Limit) {
      throw "$Label exceeds safety limit: $Path"
    }
    $bytes = $sha.ComputeHash($stream)
    $after = Get-Item -LiteralPath $Path -Force
    if (
      $after.PSIsContainer -or
      (($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
      $after.FullName -ne $before.FullName -or
      $after.Length -ne $stream.Length -or
      $after.LastWriteTimeUtc -ne $before.LastWriteTimeUtc
    ) {
      throw "$Label changed during hash: $Path"
    }
    return (-join($bytes | ForEach-Object { $_.ToString('x2') }))
  } finally {
    $sha.Dispose()
    $stream.Dispose()
  }
}

function Get-RouterVPNProfileStore([string]$RootText) {
  $root = Resolve-RouterVPNPrivateRoot $RootText
  $store = Read-RouterVPNPrivateJson (Join-Path $root 'routers.json') 'Router profile store'
  if ($null -eq $store -or $null -eq $store.profiles) {
    throw 'Router profile store has no profiles array.'
  }
  return $store
}

function Get-RouterVPNSelectedProfile($Store, [string]$ProfileId) {
  $selected = $ProfileId.Trim()
  if ([string]::IsNullOrWhiteSpace($selected) -and $Store.selected_id) {
    $selected = ([string]$Store.selected_id).Trim()
  }
  if ($selected -notmatch '^[A-Za-z0-9_.-]{1,128}$') {
    throw 'A valid Router VPN profile is not selected.'
  }
  foreach ($item in @($Store.profiles)) {
    if ($item -and [string]$item.id -eq $selected) {
      return $item
    }
  }
  throw "Selected Router VPN profile '$selected' was not found."
}


function Write-RouterVPNPrivateTextAtomic([string]$Path,[string]$Text) {
  $full=[IO.Path]::GetFullPath($Path)
  Assert-RouterVPNNoReparseAncestors $full
  $parent=Split-Path -Parent $full
  if([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)){
    throw "Router VPN private parent is missing: $parent"
  }
  Assert-RouterVPNNoReparseAncestors $parent
  if(Test-Path -LiteralPath $full){
    throw "Refusing to overwrite existing Router VPN process ownership record: $full"
  }
  $leaf=Split-Path -Leaf $full
  $tmp=Join-Path $parent ('.'+$leaf+'.tmp-'+[Guid]::NewGuid().ToString('N'))
  try {
    $encoding=New-Object Text.UTF8Encoding($false)
    $bytes=$encoding.GetBytes($Text)
    $stream=New-Object IO.FileStream(
      $tmp,
      [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write,
      [IO.FileShare]::None
    )
    try {
      $stream.Write($bytes,0,$bytes.Length)
      $stream.Flush($true)
    } finally {
      $stream.Dispose()
    }
    Assert-RouterVPNNoReparseAncestors $parent
    if(Test-Path -LiteralPath $full){
      throw "Router VPN process ownership target appeared before adoption: $full"
    }
    # Two-argument File.Move is intentionally non-overwriting. If a foreign
    # target wins the race after the check, adoption fails rather than replacing
    # ambiguous process-ownership evidence.
    [IO.File]::Move($tmp,$full)
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

function Get-RouterVPNProcessIdentity($Process) {
  if($null-eq$Process){throw 'Router VPN process handle is missing.'}
  try{$Process.Refresh()}catch{}
  $pidValue=[int]$Process.Id
  if($pidValue-le0){throw 'Router VPN process id is invalid.'}
  try{$start=[Int64]$Process.StartTime.ToUniversalTime().Ticks}catch{throw "Cannot read Router VPN process start identity for PID $pidValue."}
  $exe=''
  try{$exe=[string]$Process.Path}catch{}
  if([string]::IsNullOrWhiteSpace($exe)){
    try{$exe=[string]$Process.MainModule.FileName}catch{}
  }
  if([string]::IsNullOrWhiteSpace($exe)){throw "Cannot read Router VPN process executable identity for PID $pidValue."}
  $exe=[IO.Path]::GetFullPath($exe)
  return [pscustomobject]@{
    version=1
    pid=$pidValue
    start_time_utc_ticks=$start
    executable_path=$exe
  }
}

function Write-RouterVPNProcessRecord([string]$Path,$Process) {
  $record=Get-RouterVPNProcessIdentity $Process
  $json=($record|ConvertTo-Json -Compress)+"`n"
  Write-RouterVPNPrivateTextAtomic $Path $json
}

function Get-RouterVPNVerifiedRecordedProcess([string]$Path) {
  if(-not(Test-Path -LiteralPath $Path)){return $null}
  $record=Read-RouterVPNPrivateJson $Path 'Router VPN process record' 65536
  if($null-eq$record -or [int]$record.version -ne 1){return $null}
  $pidValue=0
  if(-not [int]::TryParse(([string]$record.pid),[ref]$pidValue) -or $pidValue -le 0){return $null}
  $expectedTicks=[Int64]0
  if(-not [Int64]::TryParse(([string]$record.start_time_utc_ticks),[ref]$expectedTicks) -or $expectedTicks -le 0){return $null}
  $expectedExe=[string]$record.executable_path
  if([string]::IsNullOrWhiteSpace($expectedExe)){return $null}
  try{$expectedExe=[IO.Path]::GetFullPath($expectedExe)}catch{return $null}

  $process=Get-Process -Id $pidValue -ErrorAction SilentlyContinue
  if($null-eq$process){return $null}
  try{$identity=Get-RouterVPNProcessIdentity $process}catch{return $null}
  if([Int64]$identity.start_time_utc_ticks-ne$expectedTicks){return $null}
  if(-not[string]::Equals([string]$identity.executable_path,$expectedExe,[StringComparison]::OrdinalIgnoreCase)){return $null}
  return $process
}

function Test-RouterVPNRecordedProcess([string]$Path) {
  try{return $null-ne(Get-RouterVPNVerifiedRecordedProcess $Path)}catch{return $false}
}

function Remove-RouterVPNProcessRecord([string]$Path) {
  if(-not(Test-Path -LiteralPath $Path)){return}
  Assert-RouterVPNNoReparseAncestors $Path
  $item=Get-Item -LiteralPath $Path -Force
  if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){
    throw "Refusing unsafe Router VPN process-record target: $Path"
  }
  Remove-Item -LiteralPath $Path -Force
}

function Stop-RouterVPNRecordedProcess([string]$Path) {
  $process=$null
  try{$process=Get-RouterVPNVerifiedRecordedProcess $Path}catch{$process=$null}
  if($null-ne$process){
    Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue
  }
  try{Remove-RouterVPNProcessRecord $Path}catch{}
  return $null-ne$process
}

# Long-running Windows PowerShell dataplane owners cannot receive Go's
# os.Interrupt signal. The controller publishes phase=stopping before waiting up
# to three seconds and force-killing a wrapper. Poll only the loopback controller
# and let helpers return normally when that owned stop transaction is visible, so
# their existing finally/down paths restore firewall/DNS/routes and remove private
# runtime state before the hard-kill fallback can fire.
function Test-RouterVPNControllerStopping([int]$TimeoutMilliseconds=400) {
  if($TimeoutMilliseconds-lt50-or$TimeoutMilliseconds-gt2000){$TimeoutMilliseconds=400}
  $request=$null
  $response=$null
  $reader=$null
  try {
    $request=[Net.HttpWebRequest]::Create('http://127.0.0.1:8788/api/status')
    $request.Proxy=$null
    $request.Method='GET'
    $request.Timeout=$TimeoutMilliseconds
    $request.ReadWriteTimeout=$TimeoutMilliseconds
    $response=$request.GetResponse()
    if([int]$response.StatusCode-ne200){return $false}
    $stream=$response.GetResponseStream()
    $reader=New-Object IO.StreamReader($stream,(New-Object Text.UTF8Encoding($false)),$true,1024,$false)
    $text=$reader.ReadToEnd()
    if($text.Length-gt65536){return $false}
    $status=$text|ConvertFrom-Json
    return ([string]$status.phase-eq'stopping')
  } catch {
    return $false
  } finally {
    if($null-ne$reader){$reader.Dispose()}
    if($null-ne$response){$response.Close()}
  }
}
