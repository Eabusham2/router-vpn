# Shared read-only access to controller-owned Router VPN profile state.
# This file intentionally exposes no profile-store writer. Durable profile
# mutation belongs to the Go controller transaction layer. The only write
# primitive below is create-only and scoped to ephemeral process-ownership
# records; it never mutates routers.json or other controller-owned profile state.

# These public fields are captured once from the authenticated controller's
# helper launch. Later environment changes cannot select a replacement owner.
$script:RouterVPNControllerDrainCapture = [pscustomobject]@{
  Transport = [string]$env:HOMEVPN_CONTROLLER_TRANSPORT
  ProcessId = [string]$env:HOMEVPN_CONTROLLER_PID
  Pin = [string]$env:HOMEVPN_CONTROLLER_TLS_PIN
  Executable = [string]$env:HOMEVPN_CONTROLLER_EXECUTABLE
}

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

function Get-RouterVPNHomeDnsField($Profile, [string]$Name, [string]$Default = '') {
  if ($null -ne $Profile -and $Profile.PSObject.Properties.Name -contains $Name) {
    $value = ([string]$Profile.$Name).Trim()
    if ($value.Length -gt 0) { return $value }
  }
  return $Default
}

function ConvertTo-RouterVPNHomeDnsAddress([string]$Value, [string]$Family = '') {
  $address = $Value.Trim()
  if ($address.StartsWith('[') -and $address.EndsWith(']')) {
    $address = $address.Substring(1, $address.Length - 2)
  }
  $parsed = $null
  if ($address.Contains('%') -or -not [Net.IPAddress]::TryParse($address, [ref]$parsed)) {
    throw 'Home DNS requires a literal private AdGuard address without a scope or zone.'
  }
  $bytes = $parsed.GetAddressBytes()
  if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
    # .NET also accepts shortened, octal and integer IPv4 spellings. The saved
    # node contract permits only the ordinary dotted-decimal address.
    if ($Family -eq 'ipv6' -or $address -cne $parsed.ToString() -or -not (
      $bytes[0] -eq 10 -or
      ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
      ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
    )) { throw 'Home DNS requires the same node private IPv4 AdGuard address.' }
  } elseif ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($Family -eq 'ipv4' -or $parsed.IsIPv4MappedToIPv6 -or ($bytes[0] -band 254) -ne 252) {
      throw 'Home DNS requires the same node ULA IPv6 AdGuard address.'
    }
  } else {
    throw 'Home DNS requires a literal private AdGuard address.'
  }
  return $parsed.ToString()
}

function Get-RouterVPNHomeDnsSelection($Profile) {
  if ($null -eq $Profile) { throw 'Selected Router VPN profile is unavailable for Home DNS policy.' }
  $kind = Get-RouterVPNHomeDnsField $Profile 'node_kind' 'router-vpn'
  $mode = (Get-RouterVPNHomeDnsField $Profile 'dns_mode' 'home').ToLowerInvariant()
  if ($kind -cne 'router-vpn' -or $mode -ne 'home') {
    throw 'Home DNS requires the captured Router VPN node policy.'
  }
  $addresses = @()
  foreach ($family in @('ipv4', 'ipv6')) {
    $property = $Profile.PSObject.Properties['adguard_' + $family]
    $value = if ($null -ne $property) { [string]$property.Value } else { '' }
    if ($value.Length -gt 0) {
      $address = ConvertTo-RouterVPNHomeDnsAddress $value $family
      if ($address -cne $value) { throw 'Home DNS saved AdGuard address must be canonical.' }
      $addresses += $address
    }
  }
  if ($addresses.Count -eq 0) { throw 'Home DNS has no saved AdGuard address for this node.' }
  $dnsHost = Get-RouterVPNHomeDnsField $Profile 'dns_host'
  if ($dnsHost) {
    $dnsHost = ConvertTo-RouterVPNHomeDnsAddress $dnsHost
    if ($addresses -cnotcontains $dnsHost) { throw 'Home DNS address does not belong to the captured node.' }
  } else {
    $dnsHost = $addresses[0]
  }
  $ipv6 = (Get-RouterVPNHomeDnsField $Profile 'ipv6_mode' 'on').ToLowerInvariant()
  if ($ipv6 -notin @('on', 'auto', 'off')) { throw 'Home DNS has an invalid saved IPv6 policy.' }
  if ($ipv6 -eq 'off' -and $dnsHost.Contains(':')) { throw 'Home DNS selected IPv6 while IPv6 is Off.' }

  $protocol = (Get-RouterVPNHomeDnsField $Profile 'dns_protocol' 'udp').ToLowerInvariant()
  switch ($protocol) { 'doh' { $protocol = 'https' }; 'dot' { $protocol = 'tls' }; 'doh3' { $protocol = 'h3' } }
  if ($protocol -notin @('udp', 'tcp', 'tls', 'https', 'h3')) { throw 'Unsupported Home DNS protocol.' }
  $portText = Get-RouterVPNHomeDnsField $Profile 'dns_port' '0'
  $port = 0
  if ($portText -notmatch '\A[0-9]+\z' -or -not [int]::TryParse($portText, [ref]$port) -or $port -gt 65535) {
    throw 'Home DNS port must be an integer between 1 and 65535, or 0 for the transport default.'
  }
  if ($port -eq 0) {
    $port = if ($protocol -eq 'tls') { 853 } elseif ($protocol -in @('https', 'h3')) { 443 } else { 53 }
  }
  $serverName = ''
  $path = ''
  if ($protocol -in @('tls', 'https', 'h3')) {
    $serverName = Get-RouterVPNHomeDnsField $Profile 'dns_server_name'
    $nameIP = $null
    if ($serverName.Length -gt 253 -or -not $serverName.Contains('.') -or $serverName -notmatch '\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z' -or [Net.IPAddress]::TryParse($serverName, [ref]$nameIP)) {
      throw 'Encrypted Home DNS requires the saved TLS server hostname.'
    }
    if ($protocol -in @('https', 'h3')) {
      $path = Get-RouterVPNHomeDnsField $Profile 'dns_path' '/dns-query'
      if ($path.Length -gt 2048 -or -not $path.StartsWith('/') -or $path.StartsWith('//') -or $path -match '[\x00-\x20\x7f?#\\]' -or $path -match '%(?![0-9a-fA-F]{2})') {
        throw 'Home DNS HTTPS path must be a local absolute request path.'
      }
    }
  }
  # Never consult ambient HOMEVPN_DNS_* or HOMEVPN_ADGUARD* overrides here:
  # this resolver belongs to the exact private node returned by its ID.
  return [pscustomobject]@{ mode='home'; protocol=$protocol; host=$dnsHost; port=$port; server_name=$serverName; path=$path }
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
# os.Interrupt signal. The controller publishes its terminal drain state before
# the bounded wrapper wait. The owned TLS path uses the native retained-process
# probe; a failure is unknown and never selects the legacy plaintext endpoint.
function Test-RouterVPNPinnedControllerStopping($Capture,[int]$TimeoutMilliseconds) {
  $probe=$null
  $held=$null
  $started=$false
  try {
    $owner=[uint32]0
    if($Capture.Transport-cne'pinned-tls' -or $Capture.ProcessId-cnotmatch'\A[1-9][0-9]{0,9}\z' -or
       -not[uint32]::TryParse($Capture.ProcessId,[ref]$owner) -or $owner-eq0 -or
       $Capture.Pin-cnotmatch'\A[0-9a-f]{64}\z' -or [string]::IsNullOrWhiteSpace($Capture.Executable) -or
       -not[IO.Path]::IsPathRooted($Capture.Executable)) { return $false }
    Assert-RouterVPNNoReparseAncestors $Capture.Executable
    # Hold the exact utility leaf against replacement until its owned process
    # exits. The authenticated launch separately retains the full image ancestry.
    $held=[IO.File]::Open($Capture.Executable,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$Capture.Executable
    $start.Arguments='--windows-controller-drain '+$Capture.ProcessId+' '+$Capture.Pin
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $probe=New-Object Diagnostics.Process
    $probe.StartInfo=$start
    $started=$probe.Start()
    if(-not$started){return $false}
    # Both reads are independently bounded. Excess output blocks only this
    # owned utility until the deadline kills and joins it; it cannot grow the
    # dataplane owner's memory or masquerade as a complete small receipt.
    $stdoutBuffer=New-Object char[] 1025
    $stderrBuffer=New-Object char[] 1025
    $stdout=$probe.StandardOutput.ReadBlockAsync($stdoutBuffer,0,$stdoutBuffer.Length)
    $stderr=$probe.StandardError.ReadBlockAsync($stderrBuffer,0,$stderrBuffer.Length)
    if(-not$probe.WaitForExit($TimeoutMilliseconds)){return $false}
    if(-not$stdout.Wait(100)-or-not$stderr.Wait(100)-or$probe.ExitCode-ne0){return $false}
    if($stdout.Result-gt1024-or$stderr.Result-ne0){return $false}
    $text=New-Object string($stdoutBuffer,0,[int]$stdout.Result)
    $receipt=$text|ConvertFrom-Json
    $fields=@($receipt.PSObject.Properties.Name)
    if($fields.Count-ne3-or$fields-cnotcontains'schema'-or$fields-cnotcontains'process_id'-or$fields-cnotcontains'draining'-or
       $receipt.schema-ne1-or$receipt.process_id-ne$owner-or$receipt.draining-isnot[bool]){return $false}
    return [bool]$receipt.draining
  } catch {
    return $false
  } finally {
    if($null-ne$probe){
      try { if($started-and-not$probe.HasExited){$probe.Kill();[void]$probe.WaitForExit(1000)} } catch { }
      $probe.Dispose()
    }
    if($null-ne$held){$held.Dispose()}
  }
}

function Test-RouterVPNControllerStopping([int]$TimeoutMilliseconds=400) {
  if($TimeoutMilliseconds-lt50-or$TimeoutMilliseconds-gt2000){$TimeoutMilliseconds=400}
  $capture=$script:RouterVPNControllerDrainCapture
  if($capture.Transport-or$capture.ProcessId-or$capture.Pin-or$capture.Executable){
    return Test-RouterVPNPinnedControllerStopping $capture $TimeoutMilliseconds
  }
  # Only legacy helpers launched without any owned transport capture use their
  # existing ordinary loopback status. An owned failure never reaches this code.
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
