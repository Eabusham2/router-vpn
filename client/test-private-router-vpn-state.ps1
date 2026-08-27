$ErrorActionPreference='Stop'
$helper=Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1'
. $helper
$temp=Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-private-state-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp|Out-Null
try{
  $storePath=Join-Path $temp 'routers.json'
  [IO.File]::WriteAllText($storePath,'{"selected_id":"node","profiles":[{"id":"node"},{"id":"other"}]}' + [Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
  $store=Get-RouterVPNProfileStore $temp
  $profile=Get-RouterVPNSelectedProfile $store 'node'
  if([string]$profile.id-ne'node'){throw 'exact selected profile was not returned'}

  $caught=$null
  try{[void](Get-RouterVPNSelectedProfile $store 'missing')}catch{$caught=$_.Exception.Message}
  if(-not$caught-or$caught-notmatch'was not found'){throw "missing selected profile silently fell back: $caught"}

  [IO.File]::WriteAllText($storePath,'{broken',(New-Object Text.UTF8Encoding($false)))
  $caught=$null
  try{[void](Get-RouterVPNProfileStore $temp)}catch{$caught=$_.Exception.Message}
  if(-not$caught-or$caught-notmatch'Invalid Router profile store JSON'){throw "corrupt profile store did not fail closed: $caught"}

  $real=Join-Path $temp 'real.json'
  [IO.File]::WriteAllText($real,'{"selected_id":"node","profiles":[{"id":"node"}]}' + [Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
  Remove-Item -LiteralPath $storePath -Force
  $linkCreated=$false
  try{New-Item -ItemType SymbolicLink -Path $storePath -Target $real -ErrorAction Stop|Out-Null;$linkCreated=$true}catch{}
  if($linkCreated){
    $caught=$null
    try{[void](Get-RouterVPNProfileStore $temp)}catch{$caught=$_.Exception.Message}
    if(-not$caught-or$caught-notmatch'reparse'){throw "symlink profile store was accepted: $caught"}
  }else{Write-Host 'Windows symlink creation unavailable; source reparse contract still checked.'}

  $outside=Join-Path $temp 'outside'
  New-Item -ItemType Directory -Path $outside|Out-Null
  $childLink=Join-Path $temp 'linked-child'
  $childLinkCreated=$false
  try{New-Item -ItemType SymbolicLink -Path $childLink -Target $outside -ErrorAction Stop|Out-Null;$childLinkCreated=$true}catch{}
  if($childLinkCreated){
    $caught=$null
    try{[void](Resolve-RouterVPNPrivateChild $temp (Join-Path $childLink 'runtime.exe'))}catch{$caught=$_.Exception.Message}
    if(-not$caught-or$caught-notmatch'reparse'){throw "symlink private child path was accepted: $caught"}
  }

  # Process records bind PID + process start time + executable identity. They
  # are create-only so stale/foreign ownership evidence can never be overwritten.
  $processRecord=Join-Path $temp 'owned.process.json'
  $self=Get-Process -Id $PID -ErrorAction Stop
  Write-RouterVPNProcessRecord $processRecord $self
  if(-not(Test-RouterVPNRecordedProcess $processRecord)){throw 'fresh verified process record was not recognized'}
  $caught=$null
  try{Write-RouterVPNProcessRecord $processRecord $self}catch{$caught=$_.Exception.Message}
  if(-not$caught-or$caught-notmatch'overwrite existing'){throw "existing process ownership record was overwritten: $caught"}

  $record=Read-RouterVPNPrivateJson $processRecord 'test process record' 65536
  $record.start_time_utc_ticks=[Int64]$record.start_time_utc_ticks+1
  Remove-Item -LiteralPath $processRecord -Force
  [IO.File]::WriteAllText($processRecord,(($record|ConvertTo-Json -Compress)+"`n"),(New-Object Text.UTF8Encoding($false)))
  if(Test-RouterVPNRecordedProcess $processRecord){throw 'stale process start-time record was accepted'}

  $record.start_time_utc_ticks=[Int64]$self.StartTime.ToUniversalTime().Ticks
  $record.executable_path=Join-Path $temp 'wrong-process.exe'
  Remove-Item -LiteralPath $processRecord -Force
  [IO.File]::WriteAllText($processRecord,(($record|ConvertTo-Json -Compress)+"`n"),(New-Object Text.UTF8Encoding($false)))
  if(Test-RouterVPNRecordedProcess $processRecord){throw 'wrong executable process record was accepted'}
  Remove-Item -LiteralPath $processRecord -Force

  $recordReal=Join-Path $temp 'real-process-record.json'
  Write-RouterVPNProcessRecord $recordReal $self
  $recordLink=Join-Path $temp 'linked-process-record.json'
  $recordLinkCreated=$false
  try{New-Item -ItemType SymbolicLink -Path $recordLink -Target $recordReal -ErrorAction Stop|Out-Null;$recordLinkCreated=$true}catch{}
  if($recordLinkCreated){
    if(Test-RouterVPNRecordedProcess $recordLink){throw 'symlink process ownership record was accepted'}
    if(Stop-RouterVPNRecordedProcess $recordLink){throw 'symlink process ownership record was used to stop a process'}
  }
  Remove-Item -LiteralPath $recordReal -Force -ErrorAction SilentlyContinue

  $exe=[string]$self.Path
  if([string]::IsNullOrWhiteSpace($exe)){try{$exe=[string]$self.MainModule.FileName}catch{}}
  if(-not[string]::IsNullOrWhiteSpace($exe)){
    $child=Start-Process -FilePath $exe -ArgumentList @('-NoProfile','-Command','Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden
    $childRecord=Join-Path $temp 'child.process.json'
    try{
      Write-RouterVPNProcessRecord $childRecord $child
      if(-not(Test-RouterVPNRecordedProcess $childRecord)){throw 'owned child process record was not verified'}
      if(-not(Stop-RouterVPNRecordedProcess $childRecord)){throw 'verified owned child process was not stopped'}
      [void]$child.WaitForExit(5000)
      if(-not$child.HasExited){throw 'verified owned child process survived stop'}
    }finally{
      try{$child.Refresh()}catch{}
      if(-not$child.HasExited){Stop-Process -InputObject $child -Force -ErrorAction SilentlyContinue}
      Remove-Item -LiteralPath $childRecord -Force -ErrorAction SilentlyContinue
    }
  }

  $source=Get-Content -Raw -LiteralPath $helper
  foreach($marker in @('Assert-RouterVPNNoReparseAncestors','Resolve-RouterVPNPrivateChild','FileShare]::Read','Get-RouterVPNProfileStore','Get-RouterVPNSelectedProfile','Write-RouterVPNProcessRecord','Get-RouterVPNVerifiedRecordedProcess','Stop-RouterVPNRecordedProcess','Refusing to overwrite existing Router VPN process ownership record','[IO.File]::Move($tmp,$full)')){
    if(-not$source.Contains($marker)){throw "private profile helper lost marker: $marker"}
  }
  foreach($forbidden in @('WriteAllText($Path','Move-Item','File]::Replace')){
    if($source.Contains($forbidden)){throw "read-only Windows profile helper gained write primitive: $forbidden"}
  }
  Write-Host 'Windows private profile-store + verified process ownership contract: OK'
}finally{
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
