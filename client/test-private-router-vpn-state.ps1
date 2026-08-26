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

  $source=Get-Content -Raw -LiteralPath $helper
  foreach($marker in @('Assert-RouterVPNNoReparseAncestors','FileShare]::Read','Get-RouterVPNProfileStore','Get-RouterVPNSelectedProfile')){
    if(-not$source.Contains($marker)){throw "private profile helper lost marker: $marker"}
  }
  foreach($forbidden in @('WriteAllText($Path','Move-Item','File]::Replace')){
    if($source.Contains($forbidden)){throw "read-only Windows profile helper gained write primitive: $forbidden"}
  }
  Write-Host 'Windows private profile-store read/fail-closed contract: OK'
}finally{
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
