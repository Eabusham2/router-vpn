# Shared read-only access to controller-owned Router VPN profile state.
# This file intentionally exposes no profile-store writer. Durable profile
# mutation belongs to the Go controller transaction layer.

function Assert-RouterVPNNoReparseAncestors([string]$Path) {
  $full=[IO.Path]::GetFullPath($Path)
  $cursor=if(Test-Path -LiteralPath $full){$full}else{Split-Path -Parent $full}
  while($cursor){
    if(Test-Path -LiteralPath $cursor){
      $item=Get-Item -LiteralPath $cursor -Force
      if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne0){
        throw "Refusing reparse-point/junction Router VPN private path: $cursor"
      }
    }
    $parent=Split-Path -Parent $cursor
    if(-not$parent-or$parent-eq$cursor){break}
    $cursor=$parent
  }
}

function Resolve-RouterVPNPrivateRoot([string]$RootText) {
  if([string]::IsNullOrWhiteSpace($RootText)){throw 'HOMEVPN_ROOT is required.'}
  $root=[IO.Path]::GetFullPath($RootText)
  Assert-RouterVPNNoReparseAncestors $root
  if(-not(Test-Path -LiteralPath $root -PathType Container)){throw "Router VPN private root is missing: $root"}
  $item=Get-Item -LiteralPath $root -Force
  if(-not$item.PSIsContainer-or(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne0)){
    throw "Router VPN private root is not a real directory: $root"
  }
  return $root
}

function Resolve-RouterVPNPrivateChild([string]$RootText,[string]$ChildPath) {
  $root=Resolve-RouterVPNPrivateRoot $RootText
  if([IO.Path]::IsPathRooted($ChildPath)){$full=[IO.Path]::GetFullPath($ChildPath)}
  else{$full=[IO.Path]::GetFullPath((Join-Path $root $ChildPath))}
  $prefix=$root.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
  if($full-ne$root-and-not$full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){
    throw "Refusing Router VPN path outside private root: $full"
  }
  Assert-RouterVPNNoReparseAncestors $full
  return $full
}

function Read-RouterVPNPrivateJson([string]$Path,[string]$Label='Router VPN private JSON',[int]$Limit=4194304) {
  Assert-RouterVPNNoReparseAncestors $Path
  if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "$Label is missing: $Path"}
  $before=Get-Item -LiteralPath $Path -Force
  if($before.PSIsContainer-or(($before.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne0){
    throw "Unsafe reparse/non-file $Label path: $Path"
  }
  if($before.Length-lt0-or$before.Length-gt$Limit){throw "$Label exceeds safety limit: $Path"}

  # FileShare.Read intentionally excludes write/delete sharing while the bytes
  # are read, preventing replacement of the opened leaf during policy parsing.
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{
    if($stream.Length-gt$Limit){throw "$Label exceeds safety limit: $Path"}
    $reader=New-Object IO.StreamReader($stream,(New-Object Text.UTF8Encoding($false)),$true,4096,$true)
    try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}
    $after=Get-Item -LiteralPath $Path -Force
    if($after.PSIsContainer-or(($after.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne0-or
       $after.FullName-ne$before.FullName-or$after.Length-ne$stream.Length-or
       $after.LastWriteTimeUtc-ne$before.LastWriteTimeUtc)){
      throw "$Label changed during read: $Path"
    }
  }finally{$stream.Dispose()}
  try{return $text|ConvertFrom-Json}catch{throw "Invalid $Label JSON: $Path"}
}

function Get-RouterVPNProfileStore([string]$RootText) {
  $root=Resolve-RouterVPNPrivateRoot $RootText
  $store=Read-RouterVPNPrivateJson (Join-Path $root 'routers.json') 'Router profile store'
  if($null-eq$store-or$null-eq$store.profiles){throw 'Router profile store has no profiles array.'}
  return $store
}

function Get-RouterVPNSelectedProfile($Store,[string]$ProfileId) {
  $selected=$ProfileId.Trim()
  if([string]::IsNullOrWhiteSpace($selected)-and$Store.selected_id){$selected=([string]$Store.selected_id).Trim()}
  if($selected-notmatch'^[A-Za-z0-9_.-]{1,128}$'){throw 'A valid Router VPN profile is not selected.'}
  foreach($item in @($Store.profiles)){
    if($item-and[string]$item.id-eq$selected){return $item}
  }
  throw "Selected Router VPN profile '$selected' was not found."
}
