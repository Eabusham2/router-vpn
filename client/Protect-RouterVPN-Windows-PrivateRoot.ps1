param([Parameter(Mandatory=$true)][string]$Root)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function New-RouterVPNPrivateAcl([bool]$Directory) {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  if($null-eq$identity.User){throw 'Current Windows user SID is unavailable.'}
  $user=$identity.User
  $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
  $administrators=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $rights=[Security.AccessControl.FileSystemRights]::FullControl
  $allow=[Security.AccessControl.AccessControlType]::Allow
  if($Directory){
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $prop=[Security.AccessControl.PropagationFlags]::None
    foreach($sid in @($user,$system,$administrators)){
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,$inherit,$prop,$allow)))
    }
  } else {
    $acl=New-Object Security.AccessControl.FileSecurity
    foreach($sid in @($user,$system,$administrators)){
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,$allow)))
    }
  }
  # Remove inherited grants instead of copying them. Router VPN private state is
  # intentionally accessible only to this user, SYSTEM, and Administrators.
  $acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner($user)
  return $acl
}

function Protect-RouterVPNPrivateItem([string]$Path) {
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){
    throw "Refusing reparse-point/junction in Router VPN private tree: $Path"
  }
  if($item.PSIsContainer){
    Set-Acl -LiteralPath $item.FullName -AclObject (New-RouterVPNPrivateAcl $true)
  } else {
    Set-Acl -LiteralPath $item.FullName -AclObject (New-RouterVPNPrivateAcl $false)
  }
}

$Root=[IO.Path]::GetFullPath($Root)
if(-not(Test-Path -LiteralPath $Root -PathType Container)){throw "Router VPN private root is missing: $Root"}
Protect-RouterVPNPrivateItem $Root

# Do not use Get-ChildItem -Recurse: explicitly refuse junctions/reparse points
# before descending so an installed-tree mutation cannot redirect ACL changes to
# unrelated files. Bound the walk to avoid attacker-controlled resource abuse.
$stack=New-Object 'System.Collections.Generic.Stack[string]'
$stack.Push($Root)
$visited=0
while($stack.Count-gt0){
  $dir=$stack.Pop()
  foreach($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)){
    $visited++
    if($visited-gt32768){throw 'Router VPN private tree exceeds ACL hardening safety limit.'}
    if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){
      throw "Refusing reparse-point/junction in Router VPN private tree: $($item.FullName)"
    }
    Protect-RouterVPNPrivateItem $item.FullName
    if($item.PSIsContainer){$stack.Push($item.FullName)}
  }
}

Write-Output "Hardened Router VPN Windows private ACLs for $visited child items."
