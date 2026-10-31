param([Parameter(Mandatory=$true)][string]$Root,[switch]$TraceSetup)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:RouterVPNPrivateAclWatch=[Diagnostics.Stopwatch]::StartNew()

function Write-RouterVPNPrivateAclStage([string]$Stage) {
  if($TraceSetup){
    [Console]::WriteLine(('Router VPN private ACL setup: {0} ({1} ms)' -f $Stage,$script:RouterVPNPrivateAclWatch.ElapsedMilliseconds))
  }
}

function Get-RouterVPNPrivateAclPrincipals([Security.Principal.SecurityIdentifier]$User) {
  if($null-eq$User){throw 'Current Windows user SID is unavailable.'}
  $system=Microsoft.PowerShell.Utility\New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-18')
  $administrators=Microsoft.PowerShell.Utility\New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-32-544')
  $seen=@{}
  foreach($sid in @($User,$system,$administrators)){
    if(-not$seen.ContainsKey($sid.Value)){
      $seen[$sid.Value]=$true
      $sid
    }
  }
}

function New-RouterVPNPrivateAcl([bool]$Directory) {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  if($null-eq$identity.User){throw 'Current Windows user SID is unavailable.'}
  $user=$identity.User
  $principals=@(Get-RouterVPNPrivateAclPrincipals $user)
  $rights=[Security.AccessControl.FileSystemRights]::FullControl
  $allow=[Security.AccessControl.AccessControlType]::Allow
  if($Directory){
    $acl=Microsoft.PowerShell.Utility\New-Object -TypeName Security.AccessControl.DirectorySecurity
    $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $prop=[Security.AccessControl.PropagationFlags]::None
    foreach($sid in $principals){
      $rule=Microsoft.PowerShell.Utility\New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @($sid,$rights,$inherit,$prop,$allow)
      [void]$acl.AddAccessRule($rule)
    }
  } else {
    $acl=Microsoft.PowerShell.Utility\New-Object -TypeName Security.AccessControl.FileSecurity
    foreach($sid in $principals){
      $rule=Microsoft.PowerShell.Utility\New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @($sid,$rights,$allow)
      [void]$acl.AddAccessRule($rule)
    }
  }
  # Remove inherited grants instead of copying them. Router VPN private state is
  # intentionally accessible only to this user, SYSTEM, and Administrators.
  $acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner($user)
  return $acl
}

function Get-RouterVPNPrivateAclRuleSet([Security.AccessControl.FileSystemSecurity]$Acl) {
  # Use SIDs directly: readback must not resolve account names over the network.
  # Normalize identical grants when the caller is itself SYSTEM/Administrators.
  $rules=@{}
  foreach($rule in $Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    $key='{0}|{1}|{2}|{3}|{4}|{5}' -f $rule.IdentityReference.Value,[Int64]$rule.FileSystemRights,[int]$rule.AccessControlType,[int]$rule.InheritanceFlags,[int]$rule.PropagationFlags,[bool]$rule.IsInherited
    $rules[$key]=$true
  }
  return $rules
}

function Assert-RouterVPNPrivateAcl([string]$Path,[Security.AccessControl.FileSystemSecurity]$Expected) {
  $actual=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path -ErrorAction Stop
  if(-not$actual.AreAccessRulesProtected-or$actual.GetOwner([Security.Principal.SecurityIdentifier]).Value-cne$Expected.GetOwner([Security.Principal.SecurityIdentifier]).Value){
    throw "Router VPN private ACL owner or inheritance readback differs: $Path"
  }
  $wanted=Get-RouterVPNPrivateAclRuleSet $Expected
  $observed=Get-RouterVPNPrivateAclRuleSet $actual
  if($wanted.Count-ne$observed.Count){throw "Router VPN private ACL grant readback differs: $Path"}
  foreach($key in $wanted.Keys){
    if(-not$observed.ContainsKey($key)){throw "Router VPN private ACL grant readback differs: $Path"}
  }
}

function Protect-RouterVPNPrivateItem([string]$Path,[bool]$RootItem=$false) {
  $item=Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){
    throw "Refusing reparse-point/junction in Router VPN private tree: $Path"
  }
  if($RootItem){Write-RouterVPNPrivateAclStage 'root captured'}
  $expected=New-RouterVPNPrivateAcl ([bool]$item.PSIsContainer)
  if($RootItem){Write-RouterVPNPrivateAclStage 'root ACL constructed'}
  Microsoft.PowerShell.Security\Set-Acl -LiteralPath $item.FullName -AclObject $expected -ErrorAction Stop
  if($RootItem){Write-RouterVPNPrivateAclStage 'root ACL applied'}
  Assert-RouterVPNPrivateAcl $item.FullName $expected
  if($RootItem){Write-RouterVPNPrivateAclStage 'root ACL read back'}
}

Write-RouterVPNPrivateAclStage 'helper entered'
$Root=[IO.Path]::GetFullPath($Root)
if(-not(Microsoft.PowerShell.Management\Test-Path -LiteralPath $Root -PathType Container)){throw "Router VPN private root is missing: $Root"}
Protect-RouterVPNPrivateItem $Root $true

# Do not use Get-ChildItem -Recurse: explicitly refuse junctions/reparse points
# before descending so an installed-tree mutation cannot redirect ACL changes to
# unrelated files. Bound the walk to avoid attacker-controlled resource abuse.
$stack=Microsoft.PowerShell.Utility\New-Object -TypeName 'System.Collections.Generic.Stack[string]'
$stack.Push($Root)
$visited=0
while($stack.Count-gt0){
  $dir=$stack.Pop()
  foreach($item in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)){
    $visited++
    if($visited-gt32768){throw 'Router VPN private tree exceeds ACL hardening safety limit.'}
    if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){
      throw "Refusing reparse-point/junction in Router VPN private tree: $($item.FullName)"
    }
    Protect-RouterVPNPrivateItem $item.FullName
    if($item.PSIsContainer){$stack.Push($item.FullName)}
  }
}

Write-RouterVPNPrivateAclStage 'tree verified'
Microsoft.PowerShell.Utility\Write-Output "Hardened Router VPN Windows private ACLs for $visited child items."
