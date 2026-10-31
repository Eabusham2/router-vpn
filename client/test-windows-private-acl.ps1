param([string]$SourceRoot=[IO.Directory]::GetParent($PSScriptRoot).FullName)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if([Environment]::OSVersion.Platform-ne[PlatformID]::Win32NT){throw 'Private ACL acceptance requires actual Windows.'}
# Windows PowerShell 5.1 must not load PowerShell Core's inherited modules.
if($PSVersionTable.PSEdition-eq'Desktop'){
  $env:PSModulePath=[IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::System),'WindowsPowerShell','v1.0','Modules')
}else{$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')}
$helper=[IO.Path]::Combine($SourceRoot,'client','Protect-RouterVPN-Windows-PrivateRoot.ps1')
$fixture=[IO.Path]::Combine([IO.Path]::GetTempPath(),'routervpn-private-acl-'+[Guid]::NewGuid().ToString('N'))
$privateRoot=[IO.Path]::Combine($fixture,'private')
[void][IO.Directory]::CreateDirectory($privateRoot)
$privateFile=[IO.Path]::Combine($privateRoot,'owned.txt')
[IO.File]::WriteAllText($privateFile,'owned non-secret fixture')
$script:Checks=0
function Check([bool]$Condition,[string]$Message){$script:Checks++;if(-not$Condition){throw $Message}}
function Expect-Rejection([scriptblock]$Action,[string]$Pattern){
  $caught=''
  try{& $Action}catch{$caught=$_.Exception.Message}
  Check ($caught-match$Pattern) ('Required private ACL rejection was missing: '+$caught)
}
try{
  # Execute the shipping helper and keep its actual functions for fresh kernel
  # readback negatives. No ACL provider, SID, or filesystem operation is mocked.
  . $helper -Root $privateRoot
  $directoryExpected=New-RouterVPNPrivateAcl $true
  $fileExpected=New-RouterVPNPrivateAcl $false
  Assert-RouterVPNPrivateAcl $privateRoot $directoryExpected
  Assert-RouterVPNPrivateAcl $privateFile $fileExpected
  Check ($true) 'Fresh directory/file ACL acceptance failed.'
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $readback=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $privateRoot
  Check ($readback.GetOwner([Security.Principal.SecurityIdentifier]).Value-ceq$identity.Value) 'Hardening changed the historical caller ownership contract.'

  foreach($value in @('S-1-5-18','S-1-5-32-544')){
    $sid=Microsoft.PowerShell.Utility\New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @($value)
    $principals=@(Get-RouterVPNPrivateAclPrincipals $sid)
    Check ($principals.Count-eq2) 'Caller SYSTEM/Administrators SID was counted twice.'
    Check (($principals[0].Value-cne$principals[1].Value)) 'Allowed principal normalization retained a duplicate.'
  }

  $everyone=Microsoft.PowerShell.Utility\New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @('S-1-1-0')
  foreach($kind in @('extra-allow','extra-deny','missing-system','inherited','wrong-owner','wrong-file-inheritance')){
    Protect-RouterVPNPrivateItem $privateRoot
    Protect-RouterVPNPrivateItem $privateFile
    $target=if($kind-eq'wrong-file-inheritance'){$privateFile}else{$privateRoot}
    $expected=if($kind-eq'wrong-file-inheritance'){$fileExpected}else{$directoryExpected}
    $changed=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $target
    switch($kind){
      'extra-allow' {
        $rule=Microsoft.PowerShell.Utility\New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @($everyone,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)
        [void]$changed.AddAccessRule($rule)
      }
      'extra-deny' {
        # Keep READ_CONTROL available so rejection must inspect the real extra
        # deny ACE rather than failing to read the descriptor at all.
        $rule=Microsoft.PowerShell.Utility\New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @($everyone,[Security.AccessControl.FileSystemRights]::ReadData,[Security.AccessControl.AccessControlType]::Deny)
        [void]$changed.AddAccessRule($rule)
      }
      'missing-system' {
        foreach($rule in $changed.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
          if($rule.IdentityReference.Value-ceq'S-1-5-18'){[void]$changed.RemoveAccessRuleAll($rule)}
        }
      }
      'inherited' {$changed.SetAccessRuleProtection($false,$true)}
      'wrong-owner' {
        $administrators=Microsoft.PowerShell.Utility\New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-32-544')
        $changed.SetOwner($administrators)
      }
      'wrong-file-inheritance' {$changed.SetAccessRuleProtection($false,$true)}
    }
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $target -AclObject $changed -ErrorAction Stop
    Expect-Rejection {Assert-RouterVPNPrivateAcl $target $expected} 'readback differs'
  }
  Protect-RouterVPNPrivateItem $privateRoot
  Protect-RouterVPNPrivateItem $privateFile

  # The setter must call the real readback after Set-Acl. Inject an actual new
  # grant at that boundary; returning from Set-Acl alone cannot satisfy success.
  $script:OriginalReadback=${function:Assert-RouterVPNPrivateAcl}
  $script:ReadbackCalls=0
  function Assert-RouterVPNPrivateAcl([string]$Path,[Security.AccessControl.FileSystemSecurity]$Expected){
    $script:ReadbackCalls++
    $changed=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
    $rule=Microsoft.PowerShell.Utility\New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @($everyone,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)
    [void]$changed.AddAccessRule($rule)
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $changed -ErrorAction Stop
    & $script:OriginalReadback $Path $Expected
  }
  Expect-Rejection {Protect-RouterVPNPrivateItem $privateRoot} 'readback differs'
  Check ($script:ReadbackCalls-eq1) 'Hardening skipped or cached its required fresh ACL readback.'
  Microsoft.PowerShell.Management\Set-Item -LiteralPath Function:\Assert-RouterVPNPrivateAcl -Value $script:OriginalReadback
  Protect-RouterVPNPrivateItem $privateRoot

  # Module qualification prevents unrelated command discovery before the ACL
  # operation. Parse the actual shipped script, including nested functions.
  $tokens=$null;$errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile($helper,[ref]$tokens,[ref]$errors)
  Check ($errors.Count-eq0) 'Shipping private ACL helper did not parse.'
  $required=@{'New-Object'='Microsoft.PowerShell.Utility';'Write-Output'='Microsoft.PowerShell.Utility';'Get-Item'='Microsoft.PowerShell.Management';'Test-Path'='Microsoft.PowerShell.Management';'Get-ChildItem'='Microsoft.PowerShell.Management';'Set-Acl'='Microsoft.PowerShell.Security';'Get-Acl'='Microsoft.PowerShell.Security'}
  foreach($command in $ast.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst]},$true)){
    $name=$command.GetCommandName()
    if([string]::IsNullOrEmpty($name)){continue}
    $leaf=$name.Split('\')[-1]
    if($required.ContainsKey($leaf)){Check ($name-ceq($required[$leaf]+'\'+$leaf)) ('Private ACL command lost its fixed module: '+$name)}
  }
  [Console]::WriteLine(('Actual Windows private ACL readback and failure controls: {0} checks passed.' -f $script:Checks))
}finally{
  if([IO.Directory]::Exists($fixture)){
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction Stop
  }
}
