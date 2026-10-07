param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $SourceRoot 'client/Setup-Windows-Runtime.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Shipping Tor setup does not parse.' }
$nodes=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-RouterVPNTorRuntimeDirectory'},$true))
if ($nodes.Count -ne 1) { throw 'Missing or ambiguous shipping adoption function.' }
. ([scriptblock]::Create($nodes[0].Extent.Text))
$parent=Join-Path ([IO.Path]::GetTempPath()) 'router-vpn-adoption-fixture'
$target=Join-Path $parent 'tor-expert'
$stage=Join-Path $parent ('tor-expert.stage-'+('a'*32))
$backup=Join-Path $parent ('tor-expert.backup-'+('b'*32))
$script:paths=@{}; $script:failMove=''; $script:failRestore=$false; $script:partialDelete=$false; $script:operations=@()
function Reset-Fixture {
  $script:paths=@{}; $script:paths[$stage]=@('new-tor','new-lyrebird'); $script:paths[$target]=@('old-tor','old-lyrebird')
  $script:failMove=''; $script:failRestore=$false; $script:partialDelete=$false; $script:operations=@()
}
function Test-Path { param($LiteralPath,$PathType) return $script:paths.ContainsKey($LiteralPath) }
function Move-Item {
  param($LiteralPath,$Destination,$ErrorAction)
  $script:operations+=('move '+$LiteralPath+' -> '+$Destination)
  if ($ErrorAction -ne 'Stop') { throw 'Move did not fail closed.' }
  if ($LiteralPath -eq $script:failMove -or ($script:failRestore -and $LiteralPath -eq $backup)) { throw [IO.IOException]::new('simulated locked rename') }
  if (-not $script:paths.ContainsKey($LiteralPath) -or $script:paths.ContainsKey($Destination)) { throw 'Invalid ownership during rename.' }
  $script:paths[$Destination]=$script:paths[$LiteralPath]; $script:paths.Remove($LiteralPath)
}
function Remove-Item {
  param($LiteralPath,[switch]$Recurse,[switch]$Force,$ErrorAction)
  $script:operations+=('remove '+$LiteralPath)
  if ($LiteralPath -ne $backup -or -not $Recurse -or -not $Force -or $ErrorAction -ne 'Stop') { throw 'Cleanup targeted a live or unowned path.' }
  if ($script:partialDelete) { $script:paths[$backup]=@('old-lyrebird'); throw [UnauthorizedAccessException]::new('locked old helper after partial delete') }
  $script:paths.Remove($LiteralPath)
}
function Check($ok,[string]$message) { if (-not $ok) { throw $message } }
function Fail-Adoption { try { Set-RouterVPNTorRuntimeDirectory $stage $target $backup; throw 'UNEXPECTED_SUCCESS' } catch { if ($_.Exception.Message -eq 'UNEXPECTED_SUCCESS') { throw }; return $_.Exception.Message } }
Reset-Fixture
Set-RouterVPNTorRuntimeDirectory $stage $target $backup
Check (($script:paths[$target] -join ',') -eq 'new-tor,new-lyrebird' -and $script:paths.Count -eq 1) 'Complete verified replacement was not retained.'
Write-Output 'PASS verified stage replaces old runtime with cleanup after commit'
Reset-Fixture; $script:paths.Remove($target)
Set-RouterVPNTorRuntimeDirectory $stage $target $backup
Check ($script:paths.Count -eq 1 -and $script:operations.Count -eq 1) 'Fresh install touched an unrelated backup.'
Write-Output 'PASS fresh install adopts without creating/deleting old state'
Reset-Fixture; $script:failMove=$target
$null=Fail-Adoption
Check (($script:paths[$target] -join ',') -eq 'old-tor,old-lyrebird' -and $script:operations.Count -eq 1) 'Initial backup failure deleted the working runtime.'
Write-Output 'PASS failed initial rename cannot delete the old runtime'
Reset-Fixture; $script:failMove=$stage
$null=Fail-Adoption
Check (($script:paths[$target] -join ',') -eq 'old-tor,old-lyrebird' -and -not $script:paths.ContainsKey($backup)) 'Failed stage adoption did not restore the complete original.'
Write-Output 'PASS pre-commit failure restores the complete original'
Reset-Fixture; $script:failMove=$stage; $script:failRestore=$true
$message=Fail-Adoption
Check ($message -match 'rollback failed' -and ($script:paths[$backup] -join ',') -eq 'old-tor,old-lyrebird' -and $script:paths.ContainsKey($stage)) 'Failed rollback destroyed recovery copies.'
Write-Output 'PASS failed rollback preserves both complete recovery copies'
Reset-Fixture; $script:partialDelete=$true
$message=Fail-Adoption
Check ($message -match 'cleanup pending' -and ($script:paths[$target] -join ',') -eq 'new-tor,new-lyrebird' -and ($script:paths[$backup] -join ',') -eq 'old-lyrebird') 'Partial old-backup deletion rolled back over the new complete runtime.'
Check ($script:operations.Count -eq 3) 'Cleanup failure attempted another adoption or rollback.'
Write-Output 'PASS partial backup cleanup cannot roll back the committed runtime'
Reset-Fixture; $script:paths.Remove($stage)
$null=Fail-Adoption
Check ($script:operations.Count -eq 0) 'Missing stage touched working state.'
Reset-Fixture; $script:paths[$backup]=@('foreign')
$null=Fail-Adoption
Check ($script:operations.Count -eq 0) 'Occupied backup was overwritten.'
Reset-Fixture; $failed=$false
try { Set-RouterVPNTorRuntimeDirectory (Join-Path $parent 'foreign-stage') $target $backup } catch { $failed=$true }
Check ($failed -and $script:operations.Count -eq 0) 'Unowned stage was accepted.'
Write-Output 'PASS missing stage, occupied backup and unowned paths fail before writes'
Write-Output 'Shipping Tor adoption/rollback: PASS (7 groups; filesystem operations doubled)'
