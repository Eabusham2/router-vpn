param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$source=Join-Path $SourceRoot 'client/test-windows-tor-compatibility.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Tor compatibility test does not parse.' }
$nodes=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Remove-RouterVPNTorTestDirectory'},$true))
if ($nodes.Count -ne 1) { throw 'Missing or ambiguous shipping cleanup function.' }
. ([scriptblock]::Create($nodes[0].Extent.Text))
$directory=Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-tor-test-'+[Guid]::NewGuid().ToString('N'))
$script:removals=0; $script:sleeps=0; $script:existing=$true; $script:locks=0; $script:kind='access'; $script:keep=$false
function Test-Path { param($LiteralPath,$ErrorAction) if ($LiteralPath -ne $directory) { throw 'Cleanup inspected an unrelated directory.' }; return $script:existing }
function Remove-Item {
  param($LiteralPath,[switch]$Recurse,[switch]$Force,$ErrorAction)
  if ($LiteralPath -ne $directory -or -not $Recurse -or -not $Force -or $ErrorAction -ne 'Stop') { throw 'Cleanup scope/error handling changed.' }
  $script:removals++
  if ($script:locks -gt 0) {
    $script:locks--
    if ($script:kind -eq 'io') { throw [IO.IOException]::new('sharing violation') }
    if ($script:kind -eq 'other') { throw [ArgumentException]::new('invalid call') }
    throw [UnauthorizedAccessException]::new('temporary image lock')
  }
  if (-not $script:keep) { $script:existing=$false }
}
function Start-Sleep { param($Milliseconds) if ($Milliseconds -ne 250) { throw 'Unbounded or altered retry delay.' }; $script:sleeps++ }
function Reset-Case { $script:removals=0; $script:sleeps=0; $script:existing=$true; $script:locks=0; $script:kind='access'; $script:keep=$false }
function Check($condition,[string]$message) { if (-not $condition) { throw $message } }
Reset-Case
Remove-RouterVPNTorTestDirectory $directory
Check ($script:removals -eq 1 -and $script:sleeps -eq 0 -and -not $script:existing) 'Successful cleanup did not finish immediately.'
Write-Output 'PASS successful cleanup removes exactly the owned directory'
foreach ($type in @('access','io')) {
  Reset-Case; $script:kind=$type; $script:locks=3
  Remove-RouterVPNTorTestDirectory $directory
  Check ($script:removals -eq 4 -and $script:sleeps -eq 3 -and -not $script:existing) 'Temporary file lock was not retried accurately.'
  Write-Output "PASS temporary $type lock retries and confirms removal"
}
Reset-Case; $script:locks=100; $failed=$false
try { Remove-RouterVPNTorTestDirectory $directory } catch [UnauthorizedAccessException] { $failed=$true }
Check ($failed -and $script:removals -eq 20 -and $script:sleeps -eq 19 -and $script:existing) 'Permanent cleanup failure was swallowed or unbounded.'
Write-Output 'PASS permanent lock remains a failed gate after bounded retries'
Reset-Case; $script:keep=$true; $failed=$false
try { Remove-RouterVPNTorTestDirectory $directory } catch [IO.IOException] { $failed=$true }
Check ($failed -and $script:removals -eq 20 -and $script:sleeps -eq 19) 'A leftover directory was incorrectly called removed.'
Write-Output 'PASS successful removal call with leftover files cannot become PASS'
Reset-Case; $script:kind='other'; $script:locks=1; $failed=$false
try { Remove-RouterVPNTorTestDirectory $directory } catch [ArgumentException] { $failed=$true }
Check ($failed -and $script:removals -eq 1 -and $script:sleeps -eq 0) 'Non-filesystem error was retried or hidden.'
Write-Output 'PASS unexpected errors are not retried'
Reset-Case; $script:existing=$false
Remove-RouterVPNTorTestDirectory $directory
Check ($script:removals -eq 0 -and $script:sleeps -eq 0) 'Already-clean directory was not idempotent.'
Write-Output 'PASS repeated cleanup is idempotent'
foreach ($invalid in @([IO.Path]::GetTempPath(),(Join-Path $directory 'nested'),(Join-Path ([IO.Path]::GetTempPath()) 'unrelated'),($directory+'x'))) {
  Reset-Case; $failed=$false
  try { Remove-RouterVPNTorTestDirectory $invalid } catch { $failed=$true }
  Check ($failed -and $script:removals -eq 0 -and $script:sleeps -eq 0) 'Cleanup accepted an unowned directory.'
}
Write-Output 'PASS cleanup rejects parent, nested, unrelated and malformed paths'
Write-Output 'Tor temporary image-lock cleanup: PASS (8 groups; production function executed, filesystem boundaries doubled)'
