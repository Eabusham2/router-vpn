param(
  [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
  [ValidateSet('amd64','arm64','')][string]$ExpectedArchitecture = ''
)
$ErrorActionPreference = 'Stop'
$setup = Join-Path $SourceRoot 'client\Setup-Windows-Runtime.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($setup,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'Shipping runtime setup failed PowerShell parsing.' }
# Evaluate only the reviewed Tor constants and function definitions from the
# shipping installer. Do not run general runtime installation, UAC or drivers.
foreach ($name in @('TorExpertVersion','TorVersion','TorExpertWindowsX64Sha256')) {
  $nodes = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -eq $name},$true))
  if ($nodes.Count -ne 1) { throw "Missing/ambiguous shipping Tor pin: $name" }
  . ([scriptblock]::Create($nodes[0].Extent.Text))
}
foreach ($name in @('Get-RouterVPNTorHelperExecution','Invoke-RouterVPNTorHelperVersion','Install-PinnedTorExpertBundle')) {
  $nodes = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
  if ($nodes.Count -ne 1) { throw "Missing/ambiguous shipping Tor function: $name" }
  . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$expected = if ($ExpectedArchitecture -eq 'amd64') { 'x64' } else { $ExpectedArchitecture }
if ($expected -and $architecture -ne $expected) { throw "Wrong native runner: expected $expected, got $architecture" }
$execution = Get-RouterVPNTorHelperExecution $architecture
if ($architecture -eq 'arm64' -and $execution -notmatch 'Windows emulation') { throw 'ARM64 execution was falsely described as a native x64 host.' }
$rejected = $false
try { $null = Get-RouterVPNTorHelperExecution 'unsupported' } catch { $rejected = $true }
if (-not $rejected) { throw 'Unsupported host architecture was accepted.' }
$temp = Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-tor-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
  $runtime = Join-Path $temp 'runtime'
  $url = "https://dist.torproject.org/torbrowser/$TorExpertVersion/tor-expert-bundle-windows-x86_64-$TorExpertVersion.tar.gz"
  Install-PinnedTorExpertBundle $url $TorExpertWindowsX64Sha256 $TorVersion $runtime
  $tor = @(Get-ChildItem (Join-Path $runtime 'tor-expert') -Recurse -File -Filter 'tor.exe')
  $pt = @(Get-ChildItem (Join-Path $runtime 'tor-expert') -Recurse -File -Filter 'lyrebird.exe')
  if ($tor.Count -ne 1 -or $pt.Count -ne 1) { throw 'Installed native Tor helpers are not uniquely owned.' }
  # Confirm these are really the pinned x64 helpers on BOTH architectures,
  # rather than accidentally passing the ARM test with another implementation.
  foreach ($exe in @($tor[0].FullName,$pt[0].FullName)) {
    $stream = [IO.File]::OpenRead($exe)
    $reader = New-Object IO.BinaryReader($stream)
    try {
      if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Helper is not a PE executable.' }
      [void]$stream.Seek(0x3c,[IO.SeekOrigin]::Begin); $offset = $reader.ReadUInt32()
      if ($offset -gt $stream.Length-6) { throw 'Invalid helper PE offset.' }
      [void]$stream.Seek($offset,[IO.SeekOrigin]::Begin)
      if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Expected the checksum-pinned AMD64 Tor helper.' }
    } finally { $reader.Dispose() }
  }
  $text = Invoke-RouterVPNTorHelperVersion $tor[0].FullName '--version' ('Tor version '+[regex]::Escape($TorVersion)+'(?:[. ]|$)')
  $ptText = Invoke-RouterVPNTorHelperVersion $pt[0].FullName '-version' '(?i)lyrebird'
  Write-Output "PASS real Tor/Lyrebird execution: $execution"
  Write-Output $text
  Write-Output $ptText
  Write-Output 'No Tor network, proxy, VPN interface, driver or firewall was started by this compatibility test.'
} finally {
  Remove-Item -LiteralPath $temp -Recurse -Force
}
