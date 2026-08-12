$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
$temp = Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-killswitch-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temp | Out-Null
try {
  $plan = (& $script -Action plan -Endpoint '203.0.113.7' -Policy 'on-connect' -HomeLANAccess 'false' -TunnelAlias 'router-vpn' -StateRoot $temp | ConvertFrom-Json)
  if ($plan.policy -ne 'on-connect') { throw 'plan did not retain on-connect policy' }
  if ($plan.endpoint -ne '203.0.113.7') { throw 'plan did not retain literal endpoint' }
  if ($plan.default_outbound -ne 'Block') { throw 'plan is not fail-closed' }
  if ($plan.home_lan_access) { throw 'plan unexpectedly enabled LAN access' }
  if ($plan.tunnel_alias -ne 'router-vpn') { throw 'plan lost tunnel alias' }

  $lanPlan = (& $script -Action plan -Endpoint '2001:db8::7' -Policy 'always' -HomeLANAccess 'true' -TunnelAlias 'router-vpn-max' -StateRoot $temp | ConvertFrom-Json)
  if (-not $lanPlan.home_lan_access -or $lanPlan.policy -ne 'always') { throw 'LAN/always plan is wrong' }

  $bad = & $script -Action plan -Endpoint 'vpn.example.com' -Policy 'on-connect' -StateRoot $temp 2>&1
  if ($LASTEXITCODE -eq 0) { throw 'hostname endpoint was accepted by strict kill switch' }
  if (($bad | Out-String) -notmatch 'literal IPv4/IPv6') { throw 'hostname rejection did not explain pre-tunnel DNS risk' }

  $source = Get-Content -Raw -LiteralPath $script
  foreach ($marker in @(
    'Get-NetFirewallProfile -PolicyStore ActiveStore',
    'Set-NetFirewallProfile',
    'DefaultOutboundAction Block',
    'New-NetFirewallRule',
    'Remove-NetFirewallRule',
    'original_profiles',
    'ProgramData',
    'Router VPN Kill Switch',
    'InterfaceAlias'
  )) {
    if (-not $source.Contains($marker)) { throw "Windows kill-switch source missing marker: $marker" }
  }
  if ($source -match 'Action=.Block.*RemoteAddress=.Any') { throw 'explicit block-all rule would override intended allow rules' }
  Write-Host 'Windows kill-switch plan/rollback contract: OK'
} finally {
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
