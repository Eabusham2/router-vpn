param([string]$Root = (Split-Path $PSScriptRoot -Parent), [string]$Output = '')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Source=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $Root 'client/RouterVPN-Windows-TorBridge.ps1')
$Ast=[ScriptBlock]::Create($Source).Ast
$Bodies=@($Ast.FindAll({param($Node)
    $Node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
    $Node.Value.StartsWith('function TestUnifiedExternalMutationIdle')
},$true))
if($Bodies.Count -ne 1){throw 'Shipping external form composition changed.'}
$Shipping=[ScriptBlock]::Create($Bodies[0].Value)
. $Shipping
$Callbacks=@($Shipping.Ast.FindAll({param($Node)
    $Node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
    $Node.Member.Extent.Text -eq 'Add_Click' -and
    $Node.Expression.Extent.Text -eq '$D.FindName(''ExtSave'')'
},$true))
if($Callbacks.Count -ne 1){throw 'Shipping external Save callback changed.'}
$Save=$Callbacks[0].Arguments[0].ScriptBlock.GetScriptBlock()

$Parameters='Jc=3; Jmin=40; Jmax=900; S1=56; S2=48; S3=24; S4=32; H1=10000000-19999999; H2=20000000-29999999; H3=30000000-39999999; H4=40000000-49999999'
$Expected=@{jc='3';jmin='40';jmax='900';s1='56';s2='48';s3='24';s4='32';h1='10000000-19999999';h2='20000000-29999999';h3='30000000-39999999';h4='40000000-49999999'}
$Private=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('p'*32)))
$Peer=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('q'*32)))
$Fields=@{}
foreach($Name in @('ExtPort','ExtName','ExtServer','ExtExpected','ExtUser','ExtPassword','ExtTLS','ExtMethod','ExtSecret','ExtWGPrivate','ExtWGPeer','ExtWGAddresses','ExtWGAllowed','ExtWGDNS','ExtWGPSK','ExtWGMTU','ExtWGKeepalive','ExtAWGParameters')){
    $Fields[$Name]=[pscustomobject]@{Text='';Password=''}
}
$Fields.ExtPort.Text='51820';$Fields.ExtName.Text='Imported AWG fixture';$Fields.ExtServer.Text='203.0.113.60';$Fields.ExtExpected.Text='203.0.113.60'
$Fields.ExtWGPrivate.Password=$Private;$Fields.ExtWGPeer.Text=$Peer
$Fields.ExtWGAddresses.Text='10.66.0.2/32, fd66::2/128';$Fields.ExtWGAllowed.Text='0.0.0.0/0, ::/0';$Fields.ExtWGDNS.Text='9.9.9.9'
$Fields.ExtWGMTU.Text='1280';$Fields.ExtWGKeepalive.Text='17';$Fields.ExtAWGParameters.Text=$Parameters
$D=[pscustomobject]@{Fields=$Fields}
$D|Add-Member -MemberType ScriptMethod -Name FindName -Value {param($Name) return $this.Fields[$Name]}
$Protocol=[pscustomobject]@{SelectedItem=[pscustomobject]@{Tag='amneziawg'}}
$Status=[pscustomobject]@{Text=''}
$script:Connected=$false;$script:Saved=$null
function Api($Path,$Method='GET',$Body=$null,$Timeout=0){
    if($Path -eq '/api/status'){return [pscustomobject]@{connected=$script:Connected;phase='off'}}
    if($Path -ne '/api/external-profile/create' -or $Method -ne 'POST'){throw 'Unexpected form request.'}
    $script:Saved=$Body
    return [pscustomobject]@{profile=[pscustomobject]@{name='Fixture'}}
}
function Log($Text){}
function RefreshProduct{}
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message}}
& $Save
Check ($null -ne $Saved) ('Actual AWG Save callback rejected its valid form: '+$Status.Text)
Check ($Saved.protocol -ceq 'amneziawg' -and $Saved.wg_keepalive -eq 17 -and $Saved.wg_mtu -eq 1280) 'AWG peer settings changed.'
Check ($Saved.awg_parameters.Count -eq 11) 'AWG parameters were dropped.'
foreach($Key in $Expected.Keys){Check ($Saved.awg_parameters[$Key] -is [string] -and $Saved.awg_parameters[$Key] -ceq $Expected[$Key]) ('AWG parameter changed: '+$Key)}
Check ($Saved.wg_private_key -ceq $Private -and $Saved.wg_peer_public_key -ceq $Peer) 'Peer credentials changed.'
if($Output){[void][IO.Directory]::CreateDirectory($Output);[IO.File]::WriteAllText((Join-Path $Output 'amneziawg.json'),($Saved|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))}

$Count=1
foreach($Bad in @('', ($Parameters+';Jc=3'), $Parameters.Replace('S4=32; ',''), ($Parameters+';unknown=7'), $Parameters.Replace('H1=10000000-19999999','H1=1--9'), $Parameters.Replace('S4=32','S4=bad'), ('Jc=3;'*1000))){
    $Fields.ExtAWGParameters.Text=$Bad;$script:Saved=$null;& $Save
    Check ($null -eq $Saved) ('Malformed AWG parameters reached the controller in case '+$Count+'.');$Count++
}
$Fields.ExtAWGParameters.Text=$Parameters
foreach($Bad in @('-1','65536','bad')){
    $Fields.ExtWGKeepalive.Text=$Bad;$script:Saved=$null;& $Save
    Check ($null -eq $Saved) 'Invalid keepalive reached the controller.';$Count++
}
$Fields.ExtWGKeepalive.Text='17'
foreach($Bad in @('1279','9001','bad')){
    $Fields.ExtWGMTU.Text=$Bad;$script:Saved=$null;& $Save
    Check ($null -eq $Saved) 'Invalid MTU reached the controller.';$Count++
}
$Fields.ExtWGMTU.Text='1280'
$script:Connected=$true;$script:Saved=$null;& $Save
Check ($null -eq $Saved) 'Changed VPN state permitted external profile mutation.';$Count++
$script:Connected=$false;$Protocol.SelectedItem.Tag='wireguard';$script:Saved=$null;& $Save
Check ($null -ne $Saved -and -not $Saved.ContainsKey('awg_parameters') -and $Saved.wg_keepalive -eq 17) 'Ordinary WireGuard was changed into AmneziaWG.';$Count++
if($Output){[IO.File]::WriteAllText((Join-Path $Output 'wireguard.json'),($Saved|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))}
Write-Host ('PASS shipping Windows external Save callback: '+$Count+' cases')
