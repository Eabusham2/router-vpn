param([string]$Root = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Client=Join-Path $Root 'client'
$Launcher=Get-Content -LiteralPath (Join-Path $Client 'RouterVPN-Windows-App.ps1') -Raw -Encoding UTF8

function Assert-HelpBinding([bool]$Value,[string]$Message){if(-not$Value){throw $Message}}
function Get-HelpEventCalls([string]$Source){
    $Ast=[ScriptBlock]::Create($Source).Ast
    return @($Ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $Node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $Node.Member.Value -like 'Add_*'
    },$true))
}
function Get-HelpControlName($Node){
    $Match=[regex]::Match($Node.Expression.Extent.Text,'^\(\s*Control\s+[''"]([^''"]+)[''"]\s*\)$')
    if($Match.Success){return $Match.Groups[1].Value}
    return ''
}

# Extract the production transform itself. Do not launch WPF, a controller, or a
# VPN to test source composition; no replacement implementation lives in tests.
$Ast=[ScriptBlock]::Create($Launcher).Ast
$Functions=@($Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $Node.Name -eq 'Set-RouterVPNProductHelpBinding'
},$true))
Assert-HelpBinding ($Functions.Count -eq 1) 'Shipping Help transform missing or duplicated'
. ([ScriptBlock]::Create($Functions[0].Extent.Text))

$Old="(Control 'TutorialButton').Add_Click({OldHelp})"
$New="(Control 'TutorialButton').Add_Click({Show-RouterVPNProductOnboarding -Force})"
$Suffix="(Control 'UnifiedConnectButton').Add_Click({UnifiedConnect})`n"+
    '$Window.Add_Closed({Cleanup})'+"`n"+'$BaseCombo.SelectedIndex=0'
$Count=0
function Check-Rewrite([string]$Label,[string]$Source,[string]$Expected){
    $Actual=Set-RouterVPNProductHelpBinding -Source $Source
    Assert-HelpBinding ($Actual -ceq $Expected) ("Help rewrite changed unrelated source: "+$Label)
    [void][ScriptBlock]::Create($Actual)
    $script:Count++
    Write-Host ("PASS "+$Label)
}
Check-Rewrite 'isolated callback' $Old $New
Check-Rewrite 'generated handlers and startup preserved' ($Old+"`n"+$Suffix) ($New+"`n"+$Suffix)
Check-Rewrite 'CRLF preserved' ($Old+"`r`n"+$Suffix.Replace("`n","`r`n")) ($New+"`r`n"+$Suffix.Replace("`n","`r`n"))
$UnicodePrefix='# '+[char]0x2192+' '+[char]::ConvertFromUtf32(0x1F680)+"`r`n"
Check-Rewrite 'UTF-16 offsets preserve Unicode prefix' ($UnicodePrefix+$Old+"`n"+$Suffix) ($UnicodePrefix+$New+"`n"+$Suffix)
$Nested="(Control 'TutorialButton').Add_Click({if(`$true){& {Write-Output 'literal })'}}})"
Check-Rewrite 'nested callback bodies' ($Nested+"`n"+$Suffix) ($New+"`n"+$Suffix)
$Neighbor="(Control 'OtherButton').Add_Click({Other})"
Check-Rewrite 'same-line neighboring handlers' ($Neighbor+';'+$Old+';'+$Neighbor) ($Neighbor+';'+$New+';'+$Neighbor)
$Spaced='( Control "TutorialButton" ).Add_Click( {OldHelp} )'
Check-Rewrite 'quoted and spaced receiver' $Spaced '( Control "TutorialButton" ).Add_Click( {Show-RouterVPNProductOnboarding -Force} )'
$Decoys='# '+$Old+"`n"+'$Example = "'+$Old+'"'+"`n"
Check-Rewrite 'comments and string decoys ignored' ($Decoys+$Old) ($Decoys+$New)
Check-Rewrite 'idempotent rewrite' $New $New

foreach($Case in @(
    @{Label='missing binding';Source=$Neighbor},
    @{Label='duplicate binding';Source=$Old+"`n"+$Old},
    @{Label='non-script callback';Source="(Control 'TutorialButton').Add_Click(`$Callback)"},
    @{Label='multiple arguments';Source="(Control 'TutorialButton').Add_Click({OldHelp},{Other})"},
    @{Label='invalid syntax';Source=$Old+"`nif ("}
)){
    $Rejected=$false
    try{[void](Set-RouterVPNProductHelpBinding -Source $Case.Source)}catch{$Rejected=$true}
    Assert-HelpBinding $Rejected ("Help transform accepted "+$Case.Label)
    $Count++;Write-Host ("PASS reject "+$Case.Label)
}

# Materialize the real product using the launcher's exact helper loading and
# composition statements, including session guards, telemetry, Speed Lab, Tor,
# and external-node UI. Execute source transforms only, never ProductScript.
$LoadStart=$Launcher.IndexOf('$ProfileSettingsHelpers=')
$LoadEnd=$Launcher.IndexOf('# The shipping Windows product',$LoadStart)
$ComposeStart=$Launcher.IndexOf('$Product=Join-Path')
$HelpStart=$Launcher.IndexOf('$ProductSource=Set-RouterVPNProductHelpBinding -Source $ProductSource',$ComposeStart)
$ComposeEnd=$Launcher.IndexOf('$ProductScript=[ScriptBlock]::Create($ProductSource)',$HelpStart)
Assert-HelpBinding ($LoadStart -ge 0 -and $LoadEnd -gt $LoadStart -and $ComposeStart -ge 0 -and $HelpStart -gt $ComposeStart -and $ComposeEnd -gt $HelpStart) 'Launcher composition seams changed'
$LoadSource=$Launcher.Substring($LoadStart,$LoadEnd-$LoadStart).Replace('$PSScriptRoot','$Client')
. ([ScriptBlock]::Create($LoadSource))
$ComposeSource=$Launcher.Substring($ComposeStart,$HelpStart-$ComposeStart).Replace('$PSScriptRoot','$Client')
. ([ScriptBlock]::Create($ComposeSource))
$Before=$ProductSource
. ([ScriptBlock]::Create($Launcher.Substring($HelpStart,$ComposeEnd-$HelpStart)))
$After=$ProductSource
[void][ScriptBlock]::Create($After)

$ExpectedControls=@(
    'UnifiedConnectButton','UnifiedProofButton','UnifiedEmergencyButton',
    'UnifiedNodesButton','UnifiedPresetsButton','UnifiedDnsDetailsButton',
    'UnifiedSettingsButton','UnifiedMtuButton','UnifiedBackButton',
    'UnifiedModeCombo','UnifiedKillSwitch','UnifiedDnsCombo',
    'UnifiedFastestNode','UnifiedForwardButton','UnifiedPerformanceButton',
    'UnifiedTorButton','UnifiedExternalNodeButton'
)
$BeforeEvents=@(Get-HelpEventCalls $Before)
$AfterEvents=@(Get-HelpEventCalls $After)
foreach($Name in $ExpectedControls){
    $Original=@($BeforeEvents|Where-Object{(Get-HelpControlName $_) -eq $Name})
    $Actual=@($AfterEvents|Where-Object{(Get-HelpControlName $_) -eq $Name})
    Assert-HelpBinding ($Original.Count -eq 1 -and $Actual.Count -eq 1) ("Composed control lost or duplicated its binding: "+$Name)
    Assert-HelpBinding ($Original[0].Extent.Text -ceq $Actual[0].Extent.Text) ("Help altered the callback for "+$Name)
}
$Count++;Write-Host 'PASS all 17 generated main-control event bindings preserved'
$BeforeOther=@($BeforeEvents|Where-Object{(Get-HelpControlName $_) -ne 'TutorialButton'}|ForEach-Object{$_.Extent.Text})
$AfterOther=@($AfterEvents|Where-Object{(Get-HelpControlName $_) -ne 'TutorialButton'}|ForEach-Object{$_.Extent.Text})
Assert-HelpBinding (($BeforeOther -join "`0") -ceq ($AfterOther -join "`0")) 'Help changed another generated event, timer or window cleanup binding'
$Count++;Write-Host 'PASS every other event and lifecycle callback preserved verbatim'

# Negative control: prove this fixture catches the former broad rewrite, which
# consumed the generated control bindings between Help and the startup marker.
$FormerPattern='(?s)\(Control ''TutorialButton''\)\.Add_Click\(\{.*?\}\)\r?\n\$BaseCombo\.SelectedIndex=0'
$Former=[regex]::Match($Before,$FormerPattern)
Assert-HelpBinding $Former.Success 'Former bug no longer reproduced by the regression fixture'
$Broken=$Before.Substring(0,$Former.Index)+$New+"`n"+'$BaseCombo.SelectedIndex=0'+$Before.Substring($Former.Index+$Former.Length)
$Lost=@(Get-HelpEventCalls $Broken|Where-Object{$ExpectedControls -contains (Get-HelpControlName $_)})
Assert-HelpBinding ($Lost.Count -eq 0) 'Negative control did not expose the lost generated bindings'
$Count++;Write-Host 'PASS negative control reproduces loss of all 17 main-control bindings'

# Actually register and invoke the final composed Connect and Help callbacks.
# Fake controls record callbacks; the invoked functions cannot touch a network.
$script:HelpTestButtons=@{}
$script:HelpTestConnects=0;$script:HelpTestOpens=0;$script:HelpTestForced=$false
function Control([string]$Name){
    if(-not$script:HelpTestButtons.ContainsKey($Name)){
        $Button=[pscustomobject]@{Callback=$null;Registrations=0}
        $Button|Add-Member ScriptMethod Add_Click {param($Callback)$this.Callback=$Callback;$this.Registrations++}
        $script:HelpTestButtons[$Name]=$Button
    }
    return $script:HelpTestButtons[$Name]
}
function UnifiedConnect{$script:HelpTestConnects++}
function Show-RouterVPNProductOnboarding{param([switch]$Force)$script:HelpTestOpens++;$script:HelpTestForced=[bool]$Force}
foreach($Name in @('UnifiedConnectButton','TutorialButton')){
    $Binding=@($AfterEvents|Where-Object{(Get-HelpControlName $_) -eq $Name})
    Assert-HelpBinding ($Binding.Count -eq 1) ("Executable binding missing: "+$Name)
    . ([ScriptBlock]::Create($Binding[0].Extent.Text))
    Assert-HelpBinding ($script:HelpTestButtons[$Name].Registrations -eq 1) ("Binding not registered exactly once: "+$Name)
    $Callback=$script:HelpTestButtons[$Name].Callback
    & $Callback
}
Assert-HelpBinding ($script:HelpTestConnects -eq 1 -and $script:HelpTestOpens -eq 1 -and $script:HelpTestForced) 'Composed Connect/Help callbacks did not invoke the intended actions'
$Count++;Write-Host 'PASS composed Connect works and Help explicitly opens full onboarding'
Write-Host ("Windows Help binding regression tests: PASS ("+$Count+" checks)")
