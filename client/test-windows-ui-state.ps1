param([string]$Root=(Split-Path $PSScriptRoot -Parent),[string]$StateModule='', [string]$TransportModule='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
$Client=Join-Path $Root 'client'
if(-not$StateModule){$StateModule=Join-Path $Client 'RouterVPN-Windows-UIState.psm1'}
if(-not$TransportModule){$TransportModule=Join-Path $Client 'RouterVPN-Windows-ControllerTransport.psm1'}
$Transport=Import-Module $TransportModule -Global -PassThru -ErrorAction Stop
Import-Module $StateModule -Global -ErrorAction Stop
$script:Checks=0
function Check([bool]$Value,[string]$Message){if(-not$Value){throw ('CONTROL '+$Message)};$script:Checks++}
function Reject([scriptblock]$Action,[string]$Message){$Caught=$false;try{[void](&$Action)}catch{$Caught=$true};Check $Caught $Message}
function Seed([string]$Path,[string]$Text){[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path));[IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($true))}
function SameBytes([string]$Left,[string]$Right){return [Convert]::ToBase64String([IO.File]::ReadAllBytes($Left))-ceq[Convert]::ToBase64String([IO.File]::ReadAllBytes($Right))}
function Capture([string]$Directory){
    # This fixture installs only the module-private filesystem ownership seam.
    # The real pipe/process authentication and environment capture are executed
    # separately by the native PowerShell bridge and composed Session gates.
    & $Transport {param($Value)$script:ControllerMode='owned';$script:ControllerChannel=[object]::new();$script:ControllerDataRoot=$Value} $Directory
}
function ShippingFunction([string]$Source,[string]$Name){
    $Found=@(([ScriptBlock]::Create($Source)).Ast.FindAll({param($Node)$Node-is[Management.Automation.Language.FunctionDefinitionAst]-and$Node.Name-ceq$Name},$true))
    if($Found.Count-ne1){throw ('Shipping state function count drifted: '+$Name)}
    return $Found[0].Extent.Text
}
$Owned=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-ui-state-'+[Guid]::NewGuid().ToString('N'))
$Legacy=Join-Path $Owned 'App/client';$Data=Join-Path $Owned 'Data';$Replacement=Join-Path $Owned 'replacement'
$Links=New-Object Collections.Generic.List[string]
$PriorRoot=$env:HOMEVPN_ROOT
try{
    foreach($Directory in @($Legacy,$Data,$Replacement)){[void][IO.Directory]::CreateDirectory($Directory)}
    $Names=@('windows-onboarding-v3.json','windows-selected-mode-v1.txt','windows-custom-presets-v1.json')
    $Texts=@('{"version":3,"done":true,"step":4}',"custom:Saved $([char]0x03bb)`r`n",('[{"name":"Saved '+[char]0x03bb+'","layers":["wg","pq"]}]'))
    for($Index=0;$Index-lt$Names.Count;$Index++){Seed (Join-Path $Legacy ('.routervpn-state/'+$Names[$Index])) $Texts[$Index]}
    Seed (Join-Path $Legacy '.routervpn-state/routers.json') '{"private_key":"do-not-copy"}'
    $env:HOMEVPN_ROOT=$Data
    Check ($null-eq(Get-RouterVPNControllerDataRoot)) 'legacy transport accepted an ambient data directory'
    Check ((Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1])-ceq$Texts[1]) 'standalone state lost its original directory'
    Check (-not[IO.Directory]::Exists((Join-Path $Data '.routervpn-state'))) 'legacy state copied into ambient Data'

    Capture $Data
    for($Index=0;$Index-lt$Names.Count;$Index++){
        Check ((Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[$Index])-ceq$Texts[$Index]) 'owned state changed the migrated text'
        $Destination=Join-Path $Data ('.routervpn-state/'+$Names[$Index])
        Check ([IO.File]::Exists($Destination)) 'owned read did not migrate into captured Data'
        Check (SameBytes (Join-Path $Legacy ('.routervpn-state/'+$Names[$Index])) $Destination) 'migration changed the exact saved bytes'
    }
    Check (-not[IO.File]::Exists((Join-Path $Data '.routervpn-state/routers.json'))) 'migration copied unknown private state'
    Reject {Write-RouterVPNUIState -LegacyDirectory $Legacy -Name 'routers.json' -Text '{}'} 'UI writer accepted a controller private filename'
    $Before=[IO.File]::ReadAllText((Join-Path $Data ('.routervpn-state/'+$Names[1])))
    Seed (Join-Path $Legacy ('.routervpn-state/'+$Names[1])) 'old-package-replacement'
    Check ((Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1])-ceq$Before) 'existing Data preference was overwritten by legacy state'
    $env:HOMEVPN_ROOT=$Replacement
    Write-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1] -Text 'awg2-fast'
    Check ([IO.File]::ReadAllText((Join-Path $Data ('.routervpn-state/'+$Names[1])))-ceq'awg2-fast') 'later environment replaced the captured state owner'
    Check (-not[IO.Directory]::Exists((Join-Path $Replacement '.routervpn-state'))) 'replacement environment acquired UI writes'
    Check ([IO.File]::ReadAllText((Join-Path $Legacy ('.routervpn-state/'+$Names[1])))-ceq'old-package-replacement') 'owned write changed immutable package preferences'

    # Execute the actual App, profile snapshot and generated unified-shell
    # reader/writer functions against the same captured Data directory.
    $App=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-App.ps1'),[Text.Encoding]::UTF8)
    $Profile=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-ProfileSettings.ps1'),[Text.Encoding]::UTF8)
    $Unified=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-UnifiedShell.ps1'),[Text.Encoding]::UTF8)
    . ([ScriptBlock]::Create($Unified))
    $Product=Add-RouterVPNUnifiedWindowsShell -ProductSource ([IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-Product-v2.ps1'),[Text.Encoding]::UTF8))
    foreach($Pair in @(@($App,'Get-OnboardingState'),@($App,'Save-OnboardingState'),@($Profile,'global:Get-RouterVPNCurrentModeSnapshot'),@($Profile,'global:Set-RouterVPNLoadedModeSnapshot'),@($Product,'GetUnifiedPresets'),@($Product,'SaveUnifiedPresets'),@($Product,'GetUnifiedModeID'),@($Product,'SaveUnifiedModeID'))){
        . ([ScriptBlock]::Create((ShippingFunction $Pair[0] $Pair[1]).Replace('$PSScriptRoot','$Legacy')))
    }
    $OnboardingSteps=@(0,1,2,3,4,5,6,7,8)
    Check ((Get-OnboardingState).done-and(Get-OnboardingState).step-eq4) 'actual onboarding did not read captured Data'
    Save-OnboardingState 6 $false
    Check (-not(Get-OnboardingState).done-and(Get-OnboardingState).step-eq6) 'actual onboarding did not save captured Data'
    SaveUnifiedModeID 'custom:whole path'
    SaveUnifiedPresets @([pscustomobject]@{name='whole path';layers=@('wg','pq')})
    $Snapshot=Get-RouterVPNCurrentModeSnapshot
    Check ($Snapshot.mode-ceq'custom:whole path'-and(@($Snapshot.custom_layers)-join',')-ceq'wg,pq') 'profile snapshot disagreed with unified saved state'
    Set-RouterVPNLoadedModeSnapshot ([pscustomobject]@{mode='custom:restored path';custom_layers=@('awg2-fast','pq')})
    Check ((GetUnifiedModeID)-ceq'custom:restored path') 'loaded profile did not update unified captured state'
    $Presets=@(GetUnifiedPresets)
    Check ($Presets.Count-eq2-and(@(($Presets|Where-Object{$_.name-ceq'restored path'}).layers)-join',')-ceq'awg2-fast,pq') 'loaded profile lost existing CUSTOM presets'
    Check ((@(($Presets|Where-Object{$_.name-ceq'whole path'}).layers)-join',')-ceq'wg,pq') 'loaded profile changed another CUSTOM preset'
    Set-RouterVPNLoadedModeSnapshot ([pscustomobject]@{mode='custom:whole path';custom_layers=@('awg2-strong','pq')})
    $Presets=@(GetUnifiedPresets)
    Check ($Presets.Count-eq2-and@($Presets|Where-Object{$_.name-ceq'whole path'}).Count-eq1) 'loaded profile duplicated or removed an existing CUSTOM preset'
    $Snapshot=Get-RouterVPNCurrentModeSnapshot
    Check ($Snapshot.mode-ceq'custom:whole path'-and(@($Snapshot.custom_layers)-join',')-ceq'awg2-strong,pq') 'profile snapshot did not select one preset from the saved array'
    Check ((@(($Presets|Where-Object{$_.name-ceq'restored path'}).layers)-join',')-ceq'awg2-fast,pq') 'updating one CUSTOM preset changed another'
    SaveUnifiedPresets @($Presets|Where-Object{$_.name-ceq'whole path'})
    Check (@(GetUnifiedPresets).Count-eq1-and(Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[2]).TrimStart().StartsWith('[')) 'one remaining CUSTOM preset was not saved as an array'
    SaveUnifiedPresets @()
    $EmptyPresets=@(GetUnifiedPresets);$EmptyRaw=Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[2]
    Check ($EmptyPresets.Count-eq0-and$EmptyRaw-match'^\s*\[\s*\]\s*$') ('deleting the final CUSTOM preset did not save an empty array; count='+$EmptyPresets.Count+'; saved='+($EmptyRaw|ConvertTo-Json -Compress))
    # Older releases serialized one preset as an object; preserve that input.
    Write-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[2] -Text '{"name":"legacy single","layers":["wg","pq"]}'
    Check (@(GetUnifiedPresets).Count-eq1-and[string](@(GetUnifiedPresets)[0].name)-ceq'legacy single') 'legacy single CUSTOM object was not preserved'
    Set-RouterVPNLoadedModeSnapshot ([pscustomobject]@{mode='custom:restored path';custom_layers=@('awg2-fast','pq')})
    Check (@(GetUnifiedPresets).Count-eq2) 'loading a profile discarded a legacy single CUSTOM object'

    # Match App's ScriptBlock.Create composition without replacing PSScriptRoot.
    # Copy the exact module beside disposable old package preferences so the
    # test never writes source-tree data or relies on the process working dir.
    $DynamicClient=Join-Path $Owned 'dynamic/App/client';$DynamicData=Join-Path $Owned 'dynamic/Data'
    [void][IO.Directory]::CreateDirectory($DynamicData)
    Seed (Join-Path $DynamicClient ('.routervpn-state/'+$Names[1])) 'custom:dynamic package'
    Seed (Join-Path $DynamicClient ('.routervpn-state/'+$Names[2])) '[{"name":"dynamic package","layers":["wg","pq"]}]'
    $CopiedModule=Join-Path $DynamicClient ([IO.Path]::GetFileName($StateModule))
    [IO.File]::Copy($StateModule,$CopiedModule,$false)
    Import-Module $CopiedModule -Global -Force -ErrorAction Stop
    Capture $DynamicData
    foreach($Pair in @(@($Profile,'global:Get-RouterVPNCurrentModeSnapshot'),@($Profile,'global:Set-RouterVPNLoadedModeSnapshot'),@($Product,'GetUnifiedModeID'))){
        . ([ScriptBlock]::Create((ShippingFunction $Pair[0] $Pair[1])))
    }
    $DynamicSnapshot=Get-RouterVPNCurrentModeSnapshot
    Check ($DynamicSnapshot.mode-ceq'custom:dynamic package'-and(@($DynamicSnapshot.custom_layers)-join',')-ceq'wg,pq') 'dynamic shipping functions lost package-relative legacy state'
    Set-RouterVPNLoadedModeSnapshot ([pscustomobject]@{mode='auto';custom_layers=@()})
    Check ((GetUnifiedModeID)-ceq'auto'-and[IO.File]::ReadAllText((Join-Path $DynamicData ('.routervpn-state/'+$Names[1])))-ceq'auto') 'dynamic shipping functions did not use captured Data'
    Check ([IO.File]::ReadAllText((Join-Path $DynamicClient ('.routervpn-state/'+$Names[1])))-ceq'custom:dynamic package') 'dynamic shipping write changed old package state'
    Import-Module $StateModule -Global -Force -ErrorAction Stop
    Capture $Data

    & $Transport {$script:ControllerMode='closed'}
    Reject {Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1]} 'retired UI owner retained state access'
    Reject {Write-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1] -Text 'stale'} 'retired UI owner retained state writes'
    & $Transport {$script:ControllerMode='failed'}
    Reject {Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1]} 'failed UI owner fell back to legacy state'
    Capture ''
    Reject {Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1]} 'missing native Data root fell back to legacy state'
    Capture 'relative-root'
    Reject {Write-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1] -Text 'bad'} 'relative native Data root was accepted'

    $Sentinel=Join-Path $Owned 'sentinel.txt';Seed $Sentinel 'outside-sentinel'
    $Unsafe=Join-Path $Owned 'unsafe';[void][IO.Directory]::CreateDirectory((Join-Path $Unsafe '.routervpn-state'))
    $Destination=Join-Path $Unsafe ('.routervpn-state/'+$Names[1])
    [void](New-Item -ItemType HardLink -Path $Destination -Target $Sentinel -ErrorAction Stop)
    Capture $Unsafe
    Reject {Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1]} 'linked destination read was accepted'
    Reject {Write-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1] -Text 'changed'} 'linked destination write was accepted'
    Check ([IO.File]::ReadAllText($Sentinel)-ceq'outside-sentinel') 'linked destination modified another file'
    [IO.File]::Delete($Destination)

    $LegacyLinked=Join-Path $Owned 'linked-legacy';[void][IO.Directory]::CreateDirectory((Join-Path $LegacyLinked '.routervpn-state'))
    [void](New-Item -ItemType HardLink -Path (Join-Path $LegacyLinked ('.routervpn-state/'+$Names[1])) -Target $Sentinel -ErrorAction Stop)
    Reject {Read-RouterVPNUIState -LegacyDirectory $LegacyLinked -Name $Names[1]} 'linked legacy preference was migrated'
    Check (-not[IO.File]::Exists($Destination)) 'unsafe migration left a destination'
    Write-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1] -Text 'current-destination'
    Check ((Read-RouterVPNUIState -LegacyDirectory $LegacyLinked -Name $Names[1])-ceq'current-destination') 'existing Data unnecessarily followed unsafe legacy input'

    $Outside=Join-Path $Owned 'outside';[void][IO.Directory]::CreateDirectory((Join-Path $Outside '.routervpn-state'))
    Seed (Join-Path $Outside ('.routervpn-state/'+$Names[1])) 'outside-directory'
    $Link=Join-Path $Owned 'linked-root'
    $Kind=if([IO.Path]::DirectorySeparatorChar-eq'\'){'Junction'}else{'SymbolicLink'}
    [void](New-Item -ItemType $Kind -Path $Link -Target $Outside -ErrorAction Stop);$Links.Add($Link)
    Capture $Link
    Reject {Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1]} 'linked ancestor was accepted'
    $DataLinked=Join-Path $Owned 'linked-state';[void][IO.Directory]::CreateDirectory($DataLinked)
    $Link=Join-Path $DataLinked '.routervpn-state'
    [void](New-Item -ItemType $Kind -Path $Link -Target (Join-Path $Outside '.routervpn-state') -ErrorAction Stop);$Links.Add($Link)
    Capture $DataLinked
    Reject {Write-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[1] -Text 'bad'} 'linked state directory was accepted'
    Capture $Data
    Reject {Read-RouterVPNUIState -LegacyDirectory $Legacy -Name '../windows-selected-mode-v1.txt'} 'state filename escaped its allowlist'
    $Large=New-Object byte[] 4194305
    [IO.File]::WriteAllBytes((Join-Path $Data ('.routervpn-state/'+$Names[0])),$Large)
    Reject {Read-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[0]} 'oversized state file was read'
    Reject {Write-RouterVPNUIState -LegacyDirectory $Legacy -Name $Names[2] -Text ('x'*4194305)} 'oversized state file was written'
    Check (@(Get-ChildItem -LiteralPath (Join-Path $Data '.routervpn-state') -Filter '.routervpn-ui-*.tmp' -Force).Count-eq0) 'UI writes leaked temporary files'
    Write-Host "PASS Windows UI state checks=$script:Checks"
}finally{
    $env:HOMEVPN_ROOT=$PriorRoot
    foreach($Link in $Links){if([IO.Directory]::Exists($Link)){[IO.Directory]::Delete($Link)}}
    if([IO.Directory]::Exists($Owned)){Remove-Item -LiteralPath $Owned -Recurse -Force}
}
