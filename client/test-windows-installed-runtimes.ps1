param(
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$ExpectedArchitecture
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$PackageRoot=[IO.Path]::GetFullPath($PackageRoot)
$installer=Join-Path $PackageRoot 'install-windows.ps1'
if(-not(Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Actual installed-runtime test requires an extracted Windows package.' }
$tempBase=$env:RUNNER_TEMP
if([string]::IsNullOrWhiteSpace($tempBase)) { $tempBase=[IO.Path]::GetTempPath() }
$owner=[Guid]::NewGuid().ToString('N')
$sandbox=Join-Path $tempBase ('routervpn-installed-runtimes-'+$owner)
New-Item -ItemType Directory -Path $sandbox | Out-Null
[IO.File]::WriteAllText((Join-Path $sandbox 'test-owner.txt'),$owner)
$previousProgramData=$env:ProgramData
$complete=$false

function Invoke-TestWindowsInstaller {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -Bundle $PackageRoot
    if($LASTEXITCODE -ne 0) { throw 'Actual Windows installer failed.' }
}

function Test-InstalledDesktopRuntimes([string]$Root,[string]$Pass) {
    $controller=Join-Path $Root 'router-vpn-client.exe'
    foreach($pair in @(@('--verify-native-runtime','native/sing-box-routervpn.exe'),@('--verify-amnezia-runtime','amnezia/sing-box-amnezia.exe'))) {
        $verified=(& $controller $pair[0] $Root 2>&1 | Out-String).Trim()
        if($LASTEXITCODE -ne 0) { throw ('Installed runtime verifier failed: '+$pair[0]+': '+$verified) }
        $expected=[IO.Path]::GetFullPath((Join-Path $Root ('runtime/'+$pair[1])))
        if($verified -ne $expected) { throw 'Installed verifier selected a different runtime root.' }
    }
    $native=Get-Content -LiteralPath (Join-Path $Root 'runtime/native/NATIVE-RUNTIME.json') -Raw | ConvertFrom-Json
    $amnezia=Get-Content -LiteralPath (Join-Path $Root 'runtime/amnezia/AMNEZIA-RUNTIME.json') -Raw | ConvertFrom-Json
    if($native.target -ne ('windows/'+$ExpectedArchitecture) -or $amnezia.target -ne ('windows/'+$ExpectedArchitecture)) { throw 'Installed runtime architecture differs from its native runner.' }
    # Reuse the shipping Xray hash/pin/version verifier against the installed
    # source; its throwaway destination stays in this test's private temp root.
    . (Join-Path $Root 'client/Install-Bundled-Xray.ps1')
    Install-RouterVPNBundledXray -BundleRoot $Root -Destination (Join-Path $sandbox ('xray-proof-'+$Pass)) -Architecture $ExpectedArchitecture
    foreach($name in @('RouterVPN.exe','RouterVPN.ico','router-vpn-client.exe','router-vpn-dns.exe','router-vpn-start-layer-relay.exe','router-vpn-update.exe')) {
        if(-not(Test-Path -LiteralPath (Join-Path $Root $name) -PathType Leaf)) { throw ('Installed application is incomplete: '+$name) }
    }
}

try {
    $env:ProgramData=$sandbox
    Invoke-TestWindowsInstaller
    $installed=Join-Path $sandbox 'RouterVPN'
    Test-InstalledDesktopRuntimes $installed 'first'
    $shortcut=Join-Path $sandbox 'Microsoft/Windows/Start Menu/Programs/Router VPN.lnk'
    if(-not(Test-Path -LiteralPath $shortcut -PathType Leaf)) { throw 'Installed Start Menu shortcut is missing.' }
    $shell=New-Object -ComObject WScript.Shell
    $link=$shell.CreateShortcut($shortcut)
    if($link.TargetPath -ne (Join-Path $installed 'RouterVPN.exe') -or $link.WorkingDirectory -ne $installed) { throw 'Installed Start Menu shortcut selects another application.' }

    $sentinels=@{
        'routers.json'='{"schema_version":4,"selected_id":"sentinel","profiles":[{"id":"sentinel","name":"keep-me"}]}'
        'nodes/sentinel/router-vpn-bundle.json'='{"fixture":"keep private linked node"}'
        'generated/sentinel.conf'='keep generated private profile'
        'runtime/windows/driver-sentinel.bin'='keep existing driver setup'
    }
    $digests=@{}
    foreach($relative in $sentinels.Keys) {
        $path=Join-Path $installed $relative
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
        [IO.File]::WriteAllText($path,$sentinels[$relative])
        $digests[$relative]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    Invoke-TestWindowsInstaller
    Test-InstalledDesktopRuntimes $installed 'upgrade'
    foreach($relative in $digests.Keys) {
        if((Get-FileHash -LiteralPath (Join-Path $installed $relative) -Algorithm SHA256).Hash -ne $digests[$relative]) { throw ('Upgrade replaced private state or driver assets: '+$relative) }
    }
    $sessionTest=Join-Path $installed 'client/test-windows-package-session.ps1'
    if(-not(Test-Path -LiteralPath $sessionTest -PathType Leaf)) { throw 'Installed package lacks its actual owned Session test.' }
    & $sessionTest -Root $installed
    if(@(Get-ChildItem -LiteralPath $installed -Force -Filter '.runtime-install-*').Count -ne 0) { throw 'Successful installed upgrade retained an unfinished runtime transaction.' }
    $complete=$true
    Write-Output ('Actual Windows '+$ExpectedArchitecture+' installation and upgrade: PASS (native, AmneziaWG, Xray, private state, drivers, Start Menu and launcher)')
} finally {
    $env:ProgramData=$previousProgramData
    if($complete -and [IO.File]::ReadAllText((Join-Path $sandbox 'test-owner.txt')) -ceq $owner) {
        Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction Stop
    } elseif(-not $complete) {
        Write-Host ('Installed-runtime failure evidence retained in '+$sandbox)
    }
}
