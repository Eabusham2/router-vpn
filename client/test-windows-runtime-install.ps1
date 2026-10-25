param([string]$SourceRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $SourceRoot 'client/Install-Bundled-Desktop-Runtimes.ps1')
$script:RealMove=(Get-Command Move-RouterVPNRuntimeInstallDirectory).ScriptBlock
$script:RealCleanup=(Get-Command Remove-RouterVPNRuntimeInstallTransaction).ScriptBlock
$script:Checks=0
$script:Fixture=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-runtime-install-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:Fixture | Out-Null

function Check([bool]$Condition,[string]$Message) {
    $script:Checks++
    if(-not $Condition) { throw $Message }
}

function Write-Fixture([string]$Path,[string]$Value) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) | Out-Null
    [IO.File]::WriteAllText($Path,$Value)
}

function Reset-Fixture([string]$Name,[bool]$Existing=$true) {
    $script:Case=Join-Path $script:Fixture $Name
    $script:Bundle=Join-Path $script:Case 'package'
    $script:Installed=Join-Path $script:Case 'installed'
    $script:Fault='';$script:Moves=0;$script:Verifications=0
    $script:New=@{};$script:Old=@{};$script:Private=@{}
    Write-Fixture (Join-Path $script:Bundle 'router-vpn-client.exe') 'fixture controller; process execution is doubled'
    foreach($kind in @('native','amnezia','xray')) {
        foreach($name in @(Get-RouterVPNRuntimeInstallNames $kind)) {
            $payload='new-'+$kind+'-'+$name
            if($kind -eq 'native' -and $name -ceq 'TOR-PT-NOTICES.json') { $payload='{"notice":"'+('x'*300000)+'"}' }
            Write-Fixture (Join-Path $script:Bundle ('runtime/'+$kind+'/'+$name)) $payload
            if($Existing) { Write-Fixture (Join-Path $script:Installed ('runtime/'+$kind+'/'+$name)) ('old-'+$kind+'-'+$name) }
        }
        $script:New[$kind]=Get-RouterVPNRuntimeInstallManifest (Join-Path $script:Bundle ('runtime/'+$kind)) $kind
        if($Existing) { $script:Old[$kind]=Get-RouterVPNRuntimeInstallManifest (Join-Path $script:Installed ('runtime/'+$kind)) $kind }
    }
    foreach($relative in @('routers.json','nodes/saved-private.json','generated/linked-profile.conf','runtime/windows/wintun.dll','runtime/windows/tor-expert/tor.exe')) {
        $path=Join-Path $script:Installed $relative
        Write-Fixture $path ('preserve-'+$relative)
        $script:Private[$relative]=(Get-FileHash -LiteralPath $path).Hash
    }
}

# Only native process execution is doubled. Directory ownership, bounded file
# capture, copying, atomic renames, readback and rollback use the real filesystem.
# The release matrix separately executes the actual packaged verifiers on both
# Windows architectures after installing into isolated ProgramData roots.
function Invoke-RouterVPNRuntimeInstallVerifier([string]$Controller,[string]$Flag,[string]$Root) {
    Check ($Controller -eq (Join-Path $script:Bundle 'router-vpn-client.exe')) 'Verification selected an ambient controller.'
    $kind=switch($Flag) { '--verify-native-runtime' {'native'} '--verify-amnezia-runtime' {'amnezia'} default {throw 'Unexpected native process invocation.'} }
    Check ((Get-RouterVPNRuntimeInstallManifest (Join-Path $Root ('runtime/'+$kind)) $kind) -ceq $script:New[$kind]) 'Verification received changed fixture payload.'
    $script:Verifications++
    if($script:Fault -eq 'post-verify' -and $Root -eq $script:Installed) { throw 'injected post-copy native failure' }
}

function Copy-RouterVPNRuntimeInstallXray([string]$Bundle,[string]$Destination,[string]$Architecture) {
    Check ($Bundle -eq $script:Bundle -and $Architecture -eq 'amd64') 'Xray staging changed source or architecture.'
    New-Item -ItemType Directory -Path $Destination | Out-Null
    foreach($name in @(Get-RouterVPNRuntimeInstallNames 'xray')) {
        Copy-Item -LiteralPath (Join-Path $Bundle ('runtime/xray/'+$name)) -Destination (Join-Path $Destination $name)
    }
    if($script:Fault -eq 'stage-drift') {
        Write-Fixture (Join-Path ([IO.Path]::GetDirectoryName($Destination)) 'native/libcronet.dll') 'changed after initial staged hash'
    }
    if($script:Fault -eq 'stage-notices-drift') {
        $path=Join-Path ([IO.Path]::GetDirectoryName($Destination)) 'native/TOR-PT-NOTICES.json'
        $raw=[IO.File]::ReadAllBytes($path);$raw[100]=[byte]($raw[100] -bxor 1);[IO.File]::WriteAllBytes($path,$raw)
    }
}

function Move-RouterVPNRuntimeInstallDirectory([string]$Source,[string]$Destination) {
    $script:Moves++
    $normalized=$Source.Replace('\','/')
    if($script:Fault -eq 'backup-locked' -and $Source -eq (Join-Path $script:Installed 'runtime/native')) { throw 'injected locked old engine' }
    if($script:Fault -in @('adopt-second','restore-locked') -and $normalized.EndsWith('/new/runtime/amnezia')) { throw 'injected second adoption failure' }
    if($script:Fault -eq 'restore-locked' -and $normalized.EndsWith('/backup/native')) { throw 'injected rollback rename failure' }
    if($script:Fault -eq 'foreign-target' -and $normalized.EndsWith('/new/runtime/native')) {
        Write-Fixture (Join-Path $Destination 'foreign.txt') 'foreign directory appeared'
    }
    & $script:RealMove $Source $Destination
}

function Remove-RouterVPNRuntimeInstallTransaction([string]$Path,[string]$Owner) {
    if($script:Fault -eq 'cleanup-partial') {
        Remove-Item -LiteralPath (Join-Path $Path 'backup/native/CRONET-LICENSE') -Force
        throw 'injected old-backup cleanup failure'
    }
    & $script:RealCleanup $Path $Owner
}

function Preserved-Private {
    foreach($relative in $script:Private.Keys) {
        Check ((Get-FileHash -LiteralPath (Join-Path $script:Installed $relative)).Hash -eq $script:Private[$relative]) ('Private state or driver asset changed: '+$relative)
    }
}

function Require-Payload($Expected) {
    foreach($kind in @('native','amnezia','xray')) {
        Check ((Get-RouterVPNRuntimeInstallManifest (Join-Path $script:Installed ('runtime/'+$kind)) $kind) -ceq $Expected[$kind]) ('Wrong installed payload after transaction: '+$kind)
    }
    Preserved-Private
}

function Invoke-Install { Install-RouterVPNBundledDesktopRuntimes $script:Bundle $script:Installed 'amd64' }
function Expect-Failure([string]$Pattern) {
    $message=''
    try { Invoke-Install } catch { $message=$_.Exception.Message }
    Check ($message -match $Pattern) ('Missing expected install failure '+$Pattern+': '+$message)
}

try {
    Check ('TOR-PT-NOTICES.json' -cin @(Get-RouterVPNRuntimeInstallNames 'native')) 'Native installer omitted mandatory PT notices.'
    Reset-Fixture 'upgrade'
    Invoke-Install
    Require-Payload $script:New
    Check ($script:Moves -eq 6 -and $script:Verifications -eq 6) 'Upgrade omitted staged or installed verification.'
    Check (@(Get-ChildItem -LiteralPath $script:Installed -Filter '.runtime-install-*' -Force).Count -eq 0) 'Successful upgrade retained a transaction.'

    Reset-Fixture 'fresh' $false
    Invoke-Install
    Require-Payload $script:New
    Check ($script:Moves -eq 3) 'Fresh install tried to replace unrelated runtime state.'

    Reset-Fixture 'upgrade-from-pre-pt-release'
    Remove-Item -LiteralPath (Join-Path $script:Installed 'runtime/native/TOR-PT-NOTICES.json') -Force
    Invoke-Install
    Require-Payload $script:New
    Check ((Get-Item -LiteralPath (Join-Path $script:Installed 'runtime/native/TOR-PT-NOTICES.json')).Length -gt 262144) 'PT notices did not survive installation with their explicit larger bound.'

    foreach($faultCase in @('backup-locked','adopt-second','post-verify','stage-drift','stage-notices-drift')) {
        Reset-Fixture $faultCase
        $script:Fault=$faultCase
        Expect-Failure 'injected|changed fixture'
        Require-Payload $script:Old
        Check (@(Get-ChildItem -LiteralPath $script:Installed -Filter '.runtime-install-*' -Force).Count -eq 0) 'Successful rollback retained recovery files.'
    }

    Reset-Fixture 'restore-locked'
    $script:Fault='restore-locked'
    Expect-Failure 'rollback failed; recovery copies retained'
    $retained=@(Get-ChildItem -LiteralPath $script:Installed -Filter '.runtime-install-*' -Directory -Force)
    Check ($retained.Count -eq 1) 'Failed rollback removed its owned recovery transaction.'
    Check ((Get-RouterVPNRuntimeInstallManifest (Join-Path $retained[0].FullName 'backup/native') 'native') -ceq $script:Old['native']) 'Failed rollback lost the complete old native engine.'
    Check ((Get-RouterVPNRuntimeInstallManifest (Join-Path $retained[0].FullName 'new/runtime/native') 'native') -ceq $script:New['native']) 'Failed rollback lost the complete new native engine.'
    Preserved-Private

    Reset-Fixture 'foreign-target'
    $script:Fault='foreign-target'
    Expect-Failure 'rollback failed; recovery copies retained'
    Check ([IO.File]::ReadAllText((Join-Path $script:Installed 'runtime/native/foreign.txt')) -eq 'foreign directory appeared') 'Rollback deleted an unowned target.'
    $retained=@(Get-ChildItem -LiteralPath $script:Installed -Filter '.runtime-install-*' -Directory -Force)
    Check ((Get-RouterVPNRuntimeInstallManifest (Join-Path $retained[0].FullName 'backup/native') 'native') -ceq $script:Old['native']) 'A competing destination destroyed the previous native engine.'
    Preserved-Private

    Reset-Fixture 'cleanup-partial'
    $script:Fault='cleanup-partial'
    Expect-Failure 'committed; cleanup pending'
    Require-Payload $script:New
    Check ($script:Moves -eq 6) 'Cleanup failure attempted to roll back an already committed runtime.'

    Reset-Fixture 'foreign-source'
    Write-Fixture (Join-Path $script:Bundle 'runtime/native/unowned.dll') 'foreign'
    Expect-Failure 'unowned files'
    Require-Payload $script:Old
    Check ($script:Moves -eq 0) 'Unowned package payload changed the installed runtime.'

    foreach($noticeFault in @('missing','misnamed','oversized','ordinary-license-oversized')) {
        Reset-Fixture ('pt-notices-'+$noticeFault)
        $path=Join-Path $script:Bundle 'runtime/native/TOR-PT-NOTICES.json'
        switch($noticeFault) {
            'missing' { Remove-Item -LiteralPath $path -Force }
            'misnamed' { Rename-Item -LiteralPath $path -NewName 'TOR-PT-NOTICE.json' }
            'oversized' { Write-Fixture $path ('x'*2097153) }
            'ordinary-license-oversized' { Write-Fixture (Join-Path $script:Bundle 'runtime/native/XRAY-LICENSE') ('x'*262145) }
        }
        Expect-Failure 'incomplete|unowned|file bound'
        Require-Payload $script:Old
        Check ($script:Moves -eq 0) 'Invalid notices or widened ordinary license bound reached runtime adoption.'
    }

    Reset-Fixture 'linked-source'
    $real=Join-Path $script:Bundle 'real-native'
    [IO.Directory]::Move((Join-Path $script:Bundle 'runtime/native'),$real)
    $link=Join-Path $script:Bundle 'runtime/native'
    New-Item -ItemType SymbolicLink -Path $link -Target $real | Out-Null
    try {
        Expect-Failure 'Unsafe runtime installation'
        Require-Payload $script:Old
        Check ($script:Moves -eq 0) 'Linked package source reached adoption.'
    } finally {
        Check (((Get-Item -LiteralPath $link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) 'Linked-source fixture lost its directory link.'
        # The nonrecursive .NET API removes the link itself, avoiding the
        # Windows PowerShell 5.1 provider's directory-symlink cleanup failure.
        [IO.Directory]::Delete($link)
    }
    Check (-not(Test-Path -LiteralPath $link)) 'Linked-source fixture retained its directory link.'
    Check ((Get-RouterVPNRuntimeInstallManifest $real 'native') -ceq $script:New['native']) 'Removing the source link changed its real target payload.'

    Reset-Fixture 'owner-marker'
    $owned=Join-Path $script:Installed '.runtime-install-fixture'
    Write-Fixture (Join-Path $owned 'owner.txt') 'foreign-owner'
    Write-Fixture (Join-Path $owned 'keep.bin') 'preserve'
    $message=''
    try { & $script:RealCleanup $owned 'expected-owner' } catch { $message=$_.Exception.Message }
    Check ($message -match 'ownership changed' -and (Test-Path -LiteralPath (Join-Path $owned 'keep.bin'))) 'Cleanup deleted a transaction with a different owner.'

    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $SourceRoot 'client/install-windows.ps1'),[ref]$tokens,[ref]$errors)
    Check ($errors.Count -eq 0) 'Shipping Windows installer no longer parses.'
    $calls=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Install-RouterVPNBundledDesktopRuntimes'},$true))
    Check ($calls.Count -eq 1 -and $calls[0].Extent.Text -match '-BundleRoot \$Bundle -ApplicationRoot \$Root -Architecture \$RuntimeArchitecture') 'Shipping installer bypasses the exact runtime transaction.'
    Write-Output ('Windows runtime installation: PASS ('+$script:Checks+' checks; real filesystem, process verification doubled)')
} finally {
    Remove-Item -LiteralPath $script:Fixture -Recurse -Force -ErrorAction SilentlyContinue
}
