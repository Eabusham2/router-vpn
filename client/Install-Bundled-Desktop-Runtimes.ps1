# The exact-SHA outer package establishes trust. Stage only its three owned
# engine directories; private nodes and runtime/windows remain in place.
function Assert-RouterVPNRuntimeInstallPath([string]$Path,[bool]$Directory) {
    $full=[IO.Path]::GetFullPath($Path)
    $item=Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if((($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or ($item.PSIsContainer -ne $Directory)) {
        throw ('Unsafe runtime installation path: '+$full)
    }
    $parent=[IO.Directory]::GetParent($full)
    while($null -ne $parent) {
        $ancestor=Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
        if(-not $ancestor.PSIsContainer -or (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw ('Unsafe runtime installation ancestor: '+$ancestor.FullName)
        }
        $parent=$parent.Parent
    }
}

function Get-RouterVPNRuntimeInstallNames([string]$Kind) {
    switch($Kind) {
        'native' { return @('NATIVE-RUNTIME.json','sing-box-routervpn.exe','libcronet.dll','SING-BOX-LICENSE','AMNEZIA-LICENSE','XRAY-LICENSE','ROSENPASS-LICENSE-MIT','ROSENPASS-LICENSE-APACHE','CRONET-LICENSE','TOR-PT-NOTICES.json','tor-routervpn.exe','TOR-RUNTIME.json','TOR-SOURCE-LOCK.json','TOR-PADDING-SOURCE-LOCK.json','TOR-LICENSES.json') }
        'amnezia' { return @('AMNEZIA-RUNTIME.json','sing-box-amnezia.exe','SING-BOX-LICENSE','AMNEZIA-LICENSE') }
        'xray' { return @('XRAY-RUNTIME.json','xray.exe','XRAY-LICENSE') }
        default { throw 'Unknown owned runtime directory.' }
    }
}

function Get-RouterVPNRuntimeInstallManifest([string]$Directory,[string]$Kind,[bool]$Complete=$true) {
    Assert-RouterVPNRuntimeInstallPath $Directory $true
    $allowed=@(Get-RouterVPNRuntimeInstallNames $Kind)
    $items=@(Get-ChildItem -LiteralPath $Directory -Force -ErrorAction Stop)
    if($items.Count -gt $allowed.Count -or ($Complete -and $items.Count -ne $allowed.Count)) {
        throw 'Runtime payload set is incomplete or contains unowned files.'
    }
    $manifest=New-Object 'System.Collections.Generic.List[string]'
    foreach($item in @($items | Sort-Object Name)) {
        if($item.Name -cnotin $allowed) { throw 'Runtime payload contains an unowned file.' }
        Assert-RouterVPNRuntimeInstallPath $item.FullName $false
        $limit=262144
        if($Kind -eq 'native' -and $item.Name -ceq 'TOR-PT-NOTICES.json') { $limit=2097152 }
        elseif($Kind -eq 'native' -and $item.Name -ceq 'TOR-LICENSES.json') { $limit=262144 }
        elseif($Kind -eq 'native' -and $item.Name -ceq 'tor-routervpn.exe') { $limit=67108864 }
        elseif($item.Name -like '*.json') { $limit=32768 }
        elseif($item.Name -eq 'libcronet.dll') { $limit=134217728 }
        elseif($item.Name -like '*.exe') { $limit=402653184 }
        if($item.Length -le 0 -or $item.Length -gt $limit) { throw 'Runtime payload exceeds its file bound.' }
        $digest=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $current=Get-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
        Assert-RouterVPNRuntimeInstallPath $current.FullName $false
        if($current.Length -ne $item.Length) { throw 'Runtime payload changed during capture.' }
        $manifest.Add($item.Name+'|'+$item.Length+'|'+$digest)
    }
    Assert-RouterVPNRuntimeInstallPath $Directory $true
    return [string]::Join("`n",$manifest.ToArray())
}

function Invoke-RouterVPNRuntimeInstallVerifier([string]$Controller,[string]$Flag,[string]$Root) {
    Assert-RouterVPNRuntimeInstallPath $Controller $false
    $output=(& $Controller $Flag $Root 2>&1 | Out-String)
    if($LASTEXITCODE -ne 0) { throw ('Packaged runtime verification failed: '+$Flag+': '+$output.Trim()) }
}

function Copy-RouterVPNRuntimeInstallXray([string]$Bundle,[string]$Destination,[string]$Architecture) {
    $helper=Join-Path $Bundle 'client/Install-Bundled-Xray.ps1'
    Assert-RouterVPNRuntimeInstallPath $helper $false
    . $helper
    Install-RouterVPNBundledXray -BundleRoot $Bundle -Destination $Destination -Architecture $Architecture
}

function Move-RouterVPNRuntimeInstallDirectory([string]$Source,[string]$Destination) {
    Assert-RouterVPNRuntimeInstallPath $Source $true
    Assert-RouterVPNRuntimeInstallPath ([IO.Path]::GetDirectoryName($Destination)) $true
    if(Test-Path -LiteralPath $Destination) { throw 'Runtime adoption destination is already occupied.' }
    [IO.Directory]::Move($Source,$Destination)
}

function Remove-RouterVPNRuntimeInstallTransaction([string]$Path,[string]$Owner) {
    Assert-RouterVPNRuntimeInstallPath $Path $true
    $marker=Join-Path $Path 'owner.txt'
    Assert-RouterVPNRuntimeInstallPath $marker $false
    if([IO.File]::ReadAllText($marker) -cne $Owner) { throw 'Runtime transaction ownership changed; recovery files retained.' }
    # Never recurse through a replaced directory/junction during cleanup.
    $pending=New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($Path);$visited=0
    while($pending.Count -gt 0) {
        $directory=$pending.Pop()
        Assert-RouterVPNRuntimeInstallPath $directory $true
        foreach($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            $visited++
            if($visited -gt 80) { throw 'Runtime transaction cleanup exceeds its ownership bound.' }
            Assert-RouterVPNRuntimeInstallPath $item.FullName $item.PSIsContainer
            if($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
}

function Install-RouterVPNBundledDesktopRuntimes([string]$BundleRoot,[string]$ApplicationRoot,[string]$Architecture) {
    $ErrorActionPreference='Stop'
    $BundleRoot=[IO.Path]::GetFullPath($BundleRoot)
    $ApplicationRoot=[IO.Path]::GetFullPath($ApplicationRoot)
    Assert-RouterVPNRuntimeInstallPath $BundleRoot $true
    Assert-RouterVPNRuntimeInstallPath $ApplicationRoot $true
    if($BundleRoot -eq $ApplicationRoot) { throw 'Runtime installation requires a separate package source.' }
    $controller=Join-Path $BundleRoot 'router-vpn-client.exe'
    Assert-RouterVPNRuntimeInstallPath $controller $false
    $kinds=@('native','amnezia','xray')
    $source=@{}
    foreach($kind in $kinds) {
        $source[$kind]=Get-RouterVPNRuntimeInstallManifest (Join-Path $BundleRoot ('runtime/'+$kind)) $kind
    }
    Invoke-RouterVPNRuntimeInstallVerifier $controller '--verify-native-runtime' $BundleRoot
    Invoke-RouterVPNRuntimeInstallVerifier $controller '--verify-amnezia-runtime' $BundleRoot

    $runtime=Join-Path $ApplicationRoot 'runtime'
    if(-not(Test-Path -LiteralPath $runtime)) { New-Item -ItemType Directory -Path $runtime | Out-Null }
    Assert-RouterVPNRuntimeInstallPath $runtime $true
    $owner=[Guid]::NewGuid().ToString('N')
    $transaction=Join-Path $ApplicationRoot ('.runtime-install-'+$owner)
    New-Item -ItemType Directory -Path $transaction | Out-Null
    [IO.File]::WriteAllText((Join-Path $transaction 'owner.txt'),$owner)
    $stage=Join-Path $transaction 'new'
    $backup=Join-Path $transaction 'backup'
    New-Item -ItemType Directory -Path (Join-Path $stage 'runtime'),$backup | Out-Null
    $states=New-Object 'System.Collections.Generic.List[object]'
    $committed=$false;$retain=$false
    try {
        foreach($kind in $kinds) {
            $destination=Join-Path $stage ('runtime/'+$kind)
            if($kind -eq 'xray') {
                Copy-RouterVPNRuntimeInstallXray $BundleRoot $destination $Architecture
            } else {
                New-Item -ItemType Directory -Path $destination | Out-Null
                foreach($name in @(Get-RouterVPNRuntimeInstallNames $kind)) {
                    $sourceFile=Join-Path $BundleRoot ('runtime/'+$kind+'/'+$name)
                    Assert-RouterVPNRuntimeInstallPath $sourceFile $false
                    Copy-Item -LiteralPath $sourceFile -Destination (Join-Path $destination $name) -ErrorAction Stop
                }
            }
            if((Get-RouterVPNRuntimeInstallManifest $destination $kind) -cne $source[$kind]) { throw 'Staged runtime differs from its captured package.' }
        }
        Invoke-RouterVPNRuntimeInstallVerifier $controller '--verify-native-runtime' $stage
        Invoke-RouterVPNRuntimeInstallVerifier $controller '--verify-amnezia-runtime' $stage
        foreach($kind in $kinds) {
            $target=Join-Path $runtime $kind
            $exists=Test-Path -LiteralPath $target
            $old=''
            if($exists) { $old=Get-RouterVPNRuntimeInstallManifest $target $kind $false }
            $states.Add([pscustomobject]@{Kind=$kind;Target=$target;Backup=(Join-Path $backup $kind);Stage=(Join-Path $stage ('runtime/'+$kind));Old=$old;Existing=$exists;Saved=$false;Promoted=$false})
        }
        foreach($state in $states) {
            if($state.Existing) {
                if((Get-RouterVPNRuntimeInstallManifest $state.Target $state.Kind $false) -cne $state.Old) { throw 'Installed runtime changed before replacement.' }
                Move-RouterVPNRuntimeInstallDirectory $state.Target $state.Backup
                $state.Saved=$true
            }
            Move-RouterVPNRuntimeInstallDirectory $state.Stage $state.Target
            $state.Promoted=$true
            if((Get-RouterVPNRuntimeInstallManifest $state.Target $state.Kind) -cne $source[$state.Kind]) { throw 'Adopted runtime differs from the verified stage.' }
        }
        Invoke-RouterVPNRuntimeInstallVerifier $controller '--verify-native-runtime' $ApplicationRoot
        Invoke-RouterVPNRuntimeInstallVerifier $controller '--verify-amnezia-runtime' $ApplicationRoot
        foreach($state in $states) {
            if((Get-RouterVPNRuntimeInstallManifest $state.Target $state.Kind) -cne $source[$state.Kind]) { throw 'Installed runtime changed before transaction commit.' }
        }
        $committed=$true
    } catch {
        $failure=$_
        $reverse=@($states.ToArray());[array]::Reverse($reverse)
        foreach($state in $reverse) {
            try {
                if($state.Promoted) {
                    if((Get-RouterVPNRuntimeInstallManifest $state.Target $state.Kind) -cne $source[$state.Kind]) { throw 'Adopted runtime ownership changed during rollback.' }
                    Move-RouterVPNRuntimeInstallDirectory $state.Target $state.Stage
                    $state.Promoted=$false
                }
                if($state.Saved) {
                    if((Get-RouterVPNRuntimeInstallManifest $state.Backup $state.Kind $false) -cne $state.Old) { throw 'Previous runtime changed during rollback.' }
                    Move-RouterVPNRuntimeInstallDirectory $state.Backup $state.Target
                    $state.Saved=$false
                }
            } catch { $retain=$true }
        }
        if($retain) { throw ('Runtime installation rollback failed; recovery copies retained at '+$transaction+'. Initial failure: '+$failure.Exception.Message) }
        throw $failure
    } finally {
        if(-not $retain) {
            try { Remove-RouterVPNRuntimeInstallTransaction $transaction $owner }
            catch {
                if($committed) { throw ('Runtime installation committed; cleanup pending at '+$transaction+'. '+$_.Exception.Message) }
                throw
            }
        }
    }
    Write-Host 'Installed and verified the packaged native, AmneziaWG and Xray runtimes.'
}
