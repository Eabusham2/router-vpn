# The outer exact-SHA package establishes trust; this verifies its engine's
# bytes, source identity and architecture before touching an installed runtime.
function Install-RouterVPNBundledXray([string]$BundleRoot,[string]$Destination,[string]$Architecture) {
    $ErrorActionPreference='Stop'
    $Pin='50231eaff98ccc31b5cbd247a721c16e97fe5ec1'
    $target=switch($Architecture.ToLowerInvariant()){'x64'{'amd64'} 'amd64'{'amd64'} 'arm64'{'arm64'} default{throw 'Unsupported Xray architecture'}}
    $bundle=Join-Path $BundleRoot 'runtime\xray'
    $binary=Join-Path $bundle 'xray.exe';$receipt=Join-Path $bundle 'XRAY-RUNTIME.json';$license=Join-Path $bundle 'XRAY-LICENSE'
    foreach($path in @($bundle,$binary,$receipt,$license)) {
        $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Bundled Xray contains a reparse point'}
    }
    if((Get-Item -LiteralPath $receipt).Length -gt 8192 -or (Get-Item -LiteralPath $binary).Length -gt 167772160){throw 'Invalid bundled Xray size'}
    $meta=Get-Content -LiteralPath $receipt -Raw|ConvertFrom-Json
    $required=@('schema_version','runtime','version','upstream_revision','policy_sha256','target','toolchain','size','sha256')
    $keys=@($meta.PSObject.Properties.Name)
    if($keys.Count -ne $required.Count -or @($keys|Where-Object {$_ -notin $required}).Count -ne 0){throw 'Unexpected engine receipt fields'}
    if($meta.schema_version -ne 1 -or $meta.runtime -ne 'xray' -or $meta.version -ne '26.7.11' -or $meta.upstream_revision -ne $Pin -or $meta.target -ne ('windows/'+$target) -or $meta.toolchain -ne 'go1.26.3'){
        throw 'Bundled Xray revision or architecture mismatch'
    }
    if($meta.policy_sha256 -notmatch '^[0-9a-f]{64}$' -or $meta.sha256 -notmatch '^[0-9a-f]{64}$' -or $meta.size -ne (Get-Item -LiteralPath $binary).Length){throw 'Invalid bundled Xray receipt'}
    if((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $meta.sha256){throw 'Bundled Xray checksum mismatch'}
    $version=(& $binary version 2>&1|Out-String)
    if($LASTEXITCODE -ne 0 -or -not $version.Contains('Xray 26.7.11') -or -not $version.Contains('routervpn-'+$Pin+'.'+$meta.policy_sha256)){throw 'Xray lacks the required compiled transport corrections'}
    New-Item -ItemType Directory -Force -Path $Destination|Out-Null
    if(((Get-Item -LiteralPath $Destination -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Unsafe engine installation directory'}
    $stage=Join-Path $Destination ('.xray-stage-'+[Guid]::NewGuid().ToString('N'))
    $backup=Join-Path $Destination ('.xray-backup-'+[Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage,$backup|Out-Null
    $names=@('XRAY-RUNTIME.json','XRAY-LICENSE','xray.exe');$promoted=New-Object 'System.Collections.Generic.List[string]'
    try {
        foreach($name in $names){
            $dest=Join-Path $Destination $name
            if(Test-Path -LiteralPath $dest){
                if(((Get-Item -LiteralPath $dest -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Refusing to replace a reparse point runtime file'}
                Copy-Item -LiteralPath $dest -Destination (Join-Path $backup $name)
            }
            Copy-Item -LiteralPath (Join-Path $bundle $name) -Destination (Join-Path $stage $name)
        }
        if((Get-FileHash -LiteralPath (Join-Path $stage 'xray.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $meta.sha256){throw 'Staged engine checksum mismatch'}
        foreach($name in $names){
            $dest=Join-Path $Destination $name;$source=Join-Path $stage $name
            if(Test-Path -LiteralPath $dest){[IO.File]::Replace($source,$dest,$null)}else{[IO.File]::Move($source,$dest)}
            $promoted.Add($name)
        }
    } catch {
        $failure=$_
        foreach($name in $promoted){
            $old=Join-Path $backup $name;$dest=Join-Path $Destination $name
            if(Test-Path -LiteralPath $old){Copy-Item -LiteralPath $old -Destination $dest -Force}
            else{Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue}
        }
        throw $failure
    } finally {
        Remove-Item -LiteralPath $stage,$backup -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host ('Installed corrected Xray 26.7.11 for '+$target)
}
