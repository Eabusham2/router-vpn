# The general UI state API reads three nonsecret desktop preferences. The
# profile transaction privately owns its recovery journal and lock.
Set-StrictMode -Version 2
if(-not(Get-Command Get-RouterVPNControllerDataRoot -ErrorAction SilentlyContinue)){
    Import-Module (Join-Path $PSScriptRoot 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
}
$script:UIStateNames=@('windows-onboarding-v3.json','windows-selected-mode-v1.txt','windows-custom-presets-v1.json')
$script:UIStateLimit=4194304
$script:PreferenceBatchLease=$null

function Assert-RouterVPNUIStateName([string]$Name){
    if($Name-cnotin$script:UIStateNames){throw 'The Windows UI state filename is not supported.'}
}

function Get-RouterVPNUIStateEntry([string]$Path,[bool]$Directory,[bool]$MissingAllowed=$false){
    # Keep the controller's canonical volume-GUID path unchanged. Query its
    # metadata directly instead of resolving it through a PowerShell provider.
    # Optional leaves accept only an actual file/directory not-found error.
    try{
        $Attributes=[IO.File]::GetAttributes($Path)
        $Item=if(($Attributes-band[IO.FileAttributes]::Directory)-ne0){[IO.DirectoryInfo]::new($Path)}else{[IO.FileInfo]::new($Path)}
        $Item.Refresh()
    }
    catch [IO.FileNotFoundException]{if($MissingAllowed){return $null};throw}
    catch [IO.DirectoryNotFoundException]{if($MissingAllowed){return $null};throw}
    if($Item-isnot[IO.FileSystemInfo]){throw 'The Windows UI state path is not a filesystem entry.'}
    $IsDirectory=($Item.Attributes-band[IO.FileAttributes]::Directory)-ne0
    $Link=$Item.PSObject.Properties['LinkType']
    if($IsDirectory-ne$Directory-or($Item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or
       ($null-ne$Link-and-not[string]::IsNullOrEmpty([string]$Link.Value))){
        throw 'The Windows UI state path must be a regular unlinked file or directory.'
    }
    return $Item
}

function Assert-RouterVPNUIStateDirectory([string]$Path,[bool]$MissingLeaf=$false){
    if([string]::IsNullOrWhiteSpace($Path)-or-not[IO.Path]::IsPathRooted($Path)){throw 'The Windows UI state directory must be absolute.'}
    $Full=[IO.Path]::GetFullPath($Path)
    $RootMatch=$null
    if([IO.Path]::DirectorySeparatorChar-eq'\'){
        $RootMatch=[regex]::Match($Full,'^(?:[A-Za-z]:\\|\\\\\?\\(?:[A-Za-z]:\\|Volume\{[0-9A-Fa-f-]{36}\}\\))',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if(-not$RootMatch.Success){throw 'The Windows UI state directory must be on a local captured volume.'}
    }
    $Root=[IO.Path]::GetPathRoot($Full)
    # Preserve the separator in the captured device root under legacy .NET path handling.
    if($null-ne$RootMatch){$Root=$RootMatch.Value}
    $Cursor=$Full;$First=$true
    while($Cursor){
        [void](Get-RouterVPNUIStateEntry $Cursor $true ($First-and$MissingLeaf))
        if($Cursor.TrimEnd('\','/')-ceq$Root.TrimEnd('\','/')){break}
        $Parent=[IO.Path]::GetDirectoryName($Cursor.TrimEnd('\','/'))
        if([string]::IsNullOrEmpty($Parent)-or$Parent-ceq$Cursor){throw 'The Windows UI state ancestry could not be validated.'}
        if($Parent.TrimEnd('\','/')-ceq$Root.TrimEnd('\','/')){$Parent=$Root}
        $Cursor=$Parent;$First=$false
    }
    return $Full
}

function Read-RouterVPNUIStateBytes([string]$Path,[int]$Limit=$script:UIStateLimit){
    [void](Assert-RouterVPNUIStateDirectory ([IO.Path]::GetDirectoryName($Path)))
    $Before=Get-RouterVPNUIStateEntry $Path $false
    if($Before.Length-gt$Limit){throw 'The Windows UI state file exceeds its size limit.'}
    # No write/delete sharing while consuming an existing preference. Recheck
    # the leaf and ancestry while this exact handle still owns the read.
    $Stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        if($Stream.Length-gt$Limit){throw 'The Windows UI state file exceeds its size limit.'}
        $Buffer=New-Object byte[] ([int]$Stream.Length);$Offset=0
        while($Offset-lt$Buffer.Length){$Count=$Stream.Read($Buffer,$Offset,$Buffer.Length-$Offset);if($Count-le0){throw 'The Windows UI state file changed during read.'};$Offset+=$Count}
        $After=Get-RouterVPNUIStateEntry $Path $false
        [void](Assert-RouterVPNUIStateDirectory ([IO.Path]::GetDirectoryName($Path)))
        if($Stream.Length-ne$Buffer.Length-or$After.Length-ne$Buffer.Length-or$Before.LastWriteTimeUtc-ne$After.LastWriteTimeUtc){throw 'The Windows UI state file changed during read.'}
        return ,$Buffer
    }finally{$Stream.Dispose()}
}

function Write-RouterVPNUIStateBytes([string]$Path,[byte[]]$Bytes,[bool]$CreateOnly,[int]$Limit=$script:UIStateLimit){
    if($Bytes.Length-gt$Limit){throw 'The Windows UI state file exceeds its size limit.'}
    $Directory=Assert-RouterVPNUIStateDirectory ([IO.Path]::GetDirectoryName($Path))
    $Existing=Get-RouterVPNUIStateEntry $Path $false $true
    if($CreateOnly-and$null-ne$Existing){return}
    $Temporary=[IO.Path]::Combine($Directory,('.routervpn-ui-'+[Guid]::NewGuid().ToString('N')+'.tmp'))
    $Stream=$null;$Published=$false
    try{
        $Stream=[IO.File]::Open($Temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $Stream.Write($Bytes,0,$Bytes.Length);$Stream.Flush($true);$Stream.Dispose();$Stream=$null
        [void](Assert-RouterVPNUIStateDirectory $Directory)
        [void](Get-RouterVPNUIStateEntry $Temporary $false)
        $Existing=Get-RouterVPNUIStateEntry $Path $false $true
        if($CreateOnly-and$null-ne$Existing){return}
        if($null-eq$Existing){
            # File.Move is create-only on both Framework and current .NET. A
            # concurrent destination wins instead of being overwritten.
            try{[IO.File]::Move($Temporary,$Path);$Published=$true}
            catch [IO.IOException]{if(-not$CreateOnly-or$null-eq(Get-RouterVPNUIStateEntry $Path $false $true)){throw}}
        }else{[IO.File]::Replace($Temporary,$Path,[NullString]::Value);$Published=$true}
        [void](Get-RouterVPNUIStateEntry $Path $false)
    }finally{
        if($null-ne$Stream){$Stream.Dispose()}
        if(-not$Published-and[IO.File]::Exists($Temporary)){[IO.File]::Delete($Temporary)}
    }
}

function Get-RouterVPNLegacyStateDirectory([string]$LegacyDirectory){
    if([string]::IsNullOrEmpty($LegacyDirectory)){$LegacyDirectory=$PSScriptRoot}
    return $LegacyDirectory
}
function Get-RouterVPNStateDirectory([string]$LegacyDirectory,[bool]$Create=$true){
    $LegacyDirectory=Get-RouterVPNLegacyStateDirectory $LegacyDirectory
    $Captured=Get-RouterVPNControllerDataRoot
    $Owned=-not[string]::IsNullOrEmpty($Captured)
    $Root=if($Owned){Assert-RouterVPNUIStateDirectory $Captured}else{Assert-RouterVPNUIStateDirectory $LegacyDirectory}
    $Directory=[IO.Path]::Combine($Root,'.routervpn-state')
    [void](Assert-RouterVPNUIStateDirectory $Directory $true)
    if($Create){
        [void][IO.Directory]::CreateDirectory($Directory)
        [void](Assert-RouterVPNUIStateDirectory $Directory)
    }
    return $Directory
}

function Resolve-RouterVPNUIStateFile([string]$LegacyDirectory,[string]$Name,[bool]$LockHeld=$false){
    Assert-RouterVPNUIStateName $Name
    # UTF-8 helper functions and the composed product are created from strings,
    # so their PSScriptRoot is empty. This module's own immutable package path
    # remains available and is the only default for the old client directory.
    $LegacyDirectory=Get-RouterVPNLegacyStateDirectory $LegacyDirectory
    $Captured=Get-RouterVPNControllerDataRoot
    $Owned=-not[string]::IsNullOrEmpty($Captured)
    $Directory=Get-RouterVPNStateDirectory $LegacyDirectory
    $Path=[IO.Path]::Combine($Directory,$Name)
    $Existing=Get-RouterVPNUIStateEntry $Path $false $true
    if($Owned-and$null-eq$Existing-and ($Name -ceq 'windows-onboarding-v3.json' -or -not(Test-RouterVPNIntentAt $Directory))){
        $Legacy=Assert-RouterVPNUIStateDirectory $LegacyDirectory
        $LegacyState=[IO.Path]::Combine($Legacy,'.routervpn-state')
        [void](Assert-RouterVPNUIStateDirectory $LegacyState $true)
        $Old=Get-RouterVPNUIStateEntry ([IO.Path]::Combine($LegacyState,$Name)) $false $true
        if($null-ne$Old){
            $migrationLease=$null
            try{
                if($Name -cne 'windows-onboarding-v3.json' -and -not $LockHeld){$migrationLease=Open-RouterVPNProfileState $LegacyDirectory}
                if($Name -ceq 'windows-onboarding-v3.json' -or -not(Test-RouterVPNIntentAt $Directory)){
                    $Bytes=Read-RouterVPNUIStateBytes $Old.FullName
                    Write-RouterVPNUIStateBytes $Path $Bytes $true
                }
            }finally{if($null-ne$migrationLease){$migrationLease.Stream.Dispose()}}
        }
    }
    return $Path
}

function Read-RouterVPNUIState {
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$LegacyDirectory,[Parameter(Mandatory=$true)][string]$Name)
    $batch=$script:PreferenceBatchLease
    $held=$null-ne$batch -and $batch.Directory -ceq (Get-RouterVPNStateDirectory $LegacyDirectory)
    $Path=Resolve-RouterVPNUIStateFile $LegacyDirectory $Name $held
    if($null-eq(Get-RouterVPNUIStateEntry $Path $false $true)){return $null}
    $Bytes=Read-RouterVPNUIStateBytes $Path
    # Existing Windows PowerShell files may contain a UTF-8 BOM. Preserve those
    # exact bytes during migration and remove only that text marker on read.
    $Offset=0;if($Bytes.Length-ge3-and$Bytes[0]-eq239-and$Bytes[1]-eq187-and$Bytes[2]-eq191){$Offset=3}
    return [Text.UTF8Encoding]::new($false,$true).GetString($Bytes,$Offset,$Bytes.Length-$Offset)
}

function Write-RouterVPNUIState {
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$LegacyDirectory,[Parameter(Mandatory=$true)][string]$Name,[AllowEmptyString()][string]$Text)
    Assert-RouterVPNUIStateName $Name
    $lease=$null;$release=$false
    try{
        if($Name -cne 'windows-onboarding-v3.json'){
            $lease=$script:PreferenceBatchLease
            if($null-eq$lease){$lease=Open-RouterVPNProfileState $LegacyDirectory;$release=$true}
            elseif($lease.Directory -cne (Get-RouterVPNStateDirectory $LegacyDirectory)){throw 'The preference batch belongs to a different state directory.'}
            if(Test-RouterVPNIntentAt $lease.Directory){throw 'A connection profile load is pending. Reopen Settings to recover it.'}
        }
        $Path=Resolve-RouterVPNUIStateFile $LegacyDirectory $Name ($null-ne$lease)
        Write-RouterVPNUIStateBytes $Path ([Text.UTF8Encoding]::new($false,$true).GetBytes($Text)) $false
    }finally{if($release){$lease.Stream.Dispose()}}
}
function Invoke-RouterVPNPreferenceBatch([string]$LegacyDirectory,[scriptblock]$Action){
    if($null-ne$script:PreferenceBatchLease){throw 'Another local preference edit is already in progress.'}
    $lease=Open-RouterVPNProfileState $LegacyDirectory
    try{
        if(Test-RouterVPNIntentAt $lease.Directory){throw 'Recover the interrupted connection profile load before editing presets.'}
        $script:PreferenceBatchLease=$lease
        & $Action
    }finally{$script:PreferenceBatchLease=$null;$lease.Stream.Dispose()}
}

# A stable lock file serializes preference writers, recovery and the entire
# prepare-to-finish sequence across processes. Never unlink a live lock inode.
function Open-RouterVPNProfileState([string]$LegacyDirectory){
    $directory=Get-RouterVPNStateDirectory $LegacyDirectory
    $path=Join-Path $directory 'windows-profile-load-v1.lock'
    [void](Get-RouterVPNUIStateEntry $path $false $true)
    $stream=[IO.File]::Open($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try{
        [void](Get-RouterVPNUIStateEntry $path $false)
        return [pscustomobject]@{Stream=$stream;Directory=$directory;Legacy=$LegacyDirectory;Observed=$false;Digest=$null}
    }catch{$stream.Dispose();throw}
}
function Test-RouterVPNIntentAt([string]$Directory){
    return $null-ne(Get-RouterVPNUIStateEntry (Join-Path $Directory 'windows-profile-load-v1.json') $false $true)
}
function Test-RouterVPNProfileLoadPending([string]$LegacyDirectory){
    return Test-RouterVPNIntentAt (Get-RouterVPNStateDirectory $LegacyDirectory $false)
}
function Assert-RouterVPNProfileAdmission([string]$LegacyDirectory,[string]$Path,[string]$Method){
    if($Method -ieq 'POST' -and $Path -cin @('/api/auto','/api/connect-logical','/api/external-profile/connect','/api/multihop/connect','/api/strategy/smart-auto','/api/strategy/auto','/api/strategy/custom') -and (Test-RouterVPNProfileLoadPending $LegacyDirectory)){
        throw 'Recover the pending connection profile in Settings before connecting.'
    }
}
function Get-RouterVPNIntentDigest([byte[]]$Bytes){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return [Convert]::ToBase64String($sha.ComputeHash($Bytes))}finally{$sha.Dispose()}
}
function Get-RouterVPNProfileIntent($Lease){
    if(-not $Lease.Stream.CanRead){throw 'The local profile load lock was released.'}
    if(-not(Test-RouterVPNIntentAt $Lease.Directory)){
        if($Lease.Observed -and $null-ne$Lease.Digest){throw 'The local profile load journal disappeared during its operation.'}
        $Lease.Observed=$true;$Lease.Digest=$null
        return $null
    }
    $path=Join-Path $Lease.Directory 'windows-profile-load-v1.json'
    $bytes=Read-RouterVPNUIStateBytes $path 25165824
    $digest=Get-RouterVPNIntentDigest $bytes
    if($Lease.Observed -and $Lease.Digest -cne $digest){throw 'The local profile load journal changed during its operation.'}
    $Lease.Observed=$true;$Lease.Digest=$digest
    $intent=ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false,$true).GetString($bytes)) -ErrorAction Stop
    if($intent.schema -ne 1 -or $intent.operation_id -cnotmatch '\A[0-9a-f]{32}\z' -or $intent.phase -cnotin @('preparing','staging','committing','complete','rolledback')){
        throw 'The interrupted profile load journal could not be verified.'
    }
    return $intent
}
function Set-RouterVPNProfileIntent($Lease,$Intent,[switch]$Remove){
    $existing=Get-RouterVPNProfileIntent $Lease
    if(($null-ne$existing -and $existing.operation_id -cne $Intent.operation_id) -or ($null-eq$existing -and ($Remove -or $Intent.phase -cne 'preparing'))){
        throw 'Another local profile load owns this journal.'
    }
    $path=Join-Path $Lease.Directory 'windows-profile-load-v1.json'
    if($Remove){
        [IO.File]::Delete($path)
        if(Test-RouterVPNIntentAt $Lease.Directory){throw 'The completed profile journal is still present.'}
        $Lease.Digest=$null
        return
    }
    $json=ConvertTo-Json -InputObject $Intent -Depth 10 -Compress
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($json)
    Write-RouterVPNUIStateBytes $path $bytes ($null-eq$existing) 25165824
    $actual=Read-RouterVPNUIStateBytes $path 25165824
    $digest=Get-RouterVPNIntentDigest $bytes
    if((Get-RouterVPNIntentDigest $actual) -cne $digest){throw 'The profile load journal was not persisted.'}
    $Lease.Digest=$digest
}

function Get-RouterVPNPreferenceImage($Lease){
    if(-not $Lease.Stream.CanRead){throw 'The local preference lock was released.'}
    $image=[ordered]@{}
    foreach($name in @('windows-custom-presets-v1.json','windows-selected-mode-v1.txt')){
        $path=Resolve-RouterVPNUIStateFile $Lease.Legacy $name $true
        $image[$name]=if($null-ne(Get-RouterVPNUIStateEntry $path $false $true)){[Convert]::ToBase64String((Read-RouterVPNUIStateBytes $path))}else{$null}
    }
    return [pscustomobject]$image
}
function Set-RouterVPNPreferenceImage($Lease,$From,$To,[switch]$VerifyOnly){
    $names=@('windows-custom-presets-v1.json','windows-selected-mode-v1.txt')
    foreach($image in @($From,$To)){
        if($null-eq$image -or @($image.PSObject.Properties).Count -ne 2){throw 'The local profile preference image is incomplete.'}
        foreach($name in $names){
            $field=$image.PSObject.Properties[$name]
            if($null-eq$field -or ($null-ne$field.Value -and $field.Value -isnot [string])){throw 'The local profile preference image is invalid.'}
            if($null-ne$field.Value -and [Convert]::FromBase64String($field.Value).Length -gt $script:UIStateLimit){throw 'A captured preference exceeds its size limit.'}
        }
    }
    $current=Get-RouterVPNPreferenceImage $Lease
    foreach($name in $names){
        if(-not [object]::Equals($current.$name,$To.$name) -and ($VerifyOnly -or -not [object]::Equals($current.$name,$From.$name))){throw 'Another preference writer changed the captured profile state.'}
    }
    foreach($name in $names){
        if([object]::Equals($current.$name,$To.$name)){continue}
        $path=Join-Path $Lease.Directory $name
        if($null-eq$To.$name){[IO.File]::Delete($path)}
        else{Write-RouterVPNUIStateBytes $path ([Convert]::FromBase64String($To.$name)) $false}
    }
    if(-not $VerifyOnly){Set-RouterVPNPreferenceImage $Lease $From $To -VerifyOnly}
}
Export-ModuleMember -Function Read-RouterVPNUIState,Write-RouterVPNUIState,Invoke-RouterVPNPreferenceBatch,Assert-RouterVPNProfileAdmission,Open-RouterVPNProfileState,Test-RouterVPNProfileLoadPending,Get-RouterVPNProfileIntent,Set-RouterVPNProfileIntent,Get-RouterVPNPreferenceImage,Set-RouterVPNPreferenceImage
