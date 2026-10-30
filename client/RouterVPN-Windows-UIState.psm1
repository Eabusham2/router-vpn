# Only the three non-secret desktop preferences belong here. Controller-owned
# node profiles, credentials and runtime state retain their separate APIs.
Set-StrictMode -Version 2
if(-not(Get-Command Get-RouterVPNControllerDataRoot -ErrorAction SilentlyContinue)){
    Import-Module (Join-Path $PSScriptRoot 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
}
$script:UIStateNames=@('windows-onboarding-v3.json','windows-selected-mode-v1.txt','windows-custom-presets-v1.json')
$script:UIStateLimit=4194304

function Assert-RouterVPNUIStateName([string]$Name){
    if($Name-cnotin$script:UIStateNames){throw 'The Windows UI state filename is not supported.'}
}

function Get-RouterVPNUIStateEntry([string]$Path,[bool]$Directory,[bool]$MissingAllowed=$false){
    try{$Item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop}
    catch [System.Management.Automation.ItemNotFoundException]{if($MissingAllowed){return $null};throw}
    $Link=$Item.PSObject.Properties['LinkType']
    if([bool]$Item.PSIsContainer-ne$Directory-or($Item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or
       ($null-ne$Link-and-not[string]::IsNullOrEmpty([string]$Link.Value))){
        throw 'The Windows UI state path must be a regular unlinked file or directory.'
    }
    return $Item
}

function Assert-RouterVPNUIStateDirectory([string]$Path,[bool]$MissingLeaf=$false){
    if([string]::IsNullOrWhiteSpace($Path)-or-not[IO.Path]::IsPathRooted($Path)){throw 'The Windows UI state directory must be absolute.'}
    $Full=[IO.Path]::GetFullPath($Path)
    if([IO.Path]::DirectorySeparatorChar-eq'\'-and$Full-notmatch'^(?:[A-Za-z]:\\|\\\\\?\\(?:[A-Za-z]:\\|Volume\{[0-9A-Fa-f-]{36}\}\\))'){
        throw 'The Windows UI state directory must be on a local captured volume.'
    }
    $Root=[IO.Path]::GetPathRoot($Full);$Cursor=$Full;$First=$true
    while($Cursor){
        [void](Get-RouterVPNUIStateEntry $Cursor $true ($First-and$MissingLeaf))
        if($Cursor.TrimEnd('\','/')-ceq$Root.TrimEnd('\','/')){break}
        $Parent=[IO.Path]::GetDirectoryName($Cursor.TrimEnd('\','/'))
        if([string]::IsNullOrEmpty($Parent)-or$Parent-ceq$Cursor){throw 'The Windows UI state ancestry could not be validated.'}
        $Cursor=$Parent;$First=$false
    }
    return $Full
}

function Read-RouterVPNUIStateBytes([string]$Path){
    [void](Assert-RouterVPNUIStateDirectory ([IO.Path]::GetDirectoryName($Path)))
    $Before=Get-RouterVPNUIStateEntry $Path $false
    if($Before.Length-gt$script:UIStateLimit){throw 'The Windows UI state file exceeds its size limit.'}
    # No write/delete sharing while consuming an existing preference. Recheck
    # the leaf and ancestry while this exact handle still owns the read.
    $Stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        if($Stream.Length-gt$script:UIStateLimit){throw 'The Windows UI state file exceeds its size limit.'}
        $Buffer=New-Object byte[] ([int]$Stream.Length);$Offset=0
        while($Offset-lt$Buffer.Length){$Count=$Stream.Read($Buffer,$Offset,$Buffer.Length-$Offset);if($Count-le0){throw 'The Windows UI state file changed during read.'};$Offset+=$Count}
        $After=Get-RouterVPNUIStateEntry $Path $false
        [void](Assert-RouterVPNUIStateDirectory ([IO.Path]::GetDirectoryName($Path)))
        if($Stream.Length-ne$Buffer.Length-or$After.Length-ne$Buffer.Length-or$Before.LastWriteTimeUtc-ne$After.LastWriteTimeUtc){throw 'The Windows UI state file changed during read.'}
        return ,$Buffer
    }finally{$Stream.Dispose()}
}

function Write-RouterVPNUIStateBytes([string]$Path,[byte[]]$Bytes,[bool]$CreateOnly){
    if($Bytes.Length-gt$script:UIStateLimit){throw 'The Windows UI state file exceeds its size limit.'}
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

function Resolve-RouterVPNUIStateFile([string]$LegacyDirectory,[string]$Name){
    Assert-RouterVPNUIStateName $Name
    # UTF-8 helper functions and the composed product are created from strings,
    # so their PSScriptRoot is empty. This module's own immutable package path
    # remains available and is the only default for the old client directory.
    if([string]::IsNullOrEmpty($LegacyDirectory)){$LegacyDirectory=$PSScriptRoot}
    $Captured=Get-RouterVPNControllerDataRoot
    $Owned=-not[string]::IsNullOrEmpty($Captured)
    $Root=if($Owned){Assert-RouterVPNUIStateDirectory $Captured}else{Assert-RouterVPNUIStateDirectory $LegacyDirectory}
    $Directory=[IO.Path]::Combine($Root,'.routervpn-state')
    [void](Assert-RouterVPNUIStateDirectory $Directory $true)
    [void][IO.Directory]::CreateDirectory($Directory)
    [void](Assert-RouterVPNUIStateDirectory $Directory)
    $Path=[IO.Path]::Combine($Directory,$Name)
    $Existing=Get-RouterVPNUIStateEntry $Path $false $true
    if($Owned-and$null-eq$Existing){
        $Legacy=Assert-RouterVPNUIStateDirectory $LegacyDirectory
        $LegacyState=[IO.Path]::Combine($Legacy,'.routervpn-state')
        [void](Assert-RouterVPNUIStateDirectory $LegacyState $true)
        $Old=Get-RouterVPNUIStateEntry ([IO.Path]::Combine($LegacyState,$Name)) $false $true
        if($null-ne$Old){
            $Bytes=Read-RouterVPNUIStateBytes $Old.FullName
            Write-RouterVPNUIStateBytes $Path $Bytes $true
        }
    }
    return $Path
}

function Read-RouterVPNUIState {
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$LegacyDirectory,[Parameter(Mandatory=$true)][string]$Name)
    $Path=Resolve-RouterVPNUIStateFile $LegacyDirectory $Name
    if($null-eq(Get-RouterVPNUIStateEntry $Path $false $true)){return $null}
    $Bytes=Read-RouterVPNUIStateBytes $Path
    # Existing Windows PowerShell files may contain a UTF-8 BOM. Preserve those
    # exact bytes during migration and remove only that text marker on read.
    $Offset=0;if($Bytes.Length-ge3-and$Bytes[0]-eq239-and$Bytes[1]-eq187-and$Bytes[2]-eq191){$Offset=3}
    return [Text.UTF8Encoding]::new($false,$true).GetString($Bytes,$Offset,$Bytes.Length-$Offset)
}

function Write-RouterVPNUIState {
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$LegacyDirectory,[Parameter(Mandatory=$true)][string]$Name,[AllowEmptyString()][string]$Text)
    $Path=Resolve-RouterVPNUIStateFile $LegacyDirectory $Name
    Write-RouterVPNUIStateBytes $Path ([Text.UTF8Encoding]::new($false,$true).GetBytes($Text)) $false
}

Export-ModuleMember -Function Read-RouterVPNUIState,Write-RouterVPNUIState
