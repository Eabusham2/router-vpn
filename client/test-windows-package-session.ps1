param(
    [Parameter(Mandatory=$true)][string]$Root,
    [switch]$Portable,
    [string]$RelocateTo = ''
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Packaged Session proof requires actual Windows.' }
$Root=[IO.Path]::GetFullPath($Root)
if(-not('RouterVPN.PackageSessionIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace RouterVPN {
public static class PackageSessionIdentity {
    [StructLayout(LayoutKind.Sequential)] private struct Info {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    private static string Read(string path, bool directory) {
        using(var handle=CreateFileW(path,0x80,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)) {
            if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            Info info;
            if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if((info.Attributes&0x400)!=0 || ((info.Attributes&0x10)!=0)!=directory ||
               (info.IndexHigh==0 && info.IndexLow==0) || (!directory && info.Links!=1))
                throw new InvalidOperationException("Package Session path is not its retained regular identity.");
            return info.Volume.ToString("x8")+":"+info.IndexHigh.ToString("x8")+info.IndexLow.ToString("x8");
        }
    }
    public static void RequireSame(string actual, string expected, bool directory) {
        if(!String.Equals(Read(actual,directory),Read(expected,directory),StringComparison.Ordinal))
            throw new InvalidOperationException("Package Session selected another physical file or directory.");
    }
}}
'@
}

function Invoke-PackagedNativeSelfTest([string]$Directory,[bool]$IsPortable) {
    $name=if($IsPortable){'RouterVPNPortable.exe'}else{'RouterVPN.exe'}
    $executable=Join-Path $Directory $name
    if(-not(Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Packaged Session has no adjacent native launcher.' }
    $logRoot=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-package-session-'+[Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $logRoot -ErrorAction Stop | Out-Null
    $stdout=Join-Path $logRoot 'stdout.txt';$stderr=Join-Path $logRoot 'stderr.txt'
    # This is the real GUI-subsystem package executable. Capture its explicit
    # child stdio so a failed native self-test has bounded, owned diagnostics.
    $process=Start-Process -FilePath $executable -ArgumentList '--self-test' -WorkingDirectory $Directory -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $process.Refresh()
    try {
        if(-not $process.HasExited -or $process.ExitCode -ne 0) {
            $detail=''
            foreach($file in @($stdout,$stderr)) {
                if(Test-Path -LiteralPath $file -PathType Leaf) {
                    $stream=[IO.File]::OpenRead($file)
                    try {
                        $count=[int][Math]::Min([long]32768,[long]$stream.Length)
                        $null=$stream.Seek(-$count,[IO.SeekOrigin]::End)
                        $buffer=New-Object byte[] $count
                        $read=0
                        while($read -lt $count) {
                            $next=$stream.Read($buffer,$read,$count-$read)
                            if($next -eq 0){break}
                            $read+=$next
                        }
                        $text=[Text.Encoding]::UTF8.GetString($buffer,0,$read)
                    } finally { $stream.Dispose() }
                    if($text.Length -gt 8192){$text=$text.Substring($text.Length-8192)}
                    $detail+=$text
                }
            }
            throw ('Actual packaged native Session self-test failed: '+$process.ExitCode+': '+$detail+'; evidence: '+$logRoot)
        }
    } finally { $process.Dispose() }
    Remove-Item -LiteralPath $logRoot -Recurse -Force -ErrorAction Stop
}

function Get-PackageLocations([string]$Directory,[bool]$IsPortable) {
    if($IsPortable) { return @{Package=(Join-Path $Directory 'App/RouterVPN');Data=(Join-Path $Directory 'Data')} }
    return @{Package=$Directory;Data=$Directory}
}

function Test-PackagedNativeState([string]$Directory,[bool]$IsPortable) {
    $paths=Get-PackageLocations $Directory $IsPortable
    foreach($relative in @('client.json','routers.json')) {
        if(-not(Test-Path -LiteralPath (Join-Path $paths.Data $relative) -PathType Leaf)) { throw ('Native Session omitted its private '+$relative) }
    }
    $config=Get-Content -LiteralPath (Join-Path $paths.Data 'client.json') -Raw | ConvertFrom-Json
    foreach($item in @(@('modes_file',(Join-Path $paths.Package 'modes.json'),$false),@('scripts_dir',(Join-Path $paths.Package 'modes'),$true),@('profiles_file',(Join-Path $paths.Data 'routers.json'),$false))) {
        $actual=[string]$config.($item[0])
        if([string]::IsNullOrWhiteSpace($actual)) { throw 'Native Session omitted a captured configuration location.' }
        if(-not[IO.Path]::IsPathRooted($actual)) {
            if($IsPortable) { throw 'Portable Session retained an uncaptured relative configuration path.' }
            $actual=Join-Path $paths.Data $actual
        }
        [RouterVPN.PackageSessionIdentity]::RequireSame($actual,[string]$item[1],[bool]$item[2])
    }
    $state=[string]$config.state_file
    if(-not[IO.Path]::IsPathRooted($state)) {
        if($IsPortable) { throw 'Portable Session retained an uncaptured relative state path.' }
        $state=Join-Path $paths.Data $state
    }
    if([IO.Path]::GetFileName($state) -cne 'state.json') { throw 'Native Session changed its private state filename.' }
    [RouterVPN.PackageSessionIdentity]::RequireSame([IO.Path]::GetDirectoryName($state),$paths.Data,$true)
    $logical=@(Get-Content -LiteralPath (Join-Path $paths.Package 'logical-modes.json') -Raw | ConvertFrom-Json)
    if($logical.Count -ne 16) { throw 'Packaged immutable catalog lost its sixteen logical choices.' }
    # The native Session gate separately joins exact controller/App/Tray handles
    # and rejects missing receipts. These additional package checks prove that
    # this executable actually returned its checked exit and released the code
    # pins needed for relocation. A failed HTTP request is not exit evidence.
    $files=@('router-vpn-client.exe','client/RouterVPN-Windows-App.ps1','client/RouterVPN-Windows-Tray.ps1','client/RouterVPN-Windows-ControllerTransport.cs')
    foreach($relative in $files) {
        $stream=[IO.File]::Open((Join-Path $paths.Package $relative),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $stream.Dispose()
    }
    return (Get-FileHash -LiteralPath (Join-Path $paths.Data 'routers.json') -Algorithm SHA256).Hash
}

Invoke-PackagedNativeSelfTest $Root ([bool]$Portable)
$routers=Test-PackagedNativeState $Root ([bool]$Portable)
if(-not[string]::IsNullOrWhiteSpace($RelocateTo)) {
    if(-not $Portable) { throw 'Only the captured Portable package can enter its relocation test.' }
    $RelocateTo=[IO.Path]::GetFullPath($RelocateTo)
    if(Test-Path -LiteralPath $RelocateTo) { throw 'Portable relocation destination is already owned.' }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($RelocateTo)) | Out-Null
    Move-Item -LiteralPath $Root -Destination $RelocateTo -ErrorAction Stop
    Invoke-PackagedNativeSelfTest $RelocateTo $true
    $relocatedRouters=Test-PackagedNativeState $RelocateTo $true
    if($relocatedRouters -cne $routers) { throw 'Relocated Portable Session replaced its private router store.' }
}
Write-Output 'Actual packaged Windows owned Session, captured state locations and released code handles: PASS'
