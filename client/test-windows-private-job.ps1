param(
    [string]$SourceRoot=(Split-Path -Parent $PSScriptRoot),
    [switch]$CompileOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:Checks=0
$helper=Join-Path $SourceRoot 'client/Private-RouterVPN-Job.ps1'
. $helper

function Check([bool]$Condition,[string]$Message) {
    $script:Checks++
    if(-not $Condition) { throw $Message }
}
function Unwrap($ErrorValue) {
    $errorObject=if($ErrorValue -is [Management.Automation.ErrorRecord]) { $ErrorValue.Exception } else { $ErrorValue }
    while($null -ne $errorObject.InnerException) { $errorObject=$errorObject.InnerException }
    return $errorObject
}
function Reject([scriptblock]$Action,[string]$Message) {
    $rejected=$false
    try { $null=& $Action } catch { $rejected=$true }
    Check $rejected $Message
}
function Detect-Defect([scriptblock]$Action,[string]$Expected,[string]$Message) {
    $failure=$null
    try { $null=& $Action } catch { $failure=Unwrap $_ }
    Check ($null -ne $failure -and $failure.Message -ceq $Expected) $Message
}
function Static-Call([type]$Type,[string]$Name,[object[]]$Arguments,[bool]$Private=$false) {
    $flags=[Reflection.BindingFlags]::Static -bor $(if($Private) { [Reflection.BindingFlags]::NonPublic } else { [Reflection.BindingFlags]::Public })
    $method=$Type.GetMethod($Name,$flags)
    Check ($null -ne $method) ('Missing compiled method: '+$Name)
    $rawArguments=New-Object object[] $Arguments.Length
    for($index=0;$index -lt $Arguments.Length;$index++) {
        if($null -ne $Arguments[$index]) { $rawArguments[$index]=$Arguments[$index].PSObject.BaseObject }
    }
    return ,$method.Invoke($null,$rawArguments)
}
function Start-Owner([type]$Type,[string[]]$Arguments,[System.Collections.IDictionary]$CapturedEnvironment) {
    $values=New-Object object[] 4
    $values[0]=$script:ChildExe;$values[1]=$Arguments;$values[2]=$script:Fixture;$values[3]=$CapturedEnvironment
    return Static-Call $Type 'Start' $values
}
function Environment-Capture {
    $result=New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    foreach($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
        if(-not ([string]$entry.Key).StartsWith('=')) { $result.Add([string]$entry.Key,[string]$entry.Value) }
    }
    $result['ROUTERVPN_JOB_FIXTURE']='captured Unicode '+[char]0x03bb+' '+[char]0x4e2d+' = value'
    return ,$result
}

# Compile the shipping helper with the oldest supported C# syntax, then execute
# its exact argument/environment serializers even on the non-Windows build host.
$ownerType=[RouterVPN.PrivateJobOwner]
Reject { Add-RouterVPNPrivateJobType -TypeDefinition 'public static class RouterVPNJobNewerSyntax { public static string Value => "unsupported"; }' } 'The private Job compiler accepted post-C#5 syntax.'
Check $ownerType.IsSealed 'Private process ownership must not be subclassable.'
Check ($ownerType.GetConstructors().Length -eq 0) 'An unrelated caller can construct an unowned process handle.'
Check ($ownerType.GetFields([Reflection.BindingFlags]'Public,Instance').Length -eq 0) 'A native handle is publicly writable.'
$quoteCases=@(
    @('', '""'),
    @('plain', '"plain"'),
    @('two words', '"two words"'),
    @('a"b', '"a\"b"'),
    @('tail\', '"tail\\"'),
    @('two\\"quote', '"two\\\\\"quote"'),
    @('$(not-a-command) & | %PATH%', '"$(not-a-command) & | %PATH%"')
)
foreach($pair in $quoteCases) {
    $actual=Static-Call $ownerType 'QuoteArgument' ([object[]]@($pair[0])) $true
    Check ($actual -ceq $pair[1]) 'Windows argument encoding changed a boundary character.'
}
Reject { Static-Call $ownerType 'QuoteArgument' ([object[]]@($null)) $true } 'Null native arguments were accepted.'
Reject { Static-Call $ownerType 'QuoteArgument' ([object[]]@("secret`0tail")) $true } 'Embedded NUL was accepted in an argument.'
$environment=New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
$environment.Add('Zulu','last');$environment.Add('alpha',('private '+[char]0x03bb+'=value'))
$block=[char[]](Static-Call $ownerType 'EnvironmentBlock' ([object[]]@($environment)) $true)
Check ((-join $block) -ceq ("alpha=private "+[char]0x03bb+"=value`0Zulu=last`0`0")) 'The captured Unicode environment was not sorted and double-NUL terminated.'
Check (([char[]](Static-Call $ownerType 'EnvironmentBlock' ([object[]]@(@{})) $true)).Length -eq 2) 'An empty environment lost its double terminator.'
$environment.Add('ALPHA','duplicate')
Reject { Static-Call $ownerType 'EnvironmentBlock' ([object[]]@($environment)) $true } 'Case-equivalent environment names were accepted.'
foreach($invalid in @(@{'bad=name'='value'},@{'valid'="value`0tail"},@{'valid'=7},@{''='empty'})) {
    Reject { Static-Call $ownerType 'EnvironmentBlock' ([object[]]@($invalid)) $true } 'Malformed environment entry was accepted.'
}
Reject { Static-Call $ownerType 'EnvironmentBlock' ([object[]]@(@{'large'=('x'*524288)})) $true } 'An oversized environment was accepted.'
$commandArguments=New-Object object[] 2
$commandArguments[0]='C:\private path\native.exe';$commandArguments[1]=[string[]]@('','space value','quote"','end\')
$command=Static-Call $ownerType 'CommandLine' $commandArguments $true
Check ($command.ToString() -ceq '"C:\private path\native.exe" "" "space value" "quote\"" "end\\"') 'The native command line is not a sequence of exact quoted arguments.'
$commandArguments[1]=[string[]]@(('x'*32767))
Reject { Static-Call $ownerType 'CommandLine' $commandArguments $true } 'An oversized command line was accepted.'

$helperText=[IO.File]::ReadAllText($helper)
$sourceMatches=[regex]::Matches($helperText,"(?s)\`$routerVPNPrivateJobSource = @'\r?\n(.*?)\r?\n'@")
Check ($sourceMatches.Count -eq 1) 'The native helper source cannot be captured exactly.'
$script:NativeSource=$sourceMatches[0].Groups[1].Value
. $helper
Check ([RouterVPN.PrivateJobOwner]::SourceIdentity -cmatch '^[0-9a-f]{64}$') 'The compiled helper has no source identity.'
Reject { & ([scriptblock]::Create($helperText.Replace('const uint WAIT_OBJECT_0 = 0','const uint WAIT_OBJECT_0 = 7'))) } 'A stale compiled helper was silently reused for different source.'
function New-Variant([string]$Name,[string]$Source) {
    $namespace='RouterVPNJobFixture'+$Name
    Check ($Source -cne $script:NativeSource) 'A defect variant did not alter its intended source.'
    $source=$Source.Replace('namespace RouterVPN {',('namespace '+$namespace+' {'))
    Add-RouterVPNPrivateJobType -TypeDefinition $source
    $type=($namespace+'.PrivateJobOwner') -as [type]
    Check ($null -ne $type) 'The intended native defect variant did not compile.'
    return $type
}

function Require-PendingExitGuard([object]$Owner) {
    $failure=$null
    # PowerShell's adapted property access can turn a throwing getter into
    # $null. Invoke the actual accessor so the native rejection is observed.
    try { $null=$Owner.get_ExitCode() } catch { $failure=Unwrap $_ }
    Check ($failure -is [InvalidOperationException] -and $failure.Message -ceq 'The captured child has not exited.') 'A running child exposed a successful exit status.'
}
function Unproved-ClosedOwner([type]$Type) {
    # This portable witness has no process or Job handles and no exit receipt.
    # Marking it closed avoids a Win32 call while exercising the real getter.
    $owner=[Activator]::CreateInstance($Type,$true)
    $closed=$Type.GetField('closed',[Reflection.BindingFlags]'Instance,NonPublic')
    Check ($null -ne $closed) 'The portable exit witness lost its exact state boundary.'
    $closed.SetValue($owner,$true)
    return $owner
}
$exitGuard='if (!WaitLocked(0)) throw new InvalidOperationException("The captured child has not exited.");'
Check ($script:NativeSource.Contains($exitGuard)) 'The actual exit-witness guard moved without updating the executable fixture.'
$unguardedExitType=New-Variant 'UnprovedExit' ($script:NativeSource.Replace($exitGuard,'if (!WaitLocked(0)) return 0;'))
Require-PendingExitGuard (Unproved-ClosedOwner $ownerType)
Detect-Defect { Require-PendingExitGuard (Unproved-ClosedOwner $unguardedExitType) } 'A running child exposed a successful exit status.' 'The explicit getter fixture accepted an exit code without an exit witness.'

$assignment='if (!Native.AssignProcessToJobObject(owner.job, owner.process))'
Check ($script:NativeSource.Contains($assignment)) 'The actual Job assignment boundary moved without updating the executable fixture.'
$failedType=New-Variant 'AssignmentFailure' ($script:NativeSource.Replace($assignment,'if (owner.processId > 0)'))
$premature="Native.ResumeThread(owner.thread);`n                for (int attempt = 0; attempt < 750 && !File.Exists(arguments[1]); attempt++) System.Threading.Thread.Sleep(20);`n                if (owner.processId > 0)"
$prematureType=New-Variant 'PrematureResume' ($script:NativeSource.Replace($assignment,$premature))
$timeoutType=New-Variant 'FalseWait' ($script:NativeSource.Replace('if (result == WAIT_TIMEOUT) return false;','if (result == WAIT_TIMEOUT) return true;'))
$uncontainedType=New-Variant 'NoKillOnClose' ($script:NativeSource.Replace('const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;','const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0;'))

# The executable below contains no VPN, router, Tor or network operation. It
# provides real Windows process/argv/descendant observations for this helper.
$childSource=@'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class RouterVPNPrivateJobFixtureChild {
    // Normalize Windows 8.3 aliases only for comparisons within this owned
    // fixture. The product retains identity from its actual process handle.
    public static string LongPath(string path) {
        StringBuilder result = new StringBuilder(32768);
        uint length = GetLongPathNameW(path, result, (uint)result.Capacity);
        if (length == 0 || length >= result.Capacity) throw new IOException("Fixture path identity is unavailable.");
        return result.ToString();
    }
    static string Encode(string text) { return Convert.ToBase64String(Encoding.UTF8.GetBytes(text ?? "")); }
    static void Publish(string path, string[] lines) {
        string temporary = path + "." + Process.GetCurrentProcess().Id + ".tmp";
        File.WriteAllLines(temporary, lines, new UTF8Encoding(false));
        File.Move(temporary, path);
    }
    static string[] Identity() {
        using (Process current = Process.GetCurrentProcess()) {
            return new string[] { current.Id.ToString(), current.StartTime.ToUniversalTime().Ticks.ToString(), Encode(current.MainModule.FileName) };
        }
    }
    static void Hold(string release) {
        DateTime deadline = DateTime.UtcNow.AddSeconds(90);
        while (!File.Exists(release) && DateTime.UtcNow < deadline) Thread.Sleep(20);
    }
    static string QuotedPath(string path) {
        if (path.IndexOf('"') >= 0 || path.EndsWith("\\", StringComparison.Ordinal)) throw new ArgumentException();
        return "\"" + path + "\"";
    }
    public static int Main(string[] arguments) {
        try {
            if (arguments.Length < 2) return 91;
            string mode = arguments[0], report = arguments[1];
            if (mode == "echo") {
                string[] values = new string[arguments.Length + 3];
                string[] identity = Identity();
                Array.Copy(identity, values, identity.Length);
                values[3] = Encode(Environment.CurrentDirectory);
                values[4] = Encode(Environment.GetEnvironmentVariable("ROUTERVPN_JOB_FIXTURE"));
                for (int index = 2; index < arguments.Length; index++) values[index + 3] = Encode(arguments[index]);
                Publish(report, values);
                return 37;
            }
            if (mode == "hold") {
                Publish(report, Identity()); Hold(arguments[2]); return 23;
            }
            if (mode == "spawn") {
                ProcessStartInfo info = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location);
                info.UseShellExecute = false; info.CreateNoWindow = true;
                info.Arguments = "hold " + QuotedPath(arguments[2]) + " " + QuotedPath(arguments[4]);
                using (Process child = Process.Start(info)) {
                    string[] identity = Identity();
                    Publish(report, new string[] { identity[0], identity[1], identity[2], child.Id.ToString(), child.StartTime.ToUniversalTime().Ticks.ToString() });
                    Hold(arguments[3]);
                    return 11;
                }
            }
            if (mode == "breakaway") {
                StartupInfo startup = new StartupInfo(); startup.cb = (uint)Marshal.SizeOf(typeof(StartupInfo));
                ProcessInformation information;
                string executable = Assembly.GetExecutingAssembly().Location;
                StringBuilder command = new StringBuilder(QuotedPath(executable) + " hold " + QuotedPath(arguments[2]) + " " + QuotedPath(arguments[3]));
                bool created = CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, false,
                    0x01000000 | 0x00000004 | 0x08000000, IntPtr.Zero, Environment.CurrentDirectory, ref startup, out information);
                int error = Marshal.GetLastWin32Error();
                if (created) {
                    try {
                        if (!TerminateProcess(information.hProcess, 72) || WaitForSingleObject(information.hProcess, 10000) != 0) return 92;
                    } finally { CloseHandle(information.hThread); CloseHandle(information.hProcess); }
                }
                Publish(report, new string[] { created ? "created" : "refused", error.ToString() });
                return created ? 1 : 0;
            }
            return 93;
        } catch { return 94; }
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInformation { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfo {
        public uint cb; public IntPtr lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInformation information);
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] static extern uint WaitForSingleObject(IntPtr process, uint milliseconds);
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetLongPathNameW(string path, StringBuilder result, uint size);
}
'@
Add-RouterVPNPrivateJobType -TypeDefinition $childSource
if($CompileOnly) {
    Write-Output ("Windows private Job portable checks passed: {0}; C#5 helper and fixture compiled. Windows kernel execution was not requested." -f $script:Checks)
    exit 0
}
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This fixture requires Windows for actual suspended process and Job tests; use -CompileOnly only for a separate syntax/serializer check.' }

$script:Fixture=Join-Path ([IO.Path]::GetTempPath()) ('routervpn job '+[char]0x03bb+' '+[Guid]::NewGuid().ToString('N'))
$script:Owners=New-Object 'System.Collections.Generic.List[object]'
$script:Processes=New-Object 'System.Collections.Generic.List[System.Diagnostics.Process]'
$script:ChildExe=Join-Path $script:Fixture 'private child.exe'
$script:CapturedEnvironment=Environment-Capture
function Child-Report([string]$Path) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while(-not [IO.File]::Exists($Path)) {
        if($timer.ElapsedMilliseconds -gt 15000) { throw 'The captured fixture child did not publish its expected observation.' }
        Start-Sleep -Milliseconds 20
    }
    return ,[IO.File]::ReadAllLines($Path)
}
function Decode([string]$Value) { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value)) }
function Capture-ObservedProcess([string[]]$Report) {
    $process=[Diagnostics.Process]::GetProcessById([int]$Report[0])
    try {
        $null=$process.Handle # Retain this exact process object before any exit/reuse.
        Check ($process.StartTime.ToUniversalTime().Ticks -eq [long]$Report[1]) 'A fixture child PID was reused before identity capture.'
        Check ([RouterVPNPrivateJobFixtureChild]::LongPath($process.MainModule.FileName) -ieq [RouterVPNPrivateJobFixtureChild]::LongPath((Decode $Report[2]))) 'The observed fixture child executable changed.'
        Check ([RouterVPNPrivateJobFixtureChild]::LongPath($process.MainModule.FileName) -ieq [RouterVPNPrivateJobFixtureChild]::LongPath($script:ChildExe)) 'An unrelated executable appeared in the fixture.'
        $script:Processes.Add($process)
        return $process
    } catch { $process.Dispose();throw }
}
function Add-Owner([type]$Type,[string[]]$Arguments) {
    $owner=Start-Owner $Type $Arguments $script:CapturedEnvironment
    $script:Owners.Add($owner)
    return $owner
}
function Assignment-Failure([type]$Type,[string]$Name) {
    $marker=Join-Path $script:Fixture ($Name+'.ready')
    $failure=$null
    try { $unexpected=Add-Owner $Type @('hold',$marker,(Join-Path $script:Fixture ($Name+'.release'))) }
    catch { $failure=Unwrap $_ }
    Check ($null -ne $failure) 'The assignment-failure variant unexpectedly launched a child.'
    Check ($failure.GetType().Name -ceq 'PrivateJobStartException') 'A launch failure lost its typed ownership report.'
    if($null -ne $failure.RecoveryOwner) { $script:Owners.Add($failure.RecoveryOwner) }
    Check ($failure.ChildCreated -and $failure.ChildExited) 'The suspended process was not actually created and joined after assignment failure.'
    Check ($null -eq $failure.RecoveryOwner) 'A terminated suspended child retained an unexpected recovery owner.'
    Check (-not [IO.File]::Exists($marker)) 'The native child executed before private Job assignment.'
}
function Orphan-Close([type]$Type,[string]$Name) {
    $primary=Join-Path $script:Fixture ($Name+'.primary')
    $child=Join-Path $script:Fixture ($Name+'.child')
    $release=Join-Path $script:Fixture ($Name+'.release')
    $owner=Add-Owner $Type @('spawn',$primary,$child,$release,(Join-Path $script:Fixture ($Name+'.child-release')))
    $parentReport=Child-Report $primary
    $childReport=Child-Report $child
    $observed=Capture-ObservedProcess $childReport
    Check ([int]$parentReport[3] -eq $observed.Id) 'The owned fixture parent reported a different child.'
    Check ([long]$parentReport[4] -eq $observed.StartTime.ToUniversalTime().Ticks) 'The descendant creation identity changed.'
    Check (-not $observed.HasExited) 'The descendant fixture exited before the Job-close observation.'
    [IO.File]::WriteAllText($release,'release captured primary')
    Check ($owner.Wait(15000)) 'The captured primary did not actually exit.'
    Check ($owner.ExitCode -eq 11) 'The captured primary exit status was replaced.'
    Check (-not $observed.HasExited) 'The descendant did not remain alive to test final Job ownership.'
    $owner.Close()
    Check ($observed.WaitForExit(5000)) 'Closing the private Job did not terminate its owned orphan.'
}

try {
    [IO.Directory]::CreateDirectory($script:Fixture) | Out-Null
    $compilerCandidates=@(
        (Join-Path $env:SystemRoot 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'),
        (Join-Path $env:SystemRoot 'Microsoft.NET/Framework/v4.0.30319/csc.exe')
    )
    $compiler=@($compilerCandidates | Where-Object { [IO.File]::Exists($_) } | Select-Object -First 1)
    Check ($compiler.Count -eq 1) 'The runner has no installed .NET Framework C# compiler for the actual Windows child fixture.'
    $childFile=Join-Path $script:Fixture 'fixture-child.cs'
    [IO.File]::WriteAllText($childFile,$childSource,(New-Object Text.UTF8Encoding $false))
    $compilerOutput=& $compiler[0] /nologo /target:exe /platform:anycpu /optimize+ /langversion:5 ("/out:"+$script:ChildExe) $childFile 2>&1
    Check ($LASTEXITCODE -eq 0 -and [IO.File]::Exists($script:ChildExe)) ('The installed .NET Framework compiler rejected the fixture: '+($compilerOutput -join ' '))

    $echo=Join-Path $script:Fixture 'echo.ready'
    $values=[string[]]@('','plain','space value','quote"inside','trailing\','double\\"quote',('Unicode '+[char]0x03bb+' '+[char]0x4e2d),'$(not-a-command) & | %PATH%',"line1`nline2")
    $owner=Add-Owner $ownerType (@('echo',$echo)+$values)
    Check ($owner.Wait(15000)) 'The actual argument/environment child did not exit.'
    Check ($owner.ExitCode -eq 37) 'A successful process wait did not retain the exact native exit code.'
    $report=Child-Report $echo
    Check ([int]$report[0] -eq $owner.ProcessId) 'The returned process owner has the wrong PID.'
    Check ([long]$report[1] -eq $owner.CreationTimeUtc.Ticks) 'The returned owner has the wrong creation identity.'
    Check ([RouterVPNPrivateJobFixtureChild]::LongPath((Decode $report[2])) -ieq [RouterVPNPrivateJobFixtureChild]::LongPath($owner.ExecutablePath)) 'The returned owner has the wrong executable identity.'
    Check ([RouterVPNPrivateJobFixtureChild]::LongPath((Decode $report[3])) -ieq [RouterVPNPrivateJobFixtureChild]::LongPath($script:Fixture)) 'The captured working directory changed.'
    Check ((Decode $report[4]) -ceq $script:CapturedEnvironment['ROUTERVPN_JOB_FIXTURE']) 'The Unicode environment changed during native creation.'
    Check ($report.Length -eq $values.Length+5) 'The Windows parser split or lost an argument.'
    for($index=0;$index -lt $values.Length;$index++) { Check ((Decode $report[$index+5]) -ceq $values[$index]) 'The real Windows argv differed from its captured argument.' }
    Close-RouterVPNPrivateJob $owner
    Check ($owner.IsClosed -and (Wait-RouterVPNPrivateJob $owner)) 'A closed captured child lost its actual exit witness.'

    $hold=Join-Path $script:Fixture 'hold.ready'
    $owner=Add-Owner $ownerType @('hold',$hold,(Join-Path $script:Fixture 'hold.release'))
    $report=Child-Report $hold
    $observed=Capture-ObservedProcess $report
    Check $owner.IsInOwnedJob 'The actual native child is not a member of its exact private Job.'
    Check (-not (Wait-RouterVPNPrivateJob $owner -Milliseconds 0)) 'A wait timeout became a process exit acknowledgement.'
    Check (-not $owner.HasExited) 'A running child was reported exited.'
    Require-PendingExitGuard $owner
    Reject { Close-RouterVPNPrivateJob $owner } 'A live primary owner was closed implicitly.'
    Check (-not $owner.IsClosed -and -not $observed.HasExited) 'Refusing a premature Close still destroyed the live owner.'
    Check (Stop-RouterVPNPrivateJob $owner -Milliseconds 15000 -ExitCode 71) 'Explicit Job termination did not join the captured primary.'
    Check ($observed.WaitForExit(1000) -and $owner.ExitCode -eq 71) 'Explicit termination returned without actual primary exit.'
    Close-RouterVPNPrivateJob $owner
    Close-RouterVPNPrivateJob $owner
    Check (Stop-RouterVPNPrivateJob $owner) 'An already closed, exited owner lost its terminal witness.'

    Orphan-Close $ownerType 'orphan'
    $breakaway=Join-Path $script:Fixture 'breakaway.ready'
    $owner=Add-Owner $ownerType @('breakaway',$breakaway,(Join-Path $script:Fixture 'escaped.ready'),(Join-Path $script:Fixture 'escaped.release'))
    Check ($owner.Wait(15000)) 'The actual non-breakaway child did not finish.'
    $report=Child-Report $breakaway
    Check ($owner.ExitCode -eq 0 -and $report[0] -ceq 'refused') 'A native descendant escaped its captured non-breakaway Job.'
    Check (-not [IO.File]::Exists((Join-Path $script:Fixture 'escaped.ready'))) 'A breakaway fixture child executed.'
    $owner.Close()

    # A real suspended process is created, assignment is deliberately rejected,
    # and the fixture checks the helper's exact-handle termination/join path.
    Assignment-Failure $failedType 'assignment-failure'

    # Defect control: execute the child before the rejected assignment. The same
    # real observation must reject the original Start-Process/assign race.
    Detect-Defect { Assignment-Failure $prematureType 'premature-resume' } 'The native child executed before private Job assignment.' 'The process-order fixture did not detect the exact premature execution defect.'
    Check ([IO.File]::Exists((Join-Path $script:Fixture 'premature-resume.ready'))) 'The intended process-order defect was not actually exercised.'

    # Defect control: a timeout is not a completion, even if its function says so.
    $owner=Add-Owner $timeoutType @('hold',(Join-Path $script:Fixture 'false-wait.ready'),(Join-Path $script:Fixture 'false-wait.release'))
    $null=Child-Report (Join-Path $script:Fixture 'false-wait.ready')
    Detect-Defect { Check (-not $owner.Wait(0)) 'A timeout was reported as exit.' } 'A timeout was reported as exit.' 'The completion fixture did not detect the exact false wait acknowledgement.'
    Check ($owner.Stop(15000,73)) 'The timeout defect fixture did not clean up its actual process.'
    $owner.Close()

    # Defect control: final Job close must still contain inherited descendants.
    Detect-Defect { Orphan-Close $uncontainedType 'uncontained' } 'Closing the private Job did not terminate its owned orphan.' 'The orphan fixture did not detect the exact missing kill-on-close defect.'

    $failure=$null
    try { Start-RouterVPNPrivateJob -FilePath (Join-Path $script:Fixture 'absent.exe') -ArgumentList @('private-fixture-secret') -WorkingDirectory $script:Fixture -Environment @{'KEY'='private-fixture-secret'} }
    catch { $failure=Unwrap $_ }
    Check ($null -ne $failure -and -not $failure.ChildCreated -and -not $failure.ChildExited -and $null -eq $failure.RecoveryOwner) 'A validation failure claimed a native child or lost its no-child state.'
    Check (-not $failure.ToString().Contains('private-fixture-secret')) 'A launch failure disclosed captured argument or environment content.'
    Write-Output ("Windows private Job checks passed: {0}; actual suspended creation, exact Job membership, Unicode argv/environment, no-breakaway descendants, primary wait, orphan close and three executable defect controls." -f $script:Checks)
} finally {
    # Only retained fixture owner/process handles are touched. No PID sweep,
    # system process name matching or recursive application cleanup is used.
    foreach($owner in $script:Owners) {
        if(-not $owner.IsClosed) {
            try { if($owner.Stop(15000,75)) { $owner.Close() } } catch { Write-Warning 'A captured fixture owner could not be fully joined.' }
        }
    }
    foreach($process in $script:Processes) {
        try { if(-not $process.HasExited) { $process.Kill();$null=$process.WaitForExit(15000) } } finally { $process.Dispose() }
    }
    if([IO.Directory]::Exists($script:Fixture)) { Remove-Item -LiteralPath $script:Fixture -Recurse -Force }
}
