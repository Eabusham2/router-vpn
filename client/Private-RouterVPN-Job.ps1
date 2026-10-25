# The caller validates its captured native executable and private runtime first.
# This helper owns one child and one unnamed Job. It never resolves a process by
# PID, invokes a shell, changes firewall policy, or declares application drain.
# Windows contracts: CreateProcessW, AssignProcessToJobObject, Job Objects and
# Parsing C command-line arguments on learn.microsoft.com.
$routerVPNPrivateJobSource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace RouterVPN {
    public sealed class PrivateJobStartException : Exception {
        public bool ChildCreated { get; private set; }
        public bool ChildExited { get; private set; }
        public int NativeError { get; private set; }
        public PrivateJobOwner RecoveryOwner { get; private set; }
        internal PrivateJobStartException(string stage, int error, bool created, bool exited, PrivateJobOwner owner)
            : base("Private native child launch failed at " + stage + (owner == null ? "; no live primary child retained." : "; captured child ownership retained for cleanup.")) {
            ChildCreated = created; ChildExited = exited; NativeError = error; RecoveryOwner = owner;
        }
    }

    public sealed class PrivateJobOwner {
        public const string SourceIdentity = "__ROUTERVPN_JOB_SOURCE_SHA256__";
        const uint CREATE_SUSPENDED = 0x00000004, DETACHED_PROCESS = 0x00000008, CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        const uint WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 258, WAIT_FAILED = 0xffffffff;
        readonly object access = new object();
        readonly NativeHandle job = new NativeHandle();
        readonly NativeHandle process = new NativeHandle();
        readonly NativeHandle thread = new NativeHandle();
        bool assigned, closed, exited;
        uint exitCode;
        int processId;
        DateTime creationTimeUtc;
        string executablePath;
        private PrivateJobOwner() {}

        public int ProcessId { get { return processId; } }
        public DateTime CreationTimeUtc { get { return creationTimeUtc; } }
        public string ExecutablePath { get { return executablePath; } }
        public bool IsClosed { get { lock (access) { return closed; } } }
        public bool HasExited { get { return Wait(0); } }
        public uint ExitCode {
            get { lock (access) { if (!WaitLocked(0)) throw new InvalidOperationException("The captured child has not exited."); return exitCode; } }
        }
        public bool IsInOwnedJob {
            get { lock (access) {
                if (closed || !assigned) return false;
                bool member;
                if (!Native.IsProcessInJob(process, job, out member)) throw NativeError("Private Job membership query failed.");
                return member;
            } }
        }
        public override string ToString() { return "Router VPN private native owner (PID " + processId + ")"; }

        static Win32Exception NativeError(string message) { return new Win32Exception(Marshal.GetLastWin32Error(), message); }
        static void Milliseconds(int value) { if (value < 0 || value > 60000) throw new ArgumentOutOfRangeException("milliseconds"); }
        static string AbsolutePath(string value, bool directory) {
            if (String.IsNullOrWhiteSpace(value) || value.IndexOf('\0') >= 0 || !Path.IsPathRooted(value))
                throw new ArgumentException("Private native launch requires absolute paths.");
            string path = Path.GetFullPath(value);
            string root = Path.GetPathRoot(value);
            if (String.IsNullOrEmpty(root) || root.Length < 3 || !root.EndsWith("\\", StringComparison.Ordinal))
                throw new ArgumentException("Private native launch requires fully qualified paths.");
            FileAttributes attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0 || ((attributes & FileAttributes.Directory) != 0) != directory)
                throw new ArgumentException("Private native launch refuses linked or unexpected path types.");
            DirectoryInfo parent = directory ? new DirectoryInfo(path).Parent : new FileInfo(path).Directory;
            while (parent != null) {
                if ((parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new ArgumentException("Private native launch refuses linked ancestors.");
                parent = parent.Parent;
            }
            if (!directory && !String.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Private native launch requires an executable file.");
            return path;
        }

        // Always quote each argument using the Windows C/Go argv convention.
        // No command interpreter ever receives this command line.
        static string QuoteArgument(string value) {
            if (value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("Invalid private native argument.");
            StringBuilder result = new StringBuilder(); result.Append('"');
            int slashes = 0;
            foreach (char character in value) {
                if (character == '\\') { slashes++; continue; }
                if (character == '"') { result.Append('\\', slashes * 2 + 1); result.Append('"'); }
                else { result.Append('\\', slashes); result.Append(character); }
                slashes = 0;
            }
            result.Append('\\', slashes * 2); result.Append('"');
            return result.ToString();
        }

        static StringBuilder CommandLine(string executable, string[] arguments) {
            if (arguments == null || arguments.Length > 1024) throw new ArgumentException("Invalid private native argument count.");
            StringBuilder command = new StringBuilder(QuoteArgument(executable));
            foreach (string argument in arguments) { command.Append(' '); command.Append(QuoteArgument(argument)); }
            if (command.Length >= 32767) throw new ArgumentException("Private native command line exceeds its bound.");
            command.EnsureCapacity(command.Length + 1);
            return command;
        }

        static char[] EnvironmentBlock(IDictionary environment) {
            if (environment == null || environment.Count > 4096) throw new ArgumentException("Invalid private native environment.");
            SortedDictionary<string, string> selected = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            int count = 1;
            foreach (DictionaryEntry entry in environment) {
                string name = entry.Key as string, value = entry.Value as string;
                if (String.IsNullOrEmpty(name) || value == null || name.IndexOfAny(new char[] {'=', '\0'}) >= 0 || value.IndexOf('\0') >= 0 || selected.ContainsKey(name))
                    throw new ArgumentException("Invalid or duplicated private native environment entry.");
                count = checked(count + name.Length + value.Length + 2);
                if (count > 512 * 1024) throw new ArgumentException("Private native environment exceeds its bound.");
                selected.Add(name, value);
            }
            char[] block = new char[Math.Max(count, 2)];
            int offset = 0;
            foreach (KeyValuePair<string, string> entry in selected) {
                entry.Key.CopyTo(0, block, offset, entry.Key.Length); offset += entry.Key.Length;
                block[offset++] = '=';
                entry.Value.CopyTo(0, block, offset, entry.Value.Length); offset += entry.Value.Length;
                offset++;
            }
            return block;
        }

        static void RequireNonInheritable(NativeHandle handle) {
            uint flags;
            if (!Native.GetHandleInformation(handle, out flags) || (flags & 1) != 0)
                throw new InvalidOperationException("Private native handle inheritance was not disabled.");
        }

        static void ConfigureJob(NativeHandle handle) {
            ExtendedLimits info = new ExtendedLimits();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int size = Marshal.SizeOf(typeof(ExtendedLimits));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try {
                Marshal.StructureToPtr(info, buffer, false);
                if (!Native.SetInformationJobObject(handle, 9, buffer, (uint)size)) throw NativeError("Private Job configuration failed.");
            } finally { Marshal.FreeHGlobal(buffer); }
            ExtendedLimits observed; uint returned;
            if (!Native.QueryInformationJobObject(handle, 9, out observed, (uint)size, out returned) || returned != size ||
                observed.BasicLimitInformation.LimitFlags != JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
                throw new InvalidOperationException("Private Job kill-on-close or non-breakaway ownership was not established.");
        }

        public static PrivateJobOwner Start(string filePath, string[] arguments, string workingDirectory, IDictionary environment) {
            PrivateJobOwner owner = new PrivateJobOwner();
            string stage = "validation";
            IntPtr nativeEnvironment = IntPtr.Zero;
            char[] block = null;
            int environmentCharacters = 0;
            try {
                if (Environment.OSVersion.Platform != PlatformID.Win32NT) throw new PlatformNotSupportedException();
                string executable = AbsolutePath(filePath, false), directory = AbsolutePath(workingDirectory, true);
                StringBuilder command = CommandLine(executable, arguments);
                block = EnvironmentBlock(environment); environmentCharacters = block.Length;
                nativeEnvironment = Marshal.AllocHGlobal(checked(environmentCharacters * 2));
                Marshal.Copy(block, 0, nativeEnvironment, block.Length);
                Array.Clear(block, 0, block.Length); block = null;
                stage = "job creation";
                owner.job.Adopt(Native.CreateJobObjectW(IntPtr.Zero, null));
                if (owner.job.IsInvalid) throw NativeError("Private Job creation failed.");
                RequireNonInheritable(owner.job);
                ConfigureJob(owner.job);
                StartupInfo startup = new StartupInfo(); startup.cb = (uint)Marshal.SizeOf(typeof(StartupInfo));
                ProcessInformation information;
                stage = "suspended process creation";
                bool created = Native.CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, false,
                    CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT, nativeEnvironment, directory, ref startup, out information);
                int creationError = Marshal.GetLastWin32Error();
                owner.process.Adopt(information.hProcess); owner.thread.Adopt(information.hThread);
                if (!created || owner.process.IsInvalid || owner.thread.IsInvalid)
                    throw new Win32Exception(creationError, "Suspended private native creation failed.");
                owner.processId = checked((int)information.dwProcessId);
                RequireNonInheritable(owner.process); RequireNonInheritable(owner.thread);
                stage = "process identity";
                if (Native.GetProcessId(owner.process) != information.dwProcessId || information.dwProcessId == 0)
                    throw new InvalidOperationException("Private native process handle identity differs.");
                FileTime creation, exit, kernel, user;
                if (!Native.GetProcessTimes(owner.process, out creation, out exit, out kernel, out user)) throw NativeError("Private native creation time is unavailable.");
                owner.creationTimeUtc = DateTime.FromFileTimeUtc(((long)creation.High << 32) | creation.Low);
                StringBuilder image = new StringBuilder(32768); uint imageLength = (uint)image.Capacity;
                if (!Native.QueryFullProcessImageNameW(owner.process, 0, image, ref imageLength)) throw NativeError("Private native image identity is unavailable.");
                owner.executablePath = image.ToString();
                stage = "job assignment";
                if (!Native.AssignProcessToJobObject(owner.job, owner.process)) throw NativeError("Private Job assignment failed.");
                owner.assigned = true;
                if (!owner.IsInOwnedJob) throw new InvalidOperationException("Private native child is not in its captured Job.");
                stage = "primary thread resume";
                uint suspendCount = Native.ResumeThread(owner.thread);
                if (suspendCount != 1) throw NativeError("Private native resume did not release exactly its initial suspension.");
                owner.thread.Dispose();
                return owner;
            } catch (Exception error) {
                bool created = !owner.process.IsInvalid, stopped = false;
                if (created) {
                    try { stopped = owner.Stop(5000, 1); }
                    catch { try { stopped = owner.Wait(0); } catch {} }
                }
                if (!created || stopped) owner.CloseAfterExitOrNoChild();
                Win32Exception windowsError = error as Win32Exception;
                throw new PrivateJobStartException(stage, windowsError == null ? 0 : windowsError.NativeErrorCode,
                    created, created && stopped, owner.closed ? null : owner);
            } finally {
                if (block != null) Array.Clear(block, 0, block.Length);
                if (nativeEnvironment != IntPtr.Zero) {
                    for (int index = 0; index < environmentCharacters; index++) Marshal.WriteInt16(nativeEnvironment, index * 2, 0);
                    Marshal.FreeHGlobal(nativeEnvironment);
                }
            }
        }

        bool WaitLocked(int milliseconds) {
            if (closed) return exited;
            if (process.IsInvalid) throw new InvalidOperationException("No captured primary process handle is available.");
            if (exited) return true;
            uint result = Native.WaitForSingleObject(process, (uint)milliseconds);
            if (result == WAIT_TIMEOUT) return false;
            if (result == WAIT_FAILED) throw NativeError("Private native process wait failed.");
            if (result != WAIT_OBJECT_0) throw new InvalidOperationException("Private native process wait returned an unknown state.");
            uint code;
            if (!Native.GetExitCodeProcess(process, out code)) throw NativeError("Private native exit code is unavailable.");
            exitCode = code; exited = true;
            return true;
        }

        public bool Wait(int milliseconds) {
            Milliseconds(milliseconds);
            lock (access) { return WaitLocked(milliseconds); }
        }

        // Explicit forced termination is separate from graceful native mailbox
        // shutdown. A timeout retains these exact handles for a later retry.
        public bool Stop(int milliseconds, uint code) {
            Milliseconds(milliseconds);
            lock (access) {
                if (closed) return exited;
                if (assigned) {
                    if (!Native.TerminateJobObject(job, code)) throw NativeError("Private Job termination request failed.");
                } else if (!WaitLocked(0)) {
                    if (!Native.TerminateProcess(process, code) && !WaitLocked(0)) throw NativeError("Captured suspended child termination request failed.");
                }
                return WaitLocked(milliseconds);
            }
        }

        void CloseAfterExitOrNoChild() {
            lock (access) {
                if (closed) return;
                if (!process.IsInvalid && !WaitLocked(0)) throw new InvalidOperationException("A live private native owner cannot be closed.");
                // Closing this final, non-inherited Job handle contains owned
                // orphans after unexpected primary exit. This is not a claim
                // that application resources or descendants drained gracefully.
                job.Dispose(); thread.Dispose(); process.Dispose(); closed = true;
            }
        }
        public void Close() { CloseAfterExitOrNoChild(); }

        sealed class NativeHandle : SafeHandleZeroOrMinusOneIsInvalid {
            internal NativeHandle() : base(true) {}
            internal void Adopt(IntPtr value) {
                if (!IsInvalid || IsClosed) throw new InvalidOperationException("Private native handle was already captured.");
                SetHandle(value);
            }
            protected override bool ReleaseHandle() { return Native.CloseHandle(handle); }
        }
        [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low, High; }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInformation { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }
        [StructLayout(LayoutKind.Sequential)] struct StartupInfo {
            public uint cb; public IntPtr lpReserved, lpDesktop, lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }
        [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
            public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
            public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)] struct IoCounters {
            public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
        }
        [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {
            public BasicLimits BasicLimitInformation; public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
        }
        static class Native {
            [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
            internal static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool SetInformationJobObject(NativeHandle job, int informationClass, IntPtr information, uint length);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool QueryInformationJobObject(NativeHandle job, int informationClass, out ExtendedLimits information, uint length, out uint returned);
            [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes,
                [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInformation information);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool AssignProcessToJobObject(NativeHandle job, NativeHandle process);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsProcessInJob(NativeHandle process, NativeHandle job, [MarshalAs(UnmanagedType.Bool)] out bool result);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
            internal static extern uint GetProcessId(NativeHandle process);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetProcessTimes(NativeHandle process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
            [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool QueryFullProcessImageNameW(NativeHandle process, uint flags, StringBuilder name, ref uint size);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetHandleInformation(NativeHandle handle, out uint flags);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
            internal static extern uint ResumeThread(NativeHandle thread);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
            internal static extern uint WaitForSingleObject(NativeHandle handle, uint milliseconds);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetExitCodeProcess(NativeHandle process, out uint exitCode);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool TerminateProcess(NativeHandle process, uint exitCode);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool TerminateJobObject(NativeHandle job, uint exitCode);
            [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CloseHandle(IntPtr handle);
        }
    }
}
'@
$routerVPNPrivateJobHasher = [Security.Cryptography.SHA256]::Create()
try {
    $routerVPNPrivateJobHash = -join ($routerVPNPrivateJobHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($routerVPNPrivateJobSource)) | ForEach-Object { $_.ToString('x2') })
} finally { $routerVPNPrivateJobHasher.Dispose() }
$routerVPNPrivateJobSource = $routerVPNPrivateJobSource.Replace('__ROUTERVPN_JOB_SOURCE_SHA256__', $routerVPNPrivateJobHash)
if (-not ('RouterVPN.PrivateJobOwner' -as [type])) {
    Add-Type -TypeDefinition $routerVPNPrivateJobSource -CompilerOptions '/langversion:5' -ErrorAction Stop
} elseif ([RouterVPN.PrivateJobOwner]::SourceIdentity -cne $routerVPNPrivateJobHash) {
    throw 'A different Router VPN private Job helper is already loaded in this process.'
}
Remove-Variable routerVPNPrivateJobSource,routerVPNPrivateJobHash,routerVPNPrivateJobHasher

function Start-RouterVPNPrivateJob {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$ArgumentList,
        [Parameter(Mandatory=$true)][string]$WorkingDirectory,
        [Parameter(Mandatory=$true)][System.Collections.IDictionary]$Environment
    )
    return [RouterVPN.PrivateJobOwner]::Start($FilePath,$ArgumentList,$WorkingDirectory,$Environment)
}
function Wait-RouterVPNPrivateJob {
    param([Parameter(Mandatory=$true)][RouterVPN.PrivateJobOwner]$Owner,[ValidateRange(0,60000)][int]$Milliseconds=0)
    return $Owner.Wait($Milliseconds)
}
function Stop-RouterVPNPrivateJob {
    param([Parameter(Mandatory=$true)][RouterVPN.PrivateJobOwner]$Owner,[ValidateRange(0,60000)][int]$Milliseconds=5000,[uint32]$ExitCode=1)
    return $Owner.Stop($Milliseconds,$ExitCode)
}
function Close-RouterVPNPrivateJob {
    param([Parameter(Mandatory=$true)][RouterVPN.PrivateJobOwner]$Owner)
    $Owner.Close()
}
