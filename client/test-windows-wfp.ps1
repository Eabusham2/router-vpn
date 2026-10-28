param(
    [string]$SourceRoot=(Split-Path -Parent $PSScriptRoot),
    [switch]$CompileOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:Checks=0
$helper=Join-Path $SourceRoot 'client/Private-RouterVPN-Wfp.ps1'
$helperText=[IO.File]::ReadAllText($helper,[Text.Encoding]::UTF8)
$tokens=$null;$parseErrors=$null
$null=[Management.Automation.Language.Parser]::ParseInput($helperText,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count -ne 0) { throw 'The complete WFP helper has PowerShell parse errors.' }
. $helper

function Check([bool]$Value,[string]$Message) {
    $script:Checks++
    if(-not $Value) { throw $Message }
}
function Reject([scriptblock]$Action,[string]$Message) {
    $failed=$false
    try { $null=& $Action } catch { $failed=$true }
    Check $failed $Message
}
function Invoke-FixtureCleanup([scriptblock]$Action,[string]$Label,[Collections.Generic.List[string]]$Failures) {
    try { $null=& $Action }
    catch {
        $detail=$Label+': '+$_.Exception.ToString()
        $Failures.Add($detail)
        [Console]::Error.WriteLine('WFP fixture cleanup failure: '+$detail)
    }
}
# A native startup failure must remain visible even if checked cleanup also
# rejects a missing/retired owner. Every subsequent owned cleanup still runs;
# a cleanup failure is independently fatal when the kernel assertions passed.
$cleanupControl=New-Object 'Collections.Generic.List[string]'
$cleanupProgress=New-Object 'Collections.Generic.List[string]'
$savedError=[Console]::Error
$capturedError=New-Object IO.StringWriter
try {
    [Console]::SetError($capturedError)
    Invoke-FixtureCleanup { throw 'CONTROL primary cleanup failure' } 'first' $cleanupControl
    Invoke-FixtureCleanup { $cleanupProgress.Add('continued') } 'second' $cleanupControl
} finally { [Console]::SetError($savedError) }
Check ($cleanupControl.Count -eq 1 -and $cleanupControl[0].Contains('CONTROL primary cleanup failure')) 'The fixture suppressed a cleanup failure.'
Check ($cleanupProgress.Count -eq 1 -and $cleanupProgress[0] -ceq 'continued') 'A cleanup exception prevented later owned cleanup.'
Check ($capturedError.ToString().Contains('WFP fixture cleanup failure: first:')) 'The fixture lost the actual failing cleanup operation.'
$capturedError.Dispose()
function Private-Value($Value,[string]$Name) {
    $field=$Value.GetType().GetField($Name,[Reflection.BindingFlags]'Instance,NonPublic')
    Check ($null -ne $field) ('Missing compiled field '+$Name)
    return ,$field.GetValue($Value)
}
function Static-Call([type]$Type,[string]$Name,[object[]]$Arguments) {
    $method=$Type.GetMethod($Name,[Reflection.BindingFlags]'Static,NonPublic')
    Check ($null -ne $method) ('Missing compiled method '+$Name)
    $args=New-Object object[] $Arguments.Count
    for($i=0;$i -lt $Arguments.Count;$i++) { if($null -ne $Arguments[$i]) { $args[$i]=$Arguments[$i].PSObject.BaseObject } }
    return ,$method.Invoke($null,$args)
}
function Read-NativeStruct([IntPtr]$Pointer,[type]$Type) {
    $method=[Runtime.InteropServices.Marshal].GetMethod('PtrToStructure',[type[]]@([IntPtr],[type]))
    $args=New-Object object[] 2;$args[0]=$Pointer;$args[1]=$Type
    return $method.Invoke($null,$args)
}
function Create-Policy([type]$Type,[string]$Owner,[string]$Source,[string[]]$Remotes,[string[]]$Prefixes,[string[]]$Servers=[string[]]@()) {
    $args=New-Object object[] 5
    $args[0]=$Owner;$args[1]=$Source;$args[2]=$Remotes;$args[3]=$Prefixes;$args[4]=$Servers
    return $Type.GetMethod('Create').Invoke($null,$args)
}
function Scoped-Policy([type]$Type,[string]$Owner,[string[]]$Remotes,[byte[]]$AppScope) {
    $args=New-Object object[] 7
    $args[0]=$Owner;$args[1]='b'*64;$args[2]=$Remotes;$args[3]=[string[]]@();$args[4]=[string[]]@();$args[5]=$false;$args[6]=$AppScope
    return Static-Call $Type 'Compile' $args
}
function Assert-ScopedRules($Rules,[byte[]]$ExpectedScope) {
    foreach($rule in $Rules) {
        $matches=0
        foreach($condition in (Private-Value $rule 'Conditions')) {
            if([Guid](Private-Value $condition 'Field') -eq [Guid]'d78e1e87-8644-4ea5-9437-d809ecefc971') {
                $matches++
                $data=[byte[]](Private-Value $condition 'Data')
                Check ([uint32](Private-Value $condition 'Type') -eq 12 -and [uint32](Private-Value $condition 'Match') -eq 0 -and $data.Length -eq $ExpectedScope.Length -and [Convert]::ToBase64String($data) -ceq [Convert]::ToBase64String($ExpectedScope)) 'A fixture filter does not have the exact isolated executable condition.'
            }
        }
        Check ($matches -eq 1) 'Refusing a kernel fixture filter without one exact executable scope.'
    }
}
function Install-Scoped($Policy,[byte[]]$ExpectedScope) {
    Assert-ScopedRules (Private-Value $Policy 'baseline') $ExpectedScope
    Assert-ScopedRules (Private-Value $Policy 'exceptions') $ExpectedScope
    $Policy.Install()
}
function Source-Variant([string]$Name,[string]$Before,[string]$After) {
    Check ($script:NativeSource.Contains($Before)) ('Missing executable defect boundary '+$Name)
    $changed=$script:NativeSource.Replace($Before,$After).Replace('namespace RouterVPN {',('namespace RouterVPNWfp'+$Name+' {'))
    Check ($changed -cne $script:NativeSource) ('The WFP defect did not change '+$Name)
    Add-RouterVPNWfpType -TypeDefinition $changed
    return ('RouterVPNWfp'+$Name+'.WfpPolicy') -as [type]
}

$policyType=[RouterVPN.WfpPolicy]
[RouterVPN.WfpPolicy]::AssertNativeLayouts()
$nativeType=$policyType.Assembly.GetType('RouterVPN.WfpNative',$true)
foreach($name in @('FwpmEngineOpen0','FwpmGetAppIdFromFileName0','ConvertInterfaceAliasToLuid')) {
    $method=$nativeType.GetMethod($name,[Reflection.BindingFlags]'Static,NonPublic')
    $import=$method.GetCustomAttributes([Runtime.InteropServices.DllImportAttribute],$false)[0]
    Check ($import.ExactSpelling -and $import.CharSet -eq [Runtime.InteropServices.CharSet]::Unicode -and $import.EntryPoint -ceq $name) 'An unsuffixed Unicode Windows API would be resolved through a different export name.'
}
$flagsMatch=$nativeType.GetMethod('FilterFlagsMatch',[Reflection.BindingFlags]'Static,NonPublic')
foreach($persistent in @($false,$true)) {
    $required=if($persistent) { [uint32]1 } else { [uint32]0 }
    foreach($indexed in @([uint32]0,[uint32]64)) {
        Check ([bool]$flagsMatch.Invoke($null,[object[]]@(($required -bor $indexed),$persistent))) 'Actual BFE indexing was confused with a changed policy lifetime.'
        Check (-not [bool]$flagsMatch.Invoke($null,[object[]]@((($required -bxor 1) -bor $indexed),$persistent))) 'The native readback accepted another policy lifetime.'
        for($bit=1;$bit -lt 32;$bit++) {
            if($bit -eq 6) { continue }
            $changed=[uint32](([uint64]1 -shl $bit) -bor $required -bor $indexed)
            Check (-not [bool]$flagsMatch.Invoke($null,[object[]]@($changed,$persistent))) 'The native readback accepted disabled, boot-time, action-right or unknown flags.'
        }
    }
}
Check $policyType.IsSealed 'WFP plans can be subclassed.'
Check ($policyType.GetConstructors().Length -eq 0) 'An unvalidated public WFP plan can be constructed.'
Check ($policyType.GetFields([Reflection.BindingFlags]'Public,Instance').Length -eq 0) 'The WFP plan exposes mutable public fields.'
Check ([RouterVPN.WfpLease].GetConstructors().Length -eq 0) 'An unowned WFP lease can be constructed.'
Reject { Add-RouterVPNWfpType -TypeDefinition 'public static class RouterVPNWfpNewSyntax { public static int Value => 1; }' } 'The WFP compiler accepted newer C# syntax.'
$plan=Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@('tcp|203.0.113.7|443','udp|2001:db8::7|443')) ([string[]]@('192.168.42.0/24','fd12:3456::/48'))
Check ($plan.BaselineFilterCount -eq 30) 'The IPv4/IPv6 baseline or bounded maintenance rules changed.'
Check ($plan.ExceptionFilterCount -eq 8) 'The captured outer/LAN rules lost a direction or family.'
Check ($plan.PlanSHA256 -cmatch '^[a-f0-9]{64}$') 'The policy lacks a complete plan digest.'
$again=Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@('tcp|203.0.113.7|443','udp|2001:db8::7|443')) ([string[]]@('192.168.42.0/24','fd12:3456::/48'))
Check ($again.SublayerKey -eq $plan.SublayerKey -and $again.PlanSHA256 -ceq $plan.PlanSHA256) 'Exact recovery cannot reproduce its filter identities.'
$alternatives=@(
    (Create-Policy $policyType ('c'*32) ('b'*64) ([string[]]@('tcp|203.0.113.7|443','udp|2001:db8::7|443')) ([string[]]@('192.168.42.0/24','fd12:3456::/48'))),
    (Create-Policy $policyType ('a'*32) ('c'*64) ([string[]]@('tcp|203.0.113.7|443','udp|2001:db8::7|443')) ([string[]]@('192.168.42.0/24','fd12:3456::/48'))),
    (Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@('tcp|203.0.113.7|444','udp|2001:db8::7|443')) ([string[]]@('192.168.42.0/24','fd12:3456::/48'))),
    (Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@('udp|203.0.113.7|443','udp|2001:db8::7|443')) ([string[]]@('192.168.42.0/24','fd12:3456::/48'))),
    (Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@('tcp|203.0.113.7|443','udp|2001:db8::7|443')) ([string[]]@('192.168.43.0/24','fd12:3456::/48')))
)
foreach($other in $alternatives) { Check ($other.PlanSHA256 -cne $plan.PlanSHA256 -and $other.SublayerKey -ne $plan.SublayerKey) 'A changed session/source/route reused another policy generation.' }
foreach($owner in @('',('A'*32),('a'*31),('a'*33),('../'+('a'*32)))) {
    Reject { Create-Policy $policyType $owner ('b'*64) ([string[]]@('tcp|203.0.113.7|443')) ([string[]]@()) } 'An invalid owner was accepted.'
}
foreach($source in @('',('B'*64),('b'*63),('b'*65))) {
    Reject { Create-Policy $policyType ('a'*32) $source ([string[]]@('tcp|203.0.113.7|443')) ([string[]]@()) } 'An invalid source digest was accepted.'
}
foreach($remote in @('tcp|example.com|443','tcp|203.0.113.7|0','tcp|203.0.113.7|65536','tcp|203.0.113.7|0443','TCP|203.0.113.7|443','any|203.0.113.7|443','tcp|203.0.113.7|443|extra','tcp|0.0.0.0|443','tcp|127.0.0.1|443','tcp|::1|443','tcp|::ffff:203.0.113.7|443','tcp|fe80::1%3|443','tcp|224.0.0.1|443','tcp|ff02::1|443','tcp|255.255.255.255|443','tcp|203.0.113.007|443','tcp|2001:DB8::7|443')) {
    Reject { Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@($remote)) ([string[]]@()) } ('An invalid outer exception was accepted: '+$remote)
}
Reject { Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@()) ([string[]]@()) } 'An empty physical capture was accepted.'
Reject { Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@('tcp|203.0.113.7|443','tcp|203.0.113.7|443')) ([string[]]@()) } 'Duplicate physical capture was accepted.'
foreach($prefix in @('0.0.0.0/0','10.0.0.0/7','172.16.0.0/11','192.168.0.0/15','192.168.42.1/24','192.168.42.0/024','192.168.42.0/33','fe80::/10','fc00::/6','fd00::1/8','fd00::/129','2001:db8::/32','localhost/32')) {
    Reject { Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@('tcp|203.0.113.7|443')) ([string[]]@($prefix)) } ('An unsafe LAN exception was accepted: '+$prefix)
}
$bases=Private-Value $plan 'baseline'
$exceptions=Private-Value $plan 'exceptions'
$deny=0;$loopback=0;$dhcp4=0;$dhcp6=0;$ndp=0
foreach($rule in $bases) {
    $name=[string](Private-Value $rule 'Name');$permit=[bool](Private-Value $rule 'Permit');$conditions=Private-Value $rule 'Conditions';$weight=[uint64](Private-Value $rule 'Weight')
    if($name.StartsWith('deny-')) { $deny++;Check (-not $permit -and $weight -eq 1 -and $conditions.Count -eq 0) 'The host deny was weakened.' }
    elseif($name.StartsWith('loopback-')) { $loopback++;Check ($permit -and $conditions.Count -eq 1) 'The loopback condition widened.' }
    elseif($name.StartsWith('dhcp4-')) { $dhcp4++;Check ($permit -and (($name -ceq 'dhcp4-in-v4' -and $conditions.Count -eq 3) -or ($name -ceq 'dhcp4-out-v4' -and $conditions.Count -eq 4))) 'The DHCPv4 tuple widened.' }
    elseif($name.StartsWith('dhcp6-')) { $dhcp6++;Check ($permit -and $conditions.Count -eq 4) 'The DHCPv6 tuple widened.' }
    elseif($name.StartsWith('ndp-')) { $ndp++;Check ($permit -and $conditions.Count -eq 3) 'The IPv6 maintenance tuple widened.' }
    else { throw 'Unexpected durable baseline exception.' }
}
Check ($deny -eq 4 -and $loopback -eq 4 -and $dhcp4 -eq 2 -and $dhcp6 -eq 4 -and $ndp -eq 16) 'A family/direction or maintenance condition is missing.'
$renew=Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@('udp|203.0.113.7|443')) ([string[]]@()) ([string[]]@('192.168.42.1'))
Check ($renew.ExceptionFilterCount -eq 4) 'Captured DHCP renewal lost its exact lease.'
foreach($server in @('0.0.0.0','255.255.255.255','127.0.0.1','::1','fe80::1','2001:db8::1','router.local')) {
    Reject { Create-Policy $policyType ('a'*32) ('b'*64) ([string[]]@('udp|203.0.113.7|443')) ([string[]]@()) ([string[]]@($server)) } 'An invalid DHCP renewal server was accepted.'
}
foreach($rule in $exceptions) {
    $name=[string](Private-Value $rule 'Name');$conditions=Private-Value $rule 'Conditions'
    Check ([bool](Private-Value $rule 'Permit')) 'A lease exception unexpectedly blocks traffic.'
    Check ($name.StartsWith('outer-') -or $name.StartsWith('lan-')) 'A lease contains an uncaptured exception.'
    Check (($name.StartsWith('outer-') -and $conditions.Count -eq 3) -or ($name.StartsWith('lan-') -and $conditions.Count -eq 1)) 'A captured endpoint lost its exact address, protocol or port.'
}
$testScope=[Text.Encoding]::Unicode.GetBytes("fixture-only.exe`0")
$scoped=Scoped-Policy $policyType ('e'*32) ([string[]]@('tcp|127.0.0.1|443','udp|::1|444')) $testScope
Assert-ScopedRules (Private-Value $scoped 'baseline') $testScope
Assert-ScopedRules (Private-Value $scoped 'exceptions') $testScope
$opaqueScope=[Text.Encoding]::Unicode.GetBytes('opaque-api-blob')
$opaque=Scoped-Policy $policyType ('f'*32) ([string[]]@('tcp|127.0.0.1|443')) $opaqueScope
Assert-ScopedRules (Private-Value $opaque 'exceptions') $opaqueScope
Reject { Assert-ScopedRules (Private-Value $plan 'baseline') $testScope } 'The independent kernel-fixture guard admitted a host-wide filter.'
Reject { Assert-ScopedRules (Private-Value $scoped 'baseline') ([Text.Encoding]::Unicode.GetBytes("different.exe`0")) } 'The kernel fixture accepted a different executable scope.'
# Exercise the actual unmanaged marshaler and readback comparator without a
# Windows call. Each changed condition must fail, including pointed-to values.
$flags=[Reflection.BindingFlags]'Instance,NonPublic'
$memoryType=$policyType.Assembly.GetType('RouterVPN.WfpMemory',$true)
foreach($rule in (@($bases)+@($exceptions)+(Private-Value $scoped 'baseline'))) {
    foreach($condition in (Private-Value $rule 'Conditions')) {
        $memory=[Activator]::CreateInstance($memoryType,$true)
        try {
            $native=$condition.GetType().GetMethod('Native',$flags).Invoke($condition,[object[]]@($memory))
            $assert=$condition.GetType().GetMethod('Assert',$flags)
            $null=$assert.Invoke($condition,[object[]]@($native))
            $valueField=$native.GetType().GetField('Value',$flags);$value=$valueField.GetValue($native)
            $dataField=$value.GetType().GetField('Data',$flags);$data=$dataField.GetValue($value)
            $kind=[uint32](Private-Value $condition 'Type')
            if($kind -in @(1,2,3)) {
                $name=if($kind -eq 1) { 'Byte' } elseif($kind -eq 2) { 'Word' } else { 'DWord' }
                $field=$data.GetType().GetField($name,$flags)
                $changed=[Convert]::ChangeType(([uint64]$field.GetValue($data) -bxor 1),$field.FieldType)
                $field.SetValue($data,$changed);$dataField.SetValue($value,$data);$valueField.SetValue($native,$value)
            } else {
                $pointer=[IntPtr](Private-Value $data 'Pointer')
                if($kind -eq 12) {
                    $blobType=$policyType.Assembly.GetType('RouterVPN.WfpNative+Blob',$true)
                    $blob=Read-NativeStruct $pointer $blobType
                    $pointer=[IntPtr](Private-Value $blob 'Data')
                }
                [Runtime.InteropServices.Marshal]::WriteByte($pointer,([Runtime.InteropServices.Marshal]::ReadByte($pointer) -bxor 1))
            }
            Reject { $assert.Invoke($condition,[object[]]@($native)) } 'The native readback comparator accepted a changed condition value.'
        } finally { $memory.Dispose() }
    }
}
$matches=[regex]::Matches($helperText,"(?s)\`$routerVPNWfpSource = @'\r?\n(.*?)\r?\n'@")
Check ($matches.Count -eq 1) 'The actual WFP source cannot be captured for executable defect controls.'
$script:NativeSource=$matches[0].Groups[1].Value
Reject { & ([scriptblock]::Create($helperText.Replace('value.Flags = persistent ? 1U : 0U','value.Flags = persistent ? 0U : 0U'))) } 'A different WFP source silently reused the old compiled type.'
$permitType=Source-Variant 'PermitDeny' 'Pair(bases, "deny", family, 1, new WfpCondition[0], appScope, false);' 'Pair(bases, "deny", family, 1, new WfpCondition[0], appScope, true);'
$staticType=Source-Variant 'StaticLease' 'session.Flags = dynamic ? 1U : 0U;' 'session.Flags = 0U;'
$ownerType=Source-Variant 'OwnerCollision' '"RouterVPN-WFP/1\n" + owner + "\n" + source + "\n" + digest + "\n" + label' '"RouterVPN-WFP/1\n" + label'
$disabledType=Source-Variant 'DisabledReadback' '(flags & ~0x40U) == (persistent ? 1U : 0U)' '(flags & ~0x60U) == (persistent ? 1U : 0U)'
$disabledNative=$disabledType.Assembly.GetType(($disabledType.Namespace+'.WfpNative'),$true)
$disabledMatch=$disabledNative.GetMethod('FilterFlagsMatch',[Reflection.BindingFlags]'Static,NonPublic')
Check ([bool]$disabledMatch.Invoke($null,[object[]]@([uint32]0x61,$true))) 'The disabled-filter defect did not reach the intended compiled readback.'
Check (-not [bool]$flagsMatch.Invoke($null,[object[]]@([uint32]0x61,$true))) 'The readback accepted a disabled deny as effective protection.'
$mutantA=Create-Policy $ownerType ('a'*32) ('b'*64) ([string[]]@('tcp|203.0.113.7|443')) ([string[]]@())
$mutantB=Create-Policy $ownerType ('c'*32) ('d'*64) ([string[]]@('tcp|203.0.113.8|444')) ([string[]]@())
Check ($mutantA.SublayerKey -eq $mutantB.SublayerKey) 'The intended ownership collision mutation did not execute.'
Check ($alternatives[0].SublayerKey -ne $plan.SublayerKey) 'The executable ownership guard accepted colliding owners.'

$fixtureSource=@'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
public sealed class RouterVPNWfpEcho : IDisposable {
    readonly TcpListener listener;
    readonly Thread worker;
    readonly List<TcpClient> clients = new List<TcpClient>();
    bool closed;
    public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }
    public RouterVPNWfpEcho(string address) : this(address, 0) { }
    public RouterVPNWfpEcho(string address, int port) {
        listener = new TcpListener(IPAddress.Parse(address), port);
        try { listener.Start(); } catch { listener.Stop(); throw; }
        worker = new Thread(Accept); worker.IsBackground = true; worker.Start();
    }
    void Accept() {
        try {
            while (true) {
                TcpClient client = listener.AcceptTcpClient();
                lock (clients) { if (closed) { client.Close(); return; } clients.Add(client); }
                Thread echo = new Thread(delegate() {
                    try { NetworkStream stream = client.GetStream(); byte[] bytes = new byte[128]; int n; while ((n = stream.Read(bytes, 0, bytes.Length)) != 0) stream.Write(bytes, 0, n); }
                    catch (IOException) { } catch (SocketException) { } catch (ObjectDisposedException) { }
                    finally { client.Close(); }
                }); echo.IsBackground = true; echo.Start();
            }
        } catch (SocketException) { } catch (ObjectDisposedException) { }
    }
    public void Dispose() {
        lock (clients) { closed = true; foreach (TcpClient client in clients) client.Close(); }
        listener.Stop(); if (!worker.Join(3000)) throw new IOException("Fixture listener did not drain.");
    }
}
public sealed class RouterVPNWfpDatagramEcho : IDisposable {
    readonly UdpClient socket;
    readonly Thread worker;
    public RouterVPNWfpDatagramEcho(string address, int port) {
        IPAddress ip = IPAddress.Parse(address); socket = new UdpClient(ip.AddressFamily);
        try { socket.Client.Bind(new IPEndPoint(ip, port)); }
        catch { socket.Close(); throw; }
        worker = new Thread(delegate() {
            try {
                while (true) {
                    IPEndPoint peer = new IPEndPoint(ip.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
                    byte[] data = socket.Receive(ref peer); socket.Send(data, data.Length, peer);
                }
            } catch (SocketException) { } catch (ObjectDisposedException) { }
        }); worker.IsBackground = true; worker.Start();
    }
    public void Dispose() { socket.Close(); if (!worker.Join(3000)) throw new IOException("Fixture datagram listener did not drain."); }
}
public static class RouterVPNWfpFixtureClient {
    static int Transfer(TcpClient client) {
        try { NetworkStream stream = client.GetStream(); stream.ReadTimeout = 1500; stream.WriteTimeout = 1500; byte[] bytes = new byte[] { 19, 37, 211, 7 }; stream.Write(bytes, 0, bytes.Length); for (int i = 0; i < bytes.Length; i++) if (stream.ReadByte() != bytes[i]) return 22; return 0; }
        catch (IOException) { return 23; } catch (SocketException) { return 23; }
    }
    public static int Main(string[] args) {
        if (args.Length != 3 || (args[0] != "once" && args[0] != "stream" && args[0] != "udp")) return 90;
        IPAddress address; int port;
        if (!IPAddress.TryParse(args[1], out address) || !Int32.TryParse(args[2], out port) || port < 1 || port > 65535) return 91;
        if (args[0] == "udp") {
            using (UdpClient udp = new UdpClient(address.AddressFamily)) {
                udp.Client.ReceiveTimeout = 1500; udp.Client.SendTimeout = 1500;
                try {
                    udp.Connect(address, port); byte[] payload = new byte[] { 19, 37, 211, 7 }; udp.Send(payload, payload.Length);
                    IPEndPoint peer = new IPEndPoint(address, port); byte[] reply = udp.Receive(ref peer);
                    if (reply.Length != payload.Length) return 22;
                    for (int i = 0; i < payload.Length; i++) if (reply[i] != payload[i]) return 22;
                    return 0;
                } catch (SocketException e) { Console.Error.WriteLine("socket=" + e.NativeErrorCode); return 23; }
            }
        }
        using (TcpClient client = new TcpClient(address.AddressFamily)) {
            try {
                IAsyncResult pending = client.BeginConnect(address, port, null, null);
                if (!pending.AsyncWaitHandle.WaitOne(2500)) return 24;
                client.EndConnect(pending); pending.AsyncWaitHandle.Close();
                if (args[0] == "once") return Transfer(client);
                Console.WriteLine("ready"); Console.Out.Flush();
                string command;
                while ((command = Console.ReadLine()) != null) {
                    if (command == "exit") return 0;
                    if (command != "send") return 92;
                    Console.WriteLine(Transfer(client) == 0 ? "allowed" : "blocked"); Console.Out.Flush();
                }
                return 0;
            } catch (SocketException e) { Console.Error.WriteLine("socket=" + e.NativeErrorCode); return 23; }
        }
    }
}
'@
Add-RouterVPNWfpType -TypeDefinition $fixtureSource
Check ($null -ne ('RouterVPNWfpFixtureClient' -as [type])) 'The real kernel client fixture did not compile as C#5.'
if($CompileOnly) {
    Write-Output ("Windows WFP portable compiler/policy checks: PASS ({0}); kernel coverage requires Windows." -f $script:Checks)
    exit 0
}
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'The WFP kernel suite requires Windows; use CompileOnly for portable validation.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
Check ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'The executable-scoped WFP fixture requires an elevated CI runner.'
$work=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-wfp-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$child=Join-Path $work 'captured-fixture.exe'
$unrelated=Join-Path $work 'unrelated-fixture.exe'
$sourcePath=Join-Path $work 'fixture.cs'
[IO.File]::WriteAllText($sourcePath,$fixtureSource,(New-Object Text.UTF8Encoding($false)))
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { $compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
Check (Test-Path -LiteralPath $compiler -PathType Leaf) 'The Windows framework C# compiler is missing.'
& $compiler /nologo /langversion:5 /target:exe /platform:anycpu ('/out:'+$child) $sourcePath
Check ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $child -PathType Leaf)) 'The executable-scoped client failed to compile.'
[IO.File]::Copy($child,$unrelated)

function App-Scope([string]$Path) {
    $native=$policyType.Assembly.GetType('RouterVPN.WfpNative',$true)
    $method=$native.GetMethod('FwpmGetAppIdFromFileName0',[Reflection.BindingFlags]'Static,NonPublic')
    $args=New-Object object[] 2;$args[0]=$Path;$args[1]=[IntPtr]::Zero
    $code=[uint32]$method.Invoke($null,$args)
    Check ($code -eq 0 -and [IntPtr]$args[1] -ne [IntPtr]::Zero) 'The fixture executable has no WFP AppID.'
    $pointer=[IntPtr]$args[1]
    try {
        $blobType=$policyType.Assembly.GetType('RouterVPN.WfpNative+Blob',$true)
        $blob=Read-NativeStruct $pointer $blobType
        $size=[uint32](Private-Value $blob 'Size');$data=[IntPtr](Private-Value $blob 'Data')
        Check ($size -ge 4 -and $size -le 65536 -and $data -ne [IntPtr]::Zero) 'Invalid fixture AppID bounds.'
        $bytes=New-Object byte[] $size
        [Runtime.InteropServices.Marshal]::Copy($data,$bytes,0,$bytes.Length)
        return ,$bytes
    } finally {
        $freeArgs=New-Object object[] 1;$freeArgs[0]=$pointer
        $null=$native.GetMethod('FwpmFreeMemory0',[Reflection.BindingFlags]'Static,NonPublic').Invoke($null,$freeArgs)
    }
}
function Start-Client([string]$Exe,[string]$Mode,[string]$Address,[int]$Port) {
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$Exe;$start.Arguments=$Mode+' '+$Address+' '+$Port;$start.UseShellExecute=$false
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=$true
    $process=New-Object Diagnostics.Process;$process.StartInfo=$start
    Check $process.Start() 'The captured fixture process did not start.'
    return $process
}
function Probe([string]$Exe,[string]$Address,[int]$Port,[string]$Protocol='once') {
    $process=Start-Client $Exe $Protocol $Address $Port
    try {
        Check $process.WaitForExit(5000) 'The fixture probe exceeded its bounded connection deadline.'
        return [int]$process.ExitCode
    } finally { if(-not $process.HasExited) { $process.Kill();[void]$process.WaitForExit(3000) };$process.Dispose() }
}
function Read-Line([Diagnostics.Process]$Process) {
    $task=$Process.StandardOutput.ReadLineAsync()
    Check $task.Wait(5000) 'The fixture process did not produce its owned acknowledgement.'
    return $task.Result
}
function Stream-Check([Diagnostics.Process]$Process,[string]$Expected,[string]$Message) {
    $Process.StandardInput.WriteLine('send');$Process.StandardInput.Flush()
    Check ((Read-Line $Process) -ceq $Expected) $Message
}
function Stop-Fixture([Diagnostics.Process]$Process) {
    if($null -eq $Process) { return }
    if(-not $Process.HasExited) {
        try { $Process.StandardInput.WriteLine('exit');$Process.StandardInput.Flush() } catch { }
        if(-not $Process.WaitForExit(3000)) { $Process.Kill();Check $Process.WaitForExit(3000) 'An owned fixture process did not exit.' }
    }
    $Process.Dispose()
}
function Exact-MutantCleanup($Policy) {
    # An intentionally static lease survives engine close. Remove only its
    # exact, read-back-checked private fixture filter keys, then the baseline.
    $engineType=$Policy.GetType().Assembly.GetType(($Policy.GetType().Namespace+'.WfpEngine'),$true)
    $constructor=$engineType.GetConstructor([Reflection.BindingFlags]'Instance,NonPublic',$null,[type[]]@([bool]),$null)
    $engine=$constructor.Invoke([object[]]@($false))
    try {
        $flags=[Reflection.BindingFlags]'Instance,NonPublic'
        $null=$engineType.GetMethod('Begin',$flags).Invoke($engine,@())
        $null=$Policy.GetType().GetMethod('Assert',$flags).Invoke($Policy,[object[]]@($engine))
        foreach($rule in (Private-Value $Policy 'exceptions')) {
            $null=$engineType.GetMethod('AssertFilter',$flags).Invoke($engine,[object[]]@($Policy,$rule,$false))
            $name=[string](Private-Value $rule 'Name')
            $key=$Policy.GetType().GetMethod('Key',$flags).Invoke($Policy,[object[]]@($name))
            $null=$engineType.GetMethod('Delete',$flags).Invoke($engine,[object[]]@($key))
        }
        $null=$engineType.GetMethod('Commit',$flags).Invoke($engine,@())
    } finally { $engine.Dispose() }
    $Policy.RemoveChecked()
}
function Exceptions-Absent($Policy) {
    $flags=[Reflection.BindingFlags]'Instance,NonPublic'
    $engineType=$Policy.GetType().Assembly.GetType(($Policy.GetType().Namespace+'.WfpEngine'),$true)
    $constructor=$engineType.GetConstructor($flags,$null,[type[]]@([bool]),$null)
    $engine=$constructor.Invoke([object[]]@($false))
    try {
        foreach($rule in (Private-Value $Policy 'exceptions')) {
            $key=$Policy.GetType().GetMethod('Key',$flags).Invoke($Policy,[object[]]@([string](Private-Value $rule 'Name')))
            $null=$engineType.GetMethod('AssertAbsent',$flags).Invoke($engine,[object[]]@($key))
        }
    } finally { $engine.Dispose() }
}
function Delete-OneFixtureException($Policy,$Lease) {
    $flags=[Reflection.BindingFlags]'Instance,NonPublic'
    $engine=Private-Value $Lease 'engine';$engineType=$engine.GetType()
    try {
        $rules=Private-Value $Policy 'exceptions';$rule=$rules[0]
        $null=$engineType.GetMethod('Begin',$flags).Invoke($engine,@())
        $null=$engineType.GetMethod('AssertFilter',$flags).Invoke($engine,[object[]]@($Policy,$rule,$false))
        $key=$Policy.GetType().GetMethod('Key',$flags).Invoke($Policy,[object[]]@([string](Private-Value $rule 'Name')))
        $null=$engineType.GetMethod('Delete',$flags).Invoke($engine,[object[]]@($key))
        $null=$engineType.GetMethod('Commit',$flags).Invoke($engine,@())
    } catch { $null=$engineType.GetMethod('Abort',$flags).Invoke($engine,@());throw }
}
function Start-LeaseOwner([string]$Owner,[string[]]$Remotes,[byte[]]$Scope) {
    $capturePath=Join-Path $work 'lease-owner.json'
    $ownerPath=Join-Path $work 'lease-owner.ps1'
    $capture=[ordered]@{owner=$Owner;remotes=$Remotes;scope=[Convert]::ToBase64String($Scope)}
    [IO.File]::WriteAllText($capturePath,($capture|ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))
    $program=@'
param([string]$Helper,[string]$Capture)
$ErrorActionPreference='Stop'
. $Helper
$saved=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Capture,[Text.Encoding]::UTF8))
$args=New-Object object[] 7
$args[0]=[string]$saved.owner;$args[1]='b'*64;$args[2]=[string[]]$saved.remotes;$args[3]=[string[]]@();$args[4]=[string[]]@();$args[5]=$false;$args[6]=[Convert]::FromBase64String([string]$saved.scope)
$policy=[RouterVPN.WfpPolicy].GetMethod('Compile',[Reflection.BindingFlags]'Static,NonPublic').Invoke($null,$args)
$lease=$policy.OpenLease()
try {
    [Console]::WriteLine('ready');[Console]::Out.Flush()
    $null=[Console]::ReadLine()
} finally { $lease.CloseChecked() }
'@
    [IO.File]::WriteAllText($ownerPath,$program,(New-Object Text.UTF8Encoding($false)))
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $start.Arguments='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+$ownerPath+'" -Helper "'+$helper+'" -Capture "'+$capturePath+'"'
    $start.UseShellExecute=$false;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process;$process.StartInfo=$start
    Check $process.Start() 'The real exception owner process did not start.'
    return $process
}

function New-FixtureEndpointPair([string]$Address,[scriptblock]$OpenDatagram={param($IP,$Port) New-Object RouterVPNWfpDatagramEcho($IP,$Port)},[scriptblock]$ChoosePort={Get-Random -Minimum 1024 -Maximum 65536}) {
    # Windows TCP and UDP exclusions differ. Reserve both protocols before
    # adopting an endpoint so the kernel assertions still exercise the same
    # address/port with opposite TCP/UDP permissions. Retry only allocation
    # collisions, before installing any product filter, and drain partial owners.
    # The TCP ephemeral allocator can return adjacent ports in a large UDP
    # exclusion range. Sample the full unprivileged range independently instead
    # of repeatedly asking that allocator for the next inaccessible UDP port.
    for($attempt=0;$attempt -lt 32;$attempt++) {
        $tcp=$null;$udp=$null
        try {
            $port=[int](& $ChoosePort)
            if($port -lt 1024 -or $port -gt 65535) { throw 'The fixture selected an invalid unprivileged port.' }
            $tcp=New-Object RouterVPNWfpEcho($Address,$port)
            $udp=& $OpenDatagram $Address $tcp.Port
            if($null -eq $udp -or $udp -isnot [RouterVPNWfpDatagramEcho]) { throw 'The fixture did not reserve its captured UDP listener.' }
            return [pscustomobject]@{TCP=$tcp;UDP=$udp}
        } catch {
            $failure=$_.Exception
            if($null -ne $udp) { $udp.Dispose() }
            if($null -ne $tcp) { $tcp.Dispose() }
            while($null -ne $failure.InnerException) { $failure=$failure.InnerException }
            if($failure -isnot [Net.Sockets.SocketException] -or
               $failure.SocketErrorCode -notin @([Net.Sockets.SocketError]::AddressAlreadyInUse,[Net.Sockets.SocketError]::AccessDenied) -or
               $attempt -eq 31) { throw }
        }
    }
    throw 'The fixture could not reserve its bounded TCP/UDP pair.'
}

$foreignName='RouterVPN-WFP-fixture-foreign-'+[Guid]::NewGuid().ToString('N')
$scope=App-Scope $child
$servers=@();$datagrams=@();$streams=@();$active=$null;$lease=$null;$staticPlan=$null;$staticLease=$null;$leaseProcess=$null
$kernelFailure=$null
$cleanupFailures=New-Object 'Collections.Generic.List[string]'
try {
    # This rule intentionally grants the fixture executable outbound access.
    # Product WFP operations must neither delete it nor let it bypass the deny.
    $null=New-NetFirewallRule -Name $foreignName -DisplayName $foreignName -Program $child -Direction Outbound -Action Allow -Profile Any
    foreach($address in @('127.0.0.1','127.0.0.1','::1','::1')) {
        $pair=New-FixtureEndpointPair $address
        $servers+=$pair.TCP;$datagrams+=$pair.UDP
    }
    foreach($entry in @(@('127.0.0.1',$servers[0].Port),@('127.0.0.1',$servers[1].Port),@('::1',$servers[2].Port),@('::1',$servers[3].Port))) {
        Check ((Probe $child $entry[0] $entry[1]) -eq 0) 'The isolated server is not reachable before enforcement.'
        Check ((Probe $child $entry[0] $entry[1] 'udp') -eq 0) 'The isolated datagram server is not reachable before enforcement.'
    }
    $allowedStream=Start-Client $child 'stream' '127.0.0.1' $servers[0].Port;$streams+=$allowedStream
    $blockedStream=Start-Client $child 'stream' '127.0.0.1' $servers[1].Port;$streams+=$blockedStream
    Check ((Read-Line $allowedStream) -ceq 'ready') 'Allowed existing flow did not connect.'
    Check ((Read-Line $blockedStream) -ceq 'ready') 'Blocked existing flow did not connect.'
    $remotes=[string[]]@(('tcp|127.0.0.1|'+$servers[0].Port),('tcp|::1|'+$servers[2].Port),('udp|127.0.0.1|'+$servers[1].Port),('udp|::1|'+$servers[3].Port))
    $owner=[Guid]::NewGuid().ToString('N')
    $active=Scoped-Policy $policyType $owner $remotes $scope
    Install-Scoped $active $scope;$active.AssertCurrent()
    Check ((Probe $child '127.0.0.1' $servers[0].Port) -ne 0) 'Persistent baseline opened before its owned endpoint lease.'
    $lease=$active.OpenLease();$lease.AssertCurrent()
    Reject { $active.OpenLease() } 'A duplicate runtime acquired the same endpoint lease.'
    foreach($entry in @(@('127.0.0.1',$servers[0].Port,$true),@('127.0.0.1',$servers[1].Port,$false),@('::1',$servers[2].Port,$true),@('::1',$servers[3].Port,$false))) {
        $result=Probe $child $entry[0] $entry[1]
        Check (($result -eq 0) -eq [bool]$entry[2]) 'A foreign Allow rule bypassed exact IPv4/IPv6 endpoint enforcement.'
        $datagramResult=Probe $child $entry[0] $entry[1] 'udp'
        Check (($datagramResult -eq 0) -eq (-not [bool]$entry[2])) 'A captured endpoint permit was broadened to the wrong transport.'
    }
    Stream-Check $allowedStream 'allowed' 'Policy activation destroyed an admitted existing flow.'
    Stream-Check $blockedStream 'blocked' 'Policy change failed to reauthorize an already connected disallowed flow.'
    Check ((Probe $unrelated '127.0.0.1' $servers[1].Port) -eq 0) 'The fixture escaped its executable scope and changed unrelated networking.'
    Reject { $active.RemoveChecked() } 'Persistent denial was removed while the runtime lease remained live.'
    $active.AssertCurrent();$lease.AssertCurrent()
    $wrong=Scoped-Policy $policyType ([Guid]::NewGuid().ToString('N')) $remotes $scope
    Reject { $wrong.RemoveChecked() } 'A stale owner removed another generation.'
    $active.AssertCurrent();$lease.AssertCurrent()
    $loopback=@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.NetworkInterfaceType -eq [Net.NetworkInformation.NetworkInterfaceType]::Loopback })
    Check ($loopback.Count -eq 1) 'The fixture cannot capture a unique real loopback interface.'
    $capture=[RouterVPN.WfpInterface]::Capture($loopback[0].Name)
    $capture.AssertCurrent()
    $tunRules=$active.GetType().GetMethod('TunnelRules',[Reflection.BindingFlags]'Instance,NonPublic').Invoke($active,[object[]]@($capture))
    Assert-ScopedRules $tunRules $scope
    $lease.BindTunnel($capture)
    Reject { $lease.BindTunnel($capture) } 'A live lease replaced its tunnel capture.'
    Check ((Probe $child '127.0.0.1' $servers[1].Port) -eq 0) 'The exact captured interface permit was not effective.'
    $lease.CloseChecked();$lease.CloseChecked();$lease=$null
    $active.AssertCurrent()
    Check ((Probe $child '127.0.0.1' $servers[0].Port) -ne 0) 'Closing the owner left a stale physical endpoint exception.'
    Check ((Probe $child '::1' $servers[3].Port) -ne 0) 'Closing the owner left a stale IPv6 interface exception.'
    Check ((Probe $child '::1' $servers[3].Port 'udp') -ne 0) 'Closing the owner left a stale UDP endpoint exception.'
    $lease=$active.OpenLease()
    Delete-OneFixtureException $active $lease
    Reject { $lease.AssertCurrent() } 'Incomplete native readback was accepted as effective protection.'
    Exceptions-Absent $active;$active.AssertCurrent()
    Reject { $lease.AssertCurrent() } 'A retired exception owner resurrected after failed readback.'
    $lease.CloseChecked();$lease=$null
    $leaseProcess=Start-LeaseOwner $owner $remotes $scope
    Check ((Read-Line $leaseProcess) -ceq 'ready') 'The separate runtime did not acquire its actual WFP lease.'
    Check ((Probe $child '127.0.0.1' $servers[0].Port) -eq 0) 'The separate runtime did not establish its captured endpoint exception.'
    $leaseProcess.Kill();Check $leaseProcess.WaitForExit(3000) 'The actual exception owner did not exit.'
    $leaseProcess.Dispose();$leaseProcess=$null
    $deadline=[DateTime]::UtcNow.AddSeconds(5);$drained=$false
    do {
        try { Exceptions-Absent $active;$drained=$true } catch { if([DateTime]::UtcNow -ge $deadline) { throw };Start-Sleep -Milliseconds 20 }
    } while(-not $drained)
    $active.AssertCurrent()
    Check ((Probe $child '127.0.0.1' $servers[0].Port) -ne 0) 'Killing the captured runtime removed denial or retained endpoint permissions.'
    $active.RemoveChecked();$active=$null
    Check ((Probe $child '127.0.0.1' $servers[1].Port) -eq 0) 'Checked release did not restore the pre-existing foreign policy.'
    $foreign=Get-NetFirewallRule -Name $foreignName -ErrorAction Stop
    Check ([string]$foreign.Action -eq 'Allow' -and [string]$foreign.Direction -eq 'Outbound' -and [string]$foreign.Enabled -eq 'True') 'Owned protection changed the unrelated explicit Allow rule.'
    Check ([string](Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $foreign).Program -ieq $child) 'Owned protection replaced the unrelated rule target.'

    # Real native defect: a permit in place of the deny must be caught by the
    # same fixture traffic even while an explicit foreign Allow rule exists.
    $active=Scoped-Policy $permitType ([Guid]::NewGuid().ToString('N')) $remotes $scope
    Install-Scoped $active $scope
    Check ((Probe $child '127.0.0.1' $servers[1].Port) -eq 0) 'The deny-to-permit defect did not exercise its intended network behavior.'
    $detected=$false
    try { Check ((Probe $child '127.0.0.1' $servers[1].Port) -ne 0) 'CONTROL: foreign Allow bypassed the owned deny.' } catch { $detected=$_.Exception.Message -ceq 'CONTROL: foreign Allow bypassed the owned deny.' }
    Check $detected 'The kernel fixture accepted a missing deny.'
    $active.RemoveChecked();$active=$null

    # Real native defect: a static exception falsely substituted for the
    # dynamic lease must survive close and fail the checked-drain assertion.
    $staticPlan=Scoped-Policy $staticType ([Guid]::NewGuid().ToString('N')) $remotes $scope
    Install-Scoped $staticPlan $scope;$staticLease=$staticPlan.OpenLease()
    Check ((Probe $child '127.0.0.1' $servers[0].Port) -eq 0) 'The static-lease defect never established its fixture exception.'
    Reject { $staticLease.CloseChecked() } 'The fixture accepted a static exception as a drained dynamic lease.'
    Check ((Probe $child '127.0.0.1' $servers[0].Port) -eq 0) 'The static-lease defect did not leave the expected stale exception.'
    Exact-MutantCleanup $staticPlan;$staticPlan=$null;$staticLease=$null
} catch {
    $kernelFailure=$_
    [Console]::Error.WriteLine('WFP kernel primary failure: '+$_.Exception.ToString())
    [Console]::Error.WriteLine($_.ScriptStackTrace)
} finally {
    if($null -ne $leaseProcess) { Invoke-FixtureCleanup { if(-not $leaseProcess.HasExited) { $leaseProcess.Kill();Check $leaseProcess.WaitForExit(3000) 'The fixture lease owner did not exit during cleanup.' };$leaseProcess.Dispose() } 'lease process' $cleanupFailures }
    if($null -ne $lease) { Invoke-FixtureCleanup { $lease.CloseChecked() } 'exception lease' $cleanupFailures }
    if($null -ne $active) { Invoke-FixtureCleanup { $active.RemoveChecked() } 'persistent baseline' $cleanupFailures }
    if($null -ne $staticPlan) { Invoke-FixtureCleanup { Exact-MutantCleanup $staticPlan } 'static defect baseline' $cleanupFailures }
    foreach($process in $streams) { Invoke-FixtureCleanup { Stop-Fixture $process } 'fixture stream' $cleanupFailures }
    foreach($server in $servers) { Invoke-FixtureCleanup { $server.Dispose() } 'TCP listener' $cleanupFailures }
    foreach($server in $datagrams) { Invoke-FixtureCleanup { $server.Dispose() } 'UDP listener' $cleanupFailures }
    Invoke-FixtureCleanup { if(Get-NetFirewallRule -Name $foreignName -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $foreignName -ErrorAction Stop } } 'fixture foreign Allow rule' $cleanupFailures
    Invoke-FixtureCleanup { [IO.Directory]::Delete($work,$true) } 'fixture workspace' $cleanupFailures
}
if($null -ne $kernelFailure) { throw $kernelFailure }
if($cleanupFailures.Count -ne 0) { throw ('The WFP fixture could not prove owned cleanup: '+($cleanupFailures -join '; ')) }
Write-Output ("Windows WFP scoped kernel enforcement: PASS ({0} checks; IPv4/IPv6, existing flows, exact interface, stale owner, retained denial and 2 real kernel defect controls)." -f $script:Checks)
