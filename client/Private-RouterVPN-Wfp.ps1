# Owned Windows Filtering Platform policy. No firewall profile or foreign rule
# is changed. Persistent baseline filters survive the helper process; a dynamic
# lease owns only the current endpoint/LAN/tunnel exceptions. AppID is used only
# by the executable-scoped fixture, never described as a process identity.
# API layouts/constants: Microsoft WinSDK fwpmu.h, fwpmtypes.h and fwptypes.h.
# Lifetimes/transactions: learn.microsoft.com/windows/win32/fwp/object-management
# Arbitration: learn.microsoft.com/windows/win32/fwp/filter-arbitration
function Add-RouterVPNWfpType {
    param([Parameter(Mandatory=$true)][string]$TypeDefinition)
    $compiler=Get-Command Microsoft.PowerShell.Utility\Add-Type -ErrorAction Stop
    if($compiler.Parameters.ContainsKey('CompilerOptions')) {
        Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $TypeDefinition -CompilerOptions '/langversion:5' -ErrorAction Stop
    } elseif($compiler.Parameters.ContainsKey('CompilerParameters')) {
        $parameters=New-Object System.CodeDom.Compiler.CompilerParameters
        $parameters.GenerateInMemory=$true
        $parameters.CompilerOptions='/langversion:5'
        [void]$parameters.ReferencedAssemblies.Add('System.dll')
        [void]$parameters.ReferencedAssemblies.Add('System.Core.dll')
        Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $TypeDefinition -CompilerParameters $parameters -ErrorAction Stop
    } else { throw 'This PowerShell compiler cannot enforce the WFP C# 5 contract.' }
}
$routerVPNWfpSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace RouterVPN {
    public sealed class WfpPolicy {
        public const string SourceIdentity = "__ROUTERVPN_WFP_SOURCE_SHA256__";
        readonly string owner, source, digest;
        readonly Guid sublayer;
        readonly WfpRule[] baseline, exceptions;
        readonly byte[] scope;
        public string Owner { get { return owner; } }
        public string SourceSHA256 { get { return source; } }
        public string PlanSHA256 { get { return digest; } }
        public Guid SublayerKey { get { return sublayer; } }
        public int BaselineFilterCount { get { return baseline.Length; } }
        public int ExceptionFilterCount { get { return exceptions.Length; } }

        WfpPolicy(string ownerValue, string sourceValue, WfpRule[] baseRules, WfpRule[] leaseRules, byte[] appScope) {
            owner = ownerValue; source = sourceValue; baseline = baseRules; exceptions = leaseRules;
            scope = appScope == null ? null : (byte[])appScope.Clone();
            StringBuilder identity = new StringBuilder("RouterVPN-WFP/1\n" + owner + "\n" + source + "\n");
            foreach (WfpRule rule in baseline) identity.Append(rule.Identity()).Append('\n');
            foreach (WfpRule rule in exceptions) identity.Append(rule.Identity()).Append('\n');
            if (scope != null) identity.Append(Convert.ToBase64String(scope));
            digest = Hex(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(identity.ToString())));
            sublayer = Key("sublayer");
        }
        public static WfpPolicy Create(string owner, string sourceSHA256, string[] physicalRemotes, string[] localPrefixes, string[] dhcp4Servers) {
            return Compile(owner, sourceSHA256, physicalRemotes, localPrefixes, dhcp4Servers, true, null);
        }
        // Only the fixture accesses this private compiler with an additional
        // AppID condition on EVERY filter and without the loopback exception.
        // The public product factory always compiles the complete host policy.
        static WfpPolicy Compile(string owner, string sourceSHA256, string[] physicalRemotes, string[] localPrefixes, string[] dhcp4Servers, bool loopback, byte[] appScope) {
            if (owner == null || !Regex.IsMatch(owner, "\\A[0-9a-f]{32}\\z") || sourceSHA256 == null || !Regex.IsMatch(sourceSHA256, "\\A[0-9a-f]{64}\\z")) throw new ArgumentException("WFP requires an exact captured owner and source digest.");
            if (!loopback && (appScope == null || appScope.Length < 4)) throw new ArgumentException("A restricted fixture policy requires an executable scope.");
            if (appScope != null && (appScope.Length < 4 || appScope.Length > 65536 || (appScope.Length & 1) != 0)) throw new ArgumentException("Invalid executable policy scope.");
            if (physicalRemotes == null || physicalRemotes.Length == 0 || physicalRemotes.Length > 16 || localPrefixes == null || localPrefixes.Length > 32 || dhcp4Servers == null || dhcp4Servers.Length > 16) throw new ArgumentException("WFP endpoint or LAN policy is unbounded.");
            List<WfpRule> bases = new List<WfpRule>();
            List<WfpRule> leases = new List<WfpRule>();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (string remote in physicalRemotes) {
                if (remote == null) throw new ArgumentException("Missing physical endpoint.");
                string[] parts = remote.Split('|'); ushort port;
                if (parts.Length != 3 || (parts[0] != "tcp" && parts[0] != "udp") || !UInt16.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port == 0 || port.ToString(CultureInfo.InvariantCulture) != parts[2] || !seen.Add(remote)) throw new ArgumentException("A physical endpoint requires one exact address, transport and port.");
                IPAddress address = Address(parts[1], appScope != null);
                int family = address.AddressFamily == AddressFamily.InterNetwork ? 4 : 6;
                WfpCondition[] conditions = new WfpCondition[] { WfpCondition.Address(WfpNative.RemoteAddress, address), WfpCondition.Number(WfpNative.Protocol, 1, parts[0] == "tcp" ? 6U : 17U), WfpCondition.Number(WfpNative.RemotePort, 2, port) };
                Pair(leases, "outer-" + leases.Count.ToString(CultureInfo.InvariantCulture), family, 50, conditions, appScope);
            }
            seen.Clear();
            foreach (string prefix in localPrefixes) {
                if (prefix == null || !seen.Add(prefix)) throw new ArgumentException("Duplicate or absent LAN prefix.");
                WfpCondition condition = Prefix(prefix);
                Pair(leases, "lan-" + leases.Count.ToString(CultureInfo.InvariantCulture), condition.Type == 256 ? 4 : 6, 40, new WfpCondition[] { condition }, appScope);
            }
            seen.Clear();
            foreach (string server in dhcp4Servers) {
                IPAddress address = Address(server, false);
                if (address.AddressFamily != AddressFamily.InterNetwork || !seen.Add(server)) throw new ArgumentException("DHCP renewal requires distinct captured IPv4 servers.");
                Pair(leases, "dhcp4-renew-" + leases.Count.ToString(CultureInfo.InvariantCulture), 4, 30, new WfpCondition[] { WfpCondition.Number(WfpNative.Protocol, 1, 17), WfpCondition.Number(WfpNative.LocalPort, 2, 68), WfpCondition.Number(WfpNative.RemotePort, 2, 67), WfpCondition.Address(WfpNative.RemoteAddress, address) }, appScope);
            }
            for (int family = 4; family <= 6; family += 2) {
                if (loopback) Pair(bases, "loopback", family, 60, new WfpCondition[] { WfpCondition.Flags(1) }, appScope);
                Pair(bases, "deny", family, 1, new WfpCondition[0], appScope, false);
            }
            // Bound maintenance to its real protocol/ports/destination, never
            // an application-wide or all-link-local exception.
            List<WfpCondition> dhcp4 = new List<WfpCondition>(new WfpCondition[] { WfpCondition.Number(WfpNative.Protocol, 1, 17), WfpCondition.Number(WfpNative.LocalPort, 2, 68), WfpCondition.Number(WfpNative.RemotePort, 2, 67) });
            if (appScope != null) dhcp4.Add(WfpCondition.Bytes(WfpNative.AppId, 12, appScope));
            bases.Add(new WfpRule("dhcp4-in-v4", WfpNative.Accept4, 30, true, dhcp4.ToArray()));
            dhcp4.Add(WfpCondition.Address(WfpNative.RemoteAddress, IPAddress.Broadcast));
            bases.Add(new WfpRule("dhcp4-out-v4", WfpNative.Connect4, 30, true, dhcp4.ToArray()));
            Pair(bases, "dhcp6-multicast", 6, 30, new WfpCondition[] { WfpCondition.Number(WfpNative.Protocol, 1, 17), WfpCondition.Number(WfpNative.LocalPort, 2, 546), WfpCondition.Number(WfpNative.RemotePort, 2, 547), WfpCondition.RawPrefix(WfpNative.RemoteAddress, IPAddress.Parse("ff02::1:2"), 128) }, appScope);
            Pair(bases, "dhcp6-reply", 6, 30, new WfpCondition[] { WfpCondition.Number(WfpNative.Protocol, 1, 17), WfpCondition.Number(WfpNative.LocalPort, 2, 546), WfpCondition.Number(WfpNative.RemotePort, 2, 547), WfpCondition.RawPrefix(WfpNative.RemoteAddress, IPAddress.Parse("fe80::"), 10) }, appScope);
            foreach (uint type in new uint[] { 133, 134, 135, 136 }) {
                foreach (string destination in new string[] { "fe80::/10", "ff02::/16" }) {
                    string[] pieces = destination.Split('/');
                    Pair(bases, "ndp-" + type.ToString(CultureInfo.InvariantCulture) + "-" + pieces[0], 6, 30, new WfpCondition[] { WfpCondition.Number(WfpNative.Protocol, 1, 58), WfpCondition.Number(WfpNative.LocalPort, 2, type), WfpCondition.RawPrefix(WfpNative.RemoteAddress, IPAddress.Parse(pieces[0]), Byte.Parse(pieces[1], CultureInfo.InvariantCulture)) }, appScope);
                }
            }
            return new WfpPolicy(owner, sourceSHA256, bases.ToArray(), leases.ToArray(), appScope);
        }
        static IPAddress Address(string value, bool scopedFixture) {
            IPAddress address;
            if (value == null || !IPAddress.TryParse(value, out address) || address.ToString() != value || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast)) throw new ArgumentException("Physical endpoint must be a canonical unicast literal.");
            byte[] bytes = address.GetAddressBytes();
            if ((!scopedFixture && IPAddress.IsLoopback(address)) || (bytes.Length == 4 && (bytes[0] >= 224 || bytes[0] == 0 || (bytes[0] == 169 && bytes[1] == 254))) || (bytes.Length == 16 && (address.IsIPv4MappedToIPv6 || address.IsIPv6Multicast || address.IsIPv6LinkLocal || address.ScopeId != 0))) throw new ArgumentException("Physical endpoint is not an admissible unicast address.");
            return address;
        }
        static WfpCondition Prefix(string value) {
            string[] parts = value.Split('/'); byte bits; IPAddress address;
            if (parts.Length != 2 || !Byte.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out bits) || bits.ToString(CultureInfo.InvariantCulture) != parts[1] || !IPAddress.TryParse(parts[0], out address) || address.ToString() != parts[0]) throw new ArgumentException("LAN prefix is not canonical.");
            byte[] bytes = address.GetAddressBytes();
            bool allowed = bytes.Length == 4 ? ((bytes[0] == 10 && bits >= 8) || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31 && bits >= 12) || (bytes[0] == 192 && bytes[1] == 168 && bits >= 16)) : ((bytes[0] & 254) == 252 && bits >= 7 && address.ScopeId == 0);
            if (!allowed || bits > bytes.Length * 8) throw new ArgumentException("LAN exception must remain inside a captured private IPv4 or ULA subnet.");
            for (int bit = bits; bit < bytes.Length * 8; bit++) if ((bytes[bit / 8] & (1 << (7 - bit % 8))) != 0) throw new ArgumentException("LAN prefix contains host bits.");
            return WfpCondition.RawPrefix(WfpNative.RemoteAddress, address, bits);
        }
        static void Pair(List<WfpRule> rules, string name, int family, ulong weight, WfpCondition[] conditions, byte[] appScope) { Pair(rules, name, family, weight, conditions, appScope, true); }
        static void Pair(List<WfpRule> rules, string name, int family, ulong weight, WfpCondition[] conditions, byte[] appScope, bool permit) {
            List<WfpCondition> bounded = new List<WfpCondition>(conditions);
            if (appScope != null) bounded.Add(WfpCondition.Bytes(WfpNative.AppId, 12, appScope));
            rules.Add(new WfpRule(name + "-out-v" + family, family == 4 ? WfpNative.Connect4 : WfpNative.Connect6, weight, permit, bounded.ToArray()));
            rules.Add(new WfpRule(name + "-in-v" + family, family == 4 ? WfpNative.Accept4 : WfpNative.Accept6, weight, permit, bounded.ToArray()));
        }
        internal Guid Key(string label) {
            byte[] bytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("RouterVPN-WFP/1\n" + owner + "\n" + source + "\n" + digest + "\n" + label));
            byte[] result = new byte[16]; Array.Copy(bytes, result, 16); return new Guid(result);
        }
        internal byte[] Metadata(string label) { return Encoding.UTF8.GetBytes("RouterVPN-WFP/1|" + owner + "|" + source + "|" + digest + "|" + label); }
        internal static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
        internal WfpRule[] LeaseRules() { return (WfpRule[])exceptions.Clone(); }
        internal WfpRule[] TunnelRules(WfpInterface capture) {
            List<WfpRule> rules = new List<WfpRule>();
            for (int family = 4; family <= 6; family += 2) Pair(rules, "tun-" + capture.Luid.ToString(CultureInfo.InvariantCulture), family, 55, new WfpCondition[] { WfpCondition.Number64(WfpNative.Interface, capture.Luid) }, scope);
            return rules.ToArray();
        }
        public void Install() {
            using (WfpEngine engine = new WfpEngine(false)) {
                engine.Begin();
                try {
                    if (engine.SublayerExists(sublayer)) Assert(engine);
                    else {
                        engine.AddSublayer(this);
                        foreach (WfpRule rule in baseline) engine.Add(this, rule, true);
                        Assert(engine);
                    }
                    engine.Commit();
                } catch { engine.Abort(); throw; }
            }
            AssertCurrent();
        }
        public void AssertCurrent() { using (WfpEngine engine = new WfpEngine(false)) Assert(engine); }
        internal void Assert(WfpEngine engine) {
            engine.AssertSublayer(this);
            foreach (WfpRule rule in baseline) engine.AssertFilter(this, rule, true);
        }
        public void RemoveChecked() {
            using (WfpEngine engine = new WfpEngine(false)) {
                engine.Begin();
                try {
                    Assert(engine);
                    foreach (WfpRule rule in baseline) engine.Delete(Key(rule.Name));
                    // Any live lease or unexpected object makes this deletion
                    // fail. Aborting restores every baseline filter atomically.
                    engine.DeleteSublayer(sublayer);
                    engine.Commit();
                } catch { engine.Abort(); throw; }
                if (engine.SublayerExists(sublayer)) throw new InvalidOperationException("WFP baseline removal has no checked receipt.");
                foreach (WfpRule rule in baseline) engine.AssertAbsent(Key(rule.Name));
            }
        }
        public WfpLease OpenLease() { return WfpLease.Open(this); }
        public static void AssertNativeLayouts() { WfpNative.AssertLayouts(); }
    }

    public sealed class WfpInterface {
        readonly string alias;
        readonly ulong luid;
        readonly Guid identity;
        readonly uint index;
        public string Alias { get { return alias; } }
        public ulong Luid { get { return luid; } }
        public Guid Identity { get { return identity; } }
        public uint Index { get { return index; } }
        WfpInterface(string name, ulong value, Guid guid, uint number) { alias = name; luid = value; identity = guid; index = number; }
        public static WfpInterface Capture(string alias) {
            if (String.IsNullOrWhiteSpace(alias) || alias.Length > 256 || alias.IndexOf('\0') >= 0) throw new ArgumentException("Invalid captured tunnel interface alias.");
            ulong value; Guid guid; uint number;
            WfpNative.Check(WfpNative.ConvertInterfaceAliasToLuid(alias, out value), "capture tunnel LUID");
            if (value == 0) throw new InvalidOperationException("The tunnel has no interface LUID.");
            WfpNative.Check(WfpNative.ConvertInterfaceLuidToGuid(ref value, out guid), "capture tunnel GUID");
            WfpNative.Check(WfpNative.ConvertInterfaceLuidToIndex(ref value, out number), "capture tunnel index");
            if (guid == Guid.Empty || number == 0) throw new InvalidOperationException("The tunnel has no complete interface identity.");
            return new WfpInterface(alias, value, guid, number);
        }
        public void AssertCurrent() {
            WfpInterface current = Capture(alias);
            if (current.luid != luid || current.identity != identity || current.index != index) throw new InvalidOperationException("The captured tunnel interface was replaced.");
        }
    }

    public sealed class WfpLease : IDisposable {
        readonly object access = new object();
        readonly WfpPolicy policy;
        readonly List<WfpRule> rules = new List<WfpRule>();
        WfpEngine engine;
        WfpInterface tunnel;
        bool closed, retired;
        WfpLease(WfpPolicy captured, WfpEngine owned) { policy = captured; engine = owned; }
        internal static WfpLease Open(WfpPolicy policy) {
            if (policy == null) throw new ArgumentNullException("policy");
            WfpEngine owned = new WfpEngine(true);
            try {
                owned.Begin();
                policy.Assert(owned);
                WfpLease lease = new WfpLease(policy, owned);
                foreach (WfpRule rule in policy.LeaseRules()) { owned.Add(policy, rule, false); lease.rules.Add(rule); }
                foreach (WfpRule rule in lease.rules) owned.AssertFilter(policy, rule, false);
                owned.Commit();
                lease.AssertCurrent();
                return lease;
            } catch { owned.Abort(); owned.Dispose(); throw; }
        }
        public bool IsClosed { get { lock (access) { return closed; } } }
        public void BindTunnel(WfpInterface capture) {
            if (capture == null) throw new ArgumentNullException("capture");
            lock (access) {
                if (closed || retired || engine == null || tunnel != null) throw new InvalidOperationException("A WFP lease can capture a tunnel only once.");
                capture.AssertCurrent(); policy.Assert(engine);
                WfpRule[] additions = policy.TunnelRules(capture);
                engine.Begin();
                try {
                    foreach (WfpRule rule in additions) engine.Add(policy, rule, false);
                    capture.AssertCurrent();
                    foreach (WfpRule rule in additions) engine.AssertFilter(policy, rule, false);
                    engine.Commit();
                    rules.AddRange(additions); tunnel = capture;
                } catch { engine.Abort(); throw; }
                AssertCurrent();
            }
        }
        public void AssertCurrent() {
            lock (access) {
                if (closed || retired || engine == null) throw new InvalidOperationException("The WFP exception lease is closed.");
                try {
                    policy.Assert(engine);
                    if (tunnel != null) tunnel.AssertCurrent();
                    foreach (WfpRule rule in rules) engine.AssertFilter(policy, rule, false);
                } catch {
                    retired = true;
                    engine.CloseChecked(); engine = null;
                    throw;
                }
            }
        }
        public void CloseChecked() {
            lock (access) {
                if (closed) return;
                if (engine != null) { engine.CloseChecked(); engine = null; }
                using (WfpEngine check = new WfpEngine(false)) {
                    policy.Assert(check);
                    foreach (WfpRule rule in rules) check.AssertAbsent(policy.Key(rule.Name));
                }
                closed = true;
            }
        }
        public void Dispose() { CloseChecked(); GC.SuppressFinalize(this); }
        ~WfpLease() { if (engine != null) engine.CloseBestEffort(); }
    }

    sealed class WfpRule {
        internal readonly string Name;
        internal readonly Guid Layer;
        internal readonly ulong Weight;
        internal readonly bool Permit;
        internal readonly WfpCondition[] Conditions;
        internal WfpRule(string name, Guid layer, ulong weight, bool permit, WfpCondition[] conditions) { Name = name; Layer = layer; Weight = weight; Permit = permit; Conditions = conditions; }
        internal string Identity() {
            StringBuilder value = new StringBuilder(Name + "|" + Layer.ToString("D") + "|" + Weight.ToString(CultureInfo.InvariantCulture) + "|" + Permit.ToString());
            foreach (WfpCondition c in Conditions) value.Append('|').Append(c.Identity());
            return value.ToString();
        }
    }
    sealed class WfpCondition {
        internal readonly Guid Field;
        internal readonly uint Type, Match;
        internal readonly ulong Numeric;
        internal readonly byte[] Data;
        WfpCondition(Guid field, uint type, uint match, ulong number, byte[] data) { Field = field; Type = type; Match = match; Numeric = number; Data = data == null ? null : (byte[])data.Clone(); }
        internal static WfpCondition Number(Guid field, uint type, uint number) { return new WfpCondition(field, type, 0, number, null); }
        internal static WfpCondition Number64(Guid field, ulong number) { return new WfpCondition(field, 4, 0, number, null); }
        internal static WfpCondition Flags(uint value) { return new WfpCondition(WfpNative.Flags, 3, 6, value, null); }
        internal static WfpCondition Bytes(Guid field, uint type, byte[] data) { return new WfpCondition(field, type, 0, 0, data); }
        internal static WfpCondition Address(Guid field, IPAddress address) {
            byte[] bytes = address.GetAddressBytes();
            if (bytes.Length == 16) return Bytes(field, 11, bytes);
            return Number(field, 3, ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3]);
        }
        internal static WfpCondition RawPrefix(Guid field, IPAddress address, byte bits) {
            byte[] bytes = address.GetAddressBytes();
            if (bytes.Length == 16) { byte[] data = new byte[17]; Array.Copy(bytes, data, 16); data[16] = bits; return Bytes(field, 257, data); }
            uint number = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            byte[] packed = new byte[8]; Array.Copy(BitConverter.GetBytes(number), packed, 4); Array.Copy(BitConverter.GetBytes(bits == 0 ? 0U : UInt32.MaxValue << (32 - bits)), 0, packed, 4, 4); return Bytes(field, 256, packed);
        }
        internal string Identity() { return Field.ToString("D") + ":" + Type + ":" + Match + ":" + Numeric.ToString(CultureInfo.InvariantCulture) + ":" + (Data == null ? "" : Convert.ToBase64String(Data)); }
        internal WfpNative.Condition Native(WfpMemory memory) {
            WfpNative.Value value = new WfpNative.Value(); value.Type = Type;
            if (Type == 1) value.Data.Byte = (byte)Numeric;
            else if (Type == 2) value.Data.Word = (ushort)Numeric;
            else if (Type == 3) value.Data.DWord = (uint)Numeric;
            else if (Type == 4) value.Data.Pointer = memory.Bytes(BitConverter.GetBytes(Numeric));
            else if (Type == 12) value.Data.Pointer = memory.Struct(memory.Blob(Data));
            else value.Data.Pointer = memory.Bytes(Data);
            return new WfpNative.Condition { Field = Field, Match = Match, Value = value };
        }
        internal void Assert(WfpNative.Condition actual) {
            if (actual.Field != Field || actual.Match != Match || actual.Value.Type != Type) throw new InvalidOperationException("WFP condition identity changed.");
            bool same;
            if (Type == 1) same = actual.Value.Data.Byte == Numeric;
            else if (Type == 2) same = actual.Value.Data.Word == Numeric;
            else if (Type == 3) same = actual.Value.Data.DWord == Numeric;
            else if (Type == 4) same = actual.Value.Data.Pointer != IntPtr.Zero && unchecked((ulong)Marshal.ReadInt64(actual.Value.Data.Pointer)) == Numeric;
            else if (Type == 12) same = actual.Value.Data.Pointer != IntPtr.Zero && WfpMemory.EqualBlob((WfpNative.Blob)Marshal.PtrToStructure(actual.Value.Data.Pointer, typeof(WfpNative.Blob)), Data);
            else same = WfpMemory.EqualBytes(actual.Value.Data.Pointer, Data);
            if (!same) throw new InvalidOperationException("WFP condition value changed.");
        }
    }
    sealed class WfpMemory : IDisposable {
        readonly List<IntPtr> allocations = new List<IntPtr>();
        internal IntPtr Bytes(byte[] value) {
            if (value == null || value.Length == 0) throw new ArgumentException("Empty native allocation.");
            IntPtr pointer = Marshal.AllocHGlobal(value.Length); allocations.Add(pointer); Marshal.Copy(value, 0, pointer, value.Length); return pointer;
        }
        internal IntPtr Text(string value) { IntPtr p = Marshal.StringToHGlobalUni(value); allocations.Add(p); return p; }
        internal IntPtr Struct<T>(T value) { IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T))); allocations.Add(p); Marshal.StructureToPtr(value, p, false); return p; }
        internal WfpNative.Blob Blob(byte[] bytes) { return new WfpNative.Blob { Size = (uint)bytes.Length, Data = Bytes(bytes) }; }
        internal IntPtr Conditions(WfpCondition[] values) {
            if (values.Length == 0) return IntPtr.Zero;
            int stride = Marshal.SizeOf(typeof(WfpNative.Condition));
            IntPtr array = Marshal.AllocHGlobal(stride * values.Length); allocations.Add(array);
            for (int i = 0; i < values.Length; i++) Marshal.StructureToPtr(values[i].Native(this), IntPtr.Add(array, i * stride), false);
            return array;
        }
        internal static bool EqualBytes(IntPtr pointer, byte[] expected) {
            if (pointer == IntPtr.Zero || expected == null) return false;
            byte[] bytes = new byte[expected.Length]; Marshal.Copy(pointer, bytes, 0, bytes.Length);
            int different = 0; for (int i = 0; i < bytes.Length; i++) different |= bytes[i] ^ expected[i]; return different == 0;
        }
        internal static bool EqualBlob(WfpNative.Blob blob, byte[] expected) { return expected != null && blob.Size == expected.Length && EqualBytes(blob.Data, expected); }
        public void Dispose() { for (int i = allocations.Count - 1; i >= 0; i--) Marshal.FreeHGlobal(allocations[i]); allocations.Clear(); }
    }
    sealed class WfpEngine : IDisposable {
        IntPtr handle;
        bool transaction;
        internal WfpEngine(bool dynamic) {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) throw new PlatformNotSupportedException("WFP requires Windows.");
            WfpNative.AssertLayouts();
            WfpNative.Session session = new WfpNative.Session(); session.Flags = dynamic ? 1U : 0U; session.Timeout = 5000;
            WfpNative.Check(WfpNative.FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out handle), "open WFP engine");
        }
        internal void Begin() { WfpNative.Check(WfpNative.FwpmTransactionBegin0(handle, 0), "begin WFP transaction"); transaction = true; }
        internal void Commit() { WfpNative.Check(WfpNative.FwpmTransactionCommit0(handle), "commit WFP transaction"); transaction = false; }
        internal void Abort() { if (transaction && handle != IntPtr.Zero) { WfpNative.FwpmTransactionAbort0(handle); transaction = false; } }
        internal bool SublayerExists(Guid key) {
            IntPtr value; uint error = WfpNative.FwpmSubLayerGetByKey0(handle, ref key, out value);
            if (error == WfpNative.SublayerNotFound) return false;
            WfpNative.Check(error, "read WFP sublayer"); WfpNative.FwpmFreeMemory0(ref value); return true;
        }
        internal void AddSublayer(WfpPolicy policy) {
            using (WfpMemory memory = new WfpMemory()) {
                WfpNative.Sublayer value = new WfpNative.Sublayer(); value.Key = policy.SublayerKey; value.Flags = 1; value.Weight = UInt16.MaxValue;
                value.Display.Name = memory.Text("Router VPN owned protection"); value.Display.Description = memory.Text("Captured persistent fail-closed baseline"); value.Data = memory.Blob(policy.Metadata("sublayer"));
                WfpNative.Check(WfpNative.FwpmSubLayerAdd0(handle, ref value, IntPtr.Zero), "add WFP sublayer");
            }
        }
        internal void AssertSublayer(WfpPolicy policy) {
            Guid key = policy.SublayerKey; IntPtr pointer;
            WfpNative.Check(WfpNative.FwpmSubLayerGetByKey0(handle, ref key, out pointer), "read owned WFP sublayer");
            try {
                WfpNative.Sublayer value = (WfpNative.Sublayer)Marshal.PtrToStructure(pointer, typeof(WfpNative.Sublayer));
                if (value.Key != key || value.Flags != 1 || value.Weight != UInt16.MaxValue || value.Provider != IntPtr.Zero || !WfpMemory.EqualBlob(value.Data, policy.Metadata("sublayer"))) throw new InvalidOperationException("WFP sublayer does not belong to this captured generation.");
            } finally { WfpNative.FwpmFreeMemory0(ref pointer); }
        }
        internal void Add(WfpPolicy policy, WfpRule rule, bool persistent) {
            using (WfpMemory memory = new WfpMemory()) {
                WfpNative.Filter value = new WfpNative.Filter(); value.Key = policy.Key(rule.Name); value.Layer = rule.Layer; value.Sublayer = policy.SublayerKey;
                value.Display.Name = memory.Text("Router VPN " + rule.Name); value.Display.Description = memory.Text("Captured " + policy.Owner);
                value.Flags = persistent ? 1U : 0U; value.Data = memory.Blob(policy.Metadata(rule.Name));
                value.Weight.Type = 4; value.Weight.Data.Pointer = memory.Bytes(BitConverter.GetBytes(rule.Weight));
                value.ConditionCount = (uint)rule.Conditions.Length; value.Conditions = memory.Conditions(rule.Conditions);
                value.Action.Type = rule.Permit ? 0x1002U : 0x1001U;
                ulong id; WfpNative.Check(WfpNative.FwpmFilterAdd0(handle, ref value, IntPtr.Zero, out id), "add owned WFP filter " + rule.Name);
                if (id == 0) throw new InvalidOperationException("The WFP filter has no native identifier.");
            }
        }
        internal void AssertFilter(WfpPolicy policy, WfpRule rule, bool persistent) {
            Guid key = policy.Key(rule.Name); IntPtr pointer;
            WfpNative.Check(WfpNative.FwpmFilterGetByKey0(handle, ref key, out pointer), "read owned WFP filter " + rule.Name);
            try {
                WfpNative.Filter value = (WfpNative.Filter)Marshal.PtrToStructure(pointer, typeof(WfpNative.Filter));
                if (value.Key != key || value.Layer != rule.Layer || value.Sublayer != policy.SublayerKey || value.Flags != (persistent ? 1U : 0U) || value.Provider != IntPtr.Zero || value.Action.Type != (rule.Permit ? 0x1002U : 0x1001U) || value.Action.Key != Guid.Empty || value.FilterId == 0 || value.ConditionCount != rule.Conditions.Length || !WfpMemory.EqualBlob(value.Data, policy.Metadata(rule.Name)) || value.Weight.Type != 4 || value.Weight.Data.Pointer == IntPtr.Zero || unchecked((ulong)Marshal.ReadInt64(value.Weight.Data.Pointer)) != rule.Weight) throw new InvalidOperationException("WFP filter identity, action or lifetime changed: " + rule.Name);
                if (value.ConditionCount != 0 && value.Conditions == IntPtr.Zero) throw new InvalidOperationException("WFP filter lost its captured conditions.");
                int stride = Marshal.SizeOf(typeof(WfpNative.Condition));
                for (int i = 0; i < rule.Conditions.Length; i++) rule.Conditions[i].Assert((WfpNative.Condition)Marshal.PtrToStructure(IntPtr.Add(value.Conditions, i * stride), typeof(WfpNative.Condition)));
            } finally { WfpNative.FwpmFreeMemory0(ref pointer); }
        }
        internal void AssertAbsent(Guid key) {
            IntPtr pointer; uint result = WfpNative.FwpmFilterGetByKey0(handle, ref key, out pointer);
            if (result == WfpNative.FilterNotFound) return;
            if (result == 0) WfpNative.FwpmFreeMemory0(ref pointer); else WfpNative.Check(result, "verify WFP filter retirement");
            throw new InvalidOperationException("The owned WFP filter was not retired.");
        }
        internal void Delete(Guid key) { WfpNative.Check(WfpNative.FwpmFilterDeleteByKey0(handle, ref key), "delete exact owned WFP filter"); }
        internal void DeleteSublayer(Guid key) { WfpNative.Check(WfpNative.FwpmSubLayerDeleteByKey0(handle, ref key), "delete exact owned WFP sublayer"); }
        internal void CloseChecked() {
            if (handle == IntPtr.Zero) return;
            Abort(); WfpNative.Check(WfpNative.FwpmEngineClose0(handle), "close owned WFP session"); handle = IntPtr.Zero;
        }
        internal void CloseBestEffort() { if (handle != IntPtr.Zero) { try { WfpNative.FwpmEngineClose0(handle); } catch { } handle = IntPtr.Zero; } }
        public void Dispose() { CloseChecked(); GC.SuppressFinalize(this); }
        ~WfpEngine() { CloseBestEffort(); }
    }
    static class WfpNative {
        internal const uint FilterNotFound = 0x80320003, SublayerNotFound = 0x80320007;
        internal static readonly Guid Connect4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), Connect6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"), Accept4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), Accept6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
        internal static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045"), RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b"), LocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b"), Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), Flags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c"), Interface = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4"), AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        [StructLayout(LayoutKind.Sequential)] internal struct Display { internal IntPtr Name, Description; }
        [StructLayout(LayoutKind.Sequential)] internal struct Blob { internal uint Size; internal IntPtr Data; }
        [StructLayout(LayoutKind.Explicit)] internal struct Union { [FieldOffset(0)] internal byte Byte; [FieldOffset(0)] internal ushort Word; [FieldOffset(0)] internal uint DWord; [FieldOffset(0)] internal IntPtr Pointer; }
        [StructLayout(LayoutKind.Sequential)] internal struct Value { internal uint Type; internal Union Data; }
        [StructLayout(LayoutKind.Sequential)] internal struct Condition { internal Guid Field; internal uint Match; internal Value Value; }
        [StructLayout(LayoutKind.Sequential)] internal struct Action { internal uint Type; internal Guid Key; }
        [StructLayout(LayoutKind.Explicit, Size=16)] internal struct Context { [FieldOffset(0)] internal ulong Raw; [FieldOffset(0)] internal Guid Provider; }
        [StructLayout(LayoutKind.Sequential)] internal struct Filter { internal Guid Key; internal Display Display; internal uint Flags; internal IntPtr Provider; internal Blob Data; internal Guid Layer, Sublayer; internal Value Weight; internal uint ConditionCount; internal IntPtr Conditions; internal Action Action; internal Context Context; internal IntPtr Reserved; internal ulong FilterId; internal Value EffectiveWeight; }
        [StructLayout(LayoutKind.Sequential)] internal struct Sublayer { internal Guid Key; internal Display Display; internal uint Flags; internal IntPtr Provider; internal Blob Data; internal ushort Weight; }
        [StructLayout(LayoutKind.Sequential)] internal struct Session { internal Guid Key; internal Display Display; internal uint Flags, Timeout, ProcessId; internal IntPtr Sid, Username; internal int KernelMode; }
        internal static void AssertLayouts() {
            if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(Value)) != 16 || Marshal.SizeOf(typeof(Condition)) != 40 || Marshal.SizeOf(typeof(Filter)) != 200 || Marshal.SizeOf(typeof(Sublayer)) != 72 || Marshal.SizeOf(typeof(Session)) != 72 || Marshal.OffsetOf(typeof(Filter), "Conditions").ToInt32() != 120 || Marshal.OffsetOf(typeof(Filter), "Context").ToInt32() != 152 || Marshal.OffsetOf(typeof(Filter), "EffectiveWeight").ToInt32() != 184) throw new PlatformNotSupportedException("Unsupported Windows WFP ABI; no filters were changed.");
        }
        internal static void Check(uint error, string operation) { if (error != 0) throw new Win32Exception(unchecked((int)error), operation + " failed (0x" + error.ToString("x8", CultureInfo.InvariantCulture) + ")."); }
        [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode, ExactSpelling=true)] internal static extern uint FwpmEngineOpen0(string serverName, uint authentication, IntPtr identity, ref Session session, out IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer sublayer, IntPtr security);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr sublayer);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr security, out ulong id);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr filter);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] internal static extern void FwpmFreeMemory0(ref IntPtr value);
        [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode, ExactSpelling=true)] internal static extern uint FwpmGetAppIdFromFileName0(string path, out IntPtr appId);
        [DllImport("iphlpapi.dll", CharSet=CharSet.Unicode, ExactSpelling=true)] internal static extern uint ConvertInterfaceAliasToLuid(string name, out ulong luid);
        [DllImport("iphlpapi.dll")] internal static extern uint ConvertInterfaceLuidToGuid(ref ulong luid, out Guid guid);
        [DllImport("iphlpapi.dll")] internal static extern uint ConvertInterfaceLuidToIndex(ref ulong luid, out uint index);
    }
}
'@
$routerVPNWfpDigest=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($routerVPNWfpSource)))).Replace('-','').ToLowerInvariant()
$routerVPNWfpType='RouterVPN.WfpPolicy' -as [type]
if($null -eq $routerVPNWfpType) {
    Add-RouterVPNWfpType -TypeDefinition $routerVPNWfpSource.Replace('__ROUTERVPN_WFP_SOURCE_SHA256__',$routerVPNWfpDigest)
} elseif($routerVPNWfpType::SourceIdentity -cne $routerVPNWfpDigest) {
    throw 'The loaded WFP helper does not match the captured source.'
}
