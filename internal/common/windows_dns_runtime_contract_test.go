package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readWindowsDNSContractFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func TestWindowsRawWireGuardEnforcesAndProvesSelectedDNS(t *testing.T) {
	wg := readWindowsDNSContractFile(t, "client/native-wireguard-windows.ps1")
	for _, marker := range []string{
		"router-vpn-dns.exe",
		"Get-DnsSelection",
		"DNS = 127.0.0.1",
		"router-vpn-dns.process.json",
		"dns.owner",
		"Write-RouterVPNProcessRecord",
		"Stop-RouterVPNRecordedProcess",
		"run\\dns.txt",
		"Stop-DnsProxy",
		"Remove-PrivateRuntime",
		"Get-RouterVPNHomeDnsSelection $p",
		"$protocol -notin @('udp','tcp','tls','https','h3','rescue')",
		"$protocol -in @('tls','https','h3')",
		"'-protocol',[string]$Dns.protocol",
		"'-server',[string]$Dns.dns_host,'-port',[string]$Dns.port",
		"'-server-name',[string]$Dns.server_name",
		"'-path',[string]$Dns.path",
		"server_name=$($Dns.server_name)`npath=$($Dns.path)",
		"requires a literal DNS upstream IP",
		"/installtunnelservice",
		"$runtimeConfig",
	} {
		if !strings.Contains(wg, marker) {
			t.Fatalf("Windows raw WireGuard selected-DNS runtime missing %q", marker)
		}
	}
	if strings.Contains(strings.ToLower(wg), "$host=") || strings.Contains(strings.ToLower(wg), "$host =") {
		t.Fatal("Windows raw WireGuard must not assign PowerShell's read-only $Host automatic variable")
	}

	layered := readWindowsDNSContractFile(t, "client/native-windows-mode.ps1")
	for _, marker := range []string{"Get-DnsSelection", "$dnsHost", "selected-dns", "hijack-dns", "server_name"} {
		if !strings.Contains(layered, marker) {
			t.Fatalf("Windows layered selected-DNS runtime missing %q", marker)
		}
	}
	if strings.Contains(strings.ToLower(layered), "$host=") || strings.Contains(strings.ToLower(layered), "$host =") {
		t.Fatal("Windows layered DNS policy must not assign PowerShell's read-only $Host automatic variable")
	}

	proof := readWindowsDNSContractFile(t, "cmd/client/dns_proof.go")
	for _, marker := range []string{
		"if kernelDNSMode(runtimeID)",
		"verifyKernelDNSRuntimeContext(parent, root, s.RouterID, runtimeID, selected)",
		"active kernel tunnel config does not force DNS to Router VPN local proxy",
		"probeLocalDNSProxy()",
		"net.DefaultResolver.LookupHost",
		`hint["server_name"] != selected.ServerName`,
		`(selected.Protocol == "https" || selected.Protocol == "h3") && hint["path"] != selected.Path`,
	} {
		if !strings.Contains(proof, marker) {
			t.Fatalf("controller selected-DNS proof missing %q", marker)
		}
	}
	if strings.Contains(proof, `kernelDNSMode(runtimeID) && runtime.GOOS != "windows"`) {
		t.Fatal("Windows raw WireGuard must not be routed into the sing-box DNS verifier")
	}

	// H3 availability requires the actual owned QUIC transport and the
	// executable raw-helper/kernel-proof gates, not just a selectable label.
	for _, contract := range []struct {
		file    string
		markers []string
	}{
		{"cmd/dnsproxy/resolver.go", []string{`if u.Protocol == "h3"`, "newDNSHTTP3Client(u, roots)", "r.h3.resolve(request, query)"}},
		{"cmd/dnsproxy/http3.go", []string{"&http3.Transport{", "MinVersion: tls.VersionTLS13", "tlsConfig.InsecureSkipVerify", "client.quic.Dial(ctx, remote, tlsConfig, config)"}},
		{"cmd/dnsproxy/server_test.go", []string{"TestDNSProxyCLIKernelProbeThroughActualHTTP3", "common.ProbeDNSUDP", "wrong TLS identity produced a successful kernel DNS proof"}},
		{"deploy/test_windows_home_dns.py", []string{"raw-h3-downgrade", "raw-h3-launch", "raw-h3-tls"}},
		{".github/workflows/desktop-native-runtime.yml", []string{"Native DNS proxy H3 exchanges and kernel proof", "'deploy/build-dnsproxy.py', 'test', '--go'", "subprocess.run(command, check=True)"}},
	} {
		source := readWindowsDNSContractFile(t, contract.file)
		for _, marker := range contract.markers {
			if !strings.Contains(source, marker) {
				t.Fatalf("Windows raw H3 source or executable gate %s missing %q", contract.file, marker)
			}
		}
	}
}
