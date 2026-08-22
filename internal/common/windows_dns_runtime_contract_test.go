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
		"router-vpn-dns.pid",
		"run\\dns.txt",
		"Stop-DnsProxy",
		"Remove-PrivateRuntime",
		"DoH3 is unavailable on raw Windows WireGuard",
		"will not silently downgrade DoH3",
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
		"verifyKernelDNSRuntime(root, s.RouterID, runtimeID, selected)",
		"active kernel tunnel config does not force DNS to Router VPN local proxy",
		"probeLocalDNSProxy()",
		"net.DefaultResolver.LookupHost",
	} {
		if !strings.Contains(proof, marker) {
			t.Fatalf("controller selected-DNS proof missing %q", marker)
		}
	}
	if strings.Contains(proof, `kernelDNSMode(runtimeID) && runtime.GOOS != "windows"`) {
		t.Fatal("Windows raw WireGuard must not be routed into the sing-box DNS verifier")
	}
}
