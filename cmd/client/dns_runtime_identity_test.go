package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func writeDNSRuntimeTestConfig(t *testing.T, path string, mode, host string, port int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { t.Fatal(err) }
	body := `{"dns":{"servers":[{"type":"udp","tag":"selected-dns","server":"`+host+`","server_port":`+fmtInt(port)+`}],"final":"selected-dns"},"route":{"rules":[{"protocol":"dns","action":"hijack-dns"}],"final":"proxy"}}`+"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil { t.Fatal(err) }
	if err := os.Chmod(path, 0o600); err != nil { t.Fatal(err) }
}

func fmtInt(v int) string {
	const digits = "0123456789"
	if v == 0 { return "0" }
	out := ""
	for v > 0 { out = string(digits[v%10]) + out; v /= 10 }
	return out
}

func TestActiveDNSRuntimeRegistrationRejectsEscapesAndWrongBasename(t *testing.T) {
	root := t.TempDir(); t.Setenv("HOMEVPN_ROOT", root)
	a := &app{}
	defer activeDNSRuntimeIdentities.Delete(a)
	if err := registerActiveDNSRuntimeConfig(a, "node", "external-socks5", filepath.Join(root, "outside", "sing-box.json")); err == nil || !strings.Contains(err.Error(), "escaped") {
		t.Fatalf("outside-run DNS runtime was accepted: %v", err)
	}
	if err := registerActiveDNSRuntimeConfig(a, "node", "external-socks5", filepath.Join(root, "run", "owned", "other.json")); err == nil || !strings.Contains(err.Error(), "sing-box.json") {
		t.Fatalf("wrong runtime basename was accepted: %v", err)
	}
}

func TestRegisteredDNSRuntimeMissingOrUnsafeFailsClosed(t *testing.T) {
	root := t.TempDir(); t.Setenv("HOMEVPN_ROOT", root)
	a := &app{}; defer activeDNSRuntimeIdentities.Delete(a)
	missing := filepath.Join(root, "run", "owned", "sing-box.json")
	if err := registerActiveDNSRuntimeConfig(a, "node", "external-socks5", missing); err != nil { t.Fatal(err) }
	if _, owned, err := activeDNSRuntimeConfigFor(a, "node", "external-socks5"); !owned || err == nil {
		t.Fatalf("missing registered config did not fail closed: owned=%v err=%v", owned, err)
	}

	writeDNSRuntimeTestConfig(t, missing, "custom", "1.1.1.1", 53)
	if err := os.Chmod(missing, 0o644); err != nil { t.Fatal(err) }
	if _, owned, err := activeDNSRuntimeConfigFor(a, "node", "external-socks5"); !owned || err == nil || !strings.Contains(err.Error(), "not private") {
		t.Fatalf("world-readable registered config was accepted: owned=%v err=%v", owned, err)
	}

	if err := os.Remove(missing); err != nil { t.Fatal(err) }
	outside := filepath.Join(root, "outside.json"); if err := os.WriteFile(outside, []byte("{}\n"), 0o600); err != nil { t.Fatal(err) }
	if err := os.Symlink(outside, missing); err != nil { t.Fatal(err) }
	if _, owned, err := activeDNSRuntimeConfigFor(a, "node", "external-socks5"); !owned || err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink registered config was accepted: owned=%v err=%v", owned, err)
	}
}

func TestOwnedDNSRuntimeConfigOverridesCanonicalGuess(t *testing.T) {
	root := t.TempDir(); t.Setenv("HOMEVPN_ROOT", root)
	a := &app{}; defer activeDNSRuntimeIdentities.Delete(a)
	owned := filepath.Join(root, "run", "owned", "sing-box.json")
	writeDNSRuntimeTestConfig(t, owned, "custom", "9.9.9.9", 53)
	if err := registerActiveDNSRuntimeConfig(a, "node", "external-socks5", owned); err != nil { t.Fatal(err) }
	selected := dnsSelection{Mode:"custom", Protocol:"udp", Host:"9.9.9.9", Port:53}
	if err := verifySingBoxDNSRuntimeForApp(a, root, "node", "external-socks5", selected); err != nil {
		t.Fatalf("exact owned DNS runtime was not accepted: %v", err)
	}
	wrong := dnsSelection{Mode:"custom", Protocol:"udp", Host:"1.1.1.1", Port:53}
	if err := verifySingBoxDNSRuntimeForApp(a, root, "node", "external-socks5", wrong); err == nil || !strings.Contains(err.Error(), "owned DNS runtime policy mismatch") {
		t.Fatalf("owned DNS mismatch fell back to another config: %v", err)
	}
}

func TestLiveExternalCommandSupersedesStaleRegisteredIdentity(t *testing.T) {
	root := t.TempDir(); t.Setenv("HOMEVPN_ROOT", root)
	runtimeDir := filepath.Join(root, "run", "native-standard-exit", "session-live")
	config := filepath.Join(runtimeDir, "sing-box.json")
	writeDNSRuntimeTestConfig(t, config, "custom", "9.9.9.9", 53)
	p := common.RouterProfile{ID:"ext", Name:"External", NodeKind:"external", External:&common.ExternalNodeConfig{Protocol:"socks5", ExpectedPublicIP:"8.8.8.8", SOCKS5:&common.ExternalSOCKS5Config{Host:"198.51.100.10", Port:1080}}}
	a := &app{profiles:common.RouterProfileStore{SelectedID:"ext", Profiles:[]common.RouterProfile{p}}, state:state{Connected:true, Phase:"connected", Mode:"external-node", RuntimeMode:"external-socks5", RouterID:"ext"}}
	a.cmd = exec.Command("bash", "helper.sh", "up", runtimeDir, "198.51.100.10", "router-vpn")
	defer activeDNSRuntimeIdentities.Delete(a)
	activeDNSRuntimeIdentities.Store(a, activeDNSRuntimeIdentity{ProfileID:"old", RuntimeID:"external-tor-bridge", Config:filepath.Join(root,"run","old","sing-box.json")})
	got, owned, err := activeDNSRuntimeConfigFor(a, "ext", "external-socks5")
	if err != nil || !owned || got != config { t.Fatalf("live external runtime did not supersede stale registry: got=%q owned=%v err=%v", got, owned, err) }
}

func TestLinuxMultihopUsesExactGraphRuntimeWhenRegistryIsStale(t *testing.T) {
	if runtime.GOOS != "linux" { t.Skip("Linux deterministic multihop runtime path") }
	root := t.TempDir(); t.Setenv("HOMEVPN_ROOT", root)
	config := filepath.Join(root, "run", "multihop", "exit", "sing-box.json")
	writeDNSRuntimeTestConfig(t, config, "custom", "9.9.9.9", 53)
	entry := common.RouterProfile{ID:"entry", Endpoint:"203.0.113.10"}; exit := common.RouterProfile{ID:"exit", Endpoint:"203.0.113.11"}
	a := &app{profiles:common.RouterProfileStore{SelectedID:"entry", Profiles:[]common.RouterProfile{entry,exit}}, state:state{Connected:true, Phase:"connected", Mode:"multihop", LogicalMode:"multihop", RuntimeMode:"shadowsocks", Base:"wg", RouterID:"exit"}}
	setActiveMultihopGraph(a, multihopSelection{Entry:entry, Exit:exit, Base:"wg", ExitMode:"shadowsocks"})
	defer clearActiveMultihopGraph(a); defer activeDNSRuntimeIdentities.Delete(a)
	activeDNSRuntimeIdentities.Store(a, activeDNSRuntimeIdentity{ProfileID:"old", RuntimeID:"external-tor-bridge", Config:filepath.Join(root,"run","old","sing-box.json")})
	got, owned, err := activeDNSRuntimeConfigFor(a, "exit", "shadowsocks")
	if err != nil || !owned || got != config { t.Fatalf("Linux multihop DNS identity wrong: got=%q owned=%v err=%v", got, owned, err) }
}

func TestNativeMultihopRuntimeDirCommandShapes(t *testing.T) {
	win := exec.Command("powershell.exe", "-File", "helper.ps1", "-Action", "up", "-RuntimeDir", "/tmp/win-runtime", "-Endpoint", "203.0.113.1")
	if got, err := nativeMultihopRuntimeDirFromCommand(win); err != nil || got != "/tmp/win-runtime" { t.Fatalf("Windows RuntimeDir parse: %q %v", got, err) }
	unix := exec.Command("bash", "helper.sh", "up", "/tmp/unix-runtime", "203.0.113.1", "router-vpn")
	if got, err := nativeMultihopRuntimeDirFromCommand(unix); err != nil || got != "/tmp/unix-runtime" { t.Fatalf("Unix RuntimeDir parse: %q %v", got, err) }
	bad := exec.Command("bash", "helper.sh", "check")
	if _, err := nativeMultihopRuntimeDirFromCommand(bad); err == nil { t.Fatal("command without owned RuntimeDir was accepted") }
}

var _ = time.Second
