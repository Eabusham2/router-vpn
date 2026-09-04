package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func testWGKey(seed byte) string { return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{seed}), 32))) }

func validTestStandardExit(protocol string) standardExit {
	e := standardExit{ID: "exit-test", Name: "Test", Protocol: protocol, Server: "203.0.113.10", ServerPort: 443, ExpectedPublicIP: "1.1.1.1"}
	switch protocol {
	case "socks5":
		e.Username = "u"; e.Password = "p"
	case "http-connect":
		e.ServerPort = 8080; e.Username = "u"; e.Password = "p"
	case "https-connect":
		e.Username = "u"; e.Password = "p"; e.TLSServerName = "proxy.example.com"
	case "shadowsocks":
		e.Method = "2022-blake3-aes-256-gcm"; e.Secret = "secret"
	case "hysteria2":
		e.Secret = "secret"; e.TLSServerName = "vpn.example.com"
	case "wireguard":
		e.WGAddresses = []string{"10.50.0.2/32"}; e.WGPrivateKey = testWGKey('a'); e.WGPeerPublicKey = testWGKey('b'); e.WGAllowedIPs = []string{"0.0.0.0/0", "::/0"}; e.WGMTU = 1380
	case "openvpn":
		e.OpenVPNConfig = "client\nproto tcp-client\nremote 203.0.113.10 443\nremote-cert-tls server\n<ca>\nTEST-CA\n</ca>\n"; e.Username = "u"; e.Password = "p"
	}
	return e
}

func TestStandardExitCapabilitiesAreTruthful(t *testing.T) {
	caps := standardExitCapabilities(); got := map[string]standardExitCapability{}
	for _, c := range caps { got[c.Protocol] = c }
	for _, p := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		c := got[p]; if !c.Implemented || !c.Supported { t.Fatalf("%s should be implemented/supported: %#v", p, c) }
	}
	ovpn, ok := got["openvpn"]
	if !ok || !ovpn.Implemented { t.Fatalf("OpenVPN adapter must be source-implemented: %#v", caps) }
	if ovpn.Supported && ovpn.Reason != "" { t.Fatalf("ready OpenVPN capability has reason: %#v", ovpn) }
	if !ovpn.Supported && strings.TrimSpace(ovpn.Reason) == "" { t.Fatalf("unready OpenVPN capability needs exact reason: %#v", ovpn) }
}

func TestStandardExitValidationRequiresPublicProof(t *testing.T) {
	e := validTestStandardExit("socks5"); e.ExpectedPublicIP = ""
	if err := validateStandardExit(&e); err == nil || !strings.Contains(err.Error(), "expected_public_ip") { t.Fatalf("unexpected: %v", err) }
}

func TestHTTPConnectStandardExitValidation(t *testing.T) {
	for alias, want := range map[string]string{"http":"http-connect", "http_connect":"http-connect", "https":"https-connect", "https_connect":"https-connect"} {
		if got := normalizeStandardExitProtocol(alias); got != want { t.Fatalf("%s normalized to %q", alias, got) }
	}
	httpExit := validTestStandardExit("http-connect")
	if err := validateStandardExit(&httpExit); err != nil { t.Fatal(err) }
	httpExit.TLSServerName = "proxy.example.com"
	if err := validateStandardExit(&httpExit); err == nil || !strings.Contains(err.Error(), "plain HTTP CONNECT") { t.Fatalf("plain HTTP accepted TLS metadata: %v", err) }

	httpsExit := validTestStandardExit("https-connect")
	if err := validateStandardExit(&httpsExit); err != nil { t.Fatal(err) }
	httpsExit.TLSServerName = ""
	if err := validateStandardExit(&httpsExit); err == nil || !strings.Contains(err.Error(), "TLS server name") { t.Fatalf("HTTPS CONNECT accepted missing SNI: %v", err) }
	httpsExit = validTestStandardExit("https-connect"); httpsExit.Password = ""
	if err := validateStandardExit(&httpsExit); err == nil || !strings.Contains(err.Error(), "username/password") { t.Fatalf("HTTPS CONNECT accepted half credentials: %v", err) }
}

func TestOpenVPNStandardExitSanitizesAndDerivesEndpoint(t *testing.T) {
	e := validTestStandardExit("openvpn"); e.Server = "ignored.example"; e.ServerPort = 1
	if err := validateStandardExit(&e); err != nil { t.Fatal(err) }
	if e.Server != "203.0.113.10" || e.ServerPort != 443 || e.Method != "tcp-client" { t.Fatalf("OpenVPN remote was not normalized: %#v", e) }
	if !strings.Contains(e.OpenVPNConfig, "<ca>") { t.Fatal("safe inline credentials were lost") }
	if !standardExitSummaryFor(e).HasOpenVPNConfig { t.Fatal("redacted summary should report an imported OpenVPN profile") }
}

func TestOpenVPNSanitizerRejectsPrivilegedAndAmbiguousProfileDirectives(t *testing.T) {
	blocked := []string{
		"script-security 3", "up /tmp/pwn", "plugin evil.so", "config /etc/passwd",
		"auth-user-pass /etc/passwd", "ca /etc/passwd", "log /tmp/log", "management 127.0.0.1 5555",
		"socks-proxy 127.0.0.1 1080", "http-proxy 127.0.0.1 8080", "route 8.8.8.8",
		"redirect-gateway def1", "dhcp-option DNS 8.8.8.8", "dns server 0 address 8.8.8.8", "dev tap",
	}
	for _, line := range blocked {
		raw := "client\nremote 203.0.113.10 443 tcp-client\n" + line + "\n"
		if _, err := sanitizeOpenVPNConfig(raw); err == nil { t.Fatalf("expected %q to be rejected", line) }
	}
	if _, err := sanitizeOpenVPNConfig("client\nremote 203.0.113.10 443 tcp-client\nremote 203.0.113.11 443 tcp-client\n"); err == nil { t.Fatal("multiple remotes must fail closed") }
	if _, err := sanitizeOpenVPNConfig("client\nremote vpn.example.com 443 tcp-client\n"); err == nil { t.Fatal("hostname remote must fail until pre-tunnel resolver pinning exists") }
	if _, err := sanitizeOpenVPNConfig("client\nremote 203.0.113.10 443 tcp-client\n<connection>\n</connection>\n"); err == nil { t.Fatal("connection blocks must fail closed") }
}

func TestOpenVPNUsesNativeAdapterNotSingBoxCompiler(t *testing.T) {
	e := validTestStandardExit("openvpn")
	_, _, err := standardExitRuntimeParts(e, "entry-wg")
	if err == nil || !strings.Contains(err.Error(), "native OpenVPN adapter") { t.Fatalf("unexpected: %v", err) }
}

func TestStandardExitCompilerOwnsDetour(t *testing.T) {
	for _, protocol := range []string{"socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		e := validTestStandardExit(protocol); endpoint, out, err := standardExitRuntimeParts(e, "entry-wg")
		if err != nil { t.Fatal(err) }; if endpoint != nil { t.Fatalf("%s unexpectedly endpoint", protocol) }
		if out["tag"] != "custom-exit" || out["detour"] != "entry-wg" { t.Fatalf("unsafe outbound: %#v", out) }
		if protocol == "http-connect" || protocol == "https-connect" {
			if out["type"] != "http" || out["username"] != "u" || out["password"] != "p" { t.Fatalf("%s HTTP CONNECT outbound wrong: %#v", protocol, out) }
			_, hasTLS := out["tls"]
			if protocol == "https-connect" && !hasTLS { t.Fatalf("HTTPS CONNECT lost TLS: %#v", out) }
			if protocol == "http-connect" && hasTLS { t.Fatalf("plain HTTP CONNECT gained TLS: %#v", out) }
		}
	}
	e := validTestStandardExit("wireguard"); endpoint, out, err := standardExitRuntimeParts(e, "entry-wg")
	if err != nil { t.Fatal(err) }
	if out != nil || endpoint["type"] != "wireguard" || endpoint["tag"] != "custom-exit" || endpoint["detour"] != "entry-wg" { t.Fatalf("bad WG endpoint: %#v", endpoint) }
}

func TestOpenVPNSelectedDNSContract(t *testing.T) {
	control := common.RouterProfile{ID: "policy", AdGuardIPv4: "10.77.0.1", FastestDNSHost: "1.1.1.1", IPv6Mode: "auto"}
	control.DNSMode = "fastest"
	lines, err := openVPNDNSLines(control, true); if err != nil { t.Fatal(err) }
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "dns server -1 address 1.1.1.1:53") || !strings.Contains(joined, "transport plain") { t.Fatalf("unexpected DNS lines: %s", joined) }
	control.DNSMode = "home"; if _, err = openVPNDNSLines(control, true); err == nil { t.Fatal("direct OpenVPN must not pretend Home AdGuard is reachable") }
	control.DNSMode = "doh3"; if _, err = openVPNDNSLines(control, true); err == nil { t.Fatal("OpenVPN must fail closed for unsupported DoH3 transport") }
}

func TestStandardExitStoreIsPrivateAndRedactionDoesNotLeak(t *testing.T) {
	root := t.TempDir(); old := os.Getenv("HOMEVPN_ROOT"); t.Cleanup(func() { _ = os.Setenv("HOMEVPN_ROOT", old) }); _ = os.Setenv("HOMEVPN_ROOT", root)
	e := validTestStandardExit("openvpn")
	if err := persistStandardExitStore(standardExitStore{SchemaVersion: 1, Exits: []standardExit{e}}); err != nil { t.Fatal(err) }
	path := filepath.Join(root, "standard-exits.json"); info, err := os.Lstat(path); if err != nil { t.Fatal(err) }
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 { t.Fatalf("mode=%o", info.Mode().Perm()) }
	store, err := loadStandardExitStore(); if err != nil { t.Fatal(err) }
	if len(store.Exits) != 1 || !strings.Contains(store.Exits[0].OpenVPNConfig, "TEST-CA") { t.Fatal("private OpenVPN config did not round-trip") }
	summary := standardExitSummaryFor(store.Exits[0]); raw, _ := json.Marshal(summary)
	if strings.Contains(string(raw), "TEST-CA") || strings.Contains(string(raw), `"password":"p"`) { t.Fatalf("secret leaked to summary: %s", raw) }
}

func TestStandardExitStoreRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" { t.Skip("symlink permissions vary on Windows runners") }
	root := t.TempDir(); old := os.Getenv("HOMEVPN_ROOT"); t.Cleanup(func() { _ = os.Setenv("HOMEVPN_ROOT", old) }); _ = os.Setenv("HOMEVPN_ROOT", root)
	target := filepath.Join(root, "target"); if err := os.WriteFile(target, []byte(`{"schema_version":1,"exits":[]}`), 0o600); err != nil { t.Fatal(err) }
	if err := os.Symlink(target, filepath.Join(root, "standard-exits.json")); err != nil { t.Fatal(err) }
	if _, err := loadStandardExitStore(); err == nil || !strings.Contains(err.Error(), "symlink") { t.Fatalf("unexpected %v", err) }
}

func TestStandardExitStoreRejectsSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows runners")
	}
	root := t.TempDir()
	realRoot := filepath.Join(root, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(root, "linked")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	old := os.Getenv("HOMEVPN_ROOT")
	t.Cleanup(func() { _ = os.Setenv("HOMEVPN_ROOT", old) })
	_ = os.Setenv("HOMEVPN_ROOT", linkRoot)
	store := standardExitStore{SchemaVersion: 1, Exits: []standardExit{validTestStandardExit("wireguard")}}
	if err := persistStandardExitStore(store); err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("symlinked standard-exit parent was accepted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(realRoot, "standard-exits.json")); !os.IsNotExist(err) {
		t.Fatalf("write escaped through symlink parent: %v", err)
	}
}

func TestStandardExitStoreAtomicWriterLeavesNoTempFiles(t *testing.T) {
	root := t.TempDir()
	old := os.Getenv("HOMEVPN_ROOT")
	t.Cleanup(func() { _ = os.Setenv("HOMEVPN_ROOT", old) })
	_ = os.Setenv("HOMEVPN_ROOT", root)
	store := standardExitStore{SchemaVersion: 1, Exits: []standardExit{validTestStandardExit("hysteria2")}}
	if err := persistStandardExitStore(store); err != nil {
		t.Fatal(err)
	}
	if matches, err := filepath.Glob(filepath.Join(root, ".standard-exits.json.tmp-*")); err != nil {
		t.Fatal(err)
	} else if len(matches) != 0 {
		t.Fatalf("temporary standard-exit files survived commit: %v", matches)
	}
}
