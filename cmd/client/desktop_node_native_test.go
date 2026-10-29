package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func desktopNodeFixture(t *testing.T, endpoint string) (common.RouterProfile, map[string][]byte) {
	t.Helper()
	raw := []byte("[Interface]\nPrivateKey = " + testWGKey('p') + "\nAddress = 10.77.0.2/32\nDNS = 192.168.50.133\n\n[Peer]\nPublicKey = " + testWGKey('q') + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = " + endpoint + ":51820\nPersistentKeepalive = 25\n")
	node, err := nodeProofIDFromWGConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	return common.RouterProfile{ID: "captured", NodeKind: "router-vpn", Name: "Original", NodeProofID: node, Endpoint: endpoint, RouterAPI: "http://10.77.0.1:8787", APIToken: "private-token", AdGuardIPv4: "192.168.50.133", HomeLANAccess: true, IPv6Mode: "on", MTUPolicy: "auto"}, map[string][]byte{"wg.conf": raw}
}

func TestDesktopNativeHostnameCaptureAndCancellation(t *testing.T) {
	p, files := desktopNodeFixture(t, "node.example.test")
	files["wg-socks.conf"] = []byte(strings.ReplaceAll(string(files["wg.conf"]), "0.0.0.0/0, ::/0", "10.77.0.0/24"))
	original := string(files["wg.conf"])
	originalSplit := string(files["wg-socks.conf"])
	calls := 0
	lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls++
		if host != p.Endpoint {
			t.Fatal("unowned hostname", host)
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
	}
	compiled, endpoint, err := compileDesktopNode(context.Background(), p, "wg", files, nil, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "198.51.100.8" || calls != 1 || !strings.Contains(compiled.Config(), endpoint) || !strings.Contains(compiled.Config(), p.AdGuardIPv4) || original != string(files["wg.conf"]) || originalSplit != string(files["wg-socks.conf"]) {
		t.Fatal("captured node resolution changed source or DNS")
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, _, err := compileDesktopNode(ctx, p, "wg", files, nil, func(context.Context, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
	}); err == nil {
		t.Fatal("late cancelled lookup adopted")
	}
	for _, answer := range []string{"127.0.0.1", "::", "ff02::1"} {
		if _, _, err := compileDesktopNode(context.Background(), p, "wg", files, nil, func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(answer)}, nil
		}); err == nil {
			t.Fatal("unsafe answer adopted", answer)
		}
	}
	files["wg.conf"] = []byte("[Interface]\nPrivateKey = invalid\n")
	before := calls
	if _, _, err := compileDesktopNode(context.Background(), p, "wg", files, nil, lookup); err == nil || calls != before {
		t.Fatal("invalid source reached resolver")
	}
}

func TestDesktopNativeBaseRejectsStaleEndpointBeforeBootstrap(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, test := range []struct{ saved, captured string }{
			{"198.51.100.99", "198.51.100.8"},
			{"node.example.test", "198.51.100.8"},
			{"node.example.test", "old.example.test"},
		} {
			t.Run(mode+"/"+test.saved+"/"+test.captured, func(t *testing.T) {
				p, files := viaEntryBaseFixture(t, mode)
				p.Endpoint = test.saved
				for name, body := range files {
					files[name] = []byte(strings.ReplaceAll(string(body), "198.51.100.8:51820", net.JoinHostPort(test.captured, "52999")))
				}
				before := encodeDesktopNodeAssets(files)
				calls := 0
				compiled, endpoint, err := compileDesktopNode(context.Background(), p, mode, files, nil, func(context.Context, string) ([]netip.Addr, error) {
					calls++
					return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
				})
				if err == nil || compiled != nil || endpoint != "" || calls != 0 || before != encodeDesktopNodeAssets(files) {
					t.Fatal("old authentic endpoint reached bootstrap or compilation", calls, err)
				}
			})
		}
	}
}

func TestDesktopNativeBaseHostNormalizationRetainsCapturedPort(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, test := range []struct{ saved, captured, resolved string }{
			{"node.example.test", "NODE.Example.Test.", "198.51.100.8"},
			{"2001:db8::8", "2001:0db8:0000:0:0:0:0:8", "2001:db8::8"},
		} {
			t.Run(mode+"/"+test.saved, func(t *testing.T) {
				p, files := viaEntryBaseFixture(t, mode)
				p.Endpoint = test.saved
				for name, body := range files {
					files[name] = []byte(strings.ReplaceAll(string(body), "198.51.100.8:51820", net.JoinHostPort(test.captured, "52999")))
				}
				before := encodeDesktopNodeAssets(files)
				calls := 0
				compiled, endpoint, err := compileDesktopNode(context.Background(), p, mode, files, nil, func(_ context.Context, host string) ([]netip.Addr, error) {
					calls++
					if host != test.saved {
						t.Fatal("bootstrap changed the saved host")
					}
					return []netip.Addr{netip.MustParseAddr(test.resolved)}, nil
				})
				if err != nil || endpoint != test.resolved {
					t.Fatal("equivalent captured endpoint was rejected", err)
				}
				tuples, tupleErr := compiled.PhysicalEgress()
				if tupleErr != nil || len(tuples) != 1 || tuples[0].Host != test.resolved || tuples[0].Port != 52999 || tuples[0].Network != "udp" {
					t.Fatal("physical projection lost the actual resolved WG/AWG endpoint and saved port", tuples, tupleErr)
				}
				var graph map[string]any
				if err := json.Unmarshal([]byte(compiled.Config()), &graph); err != nil {
					t.Fatal(err)
				}
				peer := graph["endpoints"].([]any)[0].(map[string]any)["peers"].([]any)[0].(map[string]any)
				if peer["port"] != float64(52999) || before != encodeDesktopNodeAssets(files) {
					t.Fatal("bootstrap overwrote the captured port or saved bytes")
				}
				if want := map[bool]int{true: 1, false: 0}[test.saved == "node.example.test"]; calls != want {
					t.Fatal("unexpected resolver calls", calls)
				}
			})
		}
	}
}

func TestDesktopNativeEndpointFreezePreservesDNSAndTLS(t *testing.T) {
	body := []byte(`{"dns":{"servers":[{"server":"node.example.test"}]},"outbounds":[{"type":"hysteria2","server":"node.example.test","tls":{"enabled":true,"server_name":"certificate.example.test"}},{"protocol":"vless","settings":{"vnext":[{"address":"node.example.test","port":443,"users":[{"id":"captured"}]}]},"streamSettings":{"tlsSettings":{"serverName":"original.example.test"}}}]}`)
	frozen, err := freezeDesktopNodeAssets(map[string][]byte{"sing-box.json": body, "rosenpass-client-secret": []byte("binary\x00node.example.test")}, "node.example.test", "198.51.100.8")
	if err != nil {
		t.Fatal(err)
	}
	text := string(frozen["sing-box.json"])
	if strings.Count(text, "198.51.100.8") != 2 || !strings.Contains(text, `"server":"node.example.test"`) || !strings.Contains(text, "certificate.example.test") || !strings.Contains(text, "original.example.test") || string(frozen["rosenpass-client-secret"]) != "binary\x00node.example.test" {
		t.Fatal("resolution rewrote policy, trust or private key")
	}
	if _, err := freezeDesktopNodeAssets(map[string][]byte{"sing-box.json": []byte(`{"outbounds":[],"outbounds":[{}]}`)}, "node.example.test", "198.51.100.8"); err == nil {
		t.Fatal("duplicate fields silently normalized")
	}
}

func TestDesktopNativeDNSAndFixedPolicyReachCompiler(t *testing.T) {
	p, files := desktopNodeFixture(t, "198.51.100.8")
	p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort, p.DNSServerName = "custom", "https", "dns.example.test", 8443, "certificate.example.test"
	p.MTUPolicy, p.ManualMTU, p.EffectiveMTU, p.HomeLANAccess, p.IPv6Mode = "manual", 1392, 9000, false, "off"
	compiled, _, err := compileDesktopNode(context.Background(), p, "wg", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var graph map[string]any
	if json.Unmarshal([]byte(compiled.Config()), &graph) != nil {
		t.Fatal("invalid graph")
	}
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	if tun["mtu"] != float64(1392) {
		t.Fatal("stale measured MTU won")
	}
	dns := graph["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if len(servers) != 2 || servers[0].(map[string]any)["server"] != p.DNSHost || servers[1].(map[string]any)["server"] != p.AdGuardIPv4 || servers[1].(map[string]any)["detour"] != "proxy" {
		t.Fatal("selected DNS bootstrap escaped captured tunnel")
	}
	p.AdGuardIPv4 = ""
	if _, _, err := compileDesktopNode(context.Background(), p, "wg", files, nil, nil); err == nil {
		t.Fatal("uncaptured public bootstrap inferred")
	}
}

func TestDesktopNativeAssetReaderRejectsLinkedAndForeignFiles(t *testing.T) {
	root := t.TempDir()
	p, files := desktopNodeFixture(t, "198.51.100.8")
	dir := filepath.Join(root, "generated", p.ID, "wg")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := readDesktopNodeAssets(root, p.ID, "wg")
	if err != nil || !reflect.DeepEqual(got, files) {
		t.Fatal("exact assets changed", err)
	}
	if _, err := readDesktopNodeAssets(root, "../other", "wg"); err == nil {
		t.Fatal("profile traversal accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, "foreign"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := readDesktopNodeAssets(root, p.ID, "wg"); err == nil {
		t.Fatal("foreign directory accepted")
	}
}

func TestDesktopNativeStagingOwnsExactDirectoryAndEnvironment(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	a := &app{cfg: common.ClientConfig{ScriptsDir: filepath.Join(root, "modes")}}
	profile, files := desktopNodeFixture(t, "198.51.100.8")
	compiled, _, err := compileDesktopNode(context.Background(), profile, "wg", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch := &desktopNodeLaunch{root: root, endpoint: "198.51.100.8", profileID: "captured", mode: "wg", config: []byte(compiled.Config()), metadata: []byte(compiled.Metadata())}
	if err := stageDesktopNodeLaunch(a, launch); err != nil {
		t.Fatal(err)
	}
	if launch.directory == "" || launch.command == nil || len(launch.config) != 0 || len(launch.metadata) != 0 {
		t.Fatal("native stage did not transfer ownership")
	}
	if err := stageDesktopNodeLaunch(a, launch); err == nil {
		t.Fatal("same capture staged twice")
	}
	for _, name := range []string{"sing-box.json", "capture.json"} {
		info, err := os.Stat(filepath.Join(launch.directory, name))
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatal("private capture not protected", err)
		}
	}
	if runtimeDir, err := nativeMultihopRuntimeDirFromCommand(launch.command); err != nil || runtimeDir != launch.directory {
		t.Fatal("launcher lost exact runtime directory", err)
	}
	env := desktopNativeEnvironment([]string{"HOMEVPN_STANDARD_ENGINE=stock", "HOMEVPN_NATIVE_PACKAGE=foreign", "HOMEVPN_AMNEZIA_CONTROLLER=foreign", "HOMEVPN_ROOT=foreign", "LD_PRELOAD=foreign"}, root, "captured", "198.51.100.8")
	if strings.Contains(strings.Join(env, "\n"), "foreign") {
		t.Fatal("ambient runtime owner survived", env)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.connectionContext = ctx
	other := &desktopNodeLaunch{root: root, config: []byte(`{}`)}
	if err := stageDesktopNodeLaunch(a, other); !errors.Is(err, errConnectionOperationCancelled) || other.directory != "" {
		t.Fatal("cancelled capture staged", err)
	}
}

func TestDesktopNodeCleanupChild(t *testing.T) {
	if os.Getenv("ROUTERVPN_NATIVE_CLEANUP_TEST") != "1" {
		return
	}
	if os.Getenv("ROUTERVPN_NATIVE_CLEANUP_FAIL") == "1" {
		os.Exit(1)
	}
	if os.Getenv("ROUTERVPN_NATIVE_CLEANUP_RETAIN") != "1" {
		_ = os.RemoveAll(os.Args[len(os.Args)-1])
	}
	os.Exit(0)
}

func TestDesktopNativeStopRetainsFailedOwnerAndRejectsReplacement(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "run")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0])
	command.Dir = root
	command.Env = append(os.Environ(), "ROUTERVPN_NATIVE_CLEANUP_TEST=1", "ROUTERVPN_NATIVE_CLEANUP_FAIL=1")
	owner := &desktopNodeLaunch{directory: dir, command: command, stop: []string{os.Args[0], "-test.run=^TestDesktopNodeCleanupChild$", "--", dir}}
	a := &app{}
	desktopNodeOwners.Store(a, owner)
	defer desktopNodeOwners.Delete(a)
	if found, err := stopDesktopNodeRuntime(a, exec.Command(os.Args[0])); !found || err == nil {
		t.Fatal("different process released owner")
	}
	if found, err := stopDesktopNodeRuntime(a, command); !found || err == nil {
		t.Fatal("failed native stop reported complete")
	}
	if _, ok := desktopNodeOwners.Load(a); !ok {
		t.Fatal("failed owner forgotten")
	}
	command.Env = append(os.Environ(), "ROUTERVPN_NATIVE_CLEANUP_TEST=1", "ROUTERVPN_NATIVE_CLEANUP_RETAIN=1")
	if _, err := stopDesktopNodeRuntime(a, command); err == nil {
		t.Fatal("success without retirement accepted")
	}
	command.Env = append(os.Environ(), "ROUTERVPN_NATIVE_CLEANUP_TEST=1")
	if found, err := stopDesktopNodeRuntime(a, nil); !found || err != nil {
		t.Fatal("captured cleanup retry failed", err)
	}
	if _, ok := desktopNodeOwners.Load(a); !ok {
		t.Fatal("native identity forgotten before outer stop committed")
	}
	if err := finishDesktopNodeRuntime(a); err != nil {
		t.Fatal("retired stop did not commit", err)
	}
	if _, ok := desktopNodeOwners.Load(a); ok {
		t.Fatal("retired owner retained")
	}
}

func TestDesktopNativeStopRetainsIdentityUntilProtectionRelease(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix controller firewall release adapter")
	}
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	dir := filepath.Join(root, "native-owned")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	released := filepath.Join(root, "released")
	helper := filepath.Join(root, "kill-switch-platform.py")
	writeHelper := func(fail bool) {
		t.Helper()
		body := "from pathlib import Path\nimport sys\nPath(__file__).with_name('released').write_text('release')\n"
		if fail {
			body += "sys.exit(23)\n"
		}
		if err := os.WriteFile(helper, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeHelper(true)
	command := exec.Command(os.Args[0])
	command.Dir = root
	command.Env = append(os.Environ(), "ROUTERVPN_NATIVE_CLEANUP_TEST=1", "ROUTERVPN_NATIVE_CLEANUP_FAIL=1")
	owner := &desktopNodeLaunch{directory: dir, command: command, stop: []string{os.Args[0], "-test.run=^TestDesktopNodeCleanupChild$", "--", dir}}
	a := &app{cfg: common.ClientConfig{ScriptsDir: root}, cmd: command,
		modes: []common.Mode{{ID: "wg", StopCommand: []string{filepath.Join(root, "must-not-run-raw-stop")}}},
		state: state{Connected: true, Mode: "wg", RuntimeMode: "wg", RouterID: "captured", Phase: "connected"}}
	desktopNodeOwners.Store(a, owner)
	defer desktopNodeOwners.Delete(a)
	if err := a.stopModeWithIntent(false); err == nil {
		t.Fatal("failed native cleanup was accepted")
	}
	if _, err := os.Stat(released); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("protection released before native retirement", err)
	}
	command.Env = append(os.Environ(), "ROUTERVPN_NATIVE_CLEANUP_TEST=1")
	if err := a.stopModeWithIntent(false); err == nil || !strings.Contains(err.Error(), "release held kill switch") {
		t.Fatal("failed protection release was not retained", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native workspace did not retire", err)
	}
	if current, ok := desktopNodeOwners.Load(a); !ok || current != owner || a.state.Mode != "wg" || a.state.Phase != "failed" {
		t.Fatal("protection failure lost captured native retry identity")
	}
	writeHelper(false)
	if err := a.stopModeWithIntent(false); err != nil {
		t.Fatal("native recovery ran raw-mode cleanup or lost release", err)
	}
	if _, ok := desktopNodeOwners.Load(a); ok || a.state.Mode != "off" || a.state.Phase != "off" {
		t.Fatal("stop did not commit retirement")
	}
}
