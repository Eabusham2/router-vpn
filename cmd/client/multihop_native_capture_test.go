package main

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

func nativeMultihopCapturedFixture(t *testing.T, mode, layer string) (string, multihopSelection) {
	t.Helper()
	root := desktopAWGPrivateTestRoot(t)
	entry, files := viaEntryBaseFixture(t, mode)
	// The generated entry explicitly permits a nested dual-stack packet.
	// A missing MTU deliberately compiles to 1280 and cannot carry another
	// 1280-byte WG packet plus its authenticated transport envelope.
	for name, raw := range files {
		files[name] = []byte(strings.Replace(string(raw), "[Interface]\n", "[Interface]\nMTU = 1420\n", 1))
	}
	entry.ID, entry.StartLayer, entry.BaseTunnel = "entry", layer, "wg"
	if mode != "wg" {
		entry.BaseTunnel = "awg"
	}
	entry.SocksHost, entry.SocksPort, entry.SocksUsername, entry.SocksPassword = "10.77.0.1", 1080, "captured-private-user", "captured-private-pass"
	entry.DNSMode, entry.DNSProtocol, entry.DNSHost, entry.DNSPort = "custom", "https", "resolver.example", 8443
	entry.DNSServerName, entry.DNSPath = "resolver-certificate.example", "/captured-query"
	entry.DAITAEnabled, entry.DAITARateKbps, entry.DAITAHost, entry.DAITAPort = true, 64, "10.77.0.1", 45999
	entry.IPv6Mode, entry.HomeLANAccess = "off", false
	write := func(id, selected string, assets map[string][]byte) {
		dir := filepath.Join(root, "generated", id, selected)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for name, body := range assets {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, identity := viaEntryBaseFixture(t, "wg")
	for name, raw := range identity {
		identity[name] = []byte(strings.Replace(string(raw), "[Interface]\n", "[Interface]\nMTU = 1420\n", 1))
	}
	write(entry.ID, "wg", identity)
	write(entry.ID, mode, files)
	exit := cloneRouterProfile(entry)
	exit.ID, exit.Endpoint, exit.RouterAPI, exit.AdGuardIPv4 = "exit", "198.51.100.9", "http://10.88.0.1:8787", "10.88.0.53"
	exit.DNSMode, exit.DNSProtocol, exit.DNSHost, exit.DNSPort, exit.DNSServerName, exit.DNSPath = "home", "", "", 0, "", ""
	exit.DAITAHost = "10.88.0.1"
	for name, body := range identity {
		identity[name] = []byte(strings.ReplaceAll(strings.ReplaceAll(string(body), entry.Endpoint, exit.Endpoint), testWGKey('q'), testWGKey('r')))
	}
	exit.NodeProofID, _ = nodeProofIDFromWGConfig(identity["wg.conf"])
	write(exit.ID, "wg", identity)
	// AWG exits use their own protocol parameters and private transport key;
	// the paired WG asset above remains the stable Router node proof identity.
	for _, exitMode := range []string{"awg2-fast", "awg2-strong"} {
		_, packetAssets := viaEntryBaseFixture(t, exitMode)
		for name, raw := range packetAssets {
			text := strings.NewReplacer(entry.Endpoint, exit.Endpoint, testWGKey('p'), testWGKey('v'), testWGKey('q'), testWGKey('w'), "10.77.", "10.88.").Replace(string(raw))
			packetAssets[name] = []byte(strings.Replace(text, "[Interface]\n", "[Interface]\nMTU = 1420\n", 1))
		}
		write(exit.ID, exitMode, packetAssets)
		if exitMode == "awg2-strong" {
			write(exit.ID, "awg2-pq", nativeMultihopPQAssets(t, "awg2-pq", packetAssets, testWGKey('w')))
		}
	}
	write(exit.ID, "wg-pq", nativeMultihopPQAssets(t, "wg-pq", identity, testWGKey('r')))
	for _, p := range []common.RouterProfile{entry, exit} {
		key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
		ss, _ := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}}, "route": map[string]any{"final": "proxy"}, "outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": p.Endpoint, "server_port": 8388, "method": mobilemultihop.NativeStartLayerMethod, "password": key}}})
		write(p.ID, "shadowsocks", map[string][]byte{"sing-box.json": ss})
	}
	hy, _ := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}}, "route": map[string]any{"final": "proxy"}, "outbounds": []any{map[string]any{"type": "hysteria2", "tag": "proxy", "server": exit.Endpoint, "server_port": 443, "password": "captured-hysteria-password", "obfs": map[string]any{"type": "salamander", "password": "captured-obfuscation"}, "tls": map[string]any{"enabled": true, "server_name": "exit-certificate.example"}}}})
	write(exit.ID, "hysteria2", map[string][]byte{"sing-box.json": hy})
	for _, selected := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3"} {
		write(exit.ID, selected, nativeMultihopProxyExitAssets(t, exit, selected))
	}
	for _, selected := range []string{"ss-v2ray", "split", "max"} {
		write(exit.ID, selected, nativeMultihopCompositeExitAssets(t, exit, selected))
	}
	for _, selected := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		write(exit.ID, selected, nativeMultihopMAXAssets(t, exit, selected))
	}
	return root, multihopSelection{Control: cloneRouterProfile(entry), Entry: entry, Exit: exit, Base: entry.BaseTunnel, ExitMode: "shadowsocks"}
}

// Real raw import shapes reach the shipping compiler: the embedded Xray
// authentication document and Naive's version-2 UDP stream are never replaced
// by a generic SOCKS fixture just because their outer graph has a proxy tag.
func nativeMultihopProxyExitAssets(t *testing.T, exit common.RouterProfile, mode string) map[string][]byte {
	t.Helper()
	wrapper := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}}, "route": map[string]any{"final": "proxy"}}
	assets := map[string][]byte{}
	if multihoprelay.NaiveMode(mode) {
		wrapper["outbounds"] = []any{map[string]any{"type": "naive", "tag": "proxy", "server": exit.Endpoint, "server_port": 8443, "username": "captured-naive-user", "password": "captured-naive-password", "quic": mode == "naive-h3", "udp_over_tcp": map[string]any{"enabled": true, "version": 2}, "tls": map[string]any{"enabled": true, "server_name": "exit-certificate.example"}}}
	} else {
		key, err := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("x", 32)))
		if err != nil {
			t.Fatal(err)
		}
		pq, err := mlkem.NewDecapsulationKey768([]byte(strings.Repeat("q", 64)))
		if err != nil {
			t.Fatal(err)
		}
		user := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision", "encryption": "none"}
		stream := map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "exit-certificate.example", "fingerprint": "chrome", "password": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": "0123456789abcdef"}}
		if mode != "reality-vision" {
			user["encryption"] = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(pq.EncapsulationKey().Bytes())
		}
		if mode == "reality-xhttp" {
			delete(user, "flow")
			stream["network"] = "xhttp"
			stream["xhttpSettings"] = map[string]any{"path": "/captured-exit", "mode": "auto"}
			stream["finalmask"] = map[string]any{"tcp": []any{map[string]any{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "length": "100-300", "delay": "10-30", "maxSplit": "3-7"}}}}
		}
		xray := map[string]any{"inbounds": []any{map[string]any{"protocol": "socks", "listen": "127.0.0.1", "port": 1090, "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"protocol": "vless", "tag": "proxy", "settings": map[string]any{"vnext": []any{map[string]any{"address": exit.Endpoint, "port": 24443, "users": []any{user}}}}, "streamSettings": stream}}}
		assets["xray.json"], _ = json.Marshal(xray)
		wrapper["outbounds"] = []any{map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1090, "version": "5"}}
	}
	assets["sing-box.json"], _ = json.Marshal(wrapper)
	return assets
}

func TestNativeMultihopCapturedBaseLocalServerAndExactNativeCompiler(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				root, sel := nativeMultihopCapturedFixture(t, mode, layer)
				// Complete positive catalog includes S4=32 plus Start Layers;
				// their separately tested 1420-byte bound cannot carry that nesting.
				sel.Entry.MTUPolicy, sel.Entry.ManualMTU = "manual", 1500
				sel.Control.MTUPolicy, sel.Control.ManualMTU = "manual", 1500
				sel, err := captureNativeMultihopSelection(context.Background(), root, sel, mobilemultihop.NodeMultihopExitModes(), nil)
				if err != nil {
					t.Fatal(err)
				}
				if sel.Native.entryMode != mode || sel.Native.base != sel.Base || len(sel.Native.configs) != len(mobilemultihop.NodeMultihopExitModes()) {
					t.Fatal("actual saved base or complete Compare capture was lost", sel.Native.failures)
				}
				for _, exitMode := range mobilemultihop.NodeMultihopExitModes() {
					sel.ExitMode = exitMode
					dir, alias, err := prepareNativeMultihop(root, sel)
					wantAlias := "router-vpn-multihop"
					if runtime.GOOS == "darwin" {
						wantAlias = ""
					}
					if err != nil || alias != wantAlias {
						t.Fatal("native capture did not stage", err)
					}
					path := filepath.Join(dir, "sing-box.json")
					read := func() map[string]any {
						body, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						var graph map[string]any
						if json.Unmarshal(body, &graph) != nil {
							t.Fatal("invalid graph")
						}
						return graph
					}
					local := read()
					var endpoint map[string]any
					for _, raw := range local["endpoints"].([]any) {
						value := raw.(map[string]any)
						if value["tag"] == "entry-wg" {
							endpoint = value
						}
					}
					want := "wireguard"
					if mode != "wg" {
						want = mobilemultihop.AmneziaType
					}
					if endpoint["type"] != want || endpoint["tag"] != "entry-wg" || len(local["inbounds"].([]any)) != 3 {
						t.Fatal("native transport replaced or proof lanes lost")
					}
					checkNative := func() {
						if binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"); binary != "" {
							cmd := exec.Command(binary, "check", "-c", path, "-D", dir)
							cmd.Env = nativeLibraryEnvironment(os.Environ(), filepath.Dir(binary))
							if output, err := cmd.CombinedOutput(); err != nil {
								t.Fatalf("actual pinned compiler rejected complete native multihop: %v: %s", err, output)
							}
						}
					}
					checkNative()
					var maxOwners map[string]bool
					if mobilemultihop.MAXMode(exitMode) {
						maxOwners, err = nativeMAXExitOwners(local, sel)
						if err != nil || len(maxOwners) != 2+boolInt(layer != "off") {
							t.Fatal("complete catalog MAX source lost a mandatory or selected helper", err)
						}
					}
					_, descriptor := executionFixture()
					descriptor.Lease.ExitMode = exitMode
					if layer != "off" {
						descriptor.Lease.ExitStartLayer = layer
					}
					if err := patchDesktopExecutionConfig(path, descriptor, sel); err != nil {
						t.Fatal(err)
					}
					server := read()
					for _, key := range []string{"services", "inbounds"} {
						if !reflect.DeepEqual(local[key], server[key]) {
							t.Fatal("Server substitution changed the captured entry or policy", key)
						}
					}
					if nativeMultihopPacketExitMode(exitMode) {
						serverEndpoints := server["endpoints"].([]any)
						if len(serverEndpoints) != 1 || !reflect.DeepEqual(serverEndpoints[0], endpoint) || len(local["endpoints"].([]any)) != 2 || sel.Native.localPacketPublic[exitMode] == "" {
							t.Fatal("Server did not remove only the captured local packet/PQ/MAX exit")
						}
					} else if !reflect.DeepEqual(local["endpoints"], server["endpoints"]) {
						t.Fatal("Server substitution changed the captured entry")
					}
					dnsSource, err := json.Marshal(local["dns"])
					if err != nil {
						t.Fatal(err)
					}
					wantDNS := retainedGraph(t, dnsSource)
					if layer != "off" {
						for _, raw := range wantDNS["servers"].([]any) {
							resolver := raw.(map[string]any)
							if resolver["detour"] == mobilemultihop.NativeStartLayerTag {
								resolver["detour"] = "proxy"
							}
						}
					}
					if !reflect.DeepEqual(wantDNS, server["dns"]) {
						t.Fatal("Server changed selected DNS beyond the exact leased exit layer")
					}
					for _, raw := range server["outbounds"].([]any) {
						out := raw.(map[string]any)
						if tag, _ := out["tag"].(string); maxOwners[tag] {
							t.Fatal("Server retained a competing Local complete-MAX helper", tag)
						}
						if out["tag"] == mobilemultihop.NativeStartLayerTag {
							t.Fatal("server-owned exit Start Layer remained local")
						}
						if out["tag"] == "proxy" && (out["type"] != "socks" || out["password"] != descriptor.Lease.Password || out["detour"] != "entry-wg") {
							t.Fatal("Server lease was substituted")
						}
					}
					checkNative()
					if sel.Native.validate(sel) != nil {
						t.Fatal("staging or Server changed saved sources")
					}
				}
			})
		}
	}
}

func TestNativeMultihopCaptureRejectsChangedBaseAssetsAndPolicies(t *testing.T) {
	for _, change := range []string{"base", "variant", "entry-key", "identity-key", "entry-layer", "exit-key", "DNS", "control", "missing-mode"} {
		t.Run(change, func(t *testing.T) {
			root, sel := nativeMultihopCapturedFixture(t, "awg2-strong", "aes-256-gcm")
			sel, err := captureNativeMultihopSelection(context.Background(), root, sel, []string{"shadowsocks", "hysteria2"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			file := ""
			switch change {
			case "base":
				sel.Base = "wg"
			case "variant":
				files, _ := readDesktopNodeAssets(root, sel.Entry.ID, "awg2-strong")
				dir := filepath.Join(root, "generated", sel.Entry.ID, "awg2-fast")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "awg-socks.conf"), files["awg-socks.conf"], 0600); err != nil {
					t.Fatal(err)
				}
			case "entry-key":
				file = "entry/awg2-strong/awg.conf"
			case "identity-key":
				file = "entry/wg/wg.conf"
			case "entry-layer":
				file = "entry/shadowsocks/sing-box.json"
			case "exit-key":
				file = "exit/hysteria2/sing-box.json"
			case "DNS":
				sel.Entry.DNSHost = "changed.example"
			case "control":
				sel.Control.StartLayer = "off"
			case "missing-mode":
				sel.ExitMode = "unknown"
			}
			if file != "" {
				if err := os.WriteFile(filepath.Join(root, "generated", file), []byte("changed captured source"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := prepareNativeMultihop(root, sel); err == nil {
				t.Fatal("changed source was staged")
			}
			if entries, _ := filepath.Glob(filepath.Join(root, "run", "native-multihop*")); len(entries) != 0 {
				t.Fatal("invalid source created a partial runtime")
			}
		})
	}
}

func TestNativeMultihopOldEndpointFailsBeforeBootstrap(t *testing.T) {
	root, sel := nativeMultihopCapturedFixture(t, "awg2-fast", "off")
	sel.Entry.Endpoint, sel.Control.Endpoint = "new.example", "new.example"
	calls := 0
	if _, err := captureNativeMultihopSelection(context.Background(), root, sel, []string{"shadowsocks"}, func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
	}); err == nil || calls != 0 {
		t.Fatal("old authentic endpoint reached bootstrap")
	}
}

func TestNativeMultihopEnvironmentAndStatusKeepExactBase(t *testing.T) {
	root, sel := nativeMultihopCapturedFixture(t, "awg2-strong", "off")
	sel.Control.ID = "policy-control"
	sel, err := captureNativeMultihopSelection(context.Background(), root, sel, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_STANDARD_ENGINE", "stock")
	t.Setenv("HOMEVPN_PROFILE_ID", "foreign")
	t.Setenv("HOMEVPN_POLICY_PROFILE_ID", "foreign")
	env := nativeMultihopEnvironment(root, sel)
	for key, expected := range map[string]string{"HOMEVPN_STANDARD_ENGINE": "native", "HOMEVPN_PROFILE_ID": sel.Entry.ID, "HOMEVPN_POLICY_PROFILE_ID": sel.Control.ID, "HOMEVPN_ENDPOINT": sel.Native.endpoint} {
		count := 0
		for _, item := range env {
			if strings.HasPrefix(item, key+"=") {
				count++
				if item != key+"="+expected {
					t.Fatal("foreign native environment", key)
				}
			}
		}
		if count != 1 {
			t.Fatal("ambiguous native environment", key)
		}
	}
	a := &app{}
	setActiveMultihopGraph(a, sel)
	defer clearActiveMultihopGraph(a)
	g, _ := getActiveMultihopGraph(a)
	if g.Base != "awg" || g.EntryMode != "awg2-strong" || g.SourceSHA != sel.Native.source {
		t.Fatal("runtime graph mislabeled its captured base")
	}
	for _, requested := range []string{"auto", "wg", "awg"} {
		selected, err := resolveNativeMultihopSelection(sel.Control, []common.RouterProfile{sel.Control, sel.Entry, sel.Exit}, multihopConnectRequest{EntryID: sel.Entry.ID, ExitID: sel.Exit.ID, Base: requested})
		if err != nil || selected.Base != resolveMultihopEntryBase(sel.Control, sel.Entry, requested) {
			t.Fatal("native Connect differs from candidate base policy", err)
		}
	}
}

func TestNativeMultihopProofCannotAdoptRetiredEntryOrExit(t *testing.T) {
	for _, mode := range []string{"shadowsocks", "reality-pq-vision", "naive-h3"} {
		for _, retire := range []string{"none", "before", "entry", "exit", "cancel", "source", "wrong-entry", "expired"} {
			t.Run(mode+"/"+retire, func(t *testing.T) {
				root, sel := nativeMultihopCapturedFixture(t, "awg2-strong", "aes-256-gcm+xor-whitening")
				sel.ExitMode = mode
				sel, err := captureNativeMultihopSelection(context.Background(), root, sel, []string{mode}, nil)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				// Retirement is driven by each scenario, not by the speed of the
				// real private-source reads under race instrumentation on Windows.
				// This timer is only a failure watchdog for a stuck proof loop.
				watchdog := time.AfterFunc(5*time.Second, cancel)
				defer watchdog.Stop()
				if retire == "expired" {
					var expire context.CancelFunc
					ctx, expire = context.WithDeadline(ctx, time.Unix(0, 0))
					defer expire()
				}
				owned, calls := retire != "before", 0
				err = proveNativeMultihopCapture(ctx, sel, func() bool { return owned }, func(proofCtx context.Context, p common.RouterProfile, lane string) error {
					calls++
					if calls == 1 && (p.ID != sel.Entry.ID || lane != multihopEntryProofProxy) || calls == 2 && (p.ID != sel.Exit.ID || lane != multihopProofProxy) {
						t.Fatal("proof borrowed the other hop lane")
					}
					if retire == "none" && calls == 1 {
						// A healthy proof may take longer than the former 50ms
						// fixture deadline without losing either captured owner.
						select {
						case <-time.After(75 * time.Millisecond):
						case <-proofCtx.Done():
							return proofCtx.Err()
						}
					}
					if retire == "entry" && calls == 1 || retire == "exit" && calls == 2 {
						owned = false
					}
					if retire == "cancel" {
						cancel()
					}
					if retire == "wrong-entry" {
						cancel()
						return errors.New("wrong node proof")
					}
					if retire == "source" {
						if err := os.WriteFile(filepath.Join(root, "generated", "entry", "awg2-strong", "awg.conf"), []byte("replaced"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					return nil
				})
				if retire == "none" {
					if err != nil || calls != 2 {
						t.Fatal("both captured nodes were not proved", err)
					}
				} else {
					wantCalls := 1
					if retire == "before" || retire == "expired" {
						wantCalls = 0
					} else if retire == "exit" {
						wantCalls = 2
					}
					if err == nil || calls != wantCalls {
						t.Fatal("retired or wrong entry proof reached adoption or the next node", retire, calls, err)
					}
					if retire == "expired" && !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("already expired proof did not preserve its deadline error", err)
					}
				}
			})
		}
	}
}

func TestNativeMultihopServerCannotChangeCapturedModeLayerOrConfig(t *testing.T) {
	for _, mode := range mobilemultihop.NodeMultihopExitModes() {
		for _, change := range []string{"capture", "mode", "layer", "bytes"} {
			root, sel := nativeMultihopCapturedFixture(t, "awg2-fast", "aes-256-gcm+xor-whitening")
			sel.ExitMode = mode
			if awgpolicy.IsMode(mode) || mode == "awg2-pq" {
				sel.Entry.MTUPolicy, sel.Entry.ManualMTU = "manual", 1500
				sel.Control.MTUPolicy, sel.Control.ManualMTU = "manual", 1500
			}
			sel, err := captureNativeMultihopSelection(context.Background(), root, sel, []string{mode}, nil)
			if err != nil {
				t.Fatal(err)
			}
			dir, _, err := prepareNativeMultihop(root, sel)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "sing-box.json")
			_, d := executionFixture()
			d.Lease.ExitMode, d.Lease.ExitStartLayer = sel.ExitMode, sel.Exit.StartLayer
			switch change {
			case "capture":
				sel.Native = nil
			case "mode":
				d.Lease.ExitMode = "hysteria2"
				if mode == "hysteria2" {
					d.Lease.ExitMode = "shadowsocks"
				}
			case "layer":
				d.Lease.ExitStartLayer = ""
			case "bytes":
				body, _ := os.ReadFile(path)
				if err := os.WriteFile(path, append(body, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			if err := patchDesktopExecutionConfig(path, d, sel); err == nil {
				t.Fatal("Server accepted a changed capture", change)
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(before) {
				t.Fatal("rejected Server patch changed the runtime")
			}
		}
	}
}

func TestNativeMultihopCompareCannotAddModeAfterCapture(t *testing.T) {
	root, sel := nativeMultihopCapturedFixture(t, "awg2-fast", "off")
	dir := filepath.Join(root, "generated", "exit", "hysteria2")
	body, _ := os.ReadFile(filepath.Join(dir, "sing-box.json"))
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	sel, err := captureNativeMultihopSelection(context.Background(), root, sel, []string{"shadowsocks", "hysteria2"}, nil)
	if err != nil || len(sel.Native.configs) != 1 {
		t.Fatal("one unavailable mode prevented the captured valid comparison", err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	if sel.Native.validate(sel) == nil {
		t.Fatal("newly available exit silently entered a captured comparison")
	}
}

func TestNativeMultihopCannotFallBackToStockEngine(t *testing.T) {
	root, sel := nativeMultihopCapturedFixture(t, "awg2-fast", "off")
	t.Setenv("HOMEVPN_ROOT", root)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	a := &app{cfg: common.ClientConfig{ScriptsDir: filepath.Join(root, "modes")}}
	if _, err := nativeWindowsMultihopCommand(a, sel); err == nil {
		t.Fatal("native AWG launch borrowed an unverified stock engine")
	}
	if entries, _ := filepath.Glob(filepath.Join(root, "run", "native-multihop*")); len(entries) != 0 {
		t.Fatal("missing engine staged credentials")
	}
}

func TestNativeMultihopTUNUsesNativeDarwinAllocation(t *testing.T) {
	for _, name := range []string{"", "router-vpn-multihop", "router-vpn", "utun9"} {
		tun := map[string]any{"type": "tun", "interface_name": name, "auto_route": true, "strict_route": true}
		if nativeMultihopTUNAlias(tun, "darwin") != "" {
			t.Fatal("Darwin borrowed a fixed tunnel interface")
		}
		if _, exists := tun["interface_name"]; exists || tun["auto_route"] != true || tun["strict_route"] != true {
			t.Fatal("Darwin native allocation or protected route policy changed")
		}
	}
	for _, name := range []string{"", "router-vpn-custom"} {
		tun := map[string]any{"interface_name": name}
		want := name
		if want == "" {
			want = "router-vpn-multihop"
		}
		if nativeMultihopTUNAlias(tun, "windows") != want || tun["interface_name"] != want {
			t.Fatal("Windows firewall alias does not match its exact native tunnel")
		}
	}
}
