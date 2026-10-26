package mobiletor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// These fixtures pass through the actual complete-node compiler. No reduced
// predecessor graph or direct SOCKS substitute is used to qualify a Router.
func desktopEntryFixture(t *testing.T, mode, layer string, edit func(map[string]any)) (*DesktopPredecessor, map[string]any) {
	t.Helper()
	public := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	node := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + public))
	entry := map[string]any{"id": "captured-router", "node_kind": "router-vpn", "node_proof_id": hex.EncodeToString(node[:]),
		"router_api": "http://10.80.0.1:8787", "api_token": "entry-private-token", "endpoint": "192.0.2.44", "start_layer": layer,
		"dns_mode": "home", "adguard_ipv4": "10.80.0.53", "adguard_ipv6": "fd80::53", "mtu_policy": "auto", "effective_mtu": 9000,
		"ipv6_mode": "on", "home_lan_access": true}
	if edit != nil {
		edit(entry)
	}
	proxy := func(mode string) string {
		out := map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.44", "server_port": 443,
			"method": mobilemultihop.NativeStartLayerMethod, "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))}
		if strings.HasPrefix(mode, "naive-") {
			out = map[string]any{"type": "naive", "tag": "proxy", "server": "192.0.2.44", "server_port": 443,
				"username": "entry-naive-user", "password": "entry-naive-secret", "quic": mode == "naive-h3",
				"udp_over_tcp": map[string]any{"enabled": true, "version": 2}, "tls": map[string]any{"enabled": true, "server_name": "entry.example"}}
		}
		graph := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true, "mtu": 1280}},
			"outbounds": []any{out, map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "proxy", "rules": []any{}}}
		return torHostEncode(t, map[string]string{"sing-box.json": base64.StdEncoding.EncodeToString([]byte(torHostEncode(t, graph)))})
	}
	files, start := "", ""
	if mode == "wg" || strings.HasPrefix(mode, "awg2-") {
		private := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
		psk := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
		parameters, filename := "", "wg.conf"
		if mode != "wg" {
			filename = "awg.conf"
			parameters = "Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n"
		}
		config := "[Interface]\nAddress=10.80.0.2/24,fd80::2/64\nPrivateKey=" + private + "\nDNS=10.80.0.53\nMTU=1420\n" + parameters +
			"[Peer]\nPublicKey=" + public + "\nPresharedKey=" + psk + "\nEndpoint=192.0.2.44:51820\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n"
		files = torHostEncode(t, map[string]string{filename: base64.StdEncoding.EncodeToString([]byte(config))})
	} else {
		files = proxy(mode)
	}
	if layer != "" && mode != "shadowsocks" {
		start = proxy("shadowsocks")
	}
	source := torHostEncode(t, entry)
	compiled, err := mobilemultihop.NewNodeProfile(mode, files, source, start, "")
	if err != nil {
		t.Fatal("complete entry fixture", err)
	}
	assets := desktopDigest([]byte(files + "\x00" + start))
	captured, err := NewDesktopPredecessor(mode, source, compiled.Config(), assets)
	if err != nil {
		t.Fatal("capture entry fixture", err)
	}
	return captured, entry
}

func desktopEntryExit(entry *DesktopPredecessor) map[string]any {
	exit := desktopProfile()
	exit["multihop_enabled"], exit["multihop_entry_id"], exit["multihop_exit_id"] = true, entry.proof.id, exit["id"]
	exit["multihop_entry_mode"], exit["multihop_exit_mode"], exit["multihop_execution"] = entry.mode, "tor-bridge", "local"
	return exit
}

func TestDesktopPredecessorComposesCompleteEntryAndIndependentPolicy(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "naive-h2", "naive-h3"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			entry, _ := desktopEntryFixture(t, mode, layer, nil)
			original, _ := profileObject(entry.Config(), 4<<20)
			for _, target := range []string{"linux", "darwin", "windows"} {
				for _, dnsMode := range []string{"custom", "home"} {
					t.Run(mode+"/"+layer+"/"+target+"/"+dnsMode, func(t *testing.T) {
						exit := desktopEntryExit(entry)
						exit["dns_mode"], exit["dns_protocol"] = dnsMode, "doh"
						exit["dns_server_name"], exit["dns_path"] = "selected.example", "/chosen-dns?entry=one"
						exit["ipv6_mode"], exit["home_lan_access"] = "off", false
						if dnsMode == "home" {
							exit["dns_host"] = "10.80.0.53"
						}
						source := torHostEncode(t, exit)
						policy, err := NewDesktopBridgePolicyWithPredecessor(source, desktopSession, desktopIsolation, target, entry)
						if err != nil {
							t.Fatal(err)
						}
						meta := policy.Metadata()
						if policy.Profile() != source || source != torHostEncode(t, exit) || policy.Predecessor() != entry ||
							meta.EntryID != "captured-router" || meta.EntryMode != mode || meta.EntryTag != entry.Tag() || meta.EntrySHA256 != entry.Proof().Fingerprint() ||
							meta.EntryAssetsSHA256 != entry.AssetsSHA256() || meta.ConfiguredMTU != 1280 || !meta.AllowMTUOptimization() || meta.HomeLANAccess || meta.IPv6Mode != "off" {
							t.Fatal("complete immutable entry or independent exit policy changed", meta)
						}
						graph, _ := profileObject(policy.Config(), 4<<20)
						if len(graph["inbounds"].([]any)) != 1 || graph["route"].(map[string]any)["final"] != ProfileOutboundTag {
							t.Fatal("composition lost one VPN interface or the Tor exit")
						}
						socks := torHostTagged(t, graph["outbounds"], ProfileOutboundTag)
						if len(socks) != 7 || socks["type"] != "socks" || socks["detour"] != nil || socks["username"] != desktopSession || socks["password"] != desktopIsolation {
							t.Fatal("standalone loopback was routed through the entry or lost its isolation")
						}
						for _, family := range []string{"outbounds", "endpoints"} {
							before, _ := original[family].([]any)
							for _, raw := range before {
								owner := raw.(map[string]any)
								if !reflect.DeepEqual(owner, torHostTagged(t, graph[family], profileString(owner, "tag"))) {
									t.Fatal("entry transport, key, certificate or Start Layer changed", family)
								}
							}
						}
						dns := graph["dns"].(map[string]any)
						selected, bootstrap := torHostTagged(t, dns["servers"], profileDNS), torHostTagged(t, dns["servers"], bootstrapDNS)
						wantRoute := ProfileOutboundTag
						if dnsMode == "home" {
							wantRoute = entry.Tag()
						}
						if meta.DNSDetour != wantRoute || selected["detour"] != wantRoute || bootstrap["detour"] != entry.Tag() ||
							meta.DNS.ServerName != "selected.example" || meta.DNS.Path != "/chosen-dns?entry=one" || meta.DNS.Port != 5353 || dns["strategy"] != "ipv4_only" {
							t.Fatal("selected resolver or PT bootstrap escaped its captured path")
						}
					})
				}
			}
		}
	}
}

func TestDesktopPredecessorCaptureIsExactBoundedAndImmutable(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "shadowsocks", "aes-256-gcm+xor-whitening", nil)
	exit := desktopEntryExit(entry)
	source := torHostEncode(t, exit)
	root := t.TempDir()
	input, err := NewDesktopBridgeCaptureWithPredecessor(source, desktopSession, desktopIsolation, "linux", filepath.Join(root, "tor"), filepath.Join(root, "session"), entry)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDesktopBridgeCapture(source, input.JSON(), input.RuntimeDir())
	if err != nil || !reflect.DeepEqual(input, decoded) {
		t.Fatal("child could not reconstruct exact private entry", err)
	}
	copy := input.Capture()
	copy.Predecessor.Profile[0], copy.Predecessor.Config[0] = '!', '!'
	copy.Predecessor.EntryMode = "wrong"
	if input.Capture().Predecessor.EntryMode != entry.Mode() || input.Capture().Predecessor.Profile[0] != '{' || input.Capture().Predecessor.Config[0] != '{' {
		t.Fatal("capture getter mutated the immutable entry")
	}
	large := strings.Repeat(" ", 20<<10) + input.JSON()
	if got, err := DecodeDesktopBridgeCapture(source, large, input.RuntimeDir()); err != nil || got.Digests().CaptureSHA256 != desktopDigest([]byte(large)) || got.Policy().SourceSHA256() != input.Policy().SourceSHA256() {
		t.Fatal("bounded predecessor capture lost its exact raw digest", err)
	}
	for name, alter := range map[string]func(map[string]any){
		"missing":        func(p map[string]any) { delete(p, "predecessor") },
		"null":           func(p map[string]any) { p["predecessor"] = nil },
		"unknown":        func(p map[string]any) { p["predecessor"].(map[string]any)["command"] = "unowned" },
		"missing-assets": func(p map[string]any) { delete(p["predecessor"].(map[string]any), "assets_sha256") },
		"wrong-assets":   func(p map[string]any) { p["predecessor"].(map[string]any)["assets_sha256"] = "wrong" },
		"wrong-schema":   func(p map[string]any) { p["predecessor"].(map[string]any)["schema"] = "1" },
		"wrong-mode":     func(p map[string]any) { p["predecessor"].(map[string]any)["entry_mode"] = "wg" },
		"string-profile": func(p map[string]any) { p["predecessor"].(map[string]any)["profile"] = "{}" },
		"string-config":  func(p map[string]any) { p["predecessor"].(map[string]any)["config"] = "{}" },
		"foreign-entry": func(p map[string]any) {
			p["predecessor"].(map[string]any)["profile"].(map[string]any)["id"] = "another-router"
		},
	} {
		t.Run(name, func(t *testing.T) {
			object, _ := profileObject(input.JSON(), DesktopBridgeCaptureLimit)
			alter(object)
			if _, err := DecodeDesktopBridgeCapture(source, torHostEncode(t, object), input.RuntimeDir()); err == nil {
				t.Fatal("substituted or unowned capture was accepted")
			}
		})
	}
	for _, raw := range []string{strings.Replace(input.JSON(), `"entry_mode":`, `"entry_mode":"shadowsocks","entry_mode":`, 1), strings.Repeat(" ", DesktopBridgeCaptureLimit) + input.JSON()} {
		if _, err := DecodeDesktopBridgeCapture(source, raw, input.RuntimeDir()); err == nil {
			t.Fatal("duplicate or oversized predecessor capture was accepted")
		}
	}
	for _, execution := range []string{"auto", "server", "compare", "Compare"} {
		exit["multihop_execution"] = execution
		original := torHostEncode(t, exit)
		if _, err := NewDesktopBridgePolicyWithPredecessor(original, desktopSession, desktopIsolation, "linux", entry); err == nil || original != torHostEncode(t, exit) {
			t.Fatal("unsupported execution silently became Local", execution)
		}
	}
	for _, field := range []string{"multihop_entry_id", "multihop_exit_id", "multihop_entry_mode", "multihop_exit_mode"} {
		changed := desktopEntryExit(entry)
		changed[field] = "another-owner"
		if _, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, changed), desktopSession, desktopIsolation, "linux", entry); err == nil {
			t.Fatal("saved selection differs from the immutable entry", field)
		}
	}
}

func TestDesktopPredecessorRetainsCapturedEntryCoverService(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "shadowsocks", "", func(profile map[string]any) {
		profile["daita_enabled"], profile["daita_rate_kbps"], profile["daita_host"] = true, 64, "10.80.0.1"
	})
	policy, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, desktopEntryExit(entry)), desktopSession, desktopIsolation, "linux", entry)
	if err != nil {
		t.Fatal(err)
	}
	graph, _ := profileObject(policy.Config(), 4<<20)
	before, _ := profileObject(entry.Config(), 4<<20)
	services := graph["services"].([]any)
	if len(services) != 2 || !reflect.DeepEqual(services[0], before["services"].([]any)[0]) ||
		services[1].(map[string]any)["type"] != "routervpn-desktop-tor-network" {
		t.Fatal("Tor observer displaced the captured entry's bounded cover owner")
	}
}

func TestDesktopPredecessorRetainsEntryMTUAuthorityWithoutChangingExit(t *testing.T) {
	for _, test := range []struct {
		name, policy string
		fixed        int
		jumbo        bool
		mtu          int
		allowed      bool
	}{
		{"auto", "auto", 0, false, 1280, true}, {"default", "default", 0, false, 1280, true},
		{"fixed", "fixed", 1392, false, 1392, false}, {"fixed9000", "fixed", 9000, false, 9000, false},
		{"jumbo", "auto", 0, true, 9000, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry, _ := desktopEntryFixture(t, "shadowsocks", "", func(profile map[string]any) {
				profile["mtu_policy"], profile["manual_mtu"], profile["jumbo_tun"] = test.policy, test.fixed, test.jumbo
			})
			exit := desktopEntryExit(entry)
			policy, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, "linux", entry)
			if err != nil {
				t.Fatal(err)
			}
			meta := policy.Metadata()
			if meta.MTUPolicy != "auto" || meta.JumboTUN || meta.EntryMTUPolicy != test.policy || meta.EntryFixedMTU != test.fixed || meta.EntryJumboTUN != test.jumbo || meta.ConfiguredMTU != test.mtu || meta.AllowMTUOptimization() != test.allowed {
				t.Fatal("entry authority was dropped or relabeled as an exit preference", meta)
			}
			if test.fixed != 0 || test.jumbo {
				exit["mtu_policy"], exit["manual_mtu"] = "fixed", 1400
				if _, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, exit), desktopSession, desktopIsolation, "linux", entry); err == nil {
					t.Fatal("conflicting entry/exit capacities acquired one interface")
				}
			}
		})
	}
}

func TestDesktopPredecessorSourceBindsAssetsCredentialsAndGraph(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "shadowsocks", "", nil)
	exit := desktopEntryExit(entry)
	source := torHostEncode(t, exit)
	base, err := NewDesktopBridgePolicyWithPredecessor(source, desktopSession, desktopIsolation, "linux", entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"assets", "token", "graph-key"} {
		profile, graph, assets := entry.Profile(), entry.Config(), entry.AssetsSHA256()
		switch fault {
		case "assets":
			assets = strings.Repeat("e", 64)
		case "token":
			profile = strings.Replace(profile, "entry-private-token", "replacement-private-token", 1)
		case "graph-key":
			graph = strings.Replace(graph, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("t", 32))), 1)
		}
		changed, err := NewDesktopPredecessor(entry.Mode(), profile, graph, assets)
		if err != nil {
			t.Fatal(err)
		}
		next, err := NewDesktopBridgePolicyWithPredecessor(source, desktopSession, desktopIsolation, "linux", changed)
		if err != nil || next.SourceSHA256() == base.SourceSHA256() {
			t.Fatal("private relink retained old source identity", fault, err)
		}
	}
	canonical := entry.Capture()
	canonical.Profile = json.RawMessage("  " + string(canonical.Profile))
	raw, _ := json.Marshal(canonical)
	copy, err := decodeDesktopPredecessor(raw)
	if err != nil || !reflect.DeepEqual(entry, copy) {
		t.Fatal("canonical private identity changed", err)
	}
}
