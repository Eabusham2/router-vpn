package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/applexray"
)

func importedSOCKSXrayFixture(t *testing.T, layers ...string) []string {
	t.Helper()
	source := importedSOCKSFixture(t, "reality-vision", layers...)
	profile := externalTestRead(t, source[4])
	profile["multihop_execution"] = "local"
	if profile["start_layer"] == "" {
		profile["start_layer"] = "off"
	}
	source[4] = externalTestJSON(t, profile)
	return source
}

func importedSOCKSXrayCompile(t *testing.T, source []string) *Controller {
	t.Helper()
	if len(source) != 7 {
		t.Fatal("SOCKS REALITY lost its seven original source strings")
	}
	plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
	if err != nil {
		t.Fatal("captured SOCKS REALITY/Vision graph was rejected", err)
	}
	return plan
}

func importedSOCKSXrayRaw(t *testing.T, files string) (map[string]string, map[string]any, string) {
	t.Helper()
	var assets map[string]string
	if err := json.Unmarshal([]byte(files), &assets); err != nil {
		t.Fatal(err)
	}
	bytes, err := base64.StdEncoding.Strict().DecodeString(assets["xray.json"])
	if err != nil {
		t.Fatal(err)
	}
	return assets, externalTestRead(t, string(bytes)), string(bytes)
}

func TestImportedEntrySOCKSRealityVisionCapturedGraphs(t *testing.T) {
	for _, policy := range []string{"default-home", "explicit-off", "custom-udp", "custom-tcp", "ipv6-off", "lan-off", "fixed-mtu"} {
		t.Run(policy, func(t *testing.T) {
			source := importedSOCKSXrayFixture(t)
			capture, profile := externalTestRead(t, source[1]), externalTestRead(t, source[4])
			switch policy {
			case "explicit-off":
				capture["profile"].(map[string]any)["start_layer"] = "off"
			case "custom-udp", "custom-tcp":
				profile["dns_mode"], profile["dns_protocol"] = "custom", strings.TrimPrefix(policy, "custom-")
				profile["dns_host"], profile["dns_port"] = "203.0.113.53", 5353
			case "ipv6-off":
				profile["ipv6_mode"] = "off"
			case "lan-off":
				profile["home_lan_access"] = false
			case "fixed-mtu":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", 1392
			}
			source[1], source[4] = externalTestJSON(t, capture), externalTestJSON(t, profile)
			original := append([]string(nil), source...)
			selected, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
			if err != nil {
				t.Fatal("original paired Xray source was invalid", err)
			}
			plan := importedSOCKSXrayCompile(t, source)
			graph := externalTestRead(t, plan.Config())
			if raw, present := graph["endpoints"]; present {
				rows, ok := raw.([]any)
				if !ok || len(rows) != 0 {
					t.Fatal("SOCKS REALITY acquired an unexpected native packet endpoint")
				}
			}
			graph["endpoints"] = []any{}
			first, final := externalTestFind(t, graph, "entry-wg"), externalTestFind(t, graph, LocalTag)
			_, _, raw := importedSOCKSXrayRaw(t, source[3])
			if len(final) != 5 || final["type"] != "routervpn-xray" || final["mode"] != "reality-vision" || final["config_json"] != raw || final["detour"] != "entry-wg" {
				t.Fatal("SOCKS REALITY changed the original native Xray source or lower owner")
			}
			if first["type"] != "socks" || first["version"] != "5" || first["username"] != "captured-native-user" || first["password"] != "selected-password-e" || first["server"] != "203.0.113.20" || first["server_port"] != float64(443) || first["detour"] != nil {
				t.Fatal("SOCKS REALITY changed the independently captured entry")
			}
			selector := externalTestFind(t, graph, "proxy")
			if selector["type"] != "selector" || selector["default"] != LocalTag || !reflect.DeepEqual(selector["outbounds"], []any{LocalTag}) || len(graph["outbounds"].([]any)) != 3 {
				t.Fatal("SOCKS REALITY acquired another route or execution choice")
			}
			selectedGraph := externalTestRead(t, selected.Config())
			if !reflect.DeepEqual(graph["dns"], selectedGraph["dns"]) {
				t.Fatal("SOCKS REALITY changed the final-selected DNS")
			}
			importedSOCKSXrayDevicePolicy(t, graph, policy)
			if plan.meta.EntryKind != "external" || plan.meta.EntryMode != "socks5" || plan.meta.ExitMode != "reality-vision" || plan.meta.Execution != "local" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.EntryNodeID != "" || plan.meta.ExitID != profile["id"] || plan.meta.ExitNodeID != profile["node_proof_id"] || plan.meta.ExitAPI != profile["router_api"] || plan.meta.ExitToken != profile["api_token"] {
				t.Fatal("SOCKS REALITY substituted entry or final identity")
			}
			captureBytes, _ := json.Marshal(append([]string{"routervpn-imported-entry-v1"}, source...))
			if !reflect.DeepEqual(source, original) || plan.SourceSHA256() != externalDigest(captureBytes) {
				t.Fatal("SOCKS REALITY did not retain all seven exact original inputs")
			}
			again := importedSOCKSXrayCompile(t, source)
			if again.SourceSHA256() != plan.SourceSHA256() || again.Config() != plan.Config() || plan.Healthy() {
				t.Fatal("SOCKS REALITY restoration changed source or manufactured readiness")
			}
			if _, err = New(plan.Config(), plan.Metadata()); err == nil {
				t.Fatal("SOCKS REALITY public metadata acquired original source authority")
			}
			if policy == "default-home" {
				if directory := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); directory != "" {
					exported := append(append([]string(nil), source...), plan.SourceSHA256(), plan.Config())
					if err := os.WriteFile(filepath.Join(directory, "socks5--final-reality-vision.json"), []byte(externalTestJSON(t, exported)), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func importedSOCKSXrayDevicePolicy(t *testing.T, graph map[string]any, policy string) {
	t.Helper()
	inbounds := graph["inbounds"].([]any)
	tun := inbounds[0].(map[string]any)
	mtu := float64(1280)
	if policy == "fixed-mtu" {
		mtu = 1392
	}
	if len(inbounds) != 2 || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true || tun["mtu"] != mtu || inbounds[1].(map[string]any)["type"] != "mixed" {
		t.Fatal("SOCKS REALITY lost its one strict device interface or captured MTU")
	}
	route := graph["route"].(map[string]any)
	if route["final"] != "proxy" || route["auto_detect_interface"] != true {
		t.Fatal("SOCKS REALITY final route changed")
	}
	var v6, lan, health, dnsProtocol, dnsPort bool
	for _, value := range route["rules"].([]any) {
		rule := value.(map[string]any)
		if !reflect.DeepEqual(rule["inbound"], []any{"tun-in"}) {
			t.Fatal("SOCKS REALITY device rule lost its original TUN")
		}
		switch rule["action"] {
		case "hijack-dns":
			if rule["protocol"] == "dns" && len(rule) == 3 {
				dnsProtocol = true
			} else if rule["port"] == float64(53) && len(rule) == 3 {
				dnsPort = true
			} else {
				t.Fatal("SOCKS REALITY widened its DNS interception")
			}
		case "reject":
			if rule["ip_version"] == float64(6) && len(rule) == 3 {
				v6 = true
			} else if reflect.DeepEqual(rule["ip_cidr"], []any{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}) && len(rule) == 3 {
				lan = true
			} else {
				t.Fatal("SOCKS REALITY changed its captured reject policy")
			}
		case "route":
			if rule["network"] != "tcp" || rule["port"] != float64(8787) || rule["outbound"] != "proxy" || !reflect.DeepEqual(rule["ip_cidr"], []any{"10.77.0.1/32"}) || len(rule) != 6 {
				t.Fatal("SOCKS REALITY widened its exact final proof exception")
			}
			health = true
		default:
			t.Fatal("SOCKS REALITY added an unowned device route")
		}
	}
	if !dnsProtocol || !dnsPort || v6 != (policy == "ipv6-off") || lan != (policy == "lan-off") || health != (policy == "lan-off") {
		t.Fatal("SOCKS REALITY did not apply its saved DNS/LAN/IPv6 policy")
	}
}

func TestImportedEntrySOCKSRealityVisionEncryptedDNS(t *testing.T) {
	for _, protocol := range []string{"tls", "https", "h3"} {
		for _, address := range []string{"literal", "hostname"} {
			t.Run(protocol+"/"+address, func(t *testing.T) {
				source := importedSOCKSXrayFixture(t)
				profile := externalTestRead(t, source[4])
				profile["dns_mode"], profile["dns_protocol"] = "custom", protocol
				profile["dns_host"], profile["dns_port"] = "203.0.113.53", 8853
				profile["dns_server_name"], profile["dns_path"] = "resolver.example.net", "/owned-dns-query"
				if address == "hostname" {
					profile["dns_host"] = "resolver.example.net"
					profile["dns_mode"] = map[string]string{"tls": "dot", "https": "doh", "h3": "doh3"}[protocol]
					source[6] = externalTestJSON(t, map[string]any{"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "203.0.113.54", "server_port": 5354, "detour": "proxy"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "timeout": "3s", "disable_cache": true}})
				}
				source[4] = externalTestJSON(t, profile)
				selected, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
				if err != nil {
					t.Fatal(err)
				}
				plan := importedSOCKSXrayCompile(t, source)
				if !reflect.DeepEqual(externalTestRead(t, plan.Config())["dns"], externalTestRead(t, selected.Config())["dns"]) {
					t.Fatal("SOCKS REALITY changed encrypted DNS or its captured bootstrap")
				}
			})
		}
	}
}

func TestImportedEntrySOCKSRealityVisionRejectsChangedSources(t *testing.T) {
	for _, fault := range []string{"entry-credential", "entry-route", "entry-version", "fake-entry-proof", "fake-entry-api", "same-id", "final-not-paired", "missing-final-proof", "missing-final-token", "missing-xray", "foreign-wrapper", "xray-bypass", "xray-plaintext", "mode-mismatch", "server", "compare", "unused-start", "foreign-bootstrap"} {
		t.Run(fault, func(t *testing.T) {
			source := importedSOCKSXrayFixture(t)
			graph, capture, profile := externalTestRead(t, source[0]), externalTestRead(t, source[1]), externalTestRead(t, source[4])
			entry := externalTestFind(t, graph, ExternalFinalTag)
			assets, xray, _ := importedSOCKSXrayRaw(t, source[3])
			switch fault {
			case "entry-credential":
				entry["password"] = "foreign-entry-password"
			case "entry-route":
				entry["server"] = "203.0.113.99"
			case "entry-version":
				entry["version"] = "4a"
			case "fake-entry-proof":
				capture["profile"].(map[string]any)["node_proof_id"] = strings.Repeat("a", 64)
			case "fake-entry-api":
				capture["profile"].(map[string]any)["router_api"] = "http://10.93.0.1:8787"
			case "same-id":
				profile["id"] = capture["exit_id"]
			case "final-not-paired":
				profile["node_kind"] = "external"
			case "missing-final-proof":
				delete(profile, "node_proof_id")
			case "missing-final-token":
				delete(profile, "api_token")
			case "missing-xray":
				delete(assets, "xray.json")
			case "foreign-wrapper":
				body, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
				wrapper := externalTestRead(t, string(body))
				wrapper["outbounds"].([]any)[0].(map[string]any)["server_port"] = 2090
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, wrapper)))
			case "xray-bypass":
				xray["routing"] = map[string]any{"domainStrategy": "AsIs"}
			case "xray-plaintext":
				xray["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["security"] = "none"
			case "mode-mismatch":
				assetsText, _ := xrayEntryFixture(t, "reality-pq-vision")
				_ = json.Unmarshal([]byte(assetsText), &assets)
			case "server":
				profile["multihop_execution"] = "server"
			case "compare":
				profile["multihop_execution"] = "auto"
			case "unused-start":
				source[5] = "{}"
			case "foreign-bootstrap":
				source[6] = `{"server":{"type":"udp","tag":"external-dns-bootstrap","server":"203.0.113.54","detour":"direct"},"query":{"server":"external-dns-bootstrap"}}`
			}
			if fault == "xray-bypass" || fault == "xray-plaintext" {
				assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, xray)))
			}
			source[0], source[1], source[3], source[4] = externalTestJSON(t, graph), externalTestJSON(t, capture), externalTestJSON(t, assets), externalTestJSON(t, profile)
			if _, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil {
				t.Fatal("changed SOCKS REALITY original source was accepted")
			}
		})
	}
}

func TestImportedEntrySOCKSRealityVisionKeepsScope(t *testing.T) {
	for _, mode := range []string{"reality-pq-vision", "reality-xhttp", "split", "max"} {
		t.Run("final-"+mode, func(t *testing.T) {
			source := importedSOCKSXrayFixture(t)
			files, profile, start := nodeProfileFixture(t, mode, "")
			if _, err := NewNodeProfile(mode, files, externalTestJSON(t, profile), start, ""); err != nil {
				t.Fatal("unsupported-final control did not begin with a valid original node", err)
			}
			// PQ/XHTTP require their exact assets; retain this
			// required scope verdict as an ordinary-under-native downgrade rejection.
			if mode == "reality-pq-vision" || mode == "reality-xhttp" {
				files, _, _ = nodeProfileFixture(t, "reality-vision", "")
			}
			if _, err := NewImportedEntry(source[0], source[1], mode, files, externalTestJSON(t, profile), start, ""); err == nil {
				t.Fatal("SOCKS REALITY admitted a different final family")
			}
		})
	}
	for _, protocol := range []string{"shadowsocks", "hysteria2", "wireguard", "amneziawg", "http-connect", "https-connect", "openvpn"} {
		t.Run("entry-"+protocol, func(t *testing.T) {
			source := importedSOCKSXrayFixture(t)
			var graph, capture string
			switch protocol {
			case "shadowsocks", "hysteria2":
				entry := importedProxyXrayFixture(t, protocol, "off", "off")
				graph, capture = entry[0], entry[1]
			case "amneziawg":
				entry := importedPacketFixture(t, protocol, "shadowsocks", "", "")
				graph, capture = entry[0], entry[1]
			case "openvpn":
				entry := importedOpenVPNFixture(t, "tcp", "shadowsocks", "", "")
				graph, capture = entry[0], entry[1]
			default:
				g, c := externalTestFixture(t, protocol, "")
				graph, capture = externalTestJSON(t, g), externalTestJSON(t, c)
			}
			projection := externalTestRead(t, capture)
			projection["profile"].(map[string]any)["dns_mode"] = "rescue"
			delete(projection, "dns_bootstrap")
			if _, err := NewExternalPolicy(graph, externalTestJSON(t, projection)); err != nil {
				t.Fatal("unsupported-entry control did not begin with a valid original import", err)
			}
			plan, err := NewImportedEntry(graph, capture, source[2], source[3], source[4], source[5], source[6])
			if err != nil {
				t.Fatal("REALITY refused a valid independently captured entry", err)
			}
			defer plan.Close()
			if plan.meta.EntryMode != protocol || plan.meta.EntryKind != "external" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.EntryNodeID != "" {
				t.Fatal("REALITY entry acquired a different transport or Router proof authority")
			}
			if (protocol == "http-connect" || protocol == "https-connect") && plan.meta.TransportCapability != "vless-stream" {
				t.Fatal("CONNECT acquired the wrong captured transport capability")
			}
			if protocol == "wireguard" || protocol == "amneziawg" || protocol == "openvpn" {
				// Keep the old named scope witnesses and prove the expanded
				// packet admission still cannot manufacture Router ownership.
				foreign := externalTestRead(t, capture)
				foreign["profile"].(map[string]any)["api_token"] = "foreign-paired-authority"
				if changed, err := NewImportedEntry(graph, externalTestJSON(t, foreign), source[2], source[3], source[4], source[5], source[6]); err == nil {
					_ = changed.Close()
					t.Fatal("packet REALITY entry acquired fabricated paired authority")
				}
			}
		})
	}

}

func TestImportedEntrySOCKSRealityVisionRetainsOriginalBytes(t *testing.T) {
	source := importedSOCKSXrayFixture(t)
	plan := importedSOCKSXrayCompile(t, source)
	for _, row := range []struct {
		name  string
		index int
	}{{"entry-graph", 0}, {"entry-capture", 1}, {"final-assets", 3}, {"final-profile", 4}} {
		t.Run(row.name, func(t *testing.T) {
			changed := append([]string(nil), source...)
			changed[row.index] += "\n"
			next := importedSOCKSXrayCompile(t, changed)
			if next.SourceSHA256() == plan.SourceSHA256() || next.Config() != plan.Config() {
				t.Fatal("equivalent graph replaced the exact captured source authority")
			}
		})
	}
}

// Each role retains its own provision and the final layer is attached above the
// original imported owner, never bypassed or substituted with the entry layer.
func TestImportedEntrySOCKSRealityVisionIndependentLayers(t *testing.T) {
	for _, row := range importedSOCKSLayerMatrix("reality-vision") {
		t.Run(row.label, func(t *testing.T) {
			source := importedSOCKSXrayFixture(t, row.entry, row.final)
			selected, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
			if err != nil {
				t.Fatal("original REALITY layer source was invalid", err)
			}
			plan := importedSOCKSXrayCompile(t, source)
			graph := externalTestRead(t, plan.Config())
			graph["endpoints"] = []any{}
			importedSOCKSAssertClosure(t, graph, row)
			first, final := externalTestFind(t, graph, "entry-wg"), externalTestFind(t, graph, LocalTag)
			selectedGraph := externalTestRead(t, selected.Config())
			selectedGraph["endpoints"] = []any{}
			original := externalTestFind(t, selectedGraph, "proxy")
			if final["config_json"] != original["config_json"] || final["mode"] != "reality-vision" || final["type"] != "routervpn-xray" || len(final) != 5 {
				t.Fatal("SOCKS REALITY layer changed exact native final credentials")
			}
			if row.final == "" {
				if final["detour"] != "entry-wg" {
					t.Fatal("SOCKS REALITY Off final changed original owner")
				}
			} else {
				if final["detour"] != applexray.StartLayerTag {
					t.Fatal("SOCKS REALITY final layer lost its original authenticated edge")
				}
				outer := externalTestFind(t, graph, applexray.StartLayerTag)
				expected := externalTestFind(t, selectedGraph, applexray.StartLayerTag)
				copy := predecessorCopy(outer)
				delete(copy, "detour")
				if outer["detour"] != "entry-wg" || !reflect.DeepEqual(copy, expected) {
					t.Fatal("SOCKS REALITY final layer borrowed a different provision or owner")
				}
				if row.entry != "" {
					entryOuter := externalTestFind(t, graph, first["detour"].(string))
					if entryOuter["password"] == outer["password"] || entryOuter["server"] == outer["server"] || entryOuter["tag"] == outer["tag"] {
						t.Fatal("SOCKS REALITY independent layers collapsed into one node")
					}
				}
			}
			if !reflect.DeepEqual(graph["dns"], selectedGraph["dns"]) || plan.meta.EntryStartLayer != row.entry || strings.TrimSuffix(plan.meta.ExitStartLayer, "off") != row.final || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.Execution != "local" || plan.Healthy() {
				t.Fatal("SOCKS REALITY layer changed DNS, captured policy, or proof ownership")
			}
			importedSOCKSXrayDevicePolicy(t, graph, "default-home")
			for _, index := range []int{0, 1, 3, 4, 5} {
				if source[index] == "" {
					continue
				}
				changed := append([]string(nil), source...)
				changed[index] += "\n"
				next := importedSOCKSXrayCompile(t, changed)
				if next.Config() != plan.Config() || next.SourceSHA256() == plan.SourceSHA256() {
					t.Fatal("SOCKS REALITY layer lost original private source authority")
				}
			}
			if _, err := New(plan.Config(), plan.Metadata()); err == nil {
				t.Fatal("SOCKS REALITY layer public metadata acquired authority")
			}
			if directory := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); directory != "" {
				receipt := append(append([]string(nil), source...), plan.SourceSHA256(), plan.Config())
				if err := os.WriteFile(filepath.Join(directory, "socks5--final-"+row.label+".json"), []byte(externalTestJSON(t, receipt)), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestImportedEntrySOCKSRealityVisionLayerAuthority(t *testing.T) {
	for _, fault := range []string{"entry-missing", "entry-mismatch", "entry-foreign", "entry-off-unused", "entry-invalid", "final-missing", "final-foreign", "final-off-unused", "final-invalid", "entry-detour", "final-wrapper-detour", "final-xray-bypass", "server", "compare"} {
		t.Run(fault, func(t *testing.T) {
			source := importedSOCKSXrayFixture(t, "aes-256-gcm+xor-whitening", "aes-256-gcm")
			_ = importedSOCKSXrayCompile(t, source)
			capture, profile := externalTestRead(t, source[1]), externalTestRead(t, source[4])
			entry := capture["profile"].(map[string]any)
			external := entry["external"].(map[string]any)
			switch fault {
			case "entry-missing":
				delete(external, "start_layer")
			case "entry-mismatch":
				entry["start_layer"] = "aes-256-gcm"
			case "entry-foreign":
				external["start_layer"].(map[string]any)["transport"].(map[string]any)["server"] = "203.0.113.99"
			case "entry-off-unused":
				entry["start_layer"] = "off"
			case "entry-invalid":
				entry["start_layer"] = "xor-only"
			case "final-missing":
				source[5] = ""
			case "final-foreign":
				assets := map[string]string{}
				if json.Unmarshal([]byte(source[5]), &assets) != nil {
					t.Fatal("missing original final layer")
				}
				raw, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
				graph := externalTestRead(t, string(raw))
				graph["outbounds"].([]any)[0].(map[string]any)["server"] = "203.0.113.99"
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, graph)))
				source[5] = externalTestJSON(t, assets)
			case "final-off-unused":
				profile["start_layer"] = "off"
			case "final-invalid":
				profile["start_layer"] = "xor-only"
			case "entry-detour":
				graph := externalTestRead(t, source[0])
				externalTestFind(t, graph, ExternalFinalTag)["detour"] = "foreign-owner"
				source[0] = externalTestJSON(t, graph)
			case "final-wrapper-detour", "final-xray-bypass":
				assets, xray, _ := importedSOCKSXrayRaw(t, source[3])
				if fault == "final-wrapper-detour" {
					raw, _ := base64.StdEncoding.Strict().DecodeString(assets["sing-box.json"])
					wrapper := externalTestRead(t, string(raw))
					wrapper["outbounds"].([]any)[0].(map[string]any)["detour"] = "foreign-owner"
					assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, wrapper)))
				} else {
					xray["routing"] = map[string]any{"domainStrategy": "AsIs"}
					assets["xray.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, xray)))
				}
				source[3] = externalTestJSON(t, assets)
			case "server":
				profile["multihop_execution"] = "server"
			case "compare":
				profile["multihop_execution"] = "auto"
			}
			source[1], source[4] = externalTestJSON(t, capture), externalTestJSON(t, profile)
			if plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil || plan != nil {
				t.Fatal("SOCKS REALITY accepted an unowned independent layer")
			}
		})
	}
}
