package mobilemultihop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/nativeopenvpn"
	"strings"
	"testing"
)

func importedOpenVPNFixture(t *testing.T, network, mode, entryLayer, finalLayer string) []string {
	t.Helper()
	graph, capture := externalTestFixture(t, "hysteria2", "")
	externalOpenVPNReplace(t, graph, capture, false, network)
	profile := capture["profile"].(map[string]any)
	transport := profile["external"].(map[string]any)["openvpn"].(map[string]any)
	transport["config"] = "client\ndev tun\nproto " + network + "\nremote 203.0.113.24 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint " + strings.Repeat("ab", 32) + "\ntun-mtu 1500\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
	compiled, err := nativeopenvpn.CompileEndpoint(transport["config"].(string), transport["username"].(string), transport["password"].(string), ExternalFinalTag, "")
	if err != nil {
		t.Fatal(err)
	}
	graph["endpoints"] = []any{externalTestRead(t, compiled)}
	if entryLayer != "" {
		externalTestAddLayer(profile, entryLayer, "203.0.113.24", "10.93.0.1", "j")
	}
	final := importedSOCKSFixture(t, mode, "", finalLayer)
	final[0], final[1] = externalTestJSON(t, graph), externalTestJSON(t, capture)
	return final
}
func TestImportedOpenVPNCompleteLayerMatrix(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, mode := range []string{"shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong"} {
			for _, a := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, b := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					t.Run(network+"/"+mode+"/"+a+"/"+b, func(t *testing.T) {
						source := importedOpenVPNFixture(t, network, mode, a, b)
						plan := importedPacketCompile(t, source)
						graph := externalTestRead(t, plan.Config())
						first := externalTestFind(t, graph, "entry-wg")
						if first["type"] != externalOpenVPNType || first["system"] != false || first["mtu"] != float64(1500) || plan.imported.openvpnMTU != 1500 || !plan.hasImportedOpenVPN() || plan.meta.EntryMode != "openvpn" || plan.meta.EntryAPI != "" || plan.meta.EntryNodeID != "" || plan.meta.EntryToken != "" {
							t.Fatal("OpenVPN source acquired system/private authority or lost capacity")
						}
						if !reflect.DeepEqual(first, plan.imported.openvpnTransport) {
							t.Fatal("receipt authority differs from the exact compiled native entry")
						}
						if first["username"] != " captured user " || first["password"] != " captured secret " || plan.meta.EntryStartLayer != a || plan.meta.ExitStartLayer != b {
							t.Fatal("independent source/layer credentials changed")
						}
						if _, err := New(plan.Config(), plan.Metadata()); err == nil {
							t.Fatal("metadata alone acquired imported OpenVPN authority")
						}
						final := externalTestFind(t, graph, LocalTag)
						if mode == "wg" || strings.HasPrefix(mode, "awg2-") {
							if final["mtu"].(float64) >= 1500 {
								t.Fatal("packet final omitted full nested capacity")
							}
						}
						mtu, err := mobilemtu.NewPlan(plan.Config(), 1280)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := mtu.Config(mtu.Ceiling + 1); err == nil {
							t.Fatal("MTU admitted a candidate beyond captured nested capacity")
						}
						changed, err := mtu.Config(mtu.Ceiling)
						if err != nil {
							t.Fatal(err)
						}
						after := externalTestFind(t, externalTestRead(t, changed), "entry-wg")
						if !reflect.DeepEqual(first, after) {
							t.Fatal("application TUN retune changed imported packet endpoint")
						}
						if directory := os.Getenv("ROUTERVPN_IMPORTED_OPENVPN_FIXTURES"); directory != "" {
							name := "openvpn--" + network + "--final-" + mode + "--" + importedOpenVPNLayerName(a) + "--" + importedOpenVPNLayerName(b) + ".json"
							raw, _ := json.Marshal(append(source, plan.SourceSHA256(), plan.Config()))
							if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
								t.Fatal(err)
							}
						}

					})
				}
			}
		}
	}
}
func TestImportedOpenVPNRejectsUnownedSourceAndCapacity(t *testing.T) {
	for _, fault := range []string{"system", "script", "remote", "password", "missing-layer", "foreign-layer", "missing-final-layer", "insufficient-entry", "fixed-final", "entry-jumbo", "final-jumbo", "invented-proof"} {
		t.Run(fault, func(t *testing.T) {
			source := importedOpenVPNFixture(t, "udp", "awg2-strong", "aes-256-gcm", "aes-256-gcm+xor-whitening")
			graph, capture, final := externalTestRead(t, source[0]), externalTestRead(t, source[1]), externalTestRead(t, source[4])
			profile := capture["profile"].(map[string]any)
			ext := profile["external"].(map[string]any)
			raw := ext["openvpn"].(map[string]any)
			endpoint := externalTestFind(t, graph, ExternalFinalTag)
			switch fault {
			case "system":
				endpoint["system"] = true
			case "script":
				raw["config"] = raw["config"].(string) + "up arbitrary-command\n"
			case "remote":
				endpoint["server"] = "203.0.113.99"
			case "password":
				raw["password"] = "replacement"
			case "missing-layer":
				delete(ext, "start_layer")
			case "foreign-layer":
				ext["start_layer"].(map[string]any)["transport"].(map[string]any)["server"] = "203.0.113.99"
			case "missing-final-layer":
				source[5] = ""
			case "insufficient-entry":
				raw["config"] = strings.Replace(raw["config"].(string), "tun-mtu 1500", "tun-mtu 1280", 1)
				compiled, err := nativeopenvpn.CompileEndpoint(raw["config"].(string), raw["username"].(string), raw["password"].(string), ExternalFinalTag, "")
				if err != nil {
					t.Fatal(err)
				}
				graph["endpoints"] = []any{externalTestRead(t, compiled)}
			case "fixed-final":
				final["mtu_policy"], final["manual_mtu"] = "fixed", float64(1500)
			case "entry-jumbo":
				profile["jumbo_tun"] = true
			case "final-jumbo":
				final["jumbo_tun"] = true
			case "invented-proof":
				profile["node_proof_id"] = strings.Repeat("a", 64)
			}
			source[0], source[1], source[4] = externalTestJSON(t, graph), externalTestJSON(t, capture), externalTestJSON(t, final)
			plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
			if err == nil || plan != nil {
				t.Fatal("unowned OpenVPN source/capacity admitted")
			}
		})
	}
}

func importedOpenVPNSourceTransport(t *testing.T, source []string) map[string]any {
	t.Helper()
	var capture externalPolicyCapture
	if json.Unmarshal([]byte(source[1]), &capture) != nil {
		t.Fatal("capture")
	}
	return capture.Profile["external"].(map[string]any)["openvpn"].(map[string]any)
}

func importedOpenVPNLayerName(mode string) string {
	if mode == "" {
		return "off"
	}
	return mode
}
