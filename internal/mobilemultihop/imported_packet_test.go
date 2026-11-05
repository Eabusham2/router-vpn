package mobilemultihop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/mobilemtu"
	"strings"
	"testing"
)

func importedPacketFixture(t *testing.T, protocol, finalMode, entryLayer, finalLayer string) []string {
	t.Helper()
	graph, capture := externalTestFixture(t, "wireguard", "")
	if protocol == "amneziawg" {
		externalAmneziaReplace(t, graph, capture, false, "")
	}
	profile := capture["profile"].(map[string]any)
	profile["dns_mode"] = "home"
	endpoint := externalTestFind(t, graph, ExternalFinalTag)
	peer := endpoint["peers"].([]any)[0].(map[string]any)
	if entryLayer != "" {
		externalTestAddLayer(profile, entryLayer, peer["address"].(string), "10.93.0.1", "i")
	}
	files, final, start := nodeProfileFixture(t, finalMode, finalLayer)
	final["id"], final["daita_host"] = "paired-final", "10.77.0.1"
	if finalMode == "shadowsocks" {
		start = ""
	}
	return []string{externalTestJSON(t, graph), externalTestJSON(t, capture), finalMode, files, externalTestJSON(t, final), start, ""}
}
func importedPacketCompile(t *testing.T, source []string) *Controller {
	t.Helper()
	p, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestImportedEntryPacketCompleteGraphs(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, finalMode := range []string{"shadowsocks", "hysteria2"} {
			for _, entryLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, finalLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					label := "packet-" + protocol + "--final-" + finalMode + "--" + entryLayer + "--" + finalLayer
					t.Run(label, func(t *testing.T) {
						normalize := func(s string) string {
							if s == "off" {
								return ""
							}
							return s
						}
						source := importedPacketFixture(t, protocol, finalMode, normalize(entryLayer), normalize(finalLayer))
						plan := importedPacketCompile(t, source)
						graph := externalTestRead(t, plan.Config())
						if endpoints, ok := graph["endpoints"].([]any); !ok || len(endpoints) != 1 {
							t.Fatal("original packet endpoint closure missing")
						}
						entry := externalTestFind(t, graph, "entry-wg")
						original := externalTestFind(t, externalTestRead(t, source[0]), ExternalFinalTag)
						if len(graph["endpoints"].([]any)) != 1 || !reflect.DeepEqual(entry["private_key"], original["private_key"]) || !reflect.DeepEqual(entry["address"], original["address"]) || !reflect.DeepEqual(entry["amnezia"], original["amnezia"]) || entry["mtu"] != original["mtu"] {
							t.Fatal("original packet endpoint/key/address/parameters/MTU was lost")
						}
						if plan.meta.EntryKind != "external" || plan.meta.EntryMode != protocol || plan.meta.ExitMode != finalMode || plan.meta.EntryAPI != "" || plan.meta.EntryNodeID != "" || plan.meta.EntryToken != "" {
							t.Fatal("packet entry acquired paired authority")
						}
						peer := entry["peers"].([]any)[0].(map[string]any)
						originalPeer := original["peers"].([]any)[0].(map[string]any)
						for _, key := range []string{"public_key", "pre_shared_key", "allowed_ips", "persistent_keepalive_interval"} {
							if !reflect.DeepEqual(peer[key], originalPeer[key]) {
								t.Fatal("packet peer changed", key)
							}
						}
						if entryLayer == "off" {
							if entry["detour"] != nil || !reflect.DeepEqual(peer, originalPeer) {
								t.Fatal("unlayered physical peer changed")
							}
						} else {
							wrapper := externalTestFind(t, graph, entry["detour"].(string))
							if wrapper["detour"] != nil || wrapper["server"] != originalPeer["address"] {
								t.Fatal("packet outer layer lost original physical underlay")
							}
							if peer["address"] == originalPeer["address"] {
								t.Fatal("packet layer failed to retain private inside destination")
							}
						}
						final := externalTestFind(t, graph, LocalTag)
						outer := final
						if finalMode == "hysteria2" && finalLayer != "off" {
							if final["detour"] != NativeStartLayerTag {
								t.Fatal("inner final chain overwritten")
							}
							outer = externalTestFind(t, graph, NativeStartLayerTag)
						}
						if outer["detour"] != "entry-wg" {
							t.Fatal("final bypassed original packet entry")
						}
						dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
						if dns["server"] != "192.168.50.133" || dns["detour"] != "proxy" {
							t.Fatal("predecessor DNS replaced selected final")
						}
						if _, err := New(plan.Config(), plan.Metadata()); err == nil {
							t.Fatal("metadata minted packet ownership")
						}
						mtu, err := mobilemtu.NewPlan(plan.Config(), 1280)
						if err != nil {
							t.Fatal(err)
						}
						changed, err := mtu.Config(1400)
						if err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(externalTestFind(t, externalTestRead(t, changed), "entry-wg"), entry) {
							t.Fatal("proxy TUN candidate rewrote captured packet endpoint")
						}
						if dir := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); dir != "" {
							raw, _ := json.Marshal(append(source, plan.SourceSHA256(), plan.Config()))
							if err := os.WriteFile(filepath.Join(dir, label+".json"), raw, 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
}
func TestImportedEntryPacketSourceAndMTUOwnership(t *testing.T) {
	for _, fault := range []string{"private-key", "public-key", "psk", "address", "allowed-ips", "endpoint", "keepalive", "awg-parameter", "system", "foreign-endpoint", "entry-fixed", "entry-jumbo", "retained-source"} {
		t.Run(fault, func(t *testing.T) {
			protocol := "wireguard"
			if fault == "awg-parameter" {
				protocol = "amneziawg"
			}
			source := importedPacketFixture(t, protocol, "shadowsocks", "", "")
			graph, capture := externalTestRead(t, source[0]), externalTestRead(t, source[1])
			endpoint := externalTestFind(t, graph, ExternalFinalTag)
			peer := endpoint["peers"].([]any)[0].(map[string]any)
			profile := capture["profile"].(map[string]any)
			switch fault {
			case "private-key":
				endpoint["private_key"] = strings.Repeat("A", 44)
			case "public-key":
				peer["public_key"] = strings.Repeat("A", 44)
			case "psk":
				delete(peer, "pre_shared_key")
			case "address":
				endpoint["address"] = []string{"10.94.0.2/32"}
			case "allowed-ips":
				peer["allowed_ips"] = []string{"192.0.2.0/24"}
			case "endpoint":
				peer["address"] = "198.51.100.27"
			case "keepalive":
				peer["persistent_keepalive_interval"] = float64(24)
			case "awg-parameter":
				endpoint["amnezia"].(map[string]any)["s4"] = "33"
			case "system":
				endpoint["system"] = true
			case "foreign-endpoint":
				graph["endpoints"] = append(graph["endpoints"].([]any), map[string]any{"type": "direct", "tag": "foreign"})
			case "entry-fixed":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1360)
			case "entry-jumbo":
				profile["jumbo_tun"] = true
			case "retained-source":
				profile["name"] = "same transport new captured source"
			}
			source[0], source[1] = externalTestJSON(t, graph), externalTestJSON(t, capture)
			plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
			if fault == "entry-fixed" {
				if err != nil {
					t.Fatal(err)
				}
				g := externalTestRead(t, plan.Config())
				if externalTestFind(t, g, "entry-wg")["mtu"] != float64(1360) || g["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1280) {
					t.Fatal("packet fixed MTU changed proxy TUN")
				}
				return
			}
			if fault == "retained-source" {
				if err != nil {
					t.Fatal(err)
				}
				old := importedPacketCompile(t, importedPacketFixture(t, protocol, "shadowsocks", "", ""))
				if old.SourceSHA256() == plan.SourceSHA256() {
					t.Fatal("captured packet source change ignored")
				}
				return
			}
			if err == nil {
				t.Fatal("foreign packet source acquired ownership")
			}
		})
	}
}
