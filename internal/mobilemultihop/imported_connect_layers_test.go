package mobilemultihop

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func importedCONNECTEntryLayerFixture(t *testing.T, protocol, entryLayer, finalLayer, policy string, configured bool) []string {
	t.Helper()
	var source []string
	if configured {
		transport := "tcp"
		if policy == "home" {
			transport = "udp"
		}
		source = importedCONNECTServiceFixture(t, protocol, finalLayer, policy, transport)
	} else {
		source = importedCONNECTFixture(t, protocol, NativeStartLayerMethod, policy)
	}
	captured := externalTestRead(t, source[1])
	externalTestAddLayer(captured["profile"].(map[string]any), entryLayer, "203.0.113.20", "10.93.0.1", "i")
	source[1] = externalTestJSON(t, captured)
	return source
}

func TestImportedEntryCONNECTIndependentLayers(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, entryLayer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, finalLayer := range []string{"plain", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, policy := range []string{"home", "custom"} {
					label := protocol + "--" + entryLayer + "--" + finalLayer + "--" + policy
					t.Run(label, func(t *testing.T) {
						configured := finalLayer != "plain"
						source := importedCONNECTEntryLayerFixture(t, protocol, entryLayer, finalLayer, policy, configured)
						original := append([]string(nil), source...)
						plan := importedPacketCompile(t, source)
						graph := externalTestRead(t, plan.Config())
						graph["endpoints"] = []any{}
						entry := externalTestFind(t, graph, "entry-wg")
						final := externalTestFind(t, graph, LocalTag)
						outer := externalTestFind(t, graph, entry["detour"].(string))
						kind := "shadowsocks"
						if entryLayer == "aes-256-gcm+xor-whitening" {
							kind = "routervpn-aes-xor"
						}
						if entry["type"] != "http" || entry["server"] != "10.93.0.1" || outer["server"] != "203.0.113.20" || outer["type"] != kind || outer["detour"] != nil || outer["password"] == final["password"] || final["detour"] != "entry-wg" || plan.meta.EntryStartLayer != entryLayer || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" {
							t.Fatal("CONNECT independent entry layer changed its captured owner")
						}
						capture := externalTestRead(t, source[1])["profile"].(map[string]any)["external"].(map[string]any)
						key := "http_connect"
						if protocol == "https-connect" {
							key = "https_connect"
							if entry["tls"].(map[string]any)["server_name"] != capture[key].(map[string]any)["tls_server_name"] {
								t.Fatal("CONNECT wrapper replaced original TLS identity")
							}
						}
						credentials := capture[key].(map[string]any)
						if entry["username"] != credentials["username"] || entry["password"] != credentials["password"] || entry["server_port"] != credentials["port"] {
							t.Fatal("CONNECT wrapper replaced original authentication or port")
						}
						profile := externalTestRead(t, source[4])
						dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
						if dns["server"] != profile["dns_host"] || dns["server_port"] != profile["dns_port"] || dns["type"] != profile["dns_protocol"] || dns["detour"] != "proxy" {
							t.Fatal("CONNECT entry layer changed selected final DNS")
						}
						if configured {
							if plan.meta.TransportCapability != "uot-v2" || plan.meta.ExitStartLayer != finalLayer || !reflect.DeepEqual(final["udp_over_tcp"], map[string]any{"enabled": true, "version": float64(2)}) || final["network"] != nil {
								t.Fatal("CONNECT layer changed captured final service authority")
							}
						} else if plan.meta.TransportCapability != "tcp-only" || final["network"] != "tcp" || final["udp_over_tcp"] != nil || plan.meta.ExitStartLayer != "" {
							t.Fatal("CONNECT entry layer invented datagram/final-layer authority")
						}
						if !reflect.DeepEqual(source, original) {
							t.Fatal("CONNECT layer rewrote original source bytes")
						}
						if _, err := New(plan.Config(), plan.Metadata()); err == nil {
							t.Fatal("CONNECT metadata fabricated independent source ownership")
						}
						if directory := os.Getenv("ROUTERVPN_CONNECT_LAYER_FIXTURES"); directory != "" {
							capture := append(append([]string(nil), source...), plan.SourceSHA256(), plan.Config())
							if err := os.WriteFile(filepath.Join(directory, label+".json"), []byte(externalTestJSON(t, capture)), 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
}

func TestImportedEntryCONNECTIndependentLayerRefusals(t *testing.T) {
	for _, fault := range []string{"missing-provision", "foreign-outer", "public-inside", "mode-mismatch", "unused-provision", "borrowed-final-transport", "invented-entry-api", "server", "compare", "metadata-only"} {
		t.Run(fault, func(t *testing.T) {
			source := importedCONNECTEntryLayerFixture(t, "https-connect", "aes-256-gcm+xor-whitening", "aes-256-gcm", "home", true)
			capture := externalTestRead(t, source[1])
			profile := capture["profile"].(map[string]any)
			external := profile["external"].(map[string]any)
			layer := external["start_layer"].(map[string]any)
			switch fault {
			case "missing-provision":
				delete(external, "start_layer")
			case "foreign-outer":
				layer["transport"].(map[string]any)["server"] = "203.0.113.99"
			case "public-inside":
				layer["api"] = "http://203.0.113.20:8787"
			case "mode-mismatch":
				layer["mode"] = "aes-256-gcm"
			case "unused-provision":
				profile["start_layer"] = "off"
			case "borrowed-final-transport":
				layer["transport"].(map[string]any)["server"] = "192.0.2.1"
			case "invented-entry-api":
				profile["router_api"] = "http://10.93.0.1:8787"
			case "server", "compare":
				final := externalTestRead(t, source[4])
				final["multihop_execution"] = map[string]string{"server": "server", "compare": "auto"}[fault]
				source[4] = externalTestJSON(t, final)
			case "metadata-only":
				plan := importedPacketCompile(t, source)
				if _, err := New(plan.Config(), plan.Metadata()); err == nil {
					t.Fatal("CONNECT metadata acquired original private inputs")
				}
				return
			}
			source[1] = externalTestJSON(t, capture)
			if plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil || plan != nil {
				t.Fatal("unowned CONNECT entry layer admitted", fault)
			}
		})
	}
}
