package mobilemultihop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func importedHysteriaFixture(t *testing.T, entryLayer, finalLayer string) (string, string, string, string) {
	t.Helper()
	graph, capture := externalTestFixture(t, "hysteria2", "")
	entry := externalTestFind(t, graph, ExternalFinalTag)
	entry["tls"].(map[string]any)["server_name"] = "captured-external.example"
	profile := capture["profile"].(map[string]any)
	external := profile["external"].(map[string]any)
	external["hysteria2"].(map[string]any)["tls_server_name"] = "captured-external.example"
	profile["dns_mode"] = "home"
	if entryLayer != "" {
		externalTestAddLayer(profile, entryLayer, "203.0.113.20", "10.93.0.1", "i")
	}
	_, _, files, final := importedEntryFixture(t, "", finalLayer)
	return externalTestJSON(t, graph), externalTestJSON(t, capture), files, final
}

func TestImportedEntryHysteriaPairedFinalCompleteLayers(t *testing.T) {
	for _, a := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, b := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(a+"/"+b, func(t *testing.T) {
				layer := func(v string) string {
					if v == "off" {
						return ""
					}
					return v
				}
				config, capture, files, profile := importedHysteriaFixture(t, layer(a), layer(b))
				source := []string{config, capture, "shadowsocks", files, profile, "", ""}
				plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, plan.Config())
				graph["endpoints"] = []any{}
				first, last := externalTestFind(t, graph, "entry-wg"), externalTestFind(t, graph, LocalTag)
				if first["type"] != "hysteria2" || first["password"] != "selected-secret-e" || first["tls"].(map[string]any)["server_name"] != "captured-external.example" || last["detour"] != "entry-wg" {
					t.Fatal("original QUIC/TLS/password chain changed")
				}
				if plan.meta.EntryMode != "hysteria2" || plan.meta.EntryKind != "external" || plan.meta.EntryNodeID != "" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.EntryStartLayer != layer(a) || plan.meta.ExitStartLayer != layer(b) {
					t.Fatal("imported protocol, independent layers or identity changed")
				}
				if a != "off" && first["detour"] == nil {
					t.Fatal("imported QUIC bypassed its original layer")
				}
				if b == "aes-256-gcm+xor-whitening" && last["type"] == "shadowsocks" {
					t.Fatal("final whitening bypassed")
				}
				dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["server"] != "192.168.50.133" || dns["detour"] != "proxy" {
					t.Fatal("imported DNS replaced selected final resolver")
				}
				if _, err := New(plan.Config(), plan.Metadata()); err == nil {
					t.Fatal("metadata manufactured imported authority")
				}
				again, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
				if err != nil || again.Config() != plan.Config() || again.SourceSHA256() != plan.SourceSHA256() {
					t.Fatal("captured source is not stable", err)
				}
				if directory := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); directory != "" {
					raw, _ := json.Marshal(append(source, plan.SourceSHA256(), plan.Config()))
					if err := os.WriteFile(filepath.Join(directory, "hysteria2--"+a+"--"+b+".json"), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestImportedEntryHysteriaRejectsChangedSource(t *testing.T) {
	for _, fault := range []string{"password", "server", "tls-name", "tls-disabled", "tls-insecure", "foreign-protocol", "missing-layer", "changed-layer", "paired-identity", "server-execution"} {
		t.Run(fault, func(t *testing.T) {
			layer := ""
			if fault == "missing-layer" || fault == "changed-layer" {
				layer = "aes-256-gcm"
			}
			config, capture, files, profile := importedHysteriaFixture(t, layer, "")
			graph, selected, final := externalTestRead(t, config), externalTestRead(t, capture), externalTestRead(t, profile)
			first := externalTestFind(t, graph, ExternalFinalTag)
			p := selected["profile"].(map[string]any)
			ext := p["external"].(map[string]any)
			switch fault {
			case "password":
				first["password"] = "foreign-secret"
			case "server":
				first["server"] = "192.0.2.98"
			case "tls-name":
				first["tls"].(map[string]any)["server_name"] = "foreign.example"
			case "tls-disabled":
				first["tls"].(map[string]any)["enabled"] = false
			case "tls-insecure":
				first["tls"].(map[string]any)["insecure"] = true
			case "foreign-protocol":
				selected["protocol"] = "wireguard"
			case "missing-layer":
				delete(ext, "start_layer")
			case "changed-layer":
				ext["start_layer"].(map[string]any)["mode"] = "aes-256-gcm+xor-whitening"
			case "paired-identity":
				p["router_api"] = "http://10.93.0.1:8787"
			case "server-execution":
				final["multihop_execution"] = "server"
			}
			if _, err := NewImportedEntry(externalTestJSON(t, graph), externalTestJSON(t, selected), "shadowsocks", files, externalTestJSON(t, final), "", ""); err == nil {
				t.Fatal("changed imported QUIC source acquired a native plan")
			}
		})
	}
}
