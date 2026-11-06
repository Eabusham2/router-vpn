package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func importedSOCKSFixture(t *testing.T, final string, layers ...string) []string {
	entryLayer, finalLayer := "", ""
	if len(layers) == 2 {
		entryLayer, finalLayer = layers[0], layers[1]
	}
	t.Helper()
	if entryLayer != "" && finalLayer == "" {
		return importedSOCKSEntryLayerFixture(t, final, entryLayer)
	}
	// Preserve the published six packet-final sources, including distinct Fast parameters.
	if entryLayer == "" && finalLayer != "" && (final == "wg" || final == "awg2-fast" || final == "awg2-strong") {
		return importedSOCKSPacketLayerFixture(t, final, finalLayer)
	}
	graph, capture := externalTestFixture(t, "socks5", "")
	transport := externalTestFind(t, graph, ExternalFinalTag)
	transport["username"] = "captured-native-user"
	profile := capture["profile"].(map[string]any)
	profile["dns_mode"] = "home"
	profile["external"].(map[string]any)["socks5"].(map[string]any)["username"] = transport["username"]
	if entryLayer != "" {
		externalTestAddLayer(profile, entryLayer, "203.0.113.20", "10.93.0.1", "j")
	}
	files, last, start := nodeProfileFixture(t, final, finalLayer)
	if start != "" && (final == "wg" || final == "awg2-fast" || final == "awg2-strong") {
		var assets map[string]string
		_ = json.Unmarshal([]byte(start), &assets)
		raw, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
		outer := externalTestRead(t, string(raw))
		outer["outbounds"].([]any)[0].(map[string]any)["server"] = last["endpoint"]
		assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, outer)))
		start = externalTestJSON(t, assets)
	}
	last["id"], last["daita_host"] = "paired-final", "10.77.0.1"
	return []string{externalTestJSON(t, graph), externalTestJSON(t, capture), final, files, externalTestJSON(t, last), start, ""}
}

type importedSOCKSLayers struct{ label, entry, final string }

func importedSOCKSLayerMatrix(mode string) []importedSOCKSLayers {
	var rows []importedSOCKSLayers
	for _, a := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, b := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			label, entry, final := mode, a, b
			if a != "off" || b != "off" {
				label += "--" + a + "--" + b
			}
			if a == "off" && b != "off" {
				label = mode + "--" + b
			}
			if a != "off" && b == "off" {
				label = mode + "--entry-" + a
			}
			if a == "off" {
				entry = ""
			}
			if b == "off" {
				final = ""
			}
			rows = append(rows, importedSOCKSLayers{label, entry, final})
		}
	}
	return rows
}
func importedSOCKSAssertClosure(t *testing.T, graph map[string]any, r importedSOCKSLayers) {
	t.Helper()
	entry := externalTestFind(t, graph, "entry-wg")
	outer := externalTestFind(t, graph, LocalTag)
	for depth := 0; outer["detour"] != "entry-wg"; depth++ {
		if depth > 2 {
			t.Fatal("final layer did not terminate at original SOCKS entry")
		}
		tag, ok := outer["detour"].(string)
		if !ok || tag == "" {
			t.Fatal("final escaped retained entry")
		}
		outer = externalTestFind(t, graph, tag)
	}
	if r.entry == "" {
		if entry["detour"] != nil {
			t.Fatal("Off entry acquired wrapper")
		}
		return
	}
	if entry["server"] != "10.93.0.1" {
		t.Fatal("entry did not retain provisioned private inner host")
	}
	tag, ok := entry["detour"].(string)
	if !ok {
		t.Fatal("entry wrapper absent")
	}
	wrapper := externalTestFind(t, graph, tag)
	key := "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj"
	if r.final == "" {
		key = "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
	}
	if wrapper["server"] != "203.0.113.20" || wrapper["detour"] != nil || wrapper["password"] != base64.StdEncoding.EncodeToString([]byte(key)) {
		t.Fatal("entry layer borrowed final credentials or physical route")
	}
}

func TestImportedEntrySOCKSPairedFinalGraphs(t *testing.T) {
	for _, final := range []string{"shadowsocks", "hysteria2"} {
		for _, r := range importedSOCKSLayerMatrix(final) {
			t.Run(r.label, func(t *testing.T) {
				source := importedSOCKSFixture(t, final, r.entry, r.final)
				plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, plan.Config())
				graph["endpoints"] = []any{}
				entry := externalTestFind(t, graph, "entry-wg")
				importedSOCKSAssertClosure(t, graph, r)
				if entry["type"] != "socks" || entry["version"] != "5" || entry["username"] != "captured-native-user" || entry["password"] != "selected-password-e" {
					t.Fatal("SOCKS source or encrypted final detour changed")
				}
				if plan.meta.EntryMode != "socks5" || plan.meta.EntryKind != "external" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" {
					t.Fatal("ordinary SOCKS entry acquired paired authority")
				}
				if _, err = New(plan.Config(), plan.Metadata()); err == nil {
					t.Fatal("metadata alone acquired imported SOCKS authority")
				}
				if dir := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); dir != "" {
					source = append(source, plan.SourceSHA256(), plan.Config())
					if err = os.WriteFile(filepath.Join(dir, "socks5--final-"+r.label+".json"), []byte(externalTestJSON(t, source)), 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}

}

func TestImportedEntrySOCKSRejectsChangedSource(t *testing.T) {
	for _, fault := range []string{"username", "password", "server", "port", "version", "paired-identity", "unsupported-final", "server-execution", "entry-layer", "final-layer", "entry-layer-unprovisioned", "entry-layer-mismatch", "final-layer-unprovisioned"} {
		t.Run(fault, func(t *testing.T) {
			s := importedSOCKSFixture(t, "hysteria2")
			graph, capture, profile := externalTestRead(t, s[0]), externalTestRead(t, s[1]), externalTestRead(t, s[4])
			entry := externalTestFind(t, graph, ExternalFinalTag)
			switch fault {
			case "username", "password", "server":
				entry[fault] = "foreign"
			case "port":
				entry["server_port"] = 444
			case "version":
				entry["version"] = "4a"
			case "paired-identity":
				capture["profile"].(map[string]any)["node_proof_id"] = "invented"
			case "unsupported-final":
				s[2] = "max"
			case "entry-layer":
				externalTestAddLayer(capture["profile"].(map[string]any), "aes-256-gcm", "203.0.113.20", "10.93.0.1", "i")
				delete(capture["profile"].(map[string]any)["external"].(map[string]any), "start_layer")
			case "entry-layer-unprovisioned":
				capture["profile"].(map[string]any)["start_layer"] = "aes-256-gcm"
			case "entry-layer-mismatch":
				externalTestAddLayer(capture["profile"].(map[string]any), "aes-256-gcm", "203.0.113.99", "10.93.0.1", "j")
			case "final-layer":
				profile["start_layer"] = "foreign-layer"
			case "final-layer-unprovisioned":
				profile["start_layer"] = "aes-256-gcm"
			case "server-execution":
				profile["multihop_execution"] = "server"
			}
			if _, err := NewImportedEntry(externalTestJSON(t, graph), externalTestJSON(t, capture), s[2], s[3], externalTestJSON(t, profile), s[5], s[6]); err == nil {
				t.Fatal("changed original SOCKS source admitted")
			}
		})
	}
}
