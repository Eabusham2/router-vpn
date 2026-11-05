package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func importedHysteriaFinalFixture(t *testing.T, protocol, method, firstLayer, lastLayer string) []string {
	t.Helper()
	config, capture, _, _ := importedEntryFixture(t, firstLayer, "")
	if protocol == "hysteria2" {
		config, capture, _, _ = importedHysteriaFixture(t, firstLayer, "")
	} else if method != "" && method != NativeStartLayerMethod {
		graph, selection := externalTestRead(t, config), externalTestRead(t, capture)
		size := 32
		if method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", size)))
		out := externalTestFind(t, graph, ExternalFinalTag)
		out["method"], out["password"] = method, key
		selected := selection["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
		selected["method"], selected["password"] = method, key
		config, capture = externalTestJSON(t, graph), externalTestJSON(t, selection)
	}
	files, profile, start := nodeProfileFixture(t, "hysteria2", lastLayer)
	profile["id"], profile["daita_host"] = "paired-final", "10.77.0.1"
	return []string{config, capture, "hysteria2", files, externalTestJSON(t, profile), start, ""}
}

func TestImportedEntryHysteriaFinalCompleteGraphs(t *testing.T) {
	type row struct{ label, protocol, method, entry, final string }
	var rows []row
	layer := func(v string) string {
		if v == "off" {
			return ""
		}
		return v
	}
	for _, protocol := range []string{"shadowsocks", "hysteria2"} {
		for _, a := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, b := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				label := a + "--" + b
				if protocol == "hysteria2" {
					label = "hysteria2--" + label
				}
				rows = append(rows, row{label, protocol, NativeStartLayerMethod, layer(a), layer(b)})
			}
		}
	}
	rows = append(rows, row{"cipher-aes128", "shadowsocks", "2022-blake3-aes-128-gcm", "", ""}, row{"cipher-chacha20", "shadowsocks", "2022-blake3-chacha20-poly1305", "", ""})
	for _, r := range rows {
		t.Run(r.label, func(t *testing.T) {
			source := importedHysteriaFinalFixture(t, r.protocol, r.method, r.entry, r.final)
			plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
			if err != nil {
				t.Fatal(err)
			}
			graph := externalTestRead(t, plan.Config())
			graph["endpoints"] = []any{}
			final := externalTestFind(t, graph, LocalTag)
			if final["type"] != "hysteria2" || plan.meta.ExitMode != "hysteria2" || plan.meta.EntryMode != r.protocol || plan.meta.EntryKind != "external" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" {
				t.Fatal("final/entry identities or transport changed")
			}
			tls := final["tls"].(map[string]any)
			var assets map[string]string
			if json.Unmarshal([]byte(source[3]), &assets) != nil {
				t.Fatal("original final assets missing")
			}
			cert, err := base64.StdEncoding.DecodeString(assets["cert.pem"])
			if err != nil {
				t.Fatal(err)
			}
			if tls["enabled"] != true || tls["insecure"] == true || tls["server_name"] != "entry.example" || tls["certificate_path"] != nil || tls["certificate"].([]any)[0] != string(cert) || final["password"] != "entry-private-credential" {
				t.Fatal("final TLS/password original source changed")
			}
			obfs := final["obfs"].(map[string]any)
			if obfs["type"] != "salamander" || obfs["password"] != "entry-obfuscation" {
				t.Fatal("final QUIC obfuscation changed")
			}
			outer := final
			if r.final != "" {
				if final["detour"] != NativeStartLayerTag || final["server"] != "127.0.0.1" || source[5] == "" {
					t.Fatal("inner final layer chain overwritten")
				}
				outer = externalTestFind(t, graph, NativeStartLayerTag)
				if r.final == "aes-256-gcm+xor-whitening" && outer["type"] != "routervpn-aes-xor" {
					t.Fatal("final whitening lost")
				}
			} else if source[5] != "" {
				t.Fatal("unused final layer source")
			}
			if outer["detour"] != "entry-wg" || plan.meta.EntryStartLayer != r.entry || plan.meta.ExitStartLayer != r.final {
				t.Fatal("outer detour/layers do not retain selected entries")
			}
			dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if dns["server"] != "192.168.50.133" || dns["detour"] != "proxy" {
				t.Fatal("selected DNS bypassed paired final")
			}
			if _, err := New(plan.Config(), plan.Metadata()); err == nil {
				t.Fatal("metadata acquired imported ownership")
			}
			again, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
			if err != nil || again.Config() != plan.Config() || again.SourceSHA256() != plan.SourceSHA256() {
				t.Fatal("source/compiler changed", err)
			}
			if directory := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); directory != "" {
				raw, _ := json.Marshal(append(source, plan.SourceSHA256(), plan.Config()))
				if err := os.WriteFile(filepath.Join(directory, "final-hysteria2--"+r.label+".json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestImportedEntryHysteriaFinalRejectsUnownedLayerAndTrust(t *testing.T) {
	for _, fault := range []string{"missing-start", "wrapped-start", "foreign-start", "insecure-final", "missing-cert", "wrong-final-kind", "unused-start"} {
		t.Run(fault, func(t *testing.T) {
			source := importedHysteriaFinalFixture(t, "hysteria2", "", "", "aes-256-gcm")
			var assets map[string]string
			_ = json.Unmarshal([]byte(source[3]), &assets)
			raw, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
			graph := externalTestRead(t, string(raw))
			final := graph["outbounds"].([]any)[0].(map[string]any)
			switch fault {
			case "missing-start":
				source[5] = ""
			case "wrapped-start":
				source[5] = externalTestJSON(t, map[string]any{"mode": "aes-256-gcm", "profile": source[5]})
			case "foreign-start":
				var ss map[string]string
				_ = json.Unmarshal([]byte(source[5]), &ss)
				b, _ := base64.StdEncoding.DecodeString(ss["sing-box.json"])
				g := externalTestRead(t, string(b))
				g["outbounds"].([]any)[0].(map[string]any)["server"] = "192.0.2.98"
				ss["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, g)))
				source[5] = externalTestJSON(t, ss)
			case "insecure-final":
				final["tls"].(map[string]any)["insecure"] = true
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, graph)))
			case "missing-cert":
				delete(assets, "cert.pem")
			case "wrong-final-kind":
				p := externalTestRead(t, source[4])
				p["node_kind"] = "external"
				source[4] = externalTestJSON(t, p)
			case "unused-start":
				p := externalTestRead(t, source[4])
				p["start_layer"] = ""
				source[4] = externalTestJSON(t, p)
			}
			source[3] = externalTestJSON(t, assets)
			if _, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil {
				t.Fatal("unowned final trust or Start Layer acquired graph")
			}
		})
	}
}
