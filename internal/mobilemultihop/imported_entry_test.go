package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func importedEntryFixture(t *testing.T, entryLayer, exitLayer string) (string, string, string, string) {
	t.Helper()
	graph, capture := externalTestFixture(t, "shadowsocks", "")
	out := externalTestFind(t, graph, ExternalFinalTag)
	out["method"] = NativeStartLayerMethod
	out["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("i", 32)))
	p := capture["profile"].(map[string]any)
	ext := p["external"].(map[string]any)
	ss := ext["shadowsocks"].(map[string]any)
	ss["method"] = out["method"]
	ss["password"] = out["password"]
	p["dns_mode"] = "home" // Not the selected final resolver; no invented Home API.
	if entryLayer != "" {
		externalTestAddLayer(p, entryLayer, "203.0.113.20", "10.93.0.1", "i")
	}
	files, profile, _ := nodeProfileFixture(t, "shadowsocks", exitLayer)
	profile["id"] = "paired-final"
	profile["daita_host"] = "10.77.0.1"
	return externalTestJSON(t, graph), externalTestJSON(t, capture), files, externalTestJSON(t, profile)
}
func TestImportedEntryPairedFinalCompleteLayers(t *testing.T) {
	for _, entryLayer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, exitLayer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(entryLayer+"/"+exitLayer, func(t *testing.T) {
				config, capture, files, profile := importedEntryFixture(t, entryLayer, exitLayer)
				c, err := NewImportedEntry(config, capture, "shadowsocks", files, profile, "", "")
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, c.Config())
				graph["endpoints"] = []any{}
				entry := externalTestFind(t, graph, "entry-wg")
				last := externalTestFind(t, graph, LocalTag)
				if entry == nil || last == nil || last["detour"] != "entry-wg" || len(c.SourceSHA256()) != 64 || c.meta.EntryKind != "external" || c.meta.EntryNodeID != "" || c.meta.EntryAPI != "" || c.meta.EntryToken != "" {
					t.Fatal("imported entry acquired a paired identity or lost actual chain")
				}
				if entryLayer != "" && entry["detour"] == nil {
					t.Fatal("entry layer bypassed")
				}
				if exitLayer == "aes-256-gcm+xor-whitening" && last["type"] == "shadowsocks" {
					t.Fatal("final whitening lost")
				}
				if _, err := New(c.Config(), c.Metadata()); err == nil {
					t.Fatal("metadata alone acquired imported authority")
				}
				dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["server"] != "192.168.50.133" || dns["detour"] != "proxy" {
					t.Fatal("final selected DNS changed")
				}
				if directory := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); directory != "" {
					label := func(s string) string {
						if s == "" {
							return "off"
						}
						return s
					}
					raw, _ := json.Marshal([]string{config, capture, "shadowsocks", files, profile, "", "", c.SourceSHA256(), c.Config()})
					if err := os.WriteFile(filepath.Join(directory, label(entryLayer)+"--"+label(exitLayer)+".json"), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
				again, err := NewImportedEntry(config, capture, "shadowsocks", files, profile, "", "")
				if err != nil || again.Config() != c.Config() || again.SourceSHA256() != c.SourceSHA256() {
					t.Fatal("immutable capture not deterministic")
				}
			})
		}
	}
}
func TestImportedEntryPairedFinalRejectsChangedAuthority(t *testing.T) {
	cases := map[string]func(map[string]any, map[string]any){
		"fake-entry-proof":      func(c, p map[string]any) { c["profile"].(map[string]any)["node_proof_id"] = strings.Repeat("a", 64) },
		"fake-entry-api":        func(c, p map[string]any) { c["profile"].(map[string]any)["router_api"] = "http://10.77.0.1:8787" },
		"server":                func(c, p map[string]any) { p["multihop_execution"] = "server" },
		"same-id":               func(c, p map[string]any) { p["id"] = c["exit_id"] },
		"final-not-paired":      func(c, p map[string]any) { delete(p, "node_proof_id") },
		"wrong-entry-public-ip": func(c, p map[string]any) { c["expected_public_ip"] = "198.51.100.1" },
		"conflicting-mtu": func(c, p map[string]any) {
			a := c["profile"].(map[string]any)
			a["mtu_policy"] = "fixed"
			a["manual_mtu"] = 1400
			p["mtu_policy"] = "fixed"
			p["manual_mtu"] = 1500
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config, capture, files, profile := importedEntryFixture(t, "", "")
			a, b := externalTestRead(t, capture), externalTestRead(t, profile)
			mutate(a, b)
			if _, err := NewImportedEntry(config, externalTestJSON(t, a), "shadowsocks", files, externalTestJSON(t, b), "", ""); err == nil {
				t.Fatal("changed capture admitted")
			}
		})
	}
}

func TestImportedEntryPairedFinalPolicyAndCipherOwnership(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			config, capture, files, profile := importedEntryFixture(t, "", "")
			a, b := externalTestRead(t, config), externalTestRead(t, capture)
			n := externalTestFind(t, a, ExternalFinalTag)
			size := 32
			if method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			password := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", size)))
			n["method"], n["password"] = method, password
			ss := b["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
			ss["method"], ss["password"] = method, password
			c, err := NewImportedEntry(externalTestJSON(t, a), externalTestJSON(t, b), "shadowsocks", files, profile, "", "")
			if err != nil {
				t.Fatal(err)
			}
			if directory := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); directory != "" && method != NativeStartLayerMethod {
				label := "cipher-aes128"
				if method == "2022-blake3-chacha20-poly1305" {
					label = "cipher-chacha20"
				}
				raw, _ := json.Marshal([]string{externalTestJSON(t, a), externalTestJSON(t, b), "shadowsocks", files, profile, "", "", c.SourceSHA256(), c.Config()})
				if err := os.WriteFile(filepath.Join(directory, label+".json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			graph := externalTestRead(t, c.Config())
			graph["endpoints"] = []any{}
			out := externalTestFind(t, graph, "entry-wg")
			if out["method"] != method || out["password"] != password {
				t.Fatal("imported cipher or original key changed")
			}
		})
	}
	for _, policy := range []string{"entry-fixed", "entry-jumbo", "entry-cover-refused", "paired-final-cover"} {
		t.Run(policy, func(t *testing.T) {
			config, capture, files, profile := importedEntryFixture(t, "", "")
			a, b := externalTestRead(t, capture), externalTestRead(t, profile)
			entry := a["profile"].(map[string]any)
			switch policy {
			case "entry-fixed":
				entry["mtu_policy"] = "fixed"
				entry["manual_mtu"] = 1400
			case "entry-jumbo":
				entry["jumbo_tun"] = true
			case "entry-cover-refused":
				entry["daita_enabled"] = true
			case "paired-final-cover":
				b["daita_enabled"] = true
				b["daita_host"] = "10.77.0.1"
				b["daita_rate_kbps"] = 64
			}
			c, err := NewImportedEntry(config, externalTestJSON(t, a), "shadowsocks", files, externalTestJSON(t, b), "", "")
			if policy == "entry-cover-refused" {
				if err == nil {
					t.Fatal("unpaired entry gained Router cover authority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			graph := externalTestRead(t, c.Config())
			tun := graph["inbounds"].([]any)[0].(map[string]any)
			if policy == "entry-fixed" && (tun["mtu"] != float64(1400) || externalTestRead(t, c.MTUProfile())["mtu_policy"] != "fixed") {
				t.Fatal("entry fixed MTU overwritten by final Auto")
			}
			if policy == "entry-jumbo" && (tun["mtu"] != float64(9000) || externalTestRead(t, c.MTUProfile())["jumbo_tun"] != true) {
				t.Fatal("shared proxy Jumbo lost")
			}
			if policy == "paired-final-cover" {
				services, _ := graph["services"].([]any)
				if len(services) != 1 || services[0].(map[string]any)["proof_tag"] != "proxy" {
					t.Fatal("final paired cover lost or bypassed")
				}
			}
		})
	}
}

func TestImportedEntryLegacyPairedFinalKeepsOriginalSource(t *testing.T) {
	for _, kind := range []string{"absent", "empty", "null", "number", "external", "unpaired"} {
		t.Run(kind, func(t *testing.T) {
			config, capture, files, profile := importedEntryFixture(t, "", "")
			original, err := NewImportedEntry(config, capture, "shadowsocks", files, profile, "", "")
			if err != nil {
				t.Fatal(err)
			}
			p := externalTestRead(t, profile)
			switch kind {
			case "absent":
				delete(p, "node_kind")
			case "empty":
				p["node_kind"] = ""
			case "null":
				p["node_kind"] = nil
			case "number":
				p["node_kind"] = 1
			case "external":
				p["node_kind"] = "external"
			case "unpaired":
				delete(p, "node_kind")
				delete(p, "node_proof_id")
			}
			raw := externalTestJSON(t, p)
			changed, err := NewImportedEntry(config, capture, "shadowsocks", files, raw, "", "")
			if kind != "absent" && kind != "empty" {
				if err == nil {
					t.Fatal("normalization manufactured pairing authority")
				}
				return
			}
			if err != nil || changed.Config() != original.Config() || changed.SourceSHA256() == original.SourceSHA256() || raw != externalTestJSON(t, p) {
				t.Fatal("legacy compiler projection lost original byte identity or changed selected graph", err)
			}
		})
	}
}
