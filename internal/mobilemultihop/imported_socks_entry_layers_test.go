package mobilemultihop

import (
	"os"
	"path/filepath"
	"testing"
)

func importedSOCKSEntryLayerFixture(t *testing.T, mode, layer string) []string {
	t.Helper()
	s := importedSOCKSFixture(t, mode)
	c := externalTestRead(t, s[1])
	externalTestAddLayer(c["profile"].(map[string]any), layer, "203.0.113.20", "10.93.0.1", "i")
	s[1] = externalTestJSON(t, c)
	return s
}
func TestImportedEntrySOCKSEntryLayers(t *testing.T) {
	for _, mode := range []string{"shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				s := importedSOCKSEntryLayerFixture(t, mode, layer)
				p := importedPacketCompile(t, s)
				g := externalTestRead(t, p.Config())
				if g["endpoints"] == nil {
					g["endpoints"] = []any{}
				}
				first := externalTestFind(t, g, "entry-wg")
				last := externalTestFind(t, g, LocalTag)
				outer := externalTestFind(t, g, first["detour"].(string))
				kind := "shadowsocks"
				if layer == "aes-256-gcm+xor-whitening" {
					kind = "routervpn-aes-xor"
				}
				if first["type"] != "socks" || first["server"] != "10.93.0.1" || first["server_port"] != float64(443) || first["username"] != "captured-native-user" || first["password"] != "selected-password-e" || outer["type"] != kind || outer["server"] != "203.0.113.20" || outer["detour"] != nil || last["detour"] != "entry-wg" {
					t.Fatal("captured entry layer or independent final changed")
				}
				if p.meta.EntryStartLayer != layer || p.meta.ExitStartLayer != "" || p.meta.EntryAPI != "" || p.meta.EntryToken != "" || p.meta.ExitAPI == "" {
					t.Fatal("entry provision acquired paired authority")
				}
				if _, err := New(p.Config(), p.Metadata()); err == nil {
					t.Fatal("metadata acquired imported owner")
				}
				if dir := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); dir != "" {
					s = append(s, p.SourceSHA256(), p.Config())
					if err := os.WriteFile(filepath.Join(dir, "socks5--final-"+mode+"--entry-"+layer+".json"), []byte(externalTestJSON(t, s)), 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
func TestImportedEntrySOCKSEntryLayerAuthority(t *testing.T) {
	for _, fault := range []string{"missing-provision", "foreign-outer", "public-private-target", "mode-mismatch", "unused-provision", "both-layers", "invented-proof", "retained-source"} {
		t.Run(fault, func(t *testing.T) {
			s := importedSOCKSEntryLayerFixture(t, "shadowsocks", "aes-256-gcm+xor-whitening")
			if fault == "both-layers" {
				s = importedSOCKSFixture(t, "hysteria2", "aes-256-gcm+xor-whitening", "aes-256-gcm")
				_ = importedPacketCompile(t, s) // Independently provisioned both-layer source is valid.
			}
			c := externalTestRead(t, s[1])
			p := c["profile"].(map[string]any)
			ext := p["external"].(map[string]any)
			layer := ext["start_layer"].(map[string]any)
			switch fault {
			case "missing-provision":
				delete(ext, "start_layer")
			case "foreign-outer":
				layer["transport"].(map[string]any)["server"] = "203.0.113.99"
			case "public-private-target":
				layer["api"] = "http://203.0.113.20:8787"
			case "mode-mismatch":
				layer["mode"] = "aes-256-gcm"
			case "unused-provision":
				p["start_layer"] = "off"
			case "both-layers":
				s[5] = "" // The captured paired outer provision is mandatory.
			case "invented-proof":
				p["api_token"] = "invented"
			}
			s[1] = externalTestJSON(t, c)
			plan, err := NewImportedEntry(s[0], s[1], s[2], s[3], s[4], s[5], s[6])
			if fault != "retained-source" {
				if err == nil || plan != nil {
					t.Fatal("unowned entry layer admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			again := importedPacketCompile(t, s)
			if again.Config() != plan.Config() || again.SourceSHA256() != plan.SourceSHA256() {
				t.Fatal("captured source changed")
			}
		})
	}
}
