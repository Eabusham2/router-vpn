package mobilemultihop

import (
	"os"
	"path/filepath"
	"testing"
)

func importedSOCKSLayerFixture(t *testing.T, final, layer string) []string {
	t.Helper()
	source := importedSOCKSFixture(t, final)
	files, profile, start := nodeProfileFixture(t, final, layer)
	profile["id"], profile["daita_host"] = "paired-final", "10.77.0.1"
	source[3], source[4], source[5] = files, externalTestJSON(t, profile), start
	return source
}
func TestImportedEntrySOCKSPairedFinalLayers(t *testing.T) {
	for _, final := range []string{"shadowsocks", "hysteria2"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(final+"/"+layer, func(t *testing.T) {
				source := importedSOCKSLayerFixture(t, final, layer)
				plan := importedPacketCompile(t, source)
				graph := externalTestRead(t, plan.Config())
				graph["endpoints"] = []any{}
				entry := externalTestFind(t, graph, "entry-wg")
				last := externalTestFind(t, graph, LocalTag)
				outer := last
				if final == "hysteria2" {
					outer = externalTestFind(t, graph, NativeStartLayerTag)
					if last["detour"] != NativeStartLayerTag || last["server"] != "127.0.0.1" {
						t.Fatal("final private layer edge changed")
					}
				}
				kind := "shadowsocks"
				if layer == "aes-256-gcm+xor-whitening" {
					kind = "routervpn-aes-xor"
				}
				if entry["type"] != "socks" || entry["detour"] != nil || outer["type"] != kind || outer["method"] != NativeStartLayerMethod || outer["detour"] != "entry-wg" || entry["password"] == outer["password"] {
					t.Fatal("independent SOCKS and paired layer owners changed")
				}
				if plan.meta.EntryStartLayer != "" || plan.meta.ExitStartLayer != layer || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.ExitAPI == "" || plan.meta.ExitToken == "" {
					t.Fatal("independent proof or layer metadata changed")
				}
				if _, err := New(plan.Config(), plan.Metadata()); err == nil {
					t.Fatal("layer metadata acquired imported authority")
				}
				if dir := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); dir != "" {
					source = append(source, plan.SourceSHA256(), plan.Config())
					if err := os.WriteFile(filepath.Join(dir, "socks5--final-"+final+"--"+layer+".json"), []byte(externalTestJSON(t, source)), 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
func TestImportedEntrySOCKSLayerBoundaries(t *testing.T) {
	for _, fault := range []string{"missing-final-source", "foreign-final-source", "unused-final-source", "packet-final-layer", "entry-layer"} {
		t.Run(fault, func(t *testing.T) {
			source := importedSOCKSLayerFixture(t, "hysteria2", "aes-256-gcm+xor-whitening")
			switch fault {
			case "missing-final-source":
				source[5] = ""
			case "foreign-final-source":
				source[5] = `{}`
			case "unused-final-source":
				source = importedSOCKSLayerFixture(t, "shadowsocks", "aes-256-gcm")
				source[5] = source[3]
			case "packet-final-layer":
				source = importedSOCKSLayerFixture(t, "wg", "aes-256-gcm")
			case "entry-layer":
				capture := externalTestRead(t, source[1])
				externalTestAddLayer(capture["profile"].(map[string]any), "aes-256-gcm", "203.0.113.20", "10.93.0.1", "i")
				source[1] = externalTestJSON(t, capture)
			}
			if p, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6]); err == nil || p != nil {
				t.Fatal("unowned layer graph admitted")
			}
		})
	}
}
