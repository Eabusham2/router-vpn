package mobilemultihop

import (
	"os"
	"path/filepath"
	"testing"
)

func importedSOCKSFixture(t *testing.T, final string) []string {
	t.Helper()
	graph, capture := externalTestFixture(t, "socks5", "")
	transport := externalTestFind(t, graph, ExternalFinalTag)
	transport["username"] = "captured-native-user"
	profile := capture["profile"].(map[string]any)
	profile["dns_mode"] = "home"
	profile["external"].(map[string]any)["socks5"].(map[string]any)["username"] = transport["username"]
	files, last, start := nodeProfileFixture(t, final, "")
	last["id"], last["daita_host"] = "paired-final", "10.77.0.1"
	return []string{externalTestJSON(t, graph), externalTestJSON(t, capture), final, files, externalTestJSON(t, last), start, ""}
}

func TestImportedEntrySOCKSPairedFinalGraphs(t *testing.T) {
	for _, final := range []string{"shadowsocks", "hysteria2"} {
		t.Run(final, func(t *testing.T) {
			source := importedSOCKSFixture(t, final)
			plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
			if err != nil {
				t.Fatal(err)
			}
			graph := externalTestRead(t, plan.Config())
			graph["endpoints"] = []any{}
			entry := externalTestFind(t, graph, "entry-wg")
			last := externalTestFind(t, graph, LocalTag)
			if entry["type"] != "socks" || entry["version"] != "5" || entry["username"] != "captured-native-user" || entry["password"] != "selected-password-e" || last["detour"] != "entry-wg" {
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
				if err = os.WriteFile(filepath.Join(dir, "socks5--final-"+final+".json"), []byte(externalTestJSON(t, source)), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestImportedEntrySOCKSRejectsChangedSource(t *testing.T) {
	for _, fault := range []string{"username", "password", "server", "port", "version", "paired-identity", "unsupported-final", "server-execution", "entry-layer", "final-layer"} {
		t.Run(fault, func(t *testing.T) {
			s := importedSOCKSFixture(t, "shadowsocks")
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
			case "final-layer":
				profile["start_layer"] = "foreign-layer"
			case "server-execution":
				profile["multihop_execution"] = "server"
			}
			if _, err := NewImportedEntry(externalTestJSON(t, graph), externalTestJSON(t, capture), s[2], s[3], externalTestJSON(t, profile), s[5], s[6]); err == nil {
				t.Fatal("changed original SOCKS source admitted")
			}
		})
	}
}
