package mobilemultihop

import (
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/mobilemtu"
	"testing"
)

func importedSOCKSPacketLayerFixture(t *testing.T, mode, layer string) []string {
	t.Helper()
	source := importedSOCKSFixture(t, mode)
	packet := importedPacketFinalFixture(t, "shadowsocks", NativeStartLayerMethod, mode, "", layer)
	source[3], source[4], source[5] = packet[3], packet[4], packet[5]
	return source
}
func TestImportedEntrySOCKSPacketFinalLayers(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				source := importedSOCKSPacketLayerFixture(t, mode, layer)
				plan := importedPacketCompile(t, source)
				graph := externalTestRead(t, plan.Config())
				last := externalTestFind(t, graph, LocalTag)
				outer := externalTestFind(t, graph, NativeStartLayerTag)
				first := externalTestFind(t, graph, "entry-wg")
				peer := last["peers"].([]any)[0].(map[string]any)
				kind := "shadowsocks"
				if layer == "aes-256-gcm+xor-whitening" {
					kind = "routervpn-aes-xor"
				}
				if first["type"] != "socks" || first["detour"] != nil || last["detour"] != NativeStartLayerTag || outer["detour"] != "entry-wg" || outer["type"] != kind || outer["server"] != "192.0.2.1" || peer["address"] != "10.77.0.1" {
					t.Fatal("captured packet layer topology changed")
				}
				baseline, err := NewNodeProfile(mode, source[3], source[4], source[5], source[6])
				if err != nil {
					t.Fatal(err)
				}
				original := externalTestFind(t, externalTestRead(t, baseline.Config()), "proxy")
				compare := predecessorCopy(last)
				compare["tag"] = "proxy"
				if !reflect.DeepEqual(compare, original) {
					t.Fatal("packet keys, address, PSK, padding or MTU changed")
				}
				mtu, err := mobilemtu.NewPlan(plan.Config(), 1280)
				if err != nil {
					t.Fatal(err)
				}
				tuned, err := mtu.Config(1280)
				if err != nil || !reflect.DeepEqual(externalTestFind(t, externalTestRead(t, tuned), LocalTag), last) {
					t.Fatal("TUN retune rewrote packet endpoint", err)
				}
				if plan.meta.EntryStartLayer != "" || plan.meta.ExitStartLayer != layer || plan.meta.EntryAPI != "" || plan.meta.ExitAPI == "" {
					t.Fatal("independent proof metadata changed")
				}
				if dir := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); dir != "" {
					source = append(source, plan.SourceSHA256(), plan.Config())
					if err := os.WriteFile(filepath.Join(dir, "socks5--final-"+mode+"--"+layer+".json"), []byte(externalTestJSON(t, source)), 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
func TestImportedEntrySOCKSPacketLayerAuthority(t *testing.T) {
	for _, fault := range []string{"missing-source", "foreign-endpoint", "private-target", "final-jumbo", "fixed-conflict", "retained-source"} {
		t.Run(fault, func(t *testing.T) {
			source := importedSOCKSPacketLayerFixture(t, "wg", "aes-256-gcm+xor-whitening")
			p := externalTestRead(t, source[4])
			entry := externalTestRead(t, source[1])
			switch fault {
			case "missing-source":
				source[5] = ""
			case "foreign-endpoint":
				p["endpoint"] = "192.0.2.99"
			case "private-target":
				p["router_api"] = "http://127.0.0.1:8787"
			case "final-jumbo":
				p["jumbo_tun"] = true
			case "fixed-conflict":
				p["mtu_policy"], p["manual_mtu"] = "fixed", float64(1392)
				e := entry["profile"].(map[string]any)
				e["mtu_policy"], e["manual_mtu"] = "fixed", float64(1280)
			}
			source[4], source[1] = externalTestJSON(t, p), externalTestJSON(t, entry)
			plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
			if fault != "retained-source" {
				if err == nil || plan != nil {
					t.Fatal("unowned packet layer admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			again := importedPacketCompile(t, source)
			if again.SourceSHA256() != plan.SourceSHA256() || again.Config() != plan.Config() {
				t.Fatal("original source changed")
			}
		})
	}
}
