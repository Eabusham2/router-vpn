package mobilemultihop

import (
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/mobilemtu"
	"testing"
)

func TestImportedEntrySOCKSPacketFinalGraphs(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			source := importedSOCKSFixture(t, mode)
			plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
			if err != nil {
				t.Fatal(err)
			}
			graph := externalTestRead(t, plan.Config())
			first := externalTestFind(t, graph, "entry-wg")
			last := externalTestFind(t, graph, LocalTag)
			if first["type"] != "socks" || first["version"] != "5" || first["username"] != "captured-native-user" || first["password"] != "selected-password-e" || last["detour"] != "entry-wg" {
				t.Fatal("original SOCKS association or packet detour changed")
			}
			want := "wireguard"
			if mode != "wg" {
				want = AmneziaType
			}
			if last["type"] != want || last["system"] == true {
				t.Fatal("final did not retain its native userspace packet endpoint")
			}
			if plan.meta.EntryMode != "socks5" || plan.meta.ExitMode != mode || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" {
				t.Fatal("original metadata acquired foreign authority")
			}
			if _, err = New(plan.Config(), plan.Metadata()); err == nil {
				t.Fatal("metadata alone acquired packet owner")
			}
			baseline, e := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
			if e != nil {
				t.Fatal(e)
			}
			original := externalTestFind(t, externalTestRead(t, baseline.Config()), "proxy")
			compare := predecessorCopy(last)
			compare["tag"] = "proxy"
			delete(compare, "detour")
			if !reflect.DeepEqual(compare, original) {
				t.Fatal("original packet keys, peer, address, MTU or AWG parameters changed")
			}
			mtu, e := mobilemtu.NewPlan(plan.Config(), 1280)
			if e != nil {
				t.Fatal(e)
			}
			tuned, e := mtu.Config(1392)
			if e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(externalTestFind(t, externalTestRead(t, tuned), LocalTag), last) {
				t.Fatal("TUN retune changed original packet endpoint")
			}
			dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if dns["server"] != "192.168.50.133" || dns["detour"] != "proxy" {
				t.Fatal("selected DNS escaped final endpoint")
			}
			if dir := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); dir != "" {
				source = append(source, plan.SourceSHA256(), plan.Config())
				if err = os.WriteFile(filepath.Join(dir, "socks5--final-"+mode+".json"), []byte(externalTestJSON(t, source)), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestImportedEntrySOCKSPacketAuthorityAndMTU(t *testing.T) {
	for _, fault := range []string{"missing-proof", "wrong-wg-peer", "wrong-final-kind", "final-jumbo", "entry-jumbo", "fixed-entry-conflict", "fixed-final", "retained-source"} {
		t.Run(fault, func(t *testing.T) {
			args := importedSOCKSFixture(t, "wg")
			profile, selection := externalTestRead(t, args[4]), externalTestRead(t, args[1])
			switch fault {
			case "missing-proof":
				delete(profile, "api_token")
			case "wrong-wg-peer":
				profile["node_proof_id"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			case "wrong-final-kind":
				profile["node_kind"] = "external"
			case "final-jumbo":
				profile["jumbo_tun"] = true
			case "entry-jumbo":
				selection["profile"].(map[string]any)["jumbo_tun"] = true
			case "fixed-entry-conflict":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1392)
				p := selection["profile"].(map[string]any)
				p["mtu_policy"], p["manual_mtu"] = "fixed", float64(1280)
			case "fixed-final":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1392)
			}
			args[1], args[4] = externalTestJSON(t, selection), externalTestJSON(t, profile)
			plan, err := NewImportedEntry(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
			if fault != "fixed-final" && fault != "retained-source" {
				if err == nil {
					t.Fatal("changed packet authority or conflicting MTU admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if fault == "fixed-final" {
				graph := externalTestRead(t, plan.Config())
				if externalTestFind(t, graph, LocalTag)["mtu"] != float64(1392) || graph["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1392) {
					t.Fatal("fixed endpoint/TUN MTU changed")
				}
			}
			again, err := NewImportedEntry(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
			if err != nil || again.Config() != plan.Config() || again.SourceSHA256() != plan.SourceSHA256() {
				t.Fatal("original source lost", err)
			}
		})
	}
}
