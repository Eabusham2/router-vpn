package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/mobilemtu"
	"strings"
	"testing"
)

func importedPacketFinalFixture(t *testing.T, protocol, method, mode, entryLayer, finalLayer string) []string {
	t.Helper()
	args := importedHysteriaFinalFixture(t, protocol, method, entryLayer, "")
	files, profile, start := nodeProfileFixture(t, mode, finalLayer)
	profile["id"], profile["daita_host"] = "paired-final", "10.77.0.1"
	if start != "" {
		var assets map[string]string
		_ = json.Unmarshal([]byte(start), &assets)
		raw, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
		graph := externalTestRead(t, string(raw))
		graph["outbounds"].([]any)[0].(map[string]any)["server"] = profile["endpoint"]
		assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, graph)))
		start = externalTestJSON(t, assets)
	}

	// Distinct captured parameter sets exercise actual padding preservation, not
	// a mode label applied to the same plain WireGuard endpoint.
	if mode == "awg2-fast" {
		var assets map[string]string
		_ = json.Unmarshal([]byte(files), &assets)
		raw, _ := base64.StdEncoding.DecodeString(assets["awg.conf"])
		raw = []byte(strings.ReplaceAll(strings.ReplaceAll(string(raw), "S4=32", "S4=16"), "Jc=3", "Jc=1"))
		assets["awg.conf"] = base64.StdEncoding.EncodeToString(raw)
		files = externalTestJSON(t, assets)
	}
	args[2], args[3], args[4], args[5] = mode, files, externalTestJSON(t, profile), start
	return args
}

func TestImportedEntryPacketFinalCompleteGraphs(t *testing.T) {
	type row struct{ label, protocol, method, entry, final string }
	var rows []row
	layer := func(s string) string {
		if s == "off" {
			return ""
		}
		return s
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
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, r := range rows {
			name := "final-" + mode + "--" + r.label
			t.Run(name, func(t *testing.T) {
				args := importedPacketFinalFixture(t, r.protocol, r.method, mode, r.entry, r.final)
				plan, err := NewImportedEntry(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, plan.Config())
				final := externalTestFind(t, graph, LocalTag)
				want := "wireguard"
				if mode != "wg" {
					want = AmneziaType
				}
				if final["type"] != want || final["system"] != false || plan.meta.EntryKind != "external" || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" || plan.meta.ExitMode != mode || plan.meta.EntryMode != r.protocol {
					t.Fatal("packet final or distinct original proof ownership changed")
				}
				baseline, err := NewNodeProfile(mode, args[3], args[4], args[5], args[6])
				if err != nil {
					t.Fatal(err)
				}
				original := externalTestFind(t, externalTestRead(t, baseline.Config()), "proxy")
				compare := predecessorCopy(final)
				compare["tag"] = "proxy"
				if r.final == "" {
					delete(compare, "detour")
				}
				if !reflect.DeepEqual(compare, original) {
					t.Fatal("packet final original keys, peer, address, MTU or parameters changed")
				}
				outer := final
				if r.final != "" {
					if final["detour"] != NativeStartLayerTag || args[5] == "" {
						t.Fatal("packet final inner layer chain overwritten")
					}
					outer = externalTestFind(t, graph, NativeStartLayerTag)
					if r.final == "aes-256-gcm+xor-whitening" && outer["type"] != "routervpn-aes-xor" {
						t.Fatal("final whitening lost")
					}
				}
				if outer["detour"] != "entry-wg" {
					t.Fatal("packet final bypassed captured proxy entry")
				}
				if mode != "wg" {
					runtime, e := AmneziaRuntimeConfig(externalTestJSON(t, final))
					if e != nil {
						t.Fatal(e)
					}
					padding := 32
					if mode == "awg2-fast" {
						padding = 16
					}
					if runtime.TransportPadding != padding {
						t.Fatal("actual AWG transport overhead lost")
					}
				}
				if plan.meta.EntryStartLayer != r.entry || plan.meta.ExitStartLayer != r.final {
					t.Fatal("independent layer metadata changed")
				}
				dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["server"] != "192.168.50.133" || dns["detour"] != "proxy" {
					t.Fatal("selected DNS bypassed paired packet final")
				}
				mtu, e := mobilemtu.NewPlan(plan.Config(), 1280)
				if e != nil {
					t.Fatal(e)
				}
				retuned, e := mtu.Config(1392)
				if e != nil {
					t.Fatal(e)
				}
				if externalTestRead(t, retuned)["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1392) || !reflect.DeepEqual(externalTestFind(t, externalTestRead(t, retuned), LocalTag), final) {
					t.Fatal("TUN retune altered original final packet endpoint")
				}
				if _, e := New(plan.Config(), plan.Metadata()); e == nil {
					t.Fatal("metadata acquired imported ownership")
				}
				again, e := NewImportedEntry(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
				if e != nil || again.SourceSHA256() != plan.SourceSHA256() || again.Config() != plan.Config() {
					t.Fatal("source compilation changed", e)
				}
				if dir := os.Getenv("ROUTERVPN_IMPORTED_ENTRY_FIXTURES"); dir != "" {
					raw, _ := json.Marshal(append(args, plan.SourceSHA256(), plan.Config()))
					if e := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0600); e != nil {
						t.Fatal(e)
					}
				}
			})
		}
	}
}

func TestImportedEntryPacketFinalOwnershipAndMTU(t *testing.T) {
	for _, fault := range []string{"packet-wg", "packet-awg", "missing-start", "wrapped-start", "foreign-start", "missing-proof", "wrong-wg-peer", "wrong-final-kind", "final-jumbo", "entry-jumbo", "fixed-final", "fixed-entry-conflict", "retained-source"} {
		t.Run(fault, func(t *testing.T) {
			args := importedPacketFinalFixture(t, "shadowsocks", NativeStartLayerMethod, "wg", "", "aes-256-gcm")
			profile := externalTestRead(t, args[4])
			selection := externalTestRead(t, args[1])
			switch fault {
			case "packet-wg", "packet-awg":
				protocol := "wireguard"
				if fault == "packet-awg" {
					protocol = "amneziawg"
				}
				packet := importedPacketFixture(t, protocol, "shadowsocks", "", "")
				args[0], args[1] = packet[0], packet[1]
			case "missing-start":
				args[5] = ""
			case "wrapped-start":
				args[5] = externalTestJSON(t, map[string]any{"mode": "aes-256-gcm", "profile": args[5]})
			case "foreign-start":
				var assets map[string]string
				_ = json.Unmarshal([]byte(args[5]), &assets)
				raw, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
				g := externalTestRead(t, string(raw))
				g["outbounds"].([]any)[0].(map[string]any)["server"] = "192.0.2.99"
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, g)))
				args[5] = externalTestJSON(t, assets)
			case "missing-proof":
				delete(profile, "api_token")
			case "wrong-wg-peer":
				profile["node_proof_id"] = strings.Repeat("f", 64)
			case "wrong-final-kind":
				profile["node_kind"] = "external"
			case "final-jumbo":
				profile["jumbo_tun"] = true
			case "entry-jumbo":
				selection["profile"].(map[string]any)["jumbo_tun"] = true
				args[1] = externalTestJSON(t, selection)
			case "fixed-final":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1392)
			case "fixed-entry-conflict":
				profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1392)
				p := selection["profile"].(map[string]any)
				p["mtu_policy"], p["manual_mtu"] = "fixed", float64(1280)
				args[1] = externalTestJSON(t, selection)
			case "retained-source":
			}
			args[4] = externalTestJSON(t, profile)
			plan, e := NewImportedEntry(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
			if fault != "fixed-final" && fault != "retained-source" {
				if e == nil {
					t.Fatal("unowned packet-final source admitted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if fault == "fixed-final" {
				g := externalTestRead(t, plan.Config())
				if externalTestFind(t, g, LocalTag)["mtu"] != float64(1392) || g["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1392) {
					t.Fatal("fixed packet/TUN MTU lost")
				}
			}
			if fault == "retained-source" {
				args[3] += " "
				next, e := NewImportedEntry(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
				if e != nil || next.SourceSHA256() == plan.SourceSHA256() || next.Config() != plan.Config() {
					t.Fatal("original raw source identity normalized away", e)
				}
			}
		})
	}
}
