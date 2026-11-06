package mobilemultihop

import (
	"reflect"
	"router-vpn/internal/mobilemtu"
	"strconv"
	"testing"
)

func TestImportedEntrySOCKSBothLayerMTURetention(t *testing.T) {
	for _, mode := range []string{"shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong"} {
		for _, first := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, last := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(mode+"/"+first+"/"+last, func(t *testing.T) {
					source := importedSOCKSFixture(t, mode, first, last)
					plan := importedPacketCompile(t, source)
					graph := externalTestRead(t, plan.Config())
					if graph["endpoints"] == nil {
						graph["endpoints"] = []any{}
					}
					entry := externalTestFind(t, graph, "entry-wg")
					final := externalTestFind(t, graph, LocalTag)
					entryOuter := externalTestFind(t, graph, entry["detour"].(string))
					finalOuter := final
					if mode != "shadowsocks" {
						finalOuter = externalTestFind(t, graph, final["detour"].(string))
					}
					if entryOuter["detour"] != nil || finalOuter["detour"] != "entry-wg" || entryOuter["password"] == finalOuter["password"] || entry["server"] != "10.93.0.1" || plan.meta.EntryStartLayer != first || plan.meta.ExitStartLayer != last || plan.meta.EntryAPI != "" || plan.meta.EntryToken != "" {
						t.Fatal("independent layer or proof owner changed")
					}
					mtu, err := mobilemtu.NewPlan(plan.Config(), 1280)
					if err != nil {
						t.Fatal(err)
					}
					candidate := min(1392, mtu.Ceiling)
					tuned, err := mtu.Config(candidate)
					if err != nil {
						t.Fatal(err)
					}
					changed := externalTestRead(t, tuned)
					for _, key := range []string{"outbounds", "endpoints", "dns", "route"} {
						original := graph[key]
						if key == "endpoints" && changed[key] == nil {
							original = nil
						}
						if !reflect.DeepEqual(original, changed[key]) {
							t.Fatal("MTU retune changed encrypted graph", key)
						}
					}
					if mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" {
						bounds, err := ImportedSOCKSPacketBounds(plan.Config())
						if err != nil {
							t.Fatal(err)
						}
						if plan.meta.SOCKSDatagramBoundState != "configured-unmeasured" || plan.meta.SOCKSDatagramDataMax != strconv.Itoa(bounds.DataMax) || plan.meta.SOCKSDatagramControlMax != strconv.Itoa(bounds.ControlMax) || bounds.IPUDPBytes != 28 || bounds.UDPPayloadMax != 65507 || bounds.DataMax <= int(final["mtu"].(float64)) || bounds.ControlMax < 900+28 {
							t.Fatal("serialization bound misreported as path evidence", bounds)
						}
					}
					if _, err := New(plan.Config(), plan.Metadata()); err == nil {
						t.Fatal("metadata acquired imported owner")
					}

				})
			}
		}
	}
}
func TestImportedEntrySOCKSBothLayerBounds(t *testing.T) {
	for _, fault := range []string{"ipv6-carrier", "port53-control", "entry-eih", "final-eih", "invalid-key", "missing-final-layer", "changed-entry-owner"} {
		t.Run(fault, func(t *testing.T) {
			source := importedSOCKSFixture(t, "awg2-strong", "aes-256-gcm+xor-whitening", "aes-256-gcm")
			plan := importedPacketCompile(t, source)
			graph := externalTestRead(t, plan.Config())
			base, err := ImportedSOCKSPacketBounds(plan.Config())
			if err != nil {
				t.Fatal(err)
			}
			final := externalTestFind(t, graph, LocalTag)
			outer := externalTestFind(t, graph, NativeStartLayerTag)
			entry := externalTestFind(t, graph, "entry-wg")
			carrier := externalTestFind(t, graph, entry["detour"].(string))
			switch fault {
			case "ipv6-carrier":
				carrier["server"] = "2001:db8::20"
			case "port53-control":
				final["peers"].([]any)[0].(map[string]any)["port"] = float64(53)
			case "entry-eih":
				carrier["password"] = carrier["password"].(string) + ":" + carrier["password"].(string)
			case "final-eih":
				outer["password"] = outer["password"].(string) + ":" + outer["password"].(string)
			case "invalid-key":
				carrier["password"] = "bad"
			case "missing-final-layer":
				final["detour"] = "entry-wg"
			case "changed-entry-owner":
				carrier["detour"] = NativeStartLayerTag
			}
			bound, err := ImportedSOCKSPacketBounds(externalTestJSON(t, graph))
			if fault == "invalid-key" || fault == "missing-final-layer" || fault == "changed-entry-owner" {
				if err == nil {
					t.Fatal("unowned serialization bound accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "ipv6-carrier":
				if bound.IPUDPBytes != 48 || bound.UDPPayloadMax != 65527 || bound.DataMax != base.DataMax+20 {
					t.Fatal("IPv6 serialization length changed", base, bound)
				}
			case "port53-control":
				if bound.ControlMax < base.ControlMax {
					t.Fatal("control padding lost")
				}
			default:
				if bound.DataMax <= base.DataMax {
					t.Fatal("identity header omitted", base, bound)
				}
			}
		})
	}
}
