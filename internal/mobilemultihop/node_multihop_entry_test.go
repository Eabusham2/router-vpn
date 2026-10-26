package mobilemultihop

import (
	"reflect"
	"testing"

	"router-vpn/internal/nativecomposite"
)

func TestNodeMultihopEntryCatalogRetainsEveryCompleteNativeFamily(t *testing.T) {
	modes := NodeMultihopEntryModes()
	if len(modes) != 19 {
		t.Fatal("entry catalog lost a complete native family")
	}
	seen := map[string]bool{}
	for _, mode := range modes {
		if seen[mode] || !NodeMultihopEntryMode(mode) || !NodeProfileMode(mode) {
			t.Fatal("entry catalog contains a duplicate or unimplemented raw graph", mode)
		}
		seen[mode] = true
	}
	for _, mode := range predecessorFamilies {
		if !seen[mode] {
			t.Fatal("existing native predecessor omitted from entry catalog", mode)
		}
	}
	for _, mode := range []string{"", "auto", "smart-auto", "all", "custom", "WG", " wg", "wireguard", "awg", "socks5", "openvpn"} {
		if NodeMultihopEntryMode(mode) {
			t.Fatal("ambiguous label replaced an exact raw entry", mode)
		}
	}
	modes[0] = "foreign-owner"
	if !NodeMultihopEntryMode("wg") {
		t.Fatal("a caller mutated the shared entry catalog")
	}
}

func TestNodeMultihopEntryOwnersPreserveAllNativeDependencies(t *testing.T) {
	for _, mode := range NodeMultihopEntryModes() {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				entry := multihopNodeFixture(t, mode, layer, "entry")
				before := entry.Config()
				owners, err := entry.MultihopEntryOwners()
				if err != nil {
					t.Fatal(err)
				}
				set := map[string]bool{}
				for _, tag := range owners.Nodes {
					if tag == "" || set[tag] {
						t.Fatal("ambiguous native entry owner")
					}
					set[tag] = true
				}
				graph := startObject(t, before)
				count := 0
				for _, family := range []string{"endpoints", "outbounds"} {
					rows, _ := graph[family].([]any)
					for _, row := range rows {
						tag := predecessorText(row.(map[string]any), "tag")
						owner := predecessorNamespace("node", tag)
						if CompositeMode(mode) {
							switch tag {
							case nativecomposite.TCPTag:
								owner = "routervpn-entry-composite-tcp"
							case nativecomposite.UDPTag:
								owner = "routervpn-entry-composite-udp"
							case nativecomposite.StartTag:
								owner = "routervpn-entry-composite-start"
							}
						}
						if tag == graph["route"].(map[string]any)["final"] {
							owner = "entry-wg"
						}
						if !set[owner] {
							t.Fatal("entry dependency was omitted", mode, family, tag)
						}
						count++
					}
				}
				if len(owners.Nodes) != count || !set["entry-wg"] || len(owners.Resolvers) == 0 || entry.Config() != before {
					t.Fatal("entry closure changed the source or its transport inventory")
				}
				again, err := entry.MultihopEntryOwners()
				if err != nil || !reflect.DeepEqual(owners, again) {
					t.Fatal("entry owner capture is not stable")
				}
			})
		}
	}
}

func TestNodeMultihopEntryOwnersRejectMislabelledAndIncompleteGraph(t *testing.T) {
	entry := multihopNodeFixture(t, "split", "aes-256-gcm", "entry")
	for _, fault := range []string{"wrong-mode", "wrong-node", "missing-lane", "missing-start", "foreign-detour"} {
		t.Run(fault, func(t *testing.T) {
			copy := *entry
			copy.profile = predecessorCopy(entry.profile)
			graph := startObject(t, entry.Config())
			switch fault {
			case "wrong-mode":
				copy.mode = "hysteria2"
			case "wrong-node":
				copy.profile["node_proof_id"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			case "missing-lane", "missing-start":
				rows := graph["outbounds"].([]any)
				wanted := nativecomposite.SourcePrefix + "udp"
				if fault == "missing-start" {
					wanted = nativecomposite.SourcePrefix + "start"
				}
				kept := []any{}
				for _, row := range rows {
					if predecessorText(row.(map[string]any), "tag") != wanted {
						kept = append(kept, row)
					}
				}
				if len(kept) == len(rows) {
					t.Fatal("negative fixture did not remove its intended owner", wanted)
				}
				graph["outbounds"] = kept
			case "foreign-detour":
				graph["outbounds"].([]any)[1].(map[string]any)["detour"] = "foreign-entry"
			}
			copy.config = startJSON(t, graph)
			if _, err := copy.MultihopEntryOwners(); err == nil {
				t.Fatal("unowned entry dependency acquired public ownership tags")
			}
		})
	}
}
