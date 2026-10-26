package mobiletor

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTorJumboCompilesOnlyVirtualCapacityAndPreservesPreference(t *testing.T) {
	for _, policy := range []string{"", "auto", "default", "fixed", "manual"} {
		for _, direct := range []bool{true, false} {
			t.Run(policy+map[bool]string{true: "/direct", false: "/entry"}[direct], func(t *testing.T) {
				profile, entry := torHostProfile(), predecessorProfile()
				profile["mtu_policy"], profile["jumbo_tun"], profile["manual_mtu"], profile["effective_mtu"] = policy, true, 9000, 1492
				base, entryJSON := "", ""
				if !direct {
					torHomePair(profile, entry)
					base, entryJSON = torHostBase(t), torHostEncode(t, entry)
				}
				frozen := torHostEncode(t, profile)
				if err := ValidateProfile(frozen); err != nil {
					t.Fatal(err)
				}
				compiled, err := CompileProfileWithPredecessor(frozen, "jumbo-session", base, entryJSON)
				if err != nil {
					t.Fatal(err)
				}
				graph, _ := profileObject(compiled, 4<<20)
				tag, mtu, err := MTUInterface(compiled)
				if err != nil || tag == "" || mtu != 9000 || len(graph["inbounds"].([]any)) != 1 || frozen != torHostEncode(t, profile) || entryJSON != "" && entryJSON != torHostEncode(t, entry) {
					t.Fatal("Jumbo did not retain a single unchanged selection with virtual MTU9000", tag, mtu, err)
				}
				if !direct {
					original, _ := profileObject(base, 4<<20)
					if !reflect.DeepEqual(torHostTagged(t, graph["outbounds"], "proxy"), torHostTagged(t, original["outbounds"], "proxy")) {
						t.Fatal("Jumbo changed the predecessor transport or credentials")
					}
				}
				var predecessor *PredecessorProof
				if !direct {
					predecessor, err = NewPredecessorProof(entryJSON)
					if err != nil {
						t.Fatal(err)
					}
				}
				authority, err := MTUAuthorityWithPredecessor(compiled, frozen, "jumbo-session", predecessor)
				want := policy
				if want == "" {
					want = "default"
				}
				var got map[string]any
				if err != nil || json.Unmarshal([]byte(authority), &got) != nil || got["jumbo_tun"] != true || got["mtu_policy"] != want || got["entry_fixed_mtu"] != nil {
					t.Fatal("Jumbo relabeled the captured Auto/Default choice", authority, err)
				}
			})
		}
	}
}

func TestTorInheritedJumboAndFixedUseExactCapturedEntry(t *testing.T) {
	for _, mode := range []string{"jumbo", "fixed", "manual"} {
		for _, policy := range []string{"auto", "default"} {
			t.Run(mode+"/"+policy, func(t *testing.T) {
				profile, entry := torHostProfile(), predecessorProfile()
				profile["mtu_policy"], profile["jumbo_tun"] = policy, false
				entry["mtu_policy"], entry["jumbo_tun"] = "auto", mode == "jumbo"
				if mode != "jumbo" {
					entry["mtu_policy"], entry["manual_mtu"] = mode, 9000
				}
				torHomePair(profile, entry)
				base, _ := profileObject(torHostBase(t), 4<<20)
				base["inbounds"].([]any)[0].(map[string]any)["mtu"] = 9000
				frozen, entryJSON := torHostEncode(t, profile), torHostEncode(t, entry)
				compiled, err := CompileProfileWithPredecessor(frozen, "captured-jumbo", torHostEncode(t, base), entryJSON)
				if err != nil {
					t.Fatal(err)
				}
				captured, err := NewPredecessorProof(entryJSON)
				if err != nil {
					t.Fatal(err)
				}
				// Mutating a UI object cannot change the retained entry preference.
				entry["jumbo_tun"], entry["mtu_policy"], entry["manual_mtu"] = false, "auto", 1280
				authority, err := MTUAuthorityWithPredecessor(compiled, frozen, "captured-jumbo", captured)
				var got map[string]any
				if err != nil || json.Unmarshal([]byte(authority), &got) != nil || got["mtu_policy"] != policy || got["jumbo_tun"] != (mode == "jumbo") {
					t.Fatal("inherited interface policy was replaced or relabeled", authority, err)
				}
				if mode == "jumbo" && got["entry_fixed_mtu"] != nil || mode != "jumbo" && got["entry_fixed_mtu"] != float64(9000) {
					t.Fatal("inherited Fixed9000 became a user Jumbo request", authority)
				}
				if _, mtu, _ := MTUInterface(compiled); mtu != 9000 || frozen != torHostEncode(t, profile) {
					t.Fatal("Auto/Default downsized the captured entry interface")
				}
				if _, err := MTUAuthorityWithPredecessor(compiled, frozen, "captured-jumbo", nil); err == nil {
					t.Fatal("missing private predecessor minted inherited authority")
				}
				replacement, err := NewPredecessorProof(torHostEncode(t, entry))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := MTUAuthorityWithPredecessor(compiled, frozen, "captured-jumbo", replacement); err == nil {
					t.Fatal("changed entry retained interface authority")
				}
			})
		}
	}
}

func TestTorSingleInterfaceRejectsConflictingOrUncapturedCapacity(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any, map[string]any, map[string]any){
		"exit-jumbo-fixed-conflict": func(exit, entry, graph map[string]any) {
			exit["jumbo_tun"], exit["mtu_policy"], exit["manual_mtu"] = true, "fixed", 1380
		},
		"entry-fixed-conflict": func(exit, entry, graph map[string]any) {
			entry["mtu_policy"], entry["manual_mtu"] = "fixed", 1392
			exit["mtu_policy"], exit["manual_mtu"] = "manual", 1380
		},
		"exit-jumbo-entry-fixed": func(exit, entry, graph map[string]any) {
			entry["mtu_policy"], entry["manual_mtu"], exit["jumbo_tun"] = "fixed", 1392, true
		},
		"entry-jumbo-exit-fixed": func(exit, entry, graph map[string]any) {
			entry["jumbo_tun"] = true
			graph["inbounds"].([]any)[0].(map[string]any)["mtu"] = 9000
			exit["mtu_policy"], exit["manual_mtu"] = "fixed", 1380
		},
		"entry-fixed-wrong-tun": func(exit, entry, graph map[string]any) { entry["mtu_policy"], entry["manual_mtu"] = "fixed", 9000 },
		"entry-jumbo-wrong-tun": func(exit, entry, graph map[string]any) { entry["jumbo_tun"] = true },
		"entry-large-unclaimed": func(exit, entry, graph map[string]any) { graph["inbounds"].([]any)[0].(map[string]any)["mtu"] = 9000 },
		"entry-untyped-jumbo":   func(exit, entry, graph map[string]any) { entry["jumbo_tun"] = "true" },
		"exit-untyped-jumbo":    func(exit, entry, graph map[string]any) { exit["jumbo_tun"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			exit, entry := torHostProfile(), predecessorProfile()
			exit["mtu_policy"] = "auto"
			torHomePair(exit, entry)
			graph, _ := profileObject(torHostBase(t), 4<<20)
			mutate(exit, entry, graph)
			if compiled, err := CompileProfileWithPredecessor(torHostEncode(t, exit), "conflict-session", torHostEncode(t, graph), torHostEncode(t, entry)); err == nil || compiled != "" {
				t.Fatal("conflicting single-interface capacity was silently substituted")
			}
		})
	}
}

func TestTorJumboDoesNotChangeRawPredecessorPacketMTU(t *testing.T) {
	exit, entry := torHostProfile(), predecessorProfile()
	exit["jumbo_tun"] = true
	torHomePair(exit, entry)
	base, _ := profileObject(torHostBase(t), 4<<20)
	base["outbounds"] = []any{}
	endpoint := map[string]any{"type": "wireguard", "tag": "proxy", "mtu": 1392, "private_key": "exact-private-key", "peers": []any{map[string]any{"public_key": "exact-peer", "address": "192.0.2.2"}}}
	base["endpoints"] = []any{endpoint}
	compiled, err := CompileProfileWithPredecessor(torHostEncode(t, exit), "raw-entry-session", torHostEncode(t, base), torHostEncode(t, entry))
	if err != nil {
		t.Fatal(err)
	}
	graph, _ := profileObject(compiled, 4<<20)
	if _, mtu, _ := MTUInterface(compiled); mtu != 9000 || torHostEncode(t, graph["endpoints"]) != torHostEncode(t, base["endpoints"]) {
		t.Fatal("virtual Tor capacity enlarged the encrypted packet transport")
	}
}
