package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/macosprocess"
)

func macOSCandidatePrefixBaselineFixture(policy, phase string) desktopMacOSCandidatePrefixReceipt {
	value := desktopMacOSCandidatePrefixReceipt{Schema: 3,
		Capture: desktopMacOSCandidatePrefixSelection{Schema: 3, Family: macosprocess.CandidatePrefixFamily, ProfileID: "saved-control-final",
			Session: strings.Repeat("a", 32), Source: strings.Repeat("b", 64), Config: strings.Repeat("c", 64), MembersSHA256: strings.Repeat("e", 64), Policy: policy},
		Phase: phase, Token: "417", Baseline: desktopMacOSBaselineProof{Present: phase == "active" || phase == "held" && policy != "off" || policy == "always"}}
	if value.Baseline.Present {
		value.Baseline.Rules = strings.Repeat("d", 64)
	}
	return value
}

func TestDesktopMacOSCandidatePrefixBaselineExactReceiptAndRetirement(t *testing.T) {
	for _, policy := range []string{"off", "on-connect", "always"} {
		for _, phase := range []string{"active", "held", "retired"} {
			t.Run(policy+"/"+phase, func(t *testing.T) {
				value := macOSCandidatePrefixBaselineFixture(policy, phase)
				raw, _ := json.Marshal(value)
				actual, err := decodeDesktopMacOSCandidatePrefixReceipt(raw, value.Capture, phase)
				if err != nil || actual != value {
					t.Fatalf("original prefix PF receipt changed: %v", err)
				}
				for name, change := range map[string]func(*desktopMacOSCandidatePrefixReceipt){
					"receipt-schema": func(v *desktopMacOSCandidatePrefixReceipt) { v.Schema = 1 },
					"capture-schema": func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.Schema = 1 },
					"family":         func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.Family = macosprocess.ExternalFamily },
					"ordinary-chain": func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.Family = macosprocess.NodeChainFamily },
					"prefix-member":  func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.ProfileID = "tested-prefix-member" },
					"profile":        func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.ProfileID = "foreign" },
					"session":        func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.Session = strings.Repeat("e", 32) },
					"source":         func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.Source = strings.Repeat("e", 64) },
					"members":        func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.MembersSHA256 = strings.Repeat("f", 64) },
					"config":         func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.Config = strings.Repeat("e", 64) },
					"LAN":            func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.HomeLAN = true },
					"policy": func(v *desktopMacOSCandidatePrefixReceipt) {
						if v.Capture.Policy == "off" {
							v.Capture.Policy = "always"
						} else {
							v.Capture.Policy = "off"
						}
					},
					"phase":          func(v *desktopMacOSCandidatePrefixReceipt) { v.Phase = "joined-process" },
					"zero-token":     func(v *desktopMacOSCandidatePrefixReceipt) { v.Token = "0" },
					"token-prefix":   func(v *desktopMacOSCandidatePrefixReceipt) { v.Token = "0417" },
					"token-overflow": func(v *desktopMacOSCandidatePrefixReceipt) { v.Token = "18446744073709551616" },
					"present":        func(v *desktopMacOSCandidatePrefixReceipt) { v.Baseline.Present = !v.Baseline.Present },
					"rules":          func(v *desktopMacOSCandidatePrefixReceipt) { v.Baseline.Rules = "unproved" },
				} {
					t.Run(name, func(t *testing.T) {
						changed := value
						change(&changed)
						body, _ := json.Marshal(changed)
						if _, err := decodeDesktopMacOSCandidatePrefixReceipt(body, value.Capture, phase); err == nil {
							t.Fatal("prefix receipt admitted another source or retirement")
						}
					})
				}
				for name, body := range map[string]string{
					"duplicate":         strings.Replace(string(raw), `"schema":3`, `"schema":3,"schema":3`, 1),
					"null":              strings.Replace(string(raw), `"home_lan_access":false`, `"home_lan_access":null`, 1),
					"missing-family":    strings.Replace(string(raw), `"family":"node-candidate-prefix-v1",`, "", 1),
					"ordinary-protocol": strings.Replace(string(raw), `"family":"node-candidate-prefix-v1"`, `"protocol":"shadowsocks"`, 1),
					"case-alias":        strings.Replace(string(raw), `"family":`, `"Family":`, 1),
					"unknown":           strings.Replace(string(raw), `"present":`, `"extra":false,"present":`, 1),
					"trailing":          string(raw) + `{}`,
					"oversized":         strings.Repeat(" ", 8193) + string(raw),
				} {
					t.Run(name, func(t *testing.T) {
						if _, err := decodeDesktopMacOSCandidatePrefixReceipt([]byte(body), value.Capture, phase); err == nil {
							t.Fatal("prefix receipt admitted an ambiguous family document")
						}
					})
				}
				chain := desktopMacOSNodeChainSelection{Schema: 2, Family: macosprocess.NodeChainFamily, ProfileID: value.Capture.ProfileID,
					Session: value.Capture.Session, Source: value.Capture.Source, Config: value.Capture.Config, Policy: policy}
				if _, err := decodeDesktopMacOSNodeChainReceipt(raw, chain, phase); err == nil {
					t.Fatal("prefix receipt became complete graph protection authority")
				}
				ordinary := desktopMacOSExternalSelection{Schema: 2, ProfileID: value.Capture.ProfileID, Protocol: "shadowsocks",
					Session: value.Capture.Session, Source: value.Capture.Source, Config: value.Capture.Config, Policy: policy, FinalPolicy: policy}
				if !ordinary.valid() {
					t.Fatal("cross-family negative lost valid ordinary source")
				}
				if _, err := decodeDesktopMacOSExternalReceipt(raw, ordinary, phase); err == nil {
					t.Fatal("prefix receipt became ordinary external authority")
				}
			})
		}
	}
}

func TestDesktopMacOSCandidatePrefixBaselineOriginalRequest(t *testing.T) {
	value := macOSCandidatePrefixBaselineFixture("on-connect", "active")
	for _, action := range []string{"apply", "current", "retire", "release"} {
		var expected *desktopMacOSCandidatePrefixReceipt
		if action != "apply" {
			expected = &value
		}
		raw, err := encodeDesktopMacOSCandidatePrefixBaselineRequest(value.Capture, action, expected)
		if err != nil {
			t.Fatal(action, err)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || fields["capture"] == nil || fields["expected"] == nil {
			t.Fatal("prefix action changed its complete request inventory")
		}
		if action == "apply" && string(fields["expected"]) != "null" {
			t.Fatal("first prefix apply borrowed a previous PF reference")
		}
	}
	for _, test := range []struct {
		name     string
		action   string
		expected *desktopMacOSCandidatePrefixReceipt
	}{
		{"borrowed-apply", "apply", &value}, {"unproved-current", "current", nil}, {"unknown-action", "force-off", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := encodeDesktopMacOSCandidatePrefixBaselineRequest(value.Capture, test.action, test.expected); err == nil {
				t.Fatal("prefix request acquired a foreign action or reference")
			}
		})
	}
	changed := value
	changed.Capture.Source = strings.Repeat("e", 64)
	if _, err := encodeDesktopMacOSCandidatePrefixBaselineRequest(value.Capture, "release", &changed); err == nil {
		t.Fatal("prefix release substituted its original complete source")
	}
	for _, action := range []string{"retire", "release"} {
		if _, err := encodeDesktopMacOSCandidatePrefixBaselineRequest(value.Capture, action, nil); err != nil {
			t.Fatal("ambiguous apply lost its original retained cleanup", err)
		}
	}
}

func TestDesktopMacOSCandidatePrefixBaselineRejectsOtherFamilies(t *testing.T) {
	for _, family := range []macosprocess.Family{macosprocess.ExternalFamily, macosprocess.NodeChainFamily, "node-candidate-prefix-v2"} {
		t.Run(string(family), func(t *testing.T) {
			value := macOSCandidatePrefixBaselineFixture("on-connect", "active")
			value.Capture.Family = family
			if _, err := encodeDesktopMacOSCandidatePrefixBaselineRequest(value.Capture, "apply", nil); err == nil {
				t.Fatal("another concrete family acquired prefix journal authority")
			}
			raw, _ := json.Marshal(value)
			if _, err := decodeDesktopMacOSCandidatePrefixReceipt(raw, value.Capture, "active"); err == nil {
				t.Fatal("another concrete family acquired prefix journal authority")
			}
		})
	}
}

// This vector is consumed by the Python baseline test. It contains only saved
// identities/device settings; no credential, endpoint or successful PF proof.
func TestDesktopMacOSCandidatePrefixSavedMemberDigestVector(t *testing.T) {
	for _, variant := range []string{"explicit", "missing", "empty"} {
		t.Run(variant, func(t *testing.T) {
			a, q := orderedPreparationFixture(t, "wg")
			for i := range a.profiles.Profiles {
				a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = false, "off"
				a.profiles.Profiles[i].HomeLANAccess, a.profiles.Profiles[i].IPv6Mode = true, "on"
			}
			a.profiles.Profiles[0].KillSwitch, a.profiles.Profiles[0].KillSwitchPolicy = true, "always"
			a.profiles.Profiles[0].HomeLANAccess, a.profiles.Profiles[0].IPv6Mode = false, "off"
			raw, err := json.Marshal(a.profiles)
			if err != nil {
				t.Fatal(err)
			}
			var persisted map[string]any
			if json.Unmarshal(raw, &persisted) != nil {
				t.Fatal("saved profile vector unavailable")
			}
			for _, value := range persisted["profiles"].([]any) {
				profile := value.(map[string]any)
				if profile["id"] == a.profiles.Profiles[1].ID && variant != "explicit" {
					delete(profile, "home_lan_access")
					if variant == "missing" {
						delete(profile, "ipv6_mode")
						delete(profile, "node_kind")
					} else {
						profile["ipv6_mode"], profile["node_kind"] = "", ""
					}
				}
			}
			raw, err = json.Marshal(persisted)
			if err != nil {
				t.Fatal(err)
			}
			var restored common.RouterProfileStore
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			if restored.Profiles[1].IPv6Mode != "on" || !restored.Profiles[1].HomeLANAccess || restored.Profiles[1].NodeKind != "router-vpn" {
				t.Fatal("actual saved profile normalization changed desktop defaults")
			}
			a.profiles = restored
			q.Scope = "saved-prefix-local"
			p := beginOrderedPreparationFixture(t, a, q)
			launch, err := newDesktopNodeCandidatePrefixLaunchForPurpose(context.Background(), p.selection, strings.Repeat("b", 32), "darwin", p)
			if err != nil {
				t.Fatal(err)
			}
			capture, err := newDesktopMacOSCandidatePrefixSelection(launch.candidatePrefix.policy)
			if err != nil || capture.Policy != "always" || capture.HomeLAN || capture.ProfileID != a.profiles.SelectedID {
				t.Fatal("baseline vector lost original aggregate", err)
			}
			var profiles []map[string]any
			for _, value := range persisted["profiles"].([]any) {
				original := value.(map[string]any)
				row := map[string]any{}
				for _, name := range []string{"id", "node_kind", "kill_switch", "kill_switch_policy", "home_lan_access", "ipv6_mode"} {
					if v, ok := original[name]; ok {
						row[name] = v
					}
				}
				if original["id"] == a.profiles.SelectedID {
					for _, name := range []string{"multihop_enabled", "multihop_execution", "multihop_nodes"} {
						row[name] = original[name]
					}
				}
				profiles = append(profiles, row)
			}
			raw, err = json.Marshal(map[string]any{"case": variant, "capture": capture, "store": map[string]any{"selected_id": a.profiles.SelectedID, "profiles": profiles}})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("PREFIX_MEMBER_BINDING_VECTOR %s", raw)
		})
	}
}
