package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/macosprocess"
)

func macOSNodeChainBaselineFixture(policy, phase string) desktopMacOSNodeChainReceipt {
	value := desktopMacOSNodeChainReceipt{Schema: 2,
		Capture: desktopMacOSNodeChainSelection{Schema: 2, Family: macosprocess.NodeChainFamily, ProfileID: "owned-final",
			Session: strings.Repeat("a", 32), Source: strings.Repeat("b", 64), Config: strings.Repeat("c", 64), Policy: policy},
		Phase: phase, Token: "417", Baseline: desktopMacOSBaselineProof{Present: phase == "active" || phase == "held" && policy != "off" || policy == "always"}}
	if value.Baseline.Present {
		value.Baseline.Rules = strings.Repeat("d", 64)
	}
	return value
}

func TestDesktopMacOSNodeChainBaselineExactReceiptAndRetirement(t *testing.T) {
	for _, policy := range []string{"off", "on-connect", "always"} {
		for _, phase := range []string{"active", "held", "retired"} {
			t.Run(policy+"/"+phase, func(t *testing.T) {
				value := macOSNodeChainBaselineFixture(policy, phase)
				raw, _ := json.Marshal(value)
				actual, err := decodeDesktopMacOSNodeChainReceipt(raw, value.Capture, phase)
				if err != nil || actual != value {
					t.Fatalf("original ordered PF receipt changed: %v", err)
				}
				for name, change := range map[string]func(*desktopMacOSNodeChainReceipt){
					"receipt-schema": func(v *desktopMacOSNodeChainReceipt) { v.Schema = 1 },
					"capture-schema": func(v *desktopMacOSNodeChainReceipt) { v.Capture.Schema = 1 },
					"family":         func(v *desktopMacOSNodeChainReceipt) { v.Capture.Family = macosprocess.ExternalFamily },
					"profile":        func(v *desktopMacOSNodeChainReceipt) { v.Capture.ProfileID = "foreign" },
					"session":        func(v *desktopMacOSNodeChainReceipt) { v.Capture.Session = strings.Repeat("e", 32) },
					"source":         func(v *desktopMacOSNodeChainReceipt) { v.Capture.Source = strings.Repeat("e", 64) },
					"config":         func(v *desktopMacOSNodeChainReceipt) { v.Capture.Config = strings.Repeat("e", 64) },
					"LAN":            func(v *desktopMacOSNodeChainReceipt) { v.Capture.HomeLAN = true },
					"policy": func(v *desktopMacOSNodeChainReceipt) {
						if v.Capture.Policy == "off" {
							v.Capture.Policy = "always"
						} else {
							v.Capture.Policy = "off"
						}
					},
					"phase":          func(v *desktopMacOSNodeChainReceipt) { v.Phase = "joined-process" },
					"zero-token":     func(v *desktopMacOSNodeChainReceipt) { v.Token = "0" },
					"token-prefix":   func(v *desktopMacOSNodeChainReceipt) { v.Token = "0417" },
					"token-overflow": func(v *desktopMacOSNodeChainReceipt) { v.Token = "18446744073709551616" },
					"present":        func(v *desktopMacOSNodeChainReceipt) { v.Baseline.Present = !v.Baseline.Present },
					"rules":          func(v *desktopMacOSNodeChainReceipt) { v.Baseline.Rules = "unproved" },
				} {
					t.Run(name, func(t *testing.T) {
						changed := value
						change(&changed)
						body, _ := json.Marshal(changed)
						if _, err := decodeDesktopMacOSNodeChainReceipt(body, value.Capture, phase); err == nil {
							t.Fatal("ordered receipt admitted another source or retirement")
						}
					})
				}
				for name, body := range map[string]string{
					"duplicate":         strings.Replace(string(raw), `"schema":2`, `"schema":2,"schema":2`, 1),
					"null":              strings.Replace(string(raw), `"home_lan_access":false`, `"home_lan_access":null`, 1),
					"missing-family":    strings.Replace(string(raw), `"family":"ordered-node-chain-v1",`, "", 1),
					"ordinary-protocol": strings.Replace(string(raw), `"family":"ordered-node-chain-v1"`, `"protocol":"shadowsocks"`, 1),
					"case-alias":        strings.Replace(string(raw), `"family":`, `"Family":`, 1),
					"unknown":           strings.Replace(string(raw), `"present":`, `"extra":false,"present":`, 1),
					"trailing":          string(raw) + `{}`,
					"oversized":         strings.Repeat(" ", 8193) + string(raw),
				} {
					t.Run(name, func(t *testing.T) {
						if _, err := decodeDesktopMacOSNodeChainReceipt([]byte(body), value.Capture, phase); err == nil {
							t.Fatal("ordered receipt admitted an ambiguous family document")
						}
					})
				}
				ordinary := desktopMacOSExternalSelection{Schema: 2, ProfileID: value.Capture.ProfileID, Protocol: "shadowsocks",
					Session: value.Capture.Session, Source: value.Capture.Source, Config: value.Capture.Config, Policy: policy, FinalPolicy: policy}
				if !ordinary.valid() {
					t.Fatal("cross-family refusal requires a valid ordinary capture")
				}
				if _, err := decodeDesktopMacOSExternalReceipt(raw, ordinary, phase); err == nil {
					t.Fatal("ordered receipt became ordinary external authority")
				}
			})
		}
	}
}

func TestDesktopMacOSNodeChainBaselineOriginalRequest(t *testing.T) {
	value := macOSNodeChainBaselineMembersFixture("on-connect", "active")
	for _, action := range []string{"apply", "current", "retire", "release"} {
		var expected *desktopMacOSNodeChainReceipt
		if action != "apply" {
			expected = &value
		}
		raw, err := encodeDesktopMacOSNodeChainBaselineRequest(value.Capture, action, expected)
		if err != nil {
			t.Fatal(action, err)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || fields["capture"] == nil || fields["expected"] == nil {
			t.Fatal("ordered action changed its complete request inventory")
		}
		if action == "apply" && string(fields["expected"]) != "null" {
			t.Fatal("first ordered apply borrowed a previous PF reference")
		}
	}
	for _, test := range []struct {
		name     string
		action   string
		expected *desktopMacOSNodeChainReceipt
	}{
		{"borrowed-apply", "apply", &value}, {"unproved-current", "current", nil}, {"unknown-action", "force-off", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := encodeDesktopMacOSNodeChainBaselineRequest(value.Capture, test.action, test.expected); err == nil {
				t.Fatal("ordered request acquired a foreign action or reference")
			}
		})
	}
	changed := value
	changed.Capture.Source = strings.Repeat("e", 64)
	if _, err := encodeDesktopMacOSNodeChainBaselineRequest(value.Capture, "release", &changed); err == nil {
		t.Fatal("ordered release substituted its original complete source")
	}
	for _, action := range []string{"retire", "release"} {
		if _, err := encodeDesktopMacOSNodeChainBaselineRequest(value.Capture, action, nil); err != nil {
			t.Fatal("ambiguous apply lost its original retained cleanup", err)
		}
	}
}

func macOSNodeChainBaselineMembersFixture(policy, phase string) desktopMacOSNodeChainReceipt {
	value := macOSNodeChainBaselineFixture(policy, phase)
	rows := [][]any{{"owned-first", "wg", "router-vpn", policy, "on", false}, {"owned-final", "shadowsocks", "router-vpn", policy, "on", false}}
	raw, _ := json.Marshal(rows)
	digest := sha256.Sum256(append([]byte("routervpn-ordered-protection-members-v1\n"), raw...))
	value.Schema, value.Capture.Schema = 3, 3
	value.Capture.MembersJSON, value.Capture.MembersSHA256 = string(raw), hex.EncodeToString(digest[:])
	return value
}

func TestDesktopMacOSNodeChainBaselineLegacyCleanupOnly(t *testing.T) {
	value := macOSNodeChainBaselineFixture("always", "held")
	if _, err := encodeDesktopMacOSNodeChainBaselineRequest(value.Capture, "apply", nil); err == nil {
		t.Fatal("legacy receipt acquired fresh authority")
	}
	for _, action := range []string{"current", "retire", "release"} {
		actual := value
		if action == "current" {
			actual = macOSNodeChainBaselineFixture("always", "active")
		}
		if _, err := encodeDesktopMacOSNodeChainBaselineRequest(actual.Capture, action, &actual); err != nil {
			t.Fatal("legacy exact ownership lost cleanup", action, err)
		}
	}
}

func TestDesktopMacOSNodeChainBaselineMemberReceiptRejectsMutation(t *testing.T) {
	original := macOSNodeChainBaselineMembersFixture("always", "active")
	raw, _ := json.Marshal(original)
	if actual, err := decodeDesktopMacOSNodeChainReceipt(raw, original.Capture, "active"); err != nil || actual != original {
		t.Fatal(err)
	}
	for _, fault := range []string{"digest", "rows", "unknown", "missing", "legacy", "policy", "reordered"} {
		t.Run(fault, func(t *testing.T) {
			changed := original
			switch fault {
			case "digest":
				changed.Capture.MembersSHA256 = strings.Repeat("e", 64)
			case "rows":
				changed.Capture.MembersJSON = strings.ReplaceAll(changed.Capture.MembersJSON, "owned-first", "foreign")
			case "unknown":
				changed.Capture.MembersJSON = `[["owned-first","wg","router-vpn","always","on",false,"extra"]]`
			case "missing":
				changed.Capture.MembersJSON = ""
			case "legacy":
				changed.Capture.Schema = 2
			case "policy":
				changed.Capture.Policy = "off"
			case "reordered":
				changed.Capture.MembersJSON = `[["owned-final","shadowsocks","router-vpn","always","on",false],["owned-first","wg","router-vpn","always","on",false]]`
			}
			body, _ := json.Marshal(changed)
			if _, err := decodeDesktopMacOSNodeChainReceipt(body, original.Capture, "active"); err == nil {
				t.Fatal("different original member capture accepted")
			}
		})
	}
}

func TestDesktopMacOSNodeChainBaselineCapturesEveryOriginalPolicy(t *testing.T) {
	for _, strongest := range []string{"off", "on-connect", "always"} {
		t.Run(strongest, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			for i := range a.profiles.Profiles {
				a.profiles.Profiles[i].KillSwitch = false
				a.profiles.Profiles[i].KillSwitchPolicy = "off"
				a.profiles.Profiles[i].HomeLANAccess = true
			}
			a.profiles.Profiles[0].KillSwitchPolicy = strongest
			a.profiles.Profiles[1].HomeLANAccess = false
			control := a.profiles.Profiles[2]
			selected, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
			if err != nil {
				t.Fatal(err)
			}
			selected, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selected, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := newDesktopNodeChainLaunch(selected, strings.Repeat("a", 32), "darwin")
			if err != nil {
				t.Fatal(err)
			}
			capture, err := newDesktopMacOSNodeChainSelection(launch.chain)
			if err != nil || capture.Schema != 3 || capture.Policy != strongest || capture.HomeLAN || capture.ProfileID != control.ID {
				t.Fatal("first/middle policy did not reach actual Darwin parent capture", capture, err)
			}
			var rows [][]any
			if json.Unmarshal([]byte(capture.MembersJSON), &rows) != nil || len(rows) != 3 || rows[0][0] != nodes[0].ID || rows[0][3] != strongest || rows[1][5] != false || rows[2][3] != "off" {
				t.Fatal("original ordered source rows changed", rows)
			}
			launch.chain.selection.Nodes[0].Profile.KillSwitchPolicy = "changed"
			if _, err := newDesktopMacOSNodeChainSelection(launch.chain); err == nil {
				t.Fatal("baseline rederived authority from changed original member")
			}
		})
	}
}

func TestDesktopMacOSPairedWireGuardBaseline(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 9)
	control := a.profiles.Profiles[len(nodes)-1]
	selected, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selected, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selected, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selected, strings.Repeat("a", 32), "darwin")
	if err != nil {
		t.Fatal(err)
	}
	original, err := newDesktopMacOSNodeChainSelection(launch.chain)
	if err != nil || !original.validMembers() {
		t.Fatal("lost Darwin original paired baseline", err)
	}
	var rows [][]any
	if err := json.Unmarshal([]byte(original.MembersJSON), &rows); err != nil || len(rows) != len(nodes) {
		t.Fatal("lost original policy inventory", err)
	}
	for i, want := range nodes {
		if rows[i][0] != want.ID || rows[i][1] != want.Mode || rows[i][2] != "router-vpn" {
			t.Fatalf("original paired member %d changed", i)
		}
	}
	foreign := original
	foreign.Family = macosprocess.NodeChainExecutionFamily
	if foreign.validMembers() {
		t.Fatal("paired Local baseline crossed into a selected execution")
	}
	rows[1][1], rows[1][2] = "shadowsocks", "external"
	raw, _ := json.Marshal(rows)
	digest := sha256.Sum256(append([]byte("routervpn-ordered-protection-members-v1\n"), raw...))
	foreign = original
	foreign.MembersJSON, foreign.MembersSHA256 = string(raw), hex.EncodeToString(digest[:])
	if foreign.validMembers() {
		t.Fatal("paired packet after an imported long policy acquired the baseline")
	}
}

func TestDesktopMacOSMixedLocalBaseline(t *testing.T) {
	const count, packets = 9, 3
	imports := []int{3, 4, 5, 6, 7}
	a, nodes := desktopIndependentImportedFixture(t, desktopIndependentImportedLayout{"mixed-pf", count, imports}, "awg2-fast", "off")
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[count-1], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("c", 32), "darwin")
	if err != nil {
		t.Fatal(err)
	}
	original, err := newDesktopMacOSNodeChainSelection(launch.chain)
	if err != nil || !original.validMembers() {
		t.Fatal("original mixed Local PF capture", err)
	}
	var rows [][]any
	if err := json.Unmarshal([]byte(original.MembersJSON), &rows); err != nil || len(rows) != count {
		t.Fatal("lost original mixed PF rows", err)
	}
	for i, node := range nodes {
		kind := "router-vpn"
		if i >= packets && i < count-1 {
			kind = "external"
		}
		if rows[i][0] != node.ID || rows[i][1] != node.Mode || rows[i][2] != kind {
			t.Fatalf("lost captured policy role at position %d", i)
		}
	}
	original.Family = macosprocess.NodeChainExecutionFamily
	if original.validMembers() {
		t.Fatal("mixed Local PF capture crossed into selected execution")
	}
}
