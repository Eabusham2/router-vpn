package main

import (
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/macosprocess"
)

func macOSCandidatePrefixBaselineFixture(policy, phase string) desktopMacOSCandidatePrefixReceipt {
	value := desktopMacOSCandidatePrefixReceipt{Schema: 2,
		Capture: desktopMacOSCandidatePrefixSelection{Schema: 2, Family: macosprocess.CandidatePrefixFamily, ProfileID: "saved-control-final",
			Session: strings.Repeat("a", 32), Source: strings.Repeat("b", 64), Config: strings.Repeat("c", 64), Policy: policy},
		Phase: phase, Token: "417", Baseline: desktopMacOSBaselineProof{Present: phase != "retired" || policy == "always"}}
	if value.Baseline.Present {
		value.Baseline.Rules = strings.Repeat("d", 64)
	}
	return value
}

func TestDesktopMacOSCandidatePrefixBaselineExactReceiptAndRetirement(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
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
					"config":         func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.Config = strings.Repeat("e", 64) },
					"LAN":            func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.HomeLAN = true },
					"policy":         func(v *desktopMacOSCandidatePrefixReceipt) { v.Capture.Policy = "off" },
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
					"duplicate":         strings.Replace(string(raw), `"schema":2`, `"schema":2,"schema":2`, 1),
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
				ordinary := desktopMacOSExternalSelection{Schema: 1, ProfileID: value.Capture.ProfileID, Protocol: "shadowsocks",
					Session: value.Capture.Session, Source: value.Capture.Source, Config: value.Capture.Config, Policy: policy}
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
