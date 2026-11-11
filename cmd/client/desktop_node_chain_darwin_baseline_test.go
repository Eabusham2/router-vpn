package main

import (
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/macosprocess"
)

func macOSNodeChainBaselineFixture(policy, phase string) desktopMacOSNodeChainReceipt {
	value := desktopMacOSNodeChainReceipt{Schema: 2,
		Capture: desktopMacOSNodeChainSelection{Schema: 2, Family: macosprocess.NodeChainFamily, ProfileID: "owned-final",
			Session: strings.Repeat("a", 32), Source: strings.Repeat("b", 64), Config: strings.Repeat("c", 64), Policy: policy},
		Phase: phase, Token: "417", Baseline: desktopMacOSBaselineProof{Present: phase != "retired" || policy == "always"}}
	if value.Baseline.Present {
		value.Baseline.Rules = strings.Repeat("d", 64)
	}
	return value
}

func TestDesktopMacOSNodeChainBaselineExactReceiptAndRetirement(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
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
					"policy":         func(v *desktopMacOSNodeChainReceipt) { v.Capture.Policy = "off" },
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
				ordinary := desktopMacOSExternalSelection{Schema: 1, ProfileID: value.Capture.ProfileID, Protocol: "shadowsocks",
					Session: value.Capture.Session, Source: value.Capture.Source, Config: value.Capture.Config, Policy: policy}
				if _, err := decodeDesktopMacOSExternalReceipt(raw, ordinary, phase); err == nil {
					t.Fatal("ordered receipt became ordinary external authority")
				}
			})
		}
	}
}

func TestDesktopMacOSNodeChainBaselineOriginalRequest(t *testing.T) {
	value := macOSNodeChainBaselineFixture("on-connect", "active")
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
