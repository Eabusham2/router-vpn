package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDesktopMacOSExternalBaselineExactReceiptAndRetirement(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		for _, phase := range []string{"active", "held", "retired"} {
			s := desktopMacOSExternalSelection{Schema: 1, ProfileID: "owned-profile", Protocol: "hysteria2", Session: strings.Repeat("a", 32), Source: strings.Repeat("b", 64), Config: strings.Repeat("c", 64), Policy: policy}
			value := desktopMacOSExternalReceipt{Schema: 1, Capture: s, Phase: phase, Token: "417", Baseline: desktopMacOSBaselineProof{Present: phase != "retired" || policy == "always"}}
			if value.Baseline.Present {
				value.Baseline.Rules = strings.Repeat("d", 64)
			}
			raw, _ := json.Marshal(value)
			actual, err := decodeDesktopMacOSExternalReceipt(raw, s, phase)
			if err != nil || actual != value {
				t.Fatal("original native receipt changed selected retirement", policy, phase, err)
			}
			for name, edit := range map[string]func(*desktopMacOSExternalReceipt){
				"session":            func(v *desktopMacOSExternalReceipt) { v.Capture.Session = strings.Repeat("e", 32) },
				"source":             func(v *desktopMacOSExternalReceipt) { v.Capture.Source = strings.Repeat("e", 64) },
				"config":             func(v *desktopMacOSExternalReceipt) { v.Capture.Config = strings.Repeat("e", 64) },
				"profile":            func(v *desktopMacOSExternalReceipt) { v.Capture.ProfileID = "other" },
				"protocol":           func(v *desktopMacOSExternalReceipt) { v.Capture.Protocol = "tor" },
				"LAN":                func(v *desktopMacOSExternalReceipt) { v.Capture.HomeLAN = !v.Capture.HomeLAN },
				"policy":             func(v *desktopMacOSExternalReceipt) { v.Capture.Policy = "off" },
				"phase":              func(v *desktopMacOSExternalReceipt) { v.Phase = "joined-process" },
				"schema":             func(v *desktopMacOSExternalReceipt) { v.Schema = 0 },
				"token":              func(v *desktopMacOSExternalReceipt) { v.Token = "417 extra" },
				"zero token":         func(v *desktopMacOSExternalReceipt) { v.Token = "0" },
				"noncanonical token": func(v *desktopMacOSExternalReceipt) { v.Token = "0417" },
				"overflow token":     func(v *desktopMacOSExternalReceipt) { v.Token = "18446744073709551616" },
				"present":            func(v *desktopMacOSExternalReceipt) { v.Baseline.Present = !v.Baseline.Present },
				"digest":             func(v *desktopMacOSExternalReceipt) { v.Baseline.Rules = "unproved" },
			} {
				t.Run(policy+"/"+phase+"/"+name, func(t *testing.T) {
					changed := value
					edit(&changed)
					raw, _ := json.Marshal(changed)
					if _, err := decodeDesktopMacOSExternalReceipt(raw, s, phase); err == nil {
						t.Fatal("changed original native baseline receipt accepted")
					}
				})
			}
			for name, body := range map[string]string{
				"duplicate schema": strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1),
				"nested duplicate": strings.Replace(string(raw), `"home_lan_access":false`, `"home_lan_access":false,"home_lan_access":false`, 1),
				"nested unknown":   strings.Replace(string(raw), `"present":`, `"extra":false,"present":`, 1),
				"null bool":        strings.Replace(string(raw), `"home_lan_access":false`, `"home_lan_access":null`, 1),
				"trailing":         string(raw) + `{}`, "oversized": strings.Repeat(" ", 8193) + string(raw),
			} {
				t.Run(policy+"/"+phase+"/"+name, func(t *testing.T) {
					if _, err := decodeDesktopMacOSExternalReceipt([]byte(body), s, phase); err == nil {
						t.Fatal("ambiguous native receipt accepted")
					}
				})
			}
		}
	}
}
