package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestExternalDesktopProtectionAggregatesOnlyOriginalParticipants(t *testing.T) {
	policies := []string{"off", "on-connect", "always"}
	for _, entryKind := range []string{"wireguard", "shadowsocks"} {
		for finalRank, finalPolicy := range policies {
			for entryRank, entryPolicy := range policies {
				t.Run(entryKind+"/"+finalPolicy+"/"+entryPolicy, func(t *testing.T) {
					graph, selection := externalTestFixture(t, "shadowsocks", entryKind)
					profile := selection["profile"].(map[string]any)
					entry := selection["entry"].(map[string]any)
					profile["kill_switch_policy"], entry["kill_switch_policy"] = finalPolicy, entryPolicy
					before := externalTestJSON(t, selection)
					original := externalDesktopCompile(t, graph, selection)
					capture, err := original.DesktopCapture()
					want := finalPolicy
					if entryRank > finalRank {
						want = entryPolicy
					}
					if err != nil || capture.KillSwitchPolicy != want || capture.FinalKillSwitchPolicy != finalPolicy || capture.EntryKillSwitchPolicy != entryPolicy || capture.ExitID != "saved-exit" || capture.EntryID != "saved-entry" {
						t.Fatal("captured member strength or identity changed", err, capture)
					}
					if externalTestJSON(t, selection) != before {
						t.Fatal("aggregation rewrote original saved participants")
					}
					for _, target := range []string{"linux", "windows", "darwin"} {
						adapted, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, target)
						// The existing platform graph gate still decides protocol support.
						if target == "windows" && entryKind == "wireguard" {
							continue
						}
						if want == "off" {
							if err == nil {
								t.Fatal("all-Off native admission opened", target)
							}
							continue
						}
						if err != nil || adapted.Metadata().KillSwitchPolicy != want {
							t.Fatal("native policy downgraded original member", target, err)
						}
						next, err := adapted.Capture()
						if err != nil || next.KillSwitchPolicy != want || !reflect.DeepEqual(next.SelectedDNS, capture.SelectedDNS) || next.IPv6Mode != capture.IPv6Mode || next.HomeLANAccess != capture.HomeLANAccess || next.ConfiguredMTU != capture.ConfiguredMTU {
							t.Fatal("protection aggregation replaced another selected policy", err)
						}
					}
					// Return values cannot rewrite the private source or selected credentials.
					again, err := original.DesktopCapture()
					if err != nil || !reflect.DeepEqual(again, capture) {
						t.Fatal("original capture changed after derivation", err)
					}
				})
			}
		}
	}
}
func TestExternalDesktopProtectionDirectLegacyAndMalformedParticipants(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		graph, selection := externalTestFixture(t, "shadowsocks", "")
		profile := selection["profile"].(map[string]any)
		profile["kill_switch"] = legacy
		original := externalDesktopCompile(t, graph, selection)
		capture, err := original.DesktopCapture()
		want := "off"
		if legacy {
			want = "on-connect"
		}
		if err != nil || capture.KillSwitchPolicy != want || capture.FinalKillSwitchPolicy != want || capture.EntryKillSwitchPolicy != "" || capture.EntryID != "" {
			t.Fatal("direct capture acquired another participant", err)
		}
	}
	for _, fault := range []string{"invalid-entry", "malformed-entry-legacy", "invalid-final", "malformed-final-legacy"} {
		t.Run(fault, func(t *testing.T) {
			graph, selection := externalTestFixture(t, "shadowsocks", "wireguard")
			profile := selection["profile"].(map[string]any)
			entry := selection["entry"].(map[string]any)
			profile["kill_switch_policy"], entry["kill_switch_policy"] = "always", "off"
			switch fault {
			case "invalid-entry":
				entry["kill_switch_policy"] = "unknown"
			case "malformed-entry-legacy":
				entry["kill_switch"] = "true"
			case "invalid-final":
				profile["kill_switch_policy"] = "unknown"
			case "malformed-final-legacy":
				profile["kill_switch"] = "true"
			}
			original := externalDesktopCompile(t, graph, selection)
			if _, err := original.DesktopCapture(); err == nil {
				t.Fatal("malformed captured member acquired native policy")
			}
		})
	}
	graph, selection := externalTestFixture(t, "shadowsocks", "wireguard")
	selection["profile"].(map[string]any)["kill_switch_policy"] = "off"
	selection["entry"].(map[string]any)["kill_switch"] = true
	original := externalDesktopCompile(t, graph, selection)
	captured, err := original.DesktopCapture()
	if err != nil || captured.KillSwitchPolicy != "on-connect" {
		t.Fatal("entry legacy policy disappeared", err)
	}
	encoded, err := json.Marshal(original.capture)
	if err != nil {
		t.Fatal(err)
	}
	original.capture.Entry["kill_switch_policy"] = "always"
	if _, err := original.DesktopCapture(); err == nil {
		t.Fatal("changed captured member bypassed original source seal")
	}
	if json.Unmarshal(encoded, &original.capture) != nil {
		t.Fatal("cannot restore source fixture")
	}
}
