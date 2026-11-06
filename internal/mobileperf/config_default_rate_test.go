package mobileperf

import "testing"

func TestDisabledZeroCoverRateKeepsSourceByteIdentical(t *testing.T) {
	profile := node()
	profile["daita_rate_kbps"] = 0
	raw := jsonText(perfFixture())
	compiled, err := Apply(raw, jsonText(map[string]any{"entry": profile, "exit": profile}))
	if err != nil || compiled != raw {
		t.Fatal("a dormant default changed the disabled dataplane", err)
	}
}

func TestCapturedZeroCoverRateMatchesOmittedDefault(t *testing.T) {
	for _, multihop := range []bool{false, true} {
		root := perfFixture()
		entry, exit := node(), node()
		exit["daita_enabled"] = true
		delete(exit, "daita_rate_kbps")
		if multihop {
			root["endpoints"] = []any{map[string]any{"type": "routervpn-amneziawg", "tag": "entry-wg"}}
			root["outbounds"].([]any)[0].(map[string]any)["detour"] = "entry-wg"
			entry["id"], entry["node_proof_id"] = "entry", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			entry["daita_enabled"] = true
			delete(entry, "daita_rate_kbps")
		} else {
			entry = exit
		}
		omitted, err := compilePerf(root, entry, exit)
		if err != nil {
			t.Fatal("omitted bounded default failed", multihop, err)
		}
		entry["daita_rate_kbps"], exit["daita_rate_kbps"] = 0, 0
		original := jsonText(map[string]any{"entry": entry, "exit": exit})
		captured, err := compilePerf(root, entry, exit)
		if err != nil {
			t.Fatal("captured default rate stopped the selected path", multihop, err)
		}
		if jsonText(captured) != jsonText(omitted) {
			t.Fatal("captured zero changed the bounded default or its owned path", multihop)
		}
		for _, key := range []string{"route", "dns", "outbounds", "endpoints", "inbounds"} {
			if jsonText(captured[key]) != jsonText(root[key]) {
				t.Fatal("default resolution changed the original dataplane", key)
			}
		}
		if jsonText(map[string]any{"entry": entry, "exit": exit}) != original {
			t.Fatal("default resolution rewrote the saved source")
		}
		for _, raw := range captured["services"].([]any) {
			if raw.(map[string]any)["rate_kbps"] != float64(MaxCoverKbps) {
				t.Fatal("default padding escaped its configured rate bound")
			}
		}
	}
}

func TestCoverDefaultKeepsIndependentExplicitHopRates(t *testing.T) {
	for _, rates := range [][2]int{{0, 32}, {64, 0}, {192, 0}, {32, 192}} {
		root := perfFixture()
		root["endpoints"] = []any{map[string]any{"type": "routervpn-amneziawg", "tag": "entry-wg"}}
		root["outbounds"].([]any)[0].(map[string]any)["detour"] = "entry-wg"
		entry, exit := node(), node()
		entry["id"], entry["node_proof_id"] = "entry", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		entry["daita_enabled"], exit["daita_enabled"] = true, true
		entry["daita_rate_kbps"], exit["daita_rate_kbps"] = rates[0], rates[1]
		compiled, err := compilePerf(root, entry, exit)
		if err != nil {
			t.Fatal(rates, err)
		}
		services := compiled["services"].([]any)
		if len(services) != 2 {
			t.Fatal("independent hop services were merged")
		}
		for _, raw := range services {
			service := raw.(map[string]any)
			want := rates[1]
			if service["packet_tag"] == "entry-wg" {
				want = rates[0]
			} else if service["packet_tag"] != "proxy" {
				t.Fatal("cover acquired an unowned route")
			}
			if want == 0 {
				want = MaxCoverKbps
			}
			if service["rate_kbps"] != float64(want) {
				t.Fatal("one hop's default changed the other hop's captured rate", rates, service)
			}
		}
	}
}

func TestCoverDefaultDoesNotAdmitInvalidProfileRates(t *testing.T) {
	for _, value := range []any{-1, 1, 31, 193, 32.5, "0", true} {
		profile := node()
		profile["daita_enabled"], profile["daita_rate_kbps"] = true, value
		if _, err := compilePerf(perfFixture(), profile, profile); err == nil {
			t.Fatal("invalid profile rate acquired a default", value)
		}
	}
}
