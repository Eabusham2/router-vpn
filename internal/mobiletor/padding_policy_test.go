package mobiletor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTorPaddingPolicyRejectsLocalRuntimeOrMalformedRequest(t *testing.T) {
	cases := []struct {
		name   string
		values map[string]any
	}{
		{"requested-default", map[string]any{"daita_enabled": true}},
		{"requested-unset-rate", map[string]any{"daita_enabled": true, "daita_rate_kbps": 0}},
		{"requested-minimum", map[string]any{"daita_enabled": true, "daita_rate_kbps": 32}},
		{"requested-maximum", map[string]any{"daita_enabled": true, "daita_rate_kbps": 192}},
		{"enabled-string", map[string]any{"daita_enabled": "true"}},
		{"enabled-number", map[string]any{"daita_enabled": 1}},
		{"enabled-null", map[string]any{"daita_enabled": nil}},
		{"rate-string", map[string]any{"daita_enabled": false, "daita_rate_kbps": "64"}},
		{"rate-boolean", map[string]any{"daita_enabled": false, "daita_rate_kbps": true}},
		{"rate-null", map[string]any{"daita_enabled": false, "daita_rate_kbps": nil}},
		{"rate-fraction", map[string]any{"daita_enabled": false, "daita_rate_kbps": 64.5}},
		{"rate-negative", map[string]any{"daita_enabled": false, "daita_rate_kbps": -1}},
		{"rate-too-small", map[string]any{"daita_enabled": false, "daita_rate_kbps": 31}},
		{"rate-too-large", map[string]any{"daita_enabled": false, "daita_rate_kbps": 193}},
		{"rate-overflow", map[string]any{"daita_enabled": false, "daita_rate_kbps": json.Number("9999999999999999999999999999")}},
	}
	for _, protocol := range []string{"tor", "tor-bridge"} {
		for _, test := range cases {
			t.Run(protocol+"/"+test.name, func(t *testing.T) {
				profile := torHostProfile()
				if protocol == "tor" {
					profile["external"] = map[string]any{"protocol": "tor"}
				}
				for key, value := range test.values {
					profile[key] = value
				}
				source := torHostEncode(t, profile)
				for _, base := range []string{"", torHostBase(t)} {
					if config, err := CompileProfile(source, "padding-source-session", base); err == nil || config != "" || !strings.Contains(err.Error(), "padding") {
						t.Fatal("Tor compiler returned an unpadded runnable graph for the captured request", err)
					}
				}
				if err := ValidateProfile(source); strings.HasPrefix(test.name, "requested-") {
					if err != nil {
						t.Fatal("idle Tor validation discarded a bounded Server cover selection", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "padding") {
					t.Fatal("idle Tor validation silently accepted malformed padding", err)
				}
				entry := torHomeEntry()
				torHomePair(profile, entry)
				paired := torHostEncode(t, profile)
				if config, err := CompileProfileWithPredecessor(paired, "padding-source-session", torHostBase(t), torHostEncode(t, entry)); err == nil || config != "" || !strings.Contains(err.Error(), "padding") {
					t.Fatal("paired Tor compiler substituted predecessor protection for requested exit padding", err)
				}
				if paired != torHostEncode(t, profile) {
					t.Fatal("rejected Tor padding changed the captured source")
				}
			})
		}
	}
}

func TestTorPaddingPolicyPreservesValidDormantSettings(t *testing.T) {
	for _, explicitOff := range []bool{false, true} {
		for _, rate := range []any{nil, 0, 32, 64, 192} {
			profile := torHostProfile()
			if explicitOff {
				profile["daita_enabled"] = false
			}
			if rate != nil {
				profile["daita_rate_kbps"] = rate
			}
			source := torHostEncode(t, profile)
			if err := ValidateProfile(source); err != nil {
				t.Fatal("valid dormant padding setting cannot remain saved", err)
			}
			compiled, err := CompileProfile(source, "dormant-padding-session", "")
			if err != nil {
				t.Fatal("padding Off blocked a usable Tor graph", err)
			}
			root, err := profileObject(compiled, 4<<20)
			if err != nil || root["services"] != nil {
				t.Fatal("dormant padding installed an unrequested native service", err)
			}
			captured, err := profileObject(source, 256<<10)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := torProfileDigest(captured)
			if err != nil || torHostTagged(t, root["outbounds"], ProfileOutboundTag)["profile_sha256"] != digest || source != torHostEncode(t, profile) {
				t.Fatal("padding Off erased its dormant setting or source revision", err)
			}
		}
	}
}
