package mobiletor

import (
	"encoding/json"
	"strings"
	"testing"
)

func serverPaddingSource(t *testing.T, selection any, present bool) (*ServerTorPolicy, error) {
	t.Helper()
	node := strings.Repeat("1", 64)
	source := map[string]any{"schema": 1, "id": "owned-padding", "entry_node_id": node, "mode": "tor", "dns": map[string]any{"mode": "home"}, "adguard_ipv4": "192.168.50.133"}
	if present {
		source["padding"] = selection
	}
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	return NewServerTorPolicy(string(raw), node)
}

func TestServerTorPaddingSourcePinsExactSelectionWithoutChangingDNS(t *testing.T) {
	base, err := serverPaddingSource(t, nil, false)
	if err != nil || base.Padding() != (TorPaddingPolicy{}) || strings.Contains(base.Source(), `"padding"`) {
		t.Fatal("absent padding changed the existing private source", err)
	}
	seen := map[string]bool{}
	for _, test := range []struct {
		name     string
		selected map[string]any
		want     TorPaddingPolicy
	}{
		{"enabled-default", map[string]any{"enabled": true}, TorPaddingPolicy{true, 192}},
		{"enabled-minimum", map[string]any{"enabled": true, "rate_kbps": 32}, TorPaddingPolicy{true, 32}},
		{"enabled-middle", map[string]any{"enabled": true, "rate_kbps": 96}, TorPaddingPolicy{true, 96}},
		{"off-unset", map[string]any{"enabled": false}, TorPaddingPolicy{}},
		{"off-dormant", map[string]any{"enabled": false, "rate_kbps": 192}, TorPaddingPolicy{false, 192}},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := serverPaddingSource(t, test.selected, true)
			if err != nil || policy.Padding() != test.want || policy.SourceSHA256() == base.SourceSHA256() || seen[policy.SourceSHA256()] || policy.DNSPolicySHA256() != base.DNSPolicySHA256() {
				t.Fatal("padding selection was dropped, conflated with another source, or changed DNS", err)
			}
			seen[policy.SourceSHA256()] = true
			replayed, err := NewServerTorPolicy(policy.Source(), policy.EntryNodeID())
			if err != nil || replayed.Padding() != test.want || replayed.SourceSHA256() != policy.SourceSHA256() {
				t.Fatal("canonical padding source did not reproduce", err)
			}
			test.selected["enabled"] = !test.want.Enabled
			if policy.Padding() != test.want {
				t.Fatal("caller mutation changed captured native cover policy")
			}
			graph, err := policy.NativeConfig(19950, strings.Repeat("2", 64), strings.Repeat("3", 64))
			plain, plainErr := base.NativeConfig(19950, strings.Repeat("2", 64), strings.Repeat("3", 64))
			if err != nil || plainErr != nil || graph != plain {
				t.Fatal("Tor control-owned cover added an unrelated network service or replaced DNS", err, plainErr)
			}
		})
	}
	defaultPolicy, err := serverPaddingSource(t, map[string]any{"enabled": true}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, rate := range []int{0, 192} {
		policy, err := serverPaddingSource(t, map[string]any{"enabled": true, "rate_kbps": rate}, true)
		if err != nil || policy.Source() != defaultPolicy.Source() {
			t.Fatal("enabled unset/default rate changed the actual canonical cover policy", err)
		}
	}
}

func TestServerTorPaddingRejectsMalformedOrBorrowedNativeAuthority(t *testing.T) {
	for name, selection := range map[string]any{
		"null": nil, "boolean": true, "empty": map[string]any{},
		"enabled-text":      map[string]any{"enabled": "true"},
		"enabled-null":      map[string]any{"enabled": nil},
		"rate-text":         map[string]any{"enabled": true, "rate_kbps": "64"},
		"rate-null":         map[string]any{"enabled": true, "rate_kbps": nil},
		"rate-fraction":     map[string]any{"enabled": true, "rate_kbps": 64.5},
		"rate-small":        map[string]any{"enabled": true, "rate_kbps": 31},
		"rate-large":        map[string]any{"enabled": true, "rate_kbps": 193},
		"off-invalid":       map[string]any{"enabled": false, "rate_kbps": -1},
		"borrowed-proof":    map[string]any{"enabled": true, "is_tor": true},
		"borrowed-owner":    map[string]any{"enabled": true, "session": strings.Repeat("a", 64)},
		"borrowed-secret":   map[string]any{"enabled": true, "password": "private-padding-secret"},
		"unknown-direction": map[string]any{"enabled": true, "direction": "bidirectional"},
	} {
		t.Run(name, func(t *testing.T) {
			if policy, err := serverPaddingSource(t, selection, true); err == nil || policy != nil || strings.Contains(err.Error(), "private-padding-secret") {
				t.Fatal("malformed source gained native padding authority or exposed credentials", err)
			}
		})
	}
}
