//go:build linux

package mobiletor

import (
	"encoding/json"
	"testing"
)

func TestLinuxStandardScopedAbsenceNeverClaimsNodeOrMalformedAbsence(t *testing.T) {
	for _, test := range []struct {
		name, body   string
		scoped, full bool
	}{
		{"empty", `{"nftables":[{"metainfo":{}}]}`, true, true},
		{"node", `{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"router_vpn_node_original","handle":4}}]}`, true, false},
		{"foreign-standard", `{"nftables":[{"metainfo":{}},{"table":{"family":"ip6","name":"router_vpn_standard_foreign","handle":4}}]}`, false, false},
		{"bare-standard-prefix", `{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"router_vpn_standard_","handle":4}}]}`, false, false},
		{"legacy", `{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"router_vpn_killswitch","handle":4}}]}`, false, false},
		{"missing-metadata", `{"nftables":[]}`, false, false},
		{"missing-handle", `{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"unrelated"}}]}`, false, false},
		{"unknown-object", `{"nftables":[{"metainfo":{}},{"chain":{"family":"inet","name":"unrelated","handle":4}}]}`, false, false},
		{"duplicate-table", `{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"unrelated","handle":4}},{"table":{"family":"inet","name":"unrelated","handle":4}}]}`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Reuse the production strict JSON/list inventory, not an empty
			// record standing in for a failed native read.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(test.body), &raw); err != nil {
				t.Fatal(err)
			}
			rows, err := desktopLinuxNFTRows([]byte(test.body))
			if err != nil {
				t.Fatal(err)
			}
			if (desktopLinuxProtectionScopeAbsent(rows, false) == nil) != test.scoped {
				t.Fatal("scoped read converted native inventory into absence")
			}
			if (desktopLinuxProtectionScopeAbsent(rows, true) == nil) != test.full {
				t.Fatal("full read lost independent node inventory")
			}
		})
	}
}
