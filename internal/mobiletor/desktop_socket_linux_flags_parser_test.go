//go:build linux

package mobiletor

import "testing"

func TestDesktopLinuxNFTActiveTableFlags(t *testing.T) {
	p, original, _ := desktopLinuxProtectionFixture(t)
	for name, flags := range map[string]any{
		"empty": []any{}, "dormant": []any{"dormant"}, "owner": []any{"owner"}, "persist": []any{"persist"},
		"null": nil, "string": "dormant", "numeric": float64(1), "mixed": []any{nil},
	} {
		t.Run(name, func(t *testing.T) {
			rows := desktopLinuxProtectionCopyRows(t, original)
			rows[1]["table"].(map[string]any)["flags"] = flags
			err := p.nft.verifyRows(rows, true)
			if (err == nil) != (name == "empty") {
				t.Fatal("active guardian accepted an inactive/ambiguous table or rejected an empty flag set", err)
			}
			if err := p.nft.verifyRows(rows, false); err != nil {
				t.Fatal("flag rejection prevented exact owned-permit cleanup", err)
			}
		})
	}
	if err := p.nft.verifyRows(original, true); err != nil {
		t.Fatal("ordinary active table lost source compatibility", err)
	}
}
