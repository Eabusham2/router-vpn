package main

import (
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Read only the participants in this captured graph. Do not mutate either
// saved profile or substitute the final's protection for its original entry.
// Native source/journal/proof validation remains independently mandatory.
func desktopExternalProtectionPolicy(profile, entry common.RouterProfile, direct bool) string {
	if profile.ID == "" || direct && entry.ID != "" || !direct && (entry.ID == "" || entry.ID == profile.ID) {
		return ""
	}
	entryPolicy := ""
	if !direct {
		entryPolicy = desktopOwnedNodeProtectionPolicy(entry)
	}
	policy, err := mobilemultihop.AggregateExternalProtectionPolicy(desktopOwnedNodeProtectionPolicy(profile), entryPolicy)
	if err != nil {
		return ""
	}
	return policy
}
