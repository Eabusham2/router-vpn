package main

import (
	"errors"

	"router-vpn/internal/common"
)

// Public catalog revisions use the existing private source/policy projection.
// A credential relink must invalidate a loaded selection even when the node ID
// stays the same. Historical measurement readback is not an edited preference
// and must not retire the selection when a benchmark finishes asynchronously.
func publicProfileToken(profile common.RouterProfile) string {
	profile.EffectiveMTU = 0
	return profileStartupSettingsToken(profile)
}

// The caller holds a.mu for the complete load transaction. Return only the
// selected graph's current nodes, including hop policies restored by that same
// transaction. This map is response evidence, never saved credential material.
func (a *app) connectionProfileTokensLocked(selected common.RouterProfile) (map[string]string, error) {
	ids := []string{selected.ID}
	if selected.MultihopEnabled {
		ids = append(ids, selected.MultihopEntryID, selected.MultihopExitID)
	}
	tokens := make(map[string]string, len(ids))
	for _, id := range ids {
		profile, exists := a.profileByIDLocked(id)
		if id == "" || !exists {
			return nil, errors.New("loaded connection graph references an unlinked node")
		}
		tokens[id] = publicProfileToken(profile)
	}
	return tokens, nil
}
