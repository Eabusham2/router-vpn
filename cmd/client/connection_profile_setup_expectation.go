package main

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/common"
)

// Setup expectations protect the caller's current selection. They are not
// persisted profile data and must not replace the saved target's own source
// inventory when Load applies it.
func decodeConnectionProfileSetupExpectations(raw []byte, out any) (desktopProfileExpectations, error) {
	fields, err := externalConnectJSONObject(raw)
	if err != nil {
		return desktopProfileExpectations{}, err
	}
	expected, err := decodeDesktopProfileExpectations(fields)
	if err != nil {
		return desktopProfileExpectations{}, err
	}
	delete(fields, "expected_selected_node_id")
	delete(fields, "expected_profile_tokens")
	plain, err := json.Marshal(fields)
	if err != nil {
		return desktopProfileExpectations{}, err
	}
	if err := json.Unmarshal(plain, out); err != nil {
		return desktopProfileExpectations{}, err
	}
	return expected, nil
}

func connectionProfileSetupNodeIDs(selected common.RouterProfile) ([]string, error) {
	ids := []string{selected.ID}
	if selected.MultihopEnabled {
		if len(selected.MultihopNodes) != 0 {
			if err := common.ValidateMultihopNodes(selected.MultihopNodes); err != nil {
				return nil, err
			}
			for _, member := range selected.MultihopNodes {
				ids = append(ids, member.ID)
			}
		} else {
			ids = append(ids, selected.MultihopEntryID, selected.MultihopExitID)
		}
	}
	unique := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if !validProfileID(id) {
			return nil, errors.New("connection setup lost a selected node identity")
		}
		if !seen[id] {
			unique, seen[id] = append(unique, id), true
		}
	}
	return unique, nil
}

func connectionProfileSetupSelectedGraph(selected common.RouterProfile, q connectionProfileSetupRequest) common.RouterProfile {
	selected.MultihopEnabled, selected.MultihopEntryID, selected.MultihopExitID = q.MultihopEnabled, q.MultihopEntryID, q.MultihopExitID
	selected.MultihopNodes = append([]common.MultihopNodeSelection(nil), q.MultihopNodes...)
	return selected
}

// Caller holds operationMu and a.mu before any saved/profile mutation.
func (a *app) validateConnectionProfileSetupExpectationsLocked(expected desktopProfileExpectations, selected common.RouterProfile) error {
	if !expected.present() {
		return nil
	}
	ids, err := connectionProfileSetupNodeIDs(selected)
	if err != nil {
		return err
	}
	return a.validateDesktopProfileExpectationsLocked(expected, ids, true)
}
