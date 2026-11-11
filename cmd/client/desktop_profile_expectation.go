package main

import (
	"encoding/json"
	"errors"
	"strings"
)

var errDesktopProfileSelectionChanged = errors.New("the selected path changed or its captured node revisions are incomplete; reopen the path controls")

// These public revisions bind a UI operation to the catalog it actually showed.
// They contain no private node material. Omission of both fields preserves the
// legacy internal contract; a partial or malformed capture never does.
type desktopProfileExpectations struct {
	ExpectedSelectedNodeID *string           `json:"expected_selected_node_id,omitempty"`
	ExpectedProfileTokens  map[string]string `json:"expected_profile_tokens,omitempty"`
}

func decodeDesktopProfileExpectations(fields map[string]json.RawMessage) (desktopProfileExpectations, error) {
	var capture desktopProfileExpectations
	for name := range fields {
		for _, canonical := range []string{"expected_selected_node_id", "expected_profile_tokens"} {
			if name != canonical && strings.EqualFold(name, canonical) {
				return capture, errors.New("source expectation field must use its canonical JSON name")
			}
		}
	}
	selected, hasSelected := fields["expected_selected_node_id"]
	tokens, hasTokens := fields["expected_profile_tokens"]
	if hasSelected != hasTokens {
		return capture, errors.New("source expectations require both selected identity and node revisions")
	}
	if !hasSelected {
		return capture, nil
	}
	if err := json.Unmarshal(selected, &capture.ExpectedSelectedNodeID); err != nil || capture.ExpectedSelectedNodeID == nil ||
		(*capture.ExpectedSelectedNodeID != "" && !validProfileID(*capture.ExpectedSelectedNodeID)) {
		return desktopProfileExpectations{}, errors.New("expected selection must be a canonical node identity")
	}
	entries, err := externalConnectJSONObject(tokens)
	if err != nil || len(entries) > 64 {
		return desktopProfileExpectations{}, errors.New("expected node revisions must be a bounded unique object")
	}
	capture.ExpectedProfileTokens = make(map[string]string, len(entries))
	for id, raw := range entries {
		var token string
		if json.Unmarshal(raw, &token) != nil || !validProfileID(id) || !validExternalProfileExpectationToken(token) {
			return desktopProfileExpectations{}, errors.New("expected node revision is malformed")
		}
		capture.ExpectedProfileTokens[id] = token
	}
	return capture, nil
}

func (capture desktopProfileExpectations) present() bool {
	return capture.ExpectedSelectedNodeID != nil || capture.ExpectedProfileTokens != nil
}

// Call while a.mu and the owning mutation/connection transaction are held, so
// validation and the resulting private snapshot belong to the same operation.
// exact rejects unrelated captured nodes as well as missing path members.
func (a *app) validateDesktopProfileExpectationsLocked(capture desktopProfileExpectations, requiredIDs []string, exact bool) error {
	if !capture.present() {
		return nil
	}
	if capture.ExpectedSelectedNodeID == nil || capture.ExpectedProfileTokens == nil || len(capture.ExpectedProfileTokens) > 64 ||
		*capture.ExpectedSelectedNodeID != a.profiles.SelectedID {
		return errDesktopProfileSelectionChanged
	}
	required := make(map[string]bool, len(requiredIDs)+1)
	for _, id := range requiredIDs {
		if !validProfileID(id) {
			return errDesktopProfileSelectionChanged
		}
		required[id] = true
	}
	if selected := *capture.ExpectedSelectedNodeID; selected != "" {
		if !validProfileID(selected) {
			return errDesktopProfileSelectionChanged
		}
		required[selected] = true
	}
	if exact && len(capture.ExpectedProfileTokens) != len(required) {
		return errDesktopProfileSelectionChanged
	}
	for id := range required {
		if capture.ExpectedProfileTokens[id] == "" {
			return errDesktopProfileSelectionChanged
		}
	}
	for id, token := range capture.ExpectedProfileTokens {
		if !validProfileID(id) || !validExternalProfileExpectationToken(token) || (exact && !required[id]) {
			return errDesktopProfileSelectionChanged
		}
		matches := 0
		for _, profile := range a.profiles.Profiles {
			if profile.ID == id {
				matches++
				if token != publicProfileToken(profile) {
					return errDesktopProfileSelectionChanged
				}
			}
		}
		if matches != 1 {
			return errDesktopProfileSelectionChanged
		}
	}
	return nil
}
