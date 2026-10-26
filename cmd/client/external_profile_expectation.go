package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"router-vpn/internal/common"
)

var errExternalProfileSelectionChanged = errors.New("the selected external path changed or its captured node revisions are incomplete; reopen the external path controls")

func validExternalProfileExpectationToken(token string) bool {
	return validStartupProfileToken(token) && token == strings.ToLower(token)
}

func decodeExternalProfileConnectRequest(body io.Reader) (externalProfileConnectRequest, error) {
	var request externalProfileConnectRequest
	data, err := io.ReadAll(body)
	if err != nil {
		return request, err
	}
	err = json.Unmarshal(data, &request)
	return request, err
}

// Only the two expectation fields are new. Existing callers may omit both,
// including internal startup requests that already carry their own capture.
// Once either field is supplied, null/partial/ambiguous data cannot silently
// downgrade the request to the legacy contract.
func (q *externalProfileConnectRequest) UnmarshalJSON(data []byte) error {
	fields, err := externalConnectJSONObject(data)
	if err != nil {
		return err
	}
	for name := range fields {
		for _, canonical := range []string{"expected_selected_node_id", "expected_profile_tokens"} {
			if name != canonical && strings.EqualFold(name, canonical) {
				return errors.New("external source expectation field must use its canonical JSON name")
			}
		}
	}
	selected, hasSelected := fields["expected_selected_node_id"]
	tokens, hasTokens := fields["expected_profile_tokens"]
	if hasSelected != hasTokens {
		return errors.New("external source expectations require both selected identity and node revisions")
	}
	if hasSelected {
		if bytes.Equal(bytes.TrimSpace(selected), []byte("null")) {
			return errors.New("expected external selection cannot be null")
		}
		entries, err := externalConnectJSONObject(tokens)
		if err != nil || len(entries) > 64 {
			return errors.New("expected external node revisions must be a bounded unique object")
		}
		for id, raw := range entries {
			var token string
			if json.Unmarshal(raw, &token) != nil || !validProfileID(id) || !validExternalProfileExpectationToken(token) {
				return errors.New("expected external node revision is malformed")
			}
		}
	}
	type wire externalProfileConnectRequest
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*q = externalProfileConnectRequest(decoded)
	return nil
}

func externalConnectJSONObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	open, err := decoder.Token()
	if err != nil || open != json.Delim('{') {
		return nil, errors.New("external connection JSON must be an object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("external connection JSON field is invalid")
		}
		if _, exists := fields[name]; exists {
			return nil, errors.New("external connection JSON contains a duplicate field")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, err
		}
		fields[name] = raw
	}
	if close, err := decoder.Token(); err != nil || close != json.Delim('}') {
		return nil, errors.New("external connection JSON object is incomplete")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("external connection JSON contains trailing data")
	}
	return fields, nil
}

func (q externalProfileConnectRequest) hasExpectedProfiles() bool {
	return q.ExpectedSelectedNodeID != nil || q.ExpectedProfileTokens != nil
}

// This mirrors the existing saved-path resolution without mutating a profile:
// explicit Direct wins, then an explicit entry, then the enabled saved path
// (or the saved entry requested by explicit direct:false).
func externalConnectExpectedEntry(q externalProfileConnectRequest, profile common.RouterProfile) string {
	if q.Direct != nil && *q.Direct {
		return ""
	}
	if entry := strings.TrimSpace(q.EntryID); entry != "" {
		return entry
	}
	if profile.MultihopEnabled || q.Direct != nil && !*q.Direct {
		return strings.TrimSpace(profile.MultihopEntryID)
	}
	return ""
}

// a.mu and the owning connection transaction protect the initial comparison
// and profile snapshot together. The same comparison runs after native graph
// preparation, before any previous runtime is stopped or a new one is staged.
func (a *app) validateExternalProfileExpectedProfilesLocked(q externalProfileConnectRequest, captured common.RouterProfile) error {
	if !q.hasExpectedProfiles() {
		return nil
	}
	if q.ExpectedSelectedNodeID == nil || q.ExpectedProfileTokens == nil || len(q.ExpectedProfileTokens) > 64 ||
		*q.ExpectedSelectedNodeID != a.profiles.SelectedID || captured.ID != strings.TrimSpace(q.ProfileID) ||
		q.ExpectedProfileTokens[captured.ID] != publicProfileToken(captured) {
		return errExternalProfileSelectionChanged
	}
	required := []string{captured.ID}
	if *q.ExpectedSelectedNodeID != "" {
		required = append(required, *q.ExpectedSelectedNodeID)
	}
	if entry := externalConnectExpectedEntry(q, captured); entry != "" {
		required = append(required, entry)
	}
	for _, id := range required {
		if !validProfileID(id) || q.ExpectedProfileTokens[id] == "" {
			return errExternalProfileSelectionChanged
		}
	}
	for id, token := range q.ExpectedProfileTokens {
		if !validProfileID(id) || !validExternalProfileExpectationToken(token) {
			return errExternalProfileSelectionChanged
		}
		matches := 0
		for _, profile := range a.profiles.Profiles {
			if profile.ID == id {
				matches++
				if token != publicProfileToken(profile) {
					return errExternalProfileSelectionChanged
				}
			}
		}
		if matches != 1 {
			return errExternalProfileSelectionChanged
		}
	}
	return nil
}

func (a *app) validateExternalProfileExpectedProfiles(q externalProfileConnectRequest, captured common.RouterProfile) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.validateExternalProfileExpectedProfilesLocked(q, captured)
}
