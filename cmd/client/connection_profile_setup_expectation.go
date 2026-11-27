package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
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

// This completion purpose has a current device and a different future final.
// Path-token bounds remain unchanged; the independent device has its own token.
const connectionProfileCompletionPurpose = "draft-last-ss-final"
const connectionProfileHY2CompletionPurpose = "draft-last-hy2-final"

func connectionProfileCompletionMode(purpose string) string {
	switch purpose {
	case connectionProfileCompletionPurpose:
		return "shadowsocks"
	case connectionProfileHY2CompletionPurpose:
		return "hysteria2"
	default:
		return ""
	}
}

type connectionProfileCompletionRequest struct {
	Schema                   int                            `json:"schema"`
	Purpose                  string                         `json:"purpose"`
	Execution                string                         `json:"execution"`
	DraftRevision            string                         `json:"draft_revision"`
	DeviceID                 string                         `json:"device_id"`
	DeviceRevision           string                         `json:"device_revision"`
	FinalID                  string                         `json:"final_id"`
	Nodes                    []common.MultihopNodeSelection `json:"nodes"`
	Name                     string                         `json:"name,omitempty"`
	ExpectedCompletionSHA256 string                         `json:"expected_completion_sha256,omitempty"`
	desktopProfileExpectations
}

func decodeConnectionProfileCompletion(raw []byte, saving bool) (connectionProfileCompletionRequest, error) {
	var q connectionProfileCompletionRequest
	bad := errors.New("completion requires the exact unfinished Local path and independent current device")
	fields, err := externalConnectJSONObject(raw)
	if err != nil {
		return q, bad
	}
	for name := range fields {
		switch name {
		case "schema", "purpose", "execution", "draft_revision", "device_id", "device_revision", "final_id", "nodes", "expected_selected_node_id", "expected_profile_tokens":
		case "name", "expected_completion_sha256":
			if !saving {
				return q, bad
			}
		default:
			return q, bad
		}
	}
	count := 10
	if saving {
		count += 2
	}
	if len(fields) != count {
		return q, bad
	}
	expected, err := decodeDesktopProfileExpectations(fields)
	if err != nil {
		return q, bad
	}
	var rows []json.RawMessage
	if json.Unmarshal(fields["nodes"], &rows) != nil || len(rows) < 2 || len(rows) > mobilemultihop.NodeChainExtendedLocalMaximumNodes {
		return q, bad
	}
	for _, raw := range rows {
		row, err := externalConnectJSONObject(raw)
		if err != nil || len(row) != 2 || row["id"] == nil || row["mode"] == nil {
			return q, bad
		}
	}
	if json.Unmarshal(raw, &q) != nil {
		return q, bad
	}
	q.desktopProfileExpectations = expected
	finalMode := connectionProfileCompletionMode(q.Purpose)
	if q.Schema != 1 || finalMode == "" || q.Execution != "local" ||
		!validViaEntryRequestID(q.DraftRevision) || !validProfileID(q.DeviceID) || !validProfileID(q.FinalID) ||
		!validExternalProfileExpectationToken(q.DeviceRevision) || q.ExpectedSelectedNodeID == nil ||
		*q.ExpectedSelectedNodeID != q.DeviceID || len(q.ExpectedProfileTokens) != len(q.Nodes) ||
		q.Nodes[len(q.Nodes)-1].ID != q.FinalID || q.Nodes[len(q.Nodes)-1].Mode != finalMode {
		return q, bad
	}
	pairedHysteria := common.PairedHysteriaLocalMultihopSelection(q.Nodes)
	seen := map[string]bool{}
	for position, node := range q.Nodes {
		pairedHY2Final := q.Purpose == connectionProfileHY2CompletionPurpose && position == len(q.Nodes)-1 && node.Mode == "hysteria2"
		if !validProfileID(node.ID) || seen[node.ID] ||
			!mobilemultihop.NodeChainPrefixMode(node.Mode) && (position == 0 || node.Mode != "shadowsocks" && !pairedHY2Final && !(pairedHysteria && node.Mode == "hysteria2")) ||
			!validExternalProfileExpectationToken(q.ExpectedProfileTokens[node.ID]) {
			return q, bad
		}
		seen[node.ID] = true
	}
	if token, present := q.ExpectedProfileTokens[q.DeviceID]; present && token != q.DeviceRevision {
		return q, bad
	}
	if saving {
		q.Name = strings.TrimSpace(q.Name)
		decoded, err := hex.DecodeString(q.ExpectedCompletionSHA256)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != q.ExpectedCompletionSHA256 {
			return q, bad
		}
		if err := validateConnectionProfileName(q.Name); err != nil {
			return q, err
		}
	}
	return q, nil
}

func (q connectionProfileCompletionRequest) identity() []byte {
	q.Name, q.ExpectedCompletionSHA256 = "", ""
	raw, _ := json.Marshal(q)
	return raw
}

// Caller holds operationMu and a.mu. No complete-route expectation rule changes.
func (a *app) validateConnectionProfileCompletionLocked(q connectionProfileCompletionRequest) error {
	bad := errors.New("the original completion device, path, or idle owner changed")
	if a.controllerClosingLocked() || a.profiles.SelectedID != q.DeviceID || a.connectionContext != nil ||
		a.candidatePreparation != nil || !orderedCandidatePreparationDownLocked(a) {
		return bad
	}
	device, ok := a.profileByIDLocked(q.DeviceID)
	if !ok || device.External != nil || device.NodeKind != "" && device.NodeKind != "router-vpn" ||
		!common.ValidNodeProofID(device.NodeProofID) || publicProfileToken(device) != q.DeviceRevision {
		return bad
	}
	seen := map[string]bool{}
	for _, profile := range a.profiles.Profiles {
		if seen[profile.ID] {
			return bad
		}
		seen[profile.ID] = true
	}
	pairedHysteria := common.PairedHysteriaLocalMultihopSelection(q.Nodes)
	for position, row := range q.Nodes {
		profile, ok := a.profileByIDLocked(row.ID)
		if !ok || publicProfileToken(profile) != q.ExpectedProfileTokens[row.ID] {
			return bad
		}
		if pairedHysteria && (profile.External != nil || profile.NodeKind == "external" || profile.StartLayer != "" && profile.StartLayer != "off") {
			return bad
		}
		if profile.External != nil || profile.NodeKind == "external" {
			if position == 0 || position == len(q.Nodes)-1 || !desktopNodeChainImportedExecutionMiddle(profile) {
				return bad
			}
		} else if profile.NodeKind != "" && profile.NodeKind != "router-vpn" || !common.ValidNodeProofID(profile.NodeProofID) ||
			!desktopCONNECTExecutionPairedLayer(profile.StartLayer) || (row.Mode == "shadowsocks" || row.Mode == "hysteria2") && profile.StartLayer != "" && profile.StartLayer != "off" {
			return bad
		}
	}
	return nil
}
