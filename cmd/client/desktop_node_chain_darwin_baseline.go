package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/macosprocess"
)

// The ordered baseline has its own concrete capture. Its source digest binds
// the entire native graph; it cannot be presented as an ordinary exit proxy.
// The Python journal verifies the saved Router control policy before mutation.
type desktopMacOSNodeChainSelection struct {
	Schema        int                 `json:"schema"`
	Family        macosprocess.Family `json:"family"`
	ProfileID     string              `json:"profile_id"`
	Session       string              `json:"session_id"`
	Source        string              `json:"source_sha256"`
	Config        string              `json:"config_sha256"`
	HomeLAN       bool                `json:"home_lan_access"`
	Policy        string              `json:"policy"`
	MembersJSON   string              `json:"members_json,omitempty"`
	MembersSHA256 string              `json:"members_sha256,omitempty"`
}

type desktopMacOSNodeChainReceipt struct {
	Schema   int                            `json:"schema"`
	Capture  desktopMacOSNodeChainSelection `json:"capture"`
	Phase    string                         `json:"phase"`
	Token    string                         `json:"pf_token"`
	Baseline desktopMacOSBaselineProof      `json:"baseline"`
}

func (s desktopMacOSNodeChainSelection) valid() bool {
	return (s.Schema == 2 && s.MembersJSON == "" && s.MembersSHA256 == "" || s.Schema == 3 && s.validMembers()) && (s.Family == macosprocess.NodeChainFamily || s.Family == macosprocess.NodeChainSOCKSFamily || s.Family == macosprocess.NodeChainCONNECTFamily || s.Family == macosprocess.NodeChainExecutionFamily) && validProfileID(s.ProfileID) &&
		desktopMacOSExternalShort.MatchString(s.Session) && desktopMacOSExternalLong.MatchString(s.Source) &&
		desktopMacOSExternalLong.MatchString(s.Config) && (s.Policy == "off" || s.Policy == "on-connect" || s.Policy == "always")
}

func (s desktopMacOSNodeChainSelection) validMembers() bool {
	if len(s.MembersJSON) == 0 || len(s.MembersJSON) > 512+192*common.MultihopPhysicalTraversalDepth || !desktopMacOSExternalLong.MatchString(s.MembersSHA256) {
		return false
	}
	var rows [][]any
	if json.Unmarshal([]byte(s.MembersJSON), &rows) != nil || len(rows) < 2 || len(rows) > common.MultihopPhysicalTraversalDepth ||
		len(rows) <= common.MultihopMaximumNodes && len(s.MembersJSON) > 4096 ||
		len(rows) > common.MultihopMaximumNodes && (s.Family != macosprocess.NodeChainFamily && s.Family != macosprocess.NodeChainExecutionFamily || len(s.MembersJSON) > max(4096, 512+192*len(rows))) {
		return false
	}
	canonical, err := json.Marshal(rows)
	if err != nil || string(canonical) != s.MembersJSON {
		return false
	}
	digest := sha256.Sum256(append([]byte("routervpn-ordered-protection-members-v1\n"), canonical...))
	if hex.EncodeToString(digest[:]) != s.MembersSHA256 {
		return false
	}
	seen := map[string]bool{}
	for i, row := range rows {
		if len(row) != 6 {
			return false
		}
		id, ok := row[0].(string)
		if !ok || !validProfileID(id) || seen[id] {
			return false
		}
		seen[id] = true
		mode, ok := row[1].(string)
		if !ok || mode == "" || len(mode) > 64 {
			return false
		}
		for _, c := range mode {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		if row[2] != "router-vpn" && row[2] != "external" || row[3] != "off" && row[3] != "on-connect" && row[3] != "always" || row[4] != "on" && row[4] != "off" && row[4] != "auto" {
			return false
		}
		if _, ok := row[5].(bool); !ok {
			return false
		}
		if i == len(rows)-1 && id != s.ProfileID {
			return false
		}
		if len(rows) > common.MultihopMaximumNodes {
			expectedMode, expectedKind := "shadowsocks", "external"
			if i == 0 {
				expectedMode, expectedKind = "wg", "router-vpn"
			} else if i == len(rows)-1 {
				expectedKind = "router-vpn"
			}
			if mode != expectedMode || row[2] != expectedKind {
				return false
			}
		}
	}
	return true
}

func (s desktopMacOSNodeChainSelection) receiptLimit() int {
	if len(s.MembersJSON) > 4096 && s.validMembers() {
		return max(8192, 2*len(s.MembersJSON)+4096)
	}
	return 8192
}

func exactDesktopMacOSNodeChainFields(object map[string]any, names ...string) bool {
	if len(object) != len(names) {
		return false
	}
	for _, name := range names {
		if object[name] == nil {
			return false
		}
	}
	return true
}

func decodeDesktopMacOSNodeChainReceipt(raw []byte, capture desktopMacOSNodeChainSelection, phase string) (desktopMacOSNodeChainReceipt, error) {
	var value desktopMacOSNodeChainReceipt
	failure := errors.New("macOS ordered baseline has no exact original native receipt")
	if len(raw) == 0 || len(raw) > capture.receiptLimit() || !capture.valid() || phase != "active" && phase != "held" && phase != "retired" {
		return value, failure
	}
	object, err := applexray.Object(raw)
	if err != nil || !exactDesktopMacOSNodeChainFields(object, "schema", "capture", "phase", "pf_token", "baseline") {
		return value, failure
	}
	fields, ok := object["capture"].(map[string]any)
	names := []string{"schema", "family", "profile_id", "session_id", "source_sha256", "config_sha256", "home_lan_access", "policy"}
	if capture.Schema == 3 {
		names = append(names, "members_json", "members_sha256")
	}
	if !ok || !exactDesktopMacOSNodeChainFields(fields, names...) {
		return value, failure
	}
	proof, ok := object["baseline"].(map[string]any)
	if !ok || !exactDesktopMacOSNodeChainFields(proof, "present", "rules_sha256") {
		return value, failure
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Schema != capture.Schema || value.Capture != capture || value.Phase != phase ||
		!desktopMacOSExternalToken.MatchString(value.Token) || value.Baseline.Present != (phase == "active" || phase == "held" && capture.Policy != "off" || capture.Policy == "always") ||
		value.Baseline.Present && !desktopMacOSExternalLong.MatchString(value.Baseline.Rules) || !value.Baseline.Present && value.Baseline.Rules != "" {
		return desktopMacOSNodeChainReceipt{}, failure
	}
	if _, err := strconv.ParseUint(value.Token, 10, 64); err != nil {
		return desktopMacOSNodeChainReceipt{}, failure
	}
	return value, nil
}

func encodeDesktopMacOSNodeChainBaselineRequest(selection desktopMacOSNodeChainSelection, action string, expected *desktopMacOSNodeChainReceipt) ([]byte, error) {
	if !selection.valid() || action != "apply" && action != "current" && action != "retire" && action != "release" ||
		action == "apply" && (expected != nil || selection.Schema != 3) || action == "current" && (expected == nil || expected.Phase != "active") {
		return nil, errors.New("macOS ordered baseline requires its original typed action")
	}
	if expected != nil {
		raw, err := json.Marshal(expected)
		if err != nil {
			return nil, err
		}
		if _, err := decodeDesktopMacOSNodeChainReceipt(raw, selection, expected.Phase); err != nil {
			return nil, err
		}
	}
	return json.Marshal(struct {
		Capture  desktopMacOSNodeChainSelection `json:"capture"`
		Expected *desktopMacOSNodeChainReceipt  `json:"expected"`
	}{selection, expected})
}
