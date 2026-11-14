package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"

	"router-vpn/internal/applexray"
	"router-vpn/internal/macosprocess"
)

// The ordered baseline has its own concrete capture. Its source digest binds
// the entire native graph; it cannot be presented as an ordinary exit proxy.
// The Python journal verifies the saved Router control policy before mutation.
type desktopMacOSNodeChainSelection struct {
	Schema    int                 `json:"schema"`
	Family    macosprocess.Family `json:"family"`
	ProfileID string              `json:"profile_id"`
	Session   string              `json:"session_id"`
	Source    string              `json:"source_sha256"`
	Config    string              `json:"config_sha256"`
	HomeLAN   bool                `json:"home_lan_access"`
	Policy    string              `json:"policy"`
}

type desktopMacOSNodeChainReceipt struct {
	Schema   int                            `json:"schema"`
	Capture  desktopMacOSNodeChainSelection `json:"capture"`
	Phase    string                         `json:"phase"`
	Token    string                         `json:"pf_token"`
	Baseline desktopMacOSBaselineProof      `json:"baseline"`
}

func (s desktopMacOSNodeChainSelection) valid() bool {
	return s.Schema == 2 && (s.Family == macosprocess.NodeChainFamily || s.Family == macosprocess.NodeChainSOCKSFamily || s.Family == macosprocess.NodeChainCONNECTFamily) && validProfileID(s.ProfileID) &&
		desktopMacOSExternalShort.MatchString(s.Session) && desktopMacOSExternalLong.MatchString(s.Source) &&
		desktopMacOSExternalLong.MatchString(s.Config) && (s.Policy == "on-connect" || s.Policy == "always")
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
	if len(raw) == 0 || len(raw) > 8192 || !capture.valid() || phase != "active" && phase != "held" && phase != "retired" {
		return value, failure
	}
	object, err := applexray.Object(raw)
	if err != nil || !exactDesktopMacOSNodeChainFields(object, "schema", "capture", "phase", "pf_token", "baseline") {
		return value, failure
	}
	fields, ok := object["capture"].(map[string]any)
	if !ok || !exactDesktopMacOSNodeChainFields(fields, "schema", "family", "profile_id", "session_id", "source_sha256", "config_sha256", "home_lan_access", "policy") {
		return value, failure
	}
	proof, ok := object["baseline"].(map[string]any)
	if !ok || !exactDesktopMacOSNodeChainFields(proof, "present", "rules_sha256") {
		return value, failure
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Schema != 2 || value.Capture != capture || value.Phase != phase ||
		!desktopMacOSExternalToken.MatchString(value.Token) || value.Baseline.Present != (phase != "retired" || capture.Policy == "always") ||
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
		action == "apply" && expected != nil || action == "current" && (expected == nil || expected.Phase != "active") {
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
