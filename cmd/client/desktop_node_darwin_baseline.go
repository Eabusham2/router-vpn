package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"

	"router-vpn/internal/applexray"
	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

type desktopMacOSNodeSelection struct {
	Schema     int                 `json:"schema"`
	Family     macosprocess.Family `json:"family"`
	ProfileID  string              `json:"profile_id"`
	NodeID     string              `json:"node_id"`
	Mode       string              `json:"mode"`
	StartLayer string              `json:"start_layer"`
	Session    string              `json:"session_id"`
	Source     string              `json:"source_sha256"`
	Config     string              `json:"config_sha256"`
	HomeLAN    bool                `json:"home_lan_access"`
	Policy     string              `json:"policy"`
}
type desktopMacOSNodeReceipt struct {
	Schema   int                       `json:"schema"`
	Capture  desktopMacOSNodeSelection `json:"capture"`
	Phase    string                    `json:"phase"`
	Token    string                    `json:"pf_token"`
	Baseline desktopMacOSBaselineProof `json:"baseline"`
}

// This capture has its own family and exact single saved-profile authority.
func (s desktopMacOSNodeSelection) valid() bool {
	return s.Schema == 1 && s.Family == macosprocess.NodeFamily && validProfileID(s.ProfileID) && desktopMacOSExternalLong.MatchString(s.NodeID) &&
		desktopMacOSExternalShort.MatchString(s.Session) && desktopMacOSExternalLong.MatchString(s.Source) && desktopMacOSExternalLong.MatchString(s.Config) &&
		(s.Policy == "off" || s.Policy == "on-connect" || s.Policy == "always") &&
		mobilemultihop.DesktopLinuxNodePhysicalGraphSupported(s.Mode, s.StartLayer) && s.StartLayer != ""
}

func decodeDesktopMacOSNodeReceipt(raw []byte, capture desktopMacOSNodeSelection, phase string) (desktopMacOSNodeReceipt, error) {
	var value desktopMacOSNodeReceipt
	failure := errors.New("macOS paired-node baseline has no exact original native receipt")
	if len(raw) == 0 || len(raw) > 8192 || !capture.valid() || phase != "active" && phase != "held" && phase != "retired" {
		return value, failure
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 5 {
		return value, failure
	}
	fields, ok := object["capture"].(map[string]any)
	if !ok || len(fields) != 11 {
		return value, failure
	}
	proof, ok := object["baseline"].(map[string]any)
	if !ok || len(proof) != 2 {
		return value, failure
	}
	for _, fields := range []map[string]any{object, fields, proof} {
		for _, raw := range fields {
			if raw == nil {
				return value, failure
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Schema != 1 || value.Capture != capture || value.Phase != phase ||
		!desktopMacOSExternalToken.MatchString(value.Token) || value.Baseline.Present != (phase == "active" || phase == "held" && capture.Policy != "off" || capture.Policy == "always") ||
		value.Baseline.Present && !desktopMacOSExternalLong.MatchString(value.Baseline.Rules) || !value.Baseline.Present && value.Baseline.Rules != "" {
		return desktopMacOSNodeReceipt{}, failure
	}
	if _, err := strconv.ParseUint(value.Token, 10, 64); err != nil {
		return desktopMacOSNodeReceipt{}, failure
	}
	return value, nil
}
