package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"

	"router-vpn/internal/applexray"
	"router-vpn/internal/mobilemultihop"
)

type desktopMacOSExternalSelection struct {
	Schema         int    `json:"schema"`
	ProfileID      string `json:"profile_id"`
	EntryProfileID string `json:"entry_profile_id"`
	FinalPolicy    string `json:"final_policy"`
	EntryPolicy    string `json:"entry_policy"`
	Protocol       string `json:"protocol"`
	Session        string `json:"session_id"`
	Source         string `json:"source_sha256"`
	Config         string `json:"config_sha256"`
	HomeLAN        bool   `json:"home_lan_access"`
	Policy         string `json:"policy"`
}
type desktopMacOSBaselineProof struct {
	Present bool   `json:"present"`
	Rules   string `json:"rules_sha256"`
}
type desktopMacOSExternalReceipt struct {
	Schema   int                           `json:"schema"`
	Capture  desktopMacOSExternalSelection `json:"capture"`
	Phase    string                        `json:"phase"`
	Token    string                        `json:"pf_token"`
	Baseline desktopMacOSBaselineProof     `json:"baseline"`
}

var desktopMacOSExternalShort = regexp.MustCompile(`^[a-f0-9]{32}$`)
var desktopMacOSExternalLong = regexp.MustCompile(`^[a-f0-9]{64}$`)
var desktopMacOSExternalToken = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

func (s desktopMacOSExternalSelection) valid() bool {
	if s.EntryProfileID == "" {
		if s.EntryPolicy != "" {
			return false
		}
	} else if !validProfileID(s.EntryProfileID) || s.EntryProfileID == s.ProfileID || s.EntryPolicy == "" {
		return false
	}
	policy, err := mobilemultihop.AggregateExternalProtectionPolicy(s.FinalPolicy, s.EntryPolicy)
	return err == nil && policy == s.Policy && s.Schema == 2 && validProfileID(s.ProfileID) && desktopMacOSExternalShort.MatchString(s.Session) &&
		desktopMacOSExternalLong.MatchString(s.Source) && desktopMacOSExternalLong.MatchString(s.Config) &&
		(s.Policy == "off" || s.Policy == "on-connect" || s.Policy == "always") &&
		(s.Protocol == "socks5" || s.Protocol == "shadowsocks" || s.Protocol == "http-connect" || s.Protocol == "https-connect" || s.Protocol == "hysteria2" || s.Protocol == "wireguard" || s.Protocol == "amneziawg" || s.Protocol == "openvpn")
}

func decodeDesktopMacOSExternalReceipt(raw []byte, capture desktopMacOSExternalSelection, phase string) (desktopMacOSExternalReceipt, error) {
	var value desktopMacOSExternalReceipt
	failure := errors.New("macOS external baseline has no exact original native receipt")
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
		return desktopMacOSExternalReceipt{}, failure
	}
	if _, err := strconv.ParseUint(value.Token, 10, 64); err != nil {
		return desktopMacOSExternalReceipt{}, failure
	}
	return value, nil
}
