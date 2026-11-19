package mobilemultihop

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/mobilemtu"
)

// Preserve the original capture and lower endpoints. The source hash already
// includes the preference revision before the native owner gets inserted.
func projectDesktopExternalDevicePolicy(graph map[string]any, original *ExternalPolicy, capture ExternalDesktopCapture, meta DesktopExternalMetadata) error {
	service := map[string]any{"type": DesktopExternalNetworkType, "tag": DesktopExternalNetworkTag, "session_id": meta.SessionID, "source_sha256": meta.SourceSHA256}
	graph["services"] = []any{service}
	if meta.DeviceRevision == "" && meta.DeviceFixedMTU == 0 {
		return nil
	}
	if !desktopExternalSessionID.MatchString(meta.DeviceRevision) {
		return desktopExternalPolicyError
	}
	if err := validateDesktopExternalDeviceMTU(original, capture, meta.DeviceFixedMTU); err != nil {
		return err
	}
	inbounds, ok := graph["inbounds"].([]any)
	if !ok {
		return desktopExternalPolicyError
	}
	var tun map[string]any
	for _, row := range inbounds {
		inbound, ok := row.(map[string]any)
		if !ok {
			return desktopExternalPolicyError
		}
		if inbound["type"] == "tun" {
			if tun != nil || inbound["tag"] != capture.TUNTag {
				return desktopExternalPolicyError
			}
			tun = inbound
		}
	}
	if tun == nil {
		return desktopExternalPolicyError
	}
	tun["mtu"] = meta.DeviceFixedMTU
	service["device_mtu_revision"], service["device_fixed_mtu"] = meta.DeviceRevision, meta.DeviceFixedMTU
	return nil
}

// Extract only the proposed device setting from the private worker's graph.
// Rebuild from original profile + capture and require the complete bytes and
// parent's independent source identity before returning a native policy.
func RebuildDesktopExternalPolicy(original *ExternalPolicy, session, target, expectedSource string, staged []byte) (*DesktopExternalPolicy, error) {
	var envelope struct {
		Services []struct {
			Type     string `json:"type"`
			Tag      string `json:"tag"`
			Revision string `json:"device_mtu_revision"`
			Fixed    int    `json:"device_fixed_mtu"`
		} `json:"services"`
	}
	if len(staged) == 0 || len(staged) > 4<<20 || json.Unmarshal(staged, &envelope) != nil || len(envelope.Services) != 1 {
		return nil, desktopExternalPolicyError
	}
	s := envelope.Services[0]
	if s.Type != DesktopExternalNetworkType || s.Tag != DesktopExternalNetworkTag {
		return nil, desktopExternalPolicyError
	}
	policy, err := NewDesktopExternalPolicyWithDevicePreference(original, session, target, s.Revision, s.Fixed)
	if err != nil || policy.Metadata().SourceSHA256 != expectedSource || policy.Config() != string(staged) {
		return nil, desktopExternalPolicyError
	}
	return policy, nil
}

const DesktopExternalDeviceMTUEnvironment = "HOMEVPN_EXTERNAL_DEVICE_MTU"

// The private no-physical-helper invocation still owns a real external proof
// and native TUN. Its preference is scoped to this exact original constructor.
type DesktopExternalDevicePreference struct {
	Session  string `json:"session_id"`
	Source   string `json:"source_sha256"`
	Config   string `json:"config_sha256"`
	Revision string `json:"device_mtu_revision"`
	MTU      int    `json:"device_fixed_mtu"`
}

func NewDesktopExternalDevicePreference(original *ExternalPolicy, session, revision string, mtu int) (*DesktopExternalDevicePreference, error) {
	if original == nil || !desktopExternalSessionID.MatchString(session) || !desktopExternalSessionID.MatchString(revision) || mtu < 1280 || mtu > 9000 {
		return nil, desktopExternalPolicyError
	}
	capture, err := original.DesktopCapture()
	if err != nil {
		return nil, err
	}
	if err := validateDesktopExternalDeviceMTU(original, capture, mtu); err != nil {
		return nil, err
	}
	return &DesktopExternalDevicePreference{session, capture.SourceSHA256, capture.ConfigSHA256, revision, mtu}, nil
}
func ParseDesktopExternalDevicePreference(raw string, original *ExternalPolicy, session string) (*DesktopExternalDevicePreference, error) {
	var proposal DesktopExternalDevicePreference
	if len(raw) > 1024 || json.Unmarshal([]byte(raw), &proposal) != nil {
		return nil, desktopExternalPolicyError
	}
	rebuilt, err := NewDesktopExternalDevicePreference(original, session, proposal.Revision, proposal.MTU)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(rebuilt)
	if err != nil || string(canonical) != raw {
		return nil, desktopExternalPolicyError
	}
	return rebuilt, nil
}

func validateDesktopExternalDeviceMTU(original *ExternalPolicy, capture ExternalDesktopCapture, mtu int) error {
	jumbo, err := externalJumboPreference(original.capture.Profile)
	if err != nil || mtu < 1280 || mtu > 9000 || jumbo && mtu != 9000 {
		return errors.New("device fixed MTU conflicts with the captured external configuration")
	}
	plan, err := mobilemtu.NewDeviceFixedPlan(original.Config(), capture.ConfiguredMTU)
	if err != nil {
		return err
	}
	if _, err := plan.Config(mtu); err != nil {
		return err
	}
	return nil
}
