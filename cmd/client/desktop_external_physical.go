package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"router-vpn/internal/mobilemultihop"
)

// Capture the Windows ordinary proxy's physical owner before preflight or any
// old-session mutation. The original graph still owns DNS/exit proof; the
// derived graph owns the actual native sockets and measurement mailboxes.
// Other graph families retain their existing launch contract until their
// complete lower path has a native owner of its own.
// Automatic connection selection remains on that existing contract until the
// captured legacy-to-native protection handoff is implemented and verified.
func prepareDesktopExternalPhysical(launch *desktopNodeLaunch, targetOS string) error {
	if launch == nil || launch.external == nil || launch.tor != nil || launch.command != nil || launch.directory != "" {
		return errors.New("ordinary physical preparation requires its unstaged external owner")
	}
	owner := launch.external
	if owner.physical != nil {
		return errors.New("ordinary physical preparation cannot replace a captured owner")
	}
	if targetOS != "windows" || !owner.direct || owner.predecessor != "" {
		return nil
	}
	original, err := mobilemultihop.NewExternalPolicy(string(owner.source), string(owner.capture))
	if err != nil {
		return err
	}
	capture, err := original.DesktopCapture()
	if err != nil {
		return err
	}
	if capture.Protocol != "http-connect" && capture.Protocol != "https-connect" && capture.Protocol != "shadowsocks" ||
		capture.EntryID != "" || capture.EntryTag != "" || capture.PredecessorSHA256 != "" || capture.Execution != "" ||
		capture.StartLayer != "" || capture.EntryStartLayer != "" || capture.KillSwitchPolicy == "off" {
		return nil
	}
	// Eligibility was established from the complete compiled capture. Any
	// failure from here is fatal, never a request to use legacy endpoint rules.
	physical, err := mobilemultihop.NewDesktopExternalPolicy(original, owner.session, targetOS)
	if err != nil {
		return err
	}
	metadata := physical.Metadata()
	if !bytes.Equal(launch.config, []byte(original.Config())) || !bytes.Equal(launch.metadata, []byte(original.Metadata())) ||
		metadata.OriginalSourceSHA256 != owner.expected.SourceSHA256 || metadata.OriginalConfigSHA256 != owner.expected.ConfigSHA256 ||
		owner.expected.SessionID != owner.session || metadata.SOCKSUDPAssociationRequired {
		return errors.New("ordinary physical preparation lost its original proof or configuration identity")
	}
	receipt, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	launch.config, launch.metadata, owner.physical = []byte(physical.Config()), receipt, physical
	return nil
}

func capturedDesktopExternalPhysical(owner *desktopExternalRuntime) (*mobilemultihop.DesktopExternalMetadata, error) {
	if owner == nil {
		return nil, errors.New("ordinary physical capture has no external owner")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.physical == nil {
		return nil, nil
	}
	physical := owner.physical
	if physical.Validate() != nil || !owner.direct || owner.predecessor != "" {
		return nil, errors.New("ordinary physical capture lost its exact native policy")
	}
	meta := physical.Metadata()
	original, err := mobilemultihop.NewExternalPolicy(string(owner.source), string(owner.capture))
	if err != nil || meta.TargetOS != "windows" || meta.SessionID != owner.session || owner.expected.SessionID != owner.session ||
		meta.OriginalSourceSHA256 != owner.expected.SourceSHA256 || meta.OriginalConfigSHA256 != owner.expected.ConfigSHA256 ||
		original.SourceSHA256() != meta.OriginalSourceSHA256 || original.Config() != physical.OriginalPolicy().Config() ||
		original.Metadata() != physical.OriginalPolicy().Metadata() || meta.SOCKSUDPAssociationRequired ||
		(meta.Protocol != "http-connect" && meta.Protocol != "https-connect" && meta.Protocol != "shadowsocks") {
		return nil, errors.New("ordinary physical capture differs from its retained original graph")
	}
	return &meta, nil
}

func desktopExternalPhysicalReceipt(owner *desktopExternalRuntime, received *mobilemultihop.DesktopExternalMetadata) bool {
	expected, err := capturedDesktopExternalPhysical(owner)
	return err == nil && (expected == nil && received == nil || expected != nil && received != nil && *expected == *received)
}

func desktopExternalMeasurementIdentity(owner *desktopExternalRuntime) (string, string, error) {
	metadata, err := capturedDesktopExternalPhysical(owner)
	if err != nil {
		return "", "", err
	}
	if metadata != nil {
		return metadata.SourceSHA256, metadata.ConfigSHA256, nil
	}
	return owner.expected.SourceSHA256, owner.expected.ConfigSHA256, nil
}

func desktopExternalPhysicalEnvironment(environment []string, owner *desktopExternalRuntime) ([]string, error) {
	metadata, err := capturedDesktopExternalPhysical(owner)
	if err != nil || metadata == nil {
		return nil, errors.New("ordinary physical environment requires its captured native owner")
	}
	clean := make([]string, 0, len(environment)+3)
	for _, value := range environment {
		name, _, _ := strings.Cut(value, "=")
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "HOMEVPN_EXTERNAL_PHYSICAL_") || strings.HasPrefix(upper, "HOMEVPN_TOR_") ||
			upper == "HOMEVPN_ENDPOINT" || upper == "HOMEVPN_NATIVE_ENDPOINTS_JSON" || upper == "HOMEVPN_NATIVE_EGRESS_JSON" ||
			upper == "HOMEVPN_NODE_SESSION" || upper == "HOMEVPN_NODE_CONFIG_SHA256" {
			continue
		}
		clean = append(clean, value)
	}
	return append(clean, "HOMEVPN_ENDPOINT=", "HOMEVPN_EXTERNAL_PHYSICAL_SOURCE_SHA256="+metadata.SourceSHA256,
		"HOMEVPN_EXTERNAL_PHYSICAL_CONFIG_SHA256="+metadata.ConfigSHA256), nil
}
