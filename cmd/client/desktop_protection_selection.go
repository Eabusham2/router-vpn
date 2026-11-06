package main

import (
	"errors"

	"router-vpn/internal/mobilemultihop"
)

// The protection journal shares succession machinery, not connection proof.
// Its selection is derived from exactly one sealed policy object. An ordinary
// external exit never acquires Router-node authentication by sharing this slot.
type desktopProtectionSelection struct {
	profileID, session, source, config, policy string
}

func desktopProtectionSelectionFor(node *mobilemultihop.DesktopNodePolicy, external *mobilemultihop.DesktopExternalPolicy) (desktopProtectionSelection, error) {
	var empty desktopProtectionSelection
	if (node == nil) == (external == nil) {
		return empty, errors.New("native protection requires exactly one captured policy family")
	}
	if node != nil {
		if err := node.Validate(); err != nil {
			return empty, err
		}
		meta := node.Metadata()
		return desktopProtectionSelection{meta.ProfileID, meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256, meta.KillSwitchPolicy}, nil
	}
	if err := external.Validate(); err != nil {
		return empty, err
	}
	meta := external.Metadata()
	capture, err := external.Capture()
	paired := err == nil && validProfileID(capture.EntryID) && capture.EntryID != capture.ExitID &&
		capture.EntryTag == "external-entry" && capture.EntryNodeID == "" && meta.RootType == "shadowsocks" && meta.RootTag == capture.EntryTag &&
		capture.StartLayer == "" && (capture.Protocol == "shadowsocks" || capture.Protocol == "http-connect" || capture.Protocol == "https-connect")
	if err != nil || meta.TargetOS != "windows" || !validProfileID(capture.ExitID) ||
		!paired && (capture.EntryID != "" || capture.EntryTag != "") || capture.PredecessorSHA256 != "" || capture.Execution != "" ||
		!desktopExternalStartLayerSupported(capture.Protocol, capture.StartLayer) || capture.EntryStartLayer != "" || meta.SOCKSUDPAssociationRequired != (meta.Protocol == "socks5") ||
		meta.KillSwitchPolicy != "on-connect" && meta.KillSwitchPolicy != "always" ||
		meta.Protocol != "shadowsocks" && meta.Protocol != "http-connect" && meta.Protocol != "https-connect" && meta.Protocol != "hysteria2" && meta.Protocol != "socks5" && meta.Protocol != "wireguard" && meta.Protocol != "amneziawg" && meta.Protocol != "openvpn" {
		return empty, errors.Join(err, errors.New("native protection has no supported captured Windows external policy"))
	}
	return desktopProtectionSelection{capture.ExitID, meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256, meta.KillSwitchPolicy}, nil
}

func (attempt *desktopNodeProtectionAttempt) selection() (desktopProtectionSelection, error) {
	if attempt == nil {
		return desktopProtectionSelection{}, errors.New("native protection lost its original selection")
	}
	return desktopProtectionSelectionFor(attempt.policy, attempt.external)
}

func (attempt *desktopNodeProtectionAttempt) process() desktopNodeProcess {
	if attempt == nil || attempt.launch == nil || (attempt.policy == nil) == (attempt.external == nil) {
		return nil
	}
	if attempt.external != nil {
		return desktopWindowsExternalProcess(attempt.launch)
	}
	return desktopOwnedNodeProcess(attempt.launch)
}
