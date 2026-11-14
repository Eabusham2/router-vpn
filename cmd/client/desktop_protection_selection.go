package main

import (
	"errors"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

// The protection journal shares succession machinery, not connection proof.
// Its selection is derived from exactly one sealed policy object. An ordinary
// external exit never acquires Router-node authentication by sharing this slot.
type desktopProtectionSelection struct {
	profileID, session, source, config, policy string
}

func desktopProtectionSelectionFor(node *mobilemultihop.DesktopNodePolicy, external *mobilemultihop.DesktopExternalPolicy) (desktopProtectionSelection, error) {
	return desktopProtectionSelectionForCaptured(node, external, nil)
}

func desktopProtectionSelectionForCaptured(node *mobilemultihop.DesktopNodePolicy, external *mobilemultihop.DesktopExternalPolicy,
	imported *mobilemultihop.DesktopImportedPolicy) (desktopProtectionSelection, error) {
	return desktopProtectionSelectionForAllCaptured(node, external, imported, nil)
}

func desktopProtectionSelectionForAllCaptured(node *mobilemultihop.DesktopNodePolicy, external *mobilemultihop.DesktopExternalPolicy,
	imported *mobilemultihop.DesktopImportedPolicy, chain *mobilemultihop.DesktopNodeChainPolicy) (desktopProtectionSelection, error) {
	return desktopProtectionSelectionForAllPurposes(node, external, imported, chain, nil)
}

func desktopProtectionSelectionForAllPurposes(node *mobilemultihop.DesktopNodePolicy, external *mobilemultihop.DesktopExternalPolicy,
	imported *mobilemultihop.DesktopImportedPolicy, chain *mobilemultihop.DesktopNodeChainPolicy,
	prefix *mobilemultihop.DesktopNodeCandidatePreparationPolicy) (desktopProtectionSelection, error) {
	return desktopProtectionSelectionForConcretePurposes(node, external, imported, chain, nil, prefix)
}
func desktopProtectionSelectionForConcretePurposes(node *mobilemultihop.DesktopNodePolicy, external *mobilemultihop.DesktopExternalPolicy,
	imported *mobilemultihop.DesktopImportedPolicy, chain *mobilemultihop.DesktopNodeChainPolicy, socksChain *mobilemultihop.DesktopNodeChainSOCKSPolicy,
	prefix *mobilemultihop.DesktopNodeCandidatePreparationPolicy) (desktopProtectionSelection, error) {
	var empty desktopProtectionSelection
	families := 0
	for _, present := range []bool{node != nil, external != nil, imported != nil, chain != nil, socksChain != nil, prefix != nil} {
		if present {
			families++
		}
	}
	if families != 1 {
		return empty, errors.New("native protection requires exactly one captured policy family")
	}
	if prefix != nil {
		_, meta, _, err := prefix.PhysicalReadValidated()
		control, controlErr := mobilemultihop.ReadDesktopProtectionProfileID(prefix)
		if err != nil || controlErr != nil || meta.TargetOS != "windows" || !validProfileID(meta.ProfileID) || !validProfileID(control) ||
			meta.KillSwitchPolicy != "on-connect" && meta.KillSwitchPolicy != "always" {
			return empty, errors.Join(err, controlErr, errors.New("prefix protection lost its sealed closed native policy"))
		}
		return desktopProtectionSelection{control, meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256, meta.KillSwitchPolicy}, nil
	}
	if socksChain != nil {
		_, meta, _, err := socksChain.ReadValidated()
		if err != nil || meta.TargetOS != "windows" || !validProfileID(meta.ProfileID) || meta.KillSwitchPolicy != "on-connect" && meta.KillSwitchPolicy != "always" {
			return empty, errors.Join(err, errors.New("typed ordered protection lost its sealed native policy"))
		}
		return desktopProtectionSelection{meta.ProfileID, meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256, meta.KillSwitchPolicy}, nil
	}
	if chain != nil {
		_, meta, _, err := chain.ReadValidated()
		if err != nil || meta.TargetOS != "windows" || !validProfileID(meta.ProfileID) ||
			meta.KillSwitchPolicy != "on-connect" && meta.KillSwitchPolicy != "always" {
			return empty, errors.Join(err, errors.New("ordered protection lost its sealed aggregate native policy"))
		}
		return desktopProtectionSelection{meta.ProfileID, meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256, meta.KillSwitchPolicy}, nil
	}
	if imported != nil {
		_, meta, capture, err := imported.ReadValidated()
		if err != nil || meta.TargetOS != "windows" || meta.ProfileID != meta.ExitID || !validProfileID(meta.EntryID) || !validProfileID(meta.ExitID) ||
			meta.EntryID == meta.ExitID || capture.EntryID != meta.EntryID || capture.ExitID != meta.ExitID || capture.ExitNodeID != meta.ExitNodeID ||
			!desktopImportedEntryFinalMode(meta.EntryMode, meta.ExitMode) ||
			meta.KillSwitchPolicy != "on-connect" && meta.KillSwitchPolicy != "always" {
			return empty, errors.Join(err, errors.New("native imported protection lost its original entry and paired final"))
		}
		return desktopProtectionSelection{meta.ProfileID, meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256, meta.KillSwitchPolicy}, nil
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
	entryRoot, entryKind := capture.EntryTag, "shadowsocks"
	if capture.EntryStartLayer != "" {
		entryRoot = mobilemultihop.ExternalEntryStartLayerTag
		if capture.EntryStartLayer == "aes-256-gcm+xor-whitening" {
			entryKind = "routervpn-aes-xor"
		}
	}
	layeredPair := (capture.Protocol == "shadowsocks" || capture.Protocol == "hysteria2") && (capture.EntryStartLayer == "" || multihoprelay.ValidLayerMode(capture.EntryStartLayer)) && (capture.StartLayer == "" || multihoprelay.ValidLayerMode(capture.StartLayer))
	paired := err == nil && validProfileID(capture.EntryID) && capture.EntryID != capture.ExitID &&
		capture.EntryTag == "external-entry" && capture.EntryNodeID == "" && meta.RootType == entryKind && meta.RootTag == entryRoot &&
		(layeredPair || capture.StartLayer == "" && capture.EntryStartLayer == "") && (capture.Protocol == "shadowsocks" || capture.Protocol == "http-connect" || capture.Protocol == "https-connect" || capture.Protocol == "hysteria2")
	serverRoot := meta.RootTag == capture.EntryTag && meta.RootType == "wireguard"
	if capture.EntryStartLayer != "" {
		startup, startupErr := external.StartupSocketRequired("windows")
		serverRoot = startupErr == nil && startup && meta.StartupEndpointTag == capture.EntryTag && meta.StartupEndpointType == "wireguard"
	}
	server := err == nil && (capture.Execution == "server" || capture.Execution == "local" || capture.Execution == "auto") && capture.PredecessorSHA256 != "" && capture.EntryNodeID != "" &&
		validProfileID(capture.EntryID) && capture.EntryID != capture.ExitID && capture.EntryTag == "external-entry" &&
		serverRoot && capture.Protocol == "shadowsocks" &&
		(capture.StartLayer == "" || multihoprelay.ValidLayerMode(capture.StartLayer)) && (capture.EntryStartLayer == "" || multihoprelay.ValidLayerMode(capture.EntryStartLayer))
	if err != nil || meta.TargetOS != "windows" || !validProfileID(capture.ExitID) ||
		!paired && !server && (capture.EntryID != "" || capture.EntryTag != "") || !server && (capture.PredecessorSHA256 != "" || capture.Execution != "") ||
		!desktopExternalStartLayerSupported(capture.Protocol, capture.StartLayer) && !(paired && layeredPair) && !server || capture.EntryStartLayer != "" && !(paired && layeredPair) && !server || meta.SOCKSUDPAssociationRequired != (meta.Protocol == "socks5") ||
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
	return desktopProtectionSelectionForConcretePurposes(attempt.policy, attempt.external, attempt.imported, attempt.chain, attempt.socksChain, attempt.candidatePrefix)
}

func (attempt *desktopNodeProtectionAttempt) matchesOwned(owned *desktopOwnedNodeRuntime) bool {
	if owned != nil && owned.candidatePrefix != nil {
		return attempt != nil && attempt.external == nil && attempt.policy == nil && attempt.imported == nil && attempt.chain == nil && attempt.socksChain == nil &&
			owned.policy == nil && owned.imported == nil && owned.chain == nil && owned.candidatePrefix.policy != nil &&
			attempt.candidatePrefix == owned.candidatePrefix.policy && attempt.launch != nil && attempt.launch.candidatePrefix == owned.candidatePrefix && attempt.launch.chain == nil
	}
	if attempt != nil && attempt.candidatePrefix != nil {
		return false
	}
	if owned != nil && owned.chain != nil {
		return attempt != nil && attempt.external == nil && attempt.policy == nil && attempt.imported == nil && owned.policy == nil && owned.imported == nil &&
			owned.chain.hasPolicy() && owned.chain.originalPolicyCurrent() && attempt.chain == owned.chain.policy && attempt.socksChain == owned.chain.socksPolicy && attempt.launch != nil && attempt.launch.chain == owned.chain
	}
	if attempt != nil && (attempt.chain != nil || attempt.socksChain != nil) {
		return false
	}
	if attempt == nil || owned == nil || attempt.external != nil || (owned.policy == nil) == (owned.imported == nil) {
		return false
	}
	if owned.imported != nil {
		return owned.imported.policy != nil && attempt.policy == nil && attempt.imported == owned.imported.policy
	}
	return attempt.imported == nil && attempt.policy == owned.policy
}

func (attempt *desktopNodeProtectionAttempt) process() desktopNodeProcess {
	if attempt == nil || attempt.launch == nil {
		return nil
	}
	if _, err := attempt.selection(); err != nil {
		return nil
	}
	if attempt.external != nil {
		return desktopWindowsExternalProcess(attempt.launch)
	}
	return desktopOwnedNodeProcess(attempt.launch)
}
