package main

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This shape selects only the captured Local ordinary WG/AWG entry -> SS or HTTP(S) CONNECT exit.
// It supplies no source, socket or native admission authority by itself.
func desktopExternalPacketEntryExitProtocol(protocol string) bool {
	return protocol == "shadowsocks" || protocol == "http-connect" || protocol == "https-connect"
}

func desktopExternalPacketEntryOwner(owner *desktopExternalRuntime) bool {
	if owner == nil || owner.direct || owner.predecessor != "" || owner.selection != "local" ||
		owner.profile.NodeKind != "external" || owner.profile.External == nil || !desktopExternalPacketEntryExitProtocol(owner.profile.External.Protocol) ||
		owner.entry.NodeKind != "external" || owner.entry.External == nil || (owner.entry.External.Protocol != "wireguard" && owner.entry.External.Protocol != "amneziawg") ||
		owner.entry.ID == "" || owner.entry.ID == owner.profile.ID ||
		owner.profile.StartLayer != "" && owner.profile.StartLayer != "off" || owner.entry.StartLayer != "" && owner.entry.StartLayer != "off" ||
		owner.profile.MultihopExecution != "" && owner.profile.MultihopExecution != "local" || owner.profile.MultihopEntryMode != "" {
		return false
	}
	policy := desktopOwnedNodeProtectionPolicy(owner.profile)
	return policy == "on-connect" || policy == "always"
}

func validateDesktopMacOSExternalSources(profile, entry common.RouterProfile, launch *desktopNodeLaunch) error {
	if launch == nil || launch.external == nil {
		return errors.New("macOS external source lost its original launch")
	}
	if launch.external.direct {
		return validateDesktopWindowsExternalSource(profile, launch)
	}
	owner := launch.external
	if !desktopExternalPacketEntryOwner(owner) || profile.ID != launch.policyProfileID || entry.ID != launch.profileID ||
		profile.ID != owner.profile.ID || entry.ID != owner.entry.ID {
		return errors.New("macOS entry source lost its two original saved profiles")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	selected, err := externalRuntimePolicy(profile)
	if err == nil {
		selected, err = externalDNSPolicyForPath(selected, entry, false)
	}
	if err != nil {
		return err
	}
	selected.MultihopEnabled, selected.MultihopEntryID, selected.MultihopExitID = true, entry.ID, profile.ID
	selected.MultihopExecution, selected.MultihopEntryMode = "local", ""
	selected, err = freezeDesktopExternalProfile(selected, owner.profile.Endpoint)
	if err != nil || desktopOwnedNodeProfileToken(selected) != desktopOwnedNodeProfileToken(owner.profile) ||
		[3]bool{selected.DAITAEnabled, selected.JumboTUN, selected.SocksEnabled} != [3]bool{owner.profile.DAITAEnabled, owner.profile.JumboTUN, owner.profile.SocksEnabled} {
		return errors.Join(err, errors.New("macOS entry path replaced its captured final policy"))
	}
	frozen, err := freezeDesktopExternalProfile(entry, launch.endpoint)
	if err != nil || desktopOwnedNodeProfileToken(frozen) != desktopOwnedNodeProfileToken(owner.entry) ||
		[3]bool{frozen.DAITAEnabled, frozen.JumboTUN, frozen.SocksEnabled} != [3]bool{owner.entry.DAITAEnabled, owner.entry.JumboTUN, owner.entry.SocksEnabled} {
		return errors.Join(err, errors.New("macOS entry path replaced its original entry source"))
	}
	original, err := mobilemultihop.NewExternalPolicy(string(owner.source), string(owner.capture))
	if err != nil || owner.physical == nil || owner.physical.Validate() != nil ||
		original.SourceSHA256() != owner.physical.OriginalPolicy().SourceSHA256() || original.Config() != owner.physical.OriginalPolicy().Config() || original.Metadata() != owner.physical.OriginalPolicy().Metadata() {
		return errors.Join(err, errors.New("macOS entry path lost its independently sealed full graph"))
	}
	var captured struct {
		Profile common.RouterProfile `json:"profile"`
		Entry   common.RouterProfile `json:"entry"`
	}
	if json.Unmarshal(owner.capture, &captured) != nil || desktopOwnedNodeProfileToken(captured.Profile) != desktopOwnedNodeProfileToken(owner.profile) || desktopOwnedNodeProfileToken(captured.Entry) != desktopOwnedNodeProfileToken(owner.entry) {
		return errors.New("macOS entry path changed its captured private sources")
	}
	return nil
}

// The physical profile identifies the first hop. UI, saved policy, measurements
// and restoration identify the final external node for a composed ordinary path.
func desktopExternalPathProfileID(launch *desktopNodeLaunch) string {
	if launch == nil {
		return ""
	}
	if launch.external != nil {
		return launch.policyProfileID
	}
	return launch.profileID
}
