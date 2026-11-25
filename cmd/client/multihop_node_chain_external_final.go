package main

import (
	"context"
	"errors"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// The external final has its own public exit and DNS policy. The paired entry
// remains the selected control; it cannot impersonate the final's proof.
func desktopNodeChainExternalFinalSchema(members []desktopNodeChainMember) (int, error) {
	bad := errors.New("ordered external final requires Local WireGuard entry and independently captured literal SS2022 streams")
	if len(members) < 3 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes ||
		members[0].Mode != "wg" || members[0].Profile.External != nil ||
		members[0].Profile.NodeKind != "" && members[0].Profile.NodeKind != "router-vpn" ||
		!common.ValidNodeProofID(members[0].Profile.NodeProofID) {
		return 0, bad
	}
	seen := make(map[string]bool, len(members))
	for i, member := range members {
		p := member.Profile
		if !validProfileID(p.ID) || seen[p.ID] || p.StartLayer != "" && p.StartLayer != "off" {
			return 0, bad
		}
		seen[p.ID] = true
		if i > 0 && (member.Mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(p)) {
			return 0, bad
		}
	}
	return 8, nil
}

func desktopNodeChainHasExternalFinal(members []desktopNodeChainMember) bool {
	_, err := desktopNodeChainExternalFinalSchema(members)
	return err == nil
}

func desktopNodeChainControlCurrent(control common.RouterProfile, members []desktopNodeChainMember) bool {
	if len(members) == 0 {
		return false
	}
	original := desktopNodeChainControlProfile(members)
	return control.ID == original.ID && liveMeasurementProfileToken(control) == liveMeasurementProfileToken(original)
}

// Callers have already established a nonempty member inventory.
func desktopNodeChainControlProfile(members []desktopNodeChainMember) common.RouterProfile {
	if desktopNodeChainHasExternalFinal(members) {
		return members[0].Profile
	}
	return members[len(members)-1].Profile
}

// Capture the final with the ordinary paired external compiler, retaining its
// selected DNS and original entry. Only the bare final source and complete
// capture enter the distinct ordered compiler; the two-node graph is not used.
func (capture *desktopNodeChainCapture) compileExternalFinal(ctx context.Context, member desktopNodeChainMember, total *int) (string, string, string, error) {
	bad := errors.New("ordered external final lost its original entry or complete source")
	if capture == nil || ctx == nil || ctx.Err() != nil || total == nil ||
		!desktopNodeChainHasExternalFinal(capture.members) || member.Mode != "shadowsocks" ||
		liveMeasurementProfileToken(member.Profile) != liveMeasurementProfileToken(capture.members[len(capture.members)-1].Profile) || capture.endpoint == "" {
		return "", "", "", bad
	}
	entry, err := startupSelectedCompilerProfile(ctx, capture.members[0].Profile)
	if err != nil {
		return "", "", "", err
	}
	files, err := readDesktopNodeAssets(capture.root, entry.ID, "wg")
	if err != nil {
		return "", "", "", err
	}
	defer clearViaEntryAssets(files)
	owned := false
	for _, asset := range capture.assets {
		if asset.id == entry.ID && asset.mode == "wg" && asset.digest == viaEntryAssetDigest(files) {
			owned = true
		}
	}
	if !owned {
		return "", "", "", bad
	}
	if entry.Endpoint != capture.endpoint {
		frozen, freezeErr := freezeDesktopNodeAssets(files, entry.Endpoint, capture.endpoint)
		if freezeErr != nil {
			return "", "", "", freezeErr
		}
		defer clearViaEntryAssets(frozen)
		files = frozen
		entry.Endpoint = capture.endpoint
	}
	profile, err := externalRuntimePolicy(member.Profile)
	if err == nil {
		profile, err = externalDNSPolicyForPath(profile, entry, false)
	}
	if err != nil {
		return "", "", "", err
	}
	// These choices describe this captured operation, not a saved profile edit.
	profile.MultihopEntryMode, profile.MultihopExecution = "wg", "local"
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		return "", "", "", err
	}
	launch, err := compileDesktopExternalCaptured(ctx, profile, entry, exit, false, "", files, nil, nil)
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		clear(launch.config)
		clear(launch.metadata)
		clear(launch.external.source)
		clear(launch.external.capture)
	}()
	input, err := mobilemultihop.NodeChainExternalFinalInput(string(launch.external.source), string(launch.external.capture))
	if err != nil {
		return "", "", "", err
	}
	*total += len(input)
	if *total > mobilemultihop.NodeChainInputLimit {
		return "", "", "", errors.New("ordered external final exceeds the complete source bound")
	}
	return input, launch.endpoint, "", nil
}

// Requests explicitly name the external-final family. This public shape alone
// grants no source or runtime authority; linked identities are checked next.
func desktopExternalFinalReferences(nodes []common.MultihopNodeSelection) bool {
	if len(nodes) < 3 || len(nodes) > mobilemultihop.NodeChainExtendedLocalMaximumNodes || nodes[0].Mode != "wg" || common.ValidateMultihopNodes(nodes) != nil {
		return false
	}
	for _, node := range nodes[1:] {
		if node.Mode != "shadowsocks" {
			return false
		}
	}
	return true
}

func desktopNodeChainMetadataMatchesSelection(meta mobilemultihop.DesktopNodeChainMetadata, selection multihopSelection) bool {
	if !desktopNodeChainControlCurrent(selection.Control, selection.Nodes) || meta.ProfileID != selection.Exit.ID ||
		meta.NodeID != selection.Exit.NodeProofID || meta.Mode != selection.ExitMode {
		return false
	}
	if !desktopNodeChainHasExternalFinal(selection.Nodes) {
		return meta.ExternalFinal == nil
	}
	if meta.ExternalFinal == nil || len(meta.Prefixes) != len(selection.Nodes) || meta.NodeID != "" ||
		meta.ExternalFinal.ProfileID != selection.Exit.ID ||
		meta.ExternalFinal.ExpectedPublicIP != selection.Exit.External.ExpectedPublicIP {
		return false
	}
	entry, final := meta.Prefixes[0], meta.Prefixes[len(meta.Prefixes)-1]
	return entry.ProfileID == selection.Control.ID && entry.NodeID == selection.Control.NodeProofID && entry.NodeKind == "" && entry.Mode == "wg" &&
		final.ProfileID == selection.Exit.ID && final.NodeID == "" && final.NodeKind == "external" && final.Kind == "public-path" &&
		final.Mode == "shadowsocks" && final.Tag == meta.FinalTag && meta.ExternalFinal.SourceSHA256 == final.SourceSHA256
}
