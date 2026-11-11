package main

import (
	"context"
	"errors"
	"reflect"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func cloneDesktopNodeChainMembers(members []desktopNodeChainMember) []desktopNodeChainMember {
	if members == nil {
		return nil
	}
	result := make([]desktopNodeChainMember, len(members))
	for i, member := range members {
		result[i] = desktopNodeChainMember{Profile: common.CloneRouterProfile(member.Profile), Mode: member.Mode}
	}
	return result
}

// Existing current/restore owners enumerate the full captured ordered path.
// Control may be the final member; the repeated check is intentionally exact.
func nativeMultihopCapturedProfiles(selection multihopSelection) []common.RouterProfile {
	profiles := []common.RouterProfile{selection.Control}
	if len(selection.Nodes) == 0 {
		return append(profiles, selection.Entry, selection.Exit)
	}
	for _, member := range selection.Nodes {
		profiles = append(profiles, member.Profile)
	}
	return profiles
}

func resolveDesktopNodeChainSelection(control common.RouterProfile, profiles []common.RouterProfile,
	nodes []common.MultihopNodeSelection, execution string) (multihopSelection, error) {
	members, err := resolveDesktopNodeChainMembers(control, profiles, nodes, execution)
	if err != nil {
		return multihopSelection{}, err
	}
	// The concrete physical policy has one final authenticated control source.
	// A third profile cannot supply credentials or a weaker protection policy.
	final := members[len(members)-1]
	if control.ID != final.Profile.ID || liveMeasurementProfileToken(control) != liveMeasurementProfileToken(final.Profile) {
		return multihopSelection{}, errors.New("ordered native control must be its exact final selected node")
	}
	return multihopSelection{Control: common.CloneRouterProfile(control), Entry: common.CloneRouterProfile(members[0].Profile),
		Exit: common.CloneRouterProfile(final.Profile), Base: "wg", EntryMode: members[0].Mode, ExitMode: final.Mode,
		Nodes: cloneDesktopNodeChainMembers(members)}, nil
}

func nodeChainSelectedReferences(members []desktopNodeChainMember) []common.MultihopNodeSelection {
	selected := make([]common.MultihopNodeSelection, len(members))
	for i, member := range members {
		selected[i] = common.MultihopNodeSelection{ID: member.Profile.ID, Mode: member.Mode}
	}
	return selected
}

func captureNativeNodeChainSelection(ctx context.Context, root string, selection multihopSelection,
	modes []string, lookup applexray.Lookup) (multihopSelection, error) {
	if ctx == nil || ctx.Err() != nil || selection.Native != nil || len(modes) != 1 || modes[0] != "shadowsocks" ||
		selection.Base != "wg" || selection.EntryMode != "wg" || selection.ExitMode != "shadowsocks" ||
		selection.serverPacketPublic != "" || selection.serverPQIdentity != "" {
		return selection, errors.New("ordered native capture requires its complete explicit Local selection")
	}
	profiles := make([]common.RouterProfile, len(selection.Nodes))
	for i, member := range selection.Nodes {
		profiles[i] = common.CloneRouterProfile(member.Profile)
	}
	selected := nodeChainSelectedReferences(selection.Nodes)
	resolved, err := resolveDesktopNodeChainSelection(selection.Control, profiles, selected, "local")
	if err != nil || liveMeasurementProfileToken(resolved.Entry) != liveMeasurementProfileToken(selection.Entry) ||
		liveMeasurementProfileToken(resolved.Exit) != liveMeasurementProfileToken(selection.Exit) {
		return selection, errors.Join(err, errors.New("ordered native endpoints differ from the complete member capture"))
	}
	capture, err := captureDesktopNodeChain(ctx, root, selection.Control, profiles, selected, "local", lookup)
	if err != nil {
		return selection, err
	}
	physical, err := capture.chain.PhysicalEgress()
	if err != nil {
		return selection, err
	}
	resolved.restoreMTU = selection.restoreMTU
	resolved.Native = &nativeMultihopCapture{root: capture.root, entryID: resolved.Entry.ID, exitID: resolved.Exit.ID,
		base: "wg", entryMode: "wg", entrySelection: "wg", endpoint: capture.endpoint, source: capture.chain.SourceSHA256(),
		controlToken: liveMeasurementProfileToken(resolved.Control), entryToken: liveMeasurementProfileToken(resolved.Entry), exitToken: liveMeasurementProfileToken(resolved.Exit),
		entryPhysical: append([]mobilemultihop.PhysicalEgress(nil), physical...),
		configs:       map[string]string{resolved.ExitMode: capture.chain.Config()}, chain: capture}
	if err := resolved.Native.validateNodeChainSelection(resolved); err != nil {
		return selection, err
	}
	return resolved, nil
}

func (capture *nativeMultihopCapture) validateNodeChainSelection(selection multihopSelection) error {
	bad := errors.New("ordered native source or any selected member changed")
	if capture == nil || capture.chain == nil || capture.chain.chain == nil || capture.imported || capture.importedHost != nil ||
		capture.importedPlatform != nil || capture.openVPN != nil || capture.importedInput != "" || capture.importedOriginalSource != "" ||
		selection.Native != capture || selection.Control.ID != selection.Exit.ID || selection.Base != "wg" || selection.EntryMode != "wg" || selection.ExitMode != "shadowsocks" ||
		capture.base != "wg" || capture.entryMode != "wg" || capture.entrySelection != "wg" ||
		capture.entryID != selection.Entry.ID || capture.exitID != selection.Exit.ID || capture.root != capture.chain.root || capture.endpoint != capture.chain.endpoint ||
		capture.source != capture.chain.chain.SourceSHA256() || len(capture.configs) != 1 || capture.configs[selection.ExitMode] != capture.chain.chain.Config() ||
		capture.controlToken != liveMeasurementProfileToken(selection.Control) || capture.entryToken != liveMeasurementProfileToken(selection.Entry) || capture.exitToken != liveMeasurementProfileToken(selection.Exit) ||
		len(selection.Nodes) != len(capture.chain.members) || len(selection.Nodes) < 2 || len(selection.Nodes) > common.MultihopMaximumNodes ||
		selection.serverPacketPublic != "" || selection.serverPQIdentity != "" {
		return bad
	}
	profiles := make([]common.RouterProfile, len(selection.Nodes))
	for i, member := range selection.Nodes {
		original := capture.chain.members[i]
		if member.Mode != original.Mode || liveMeasurementProfileToken(member.Profile) != liveMeasurementProfileToken(original.Profile) {
			return bad
		}
		profiles[i] = member.Profile
	}
	physical, err := capture.chain.chain.PhysicalEgress()
	if err != nil || !reflect.DeepEqual(physical, capture.entryPhysical) {
		return bad
	}
	return capture.chain.validate(context.Background(), selection.Control, profiles)
}
