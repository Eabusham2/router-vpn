package main

import (
	"context"
	"errors"
	"reflect"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopNodeChainHasSOCKS(nodes []common.MultihopNodeSelection) bool {
	for _, node := range nodes {
		if node.Mode == "socks5" {
			return true
		}
	}
	return false
}

// The typed source remains separate from generic NodeChain authority. The
// adjunct carries only the existing host's captured member/asset inventory.
func captureNativeSOCKSNodeChainSelection(ctx context.Context, root string, selection multihopSelection,
	modes []string, lookup applexray.Lookup) (multihopSelection, error) {
	if ctx == nil || ctx.Err() != nil || selection.Native != nil || len(modes) != 1 || modes[0] != "shadowsocks" ||
		selection.ExitMode != "shadowsocks" || selection.serverPacketPublic != "" || selection.serverPQIdentity != "" {
		return selection, errors.New("typed SOCKS capture requires the exact original Local selection")
	}
	profiles := make([]common.RouterProfile, len(selection.Nodes))
	for i, member := range selection.Nodes {
		profiles[i] = common.CloneRouterProfile(member.Profile)
	}
	refs := nodeChainSelectedReferences(selection.Nodes)
	resolved, err := resolveDesktopNodeChainSelection(selection.Control, profiles, refs, "local")
	if err != nil || resolved.Base != selection.Base || resolved.EntryMode != selection.EntryMode || resolved.ExitMode != selection.ExitMode ||
		liveMeasurementProfileToken(resolved.Entry) != liveMeasurementProfileToken(selection.Entry) ||
		liveMeasurementProfileToken(resolved.Exit) != liveMeasurementProfileToken(selection.Exit) {
		return selection, errors.Join(err, errors.New("typed SOCKS endpoints changed before capture"))
	}
	typed, err := captureDesktopNodeChainSOCKS(ctx, root, selection.Control, profiles, refs, "local", lookup)
	if err != nil {
		return selection, err
	}
	_, meta, err := typed.source.ReadValidated()
	if err != nil {
		return selection, err
	}
	adjunct := *typed.original
	adjunct.socks = typed
	resolved.restoreMTU = selection.restoreMTU
	resolved.Native = &nativeMultihopCapture{root: adjunct.root, entryID: resolved.Entry.ID, exitID: resolved.Exit.ID,
		base: resolved.Base, entryMode: resolved.EntryMode, entrySelection: resolved.EntryMode, endpoint: adjunct.endpoint, source: meta.SourceSHA256,
		controlToken: liveMeasurementProfileToken(resolved.Control), entryToken: liveMeasurementProfileToken(resolved.Entry), exitToken: liveMeasurementProfileToken(resolved.Exit),
		entryPhysical: append([]mobilemultihop.PhysicalEgress(nil), meta.Physical...), configs: map[string]string{resolved.ExitMode: typed.config}, chain: &adjunct}
	if err := resolved.Native.validateSOCKSNodeChainSelection(resolved); err != nil {
		return selection, err
	}
	return resolved, nil
}

func (capture *nativeMultihopCapture) validateSOCKSNodeChainSelection(selection multihopSelection) error {
	bad := errors.New("typed SOCKS parent lost its original source or complete selection")
	if capture == nil || capture.chain == nil || capture.chain.socks == nil || capture.chain.chain != nil ||
		capture.imported || capture.importedHost != nil || capture.importedPlatform != nil || capture.openVPN != nil ||
		capture.importedInput != "" || capture.importedOriginalSource != "" || selection.Native != capture || len(selection.Nodes) != 3 ||
		selection.Control.ID != selection.Exit.ID || selection.serverPacketPublic != "" || selection.serverPQIdentity != "" {
		return bad
	}
	chain, typed := capture.chain, capture.chain.socks
	if typed.source == nil || typed.original == nil || typed.original == chain || chain.digest() != typed.original.digest() || chain.seal != typed.original.seal ||
		capture.root != chain.root || capture.endpoint != chain.endpoint || capture.base != selection.Base ||
		capture.entryMode != selection.EntryMode || capture.entrySelection != selection.EntryMode ||
		capture.entryID != selection.Entry.ID || capture.exitID != selection.Exit.ID ||
		capture.controlToken != liveMeasurementProfileToken(selection.Control) || capture.entryToken != liveMeasurementProfileToken(selection.Entry) ||
		capture.exitToken != liveMeasurementProfileToken(selection.Exit) || len(capture.configs) != 1 || capture.configs[selection.ExitMode] != typed.config {
		return bad
	}
	profiles := make([]common.RouterProfile, len(selection.Nodes))
	for i, member := range selection.Nodes {
		if i >= len(chain.members) || member.Mode != chain.members[i].Mode || liveMeasurementProfileToken(member.Profile) != liveMeasurementProfileToken(chain.members[i].Profile) {
			return bad
		}
		profiles[i] = member.Profile
	}
	resolved, err := resolveDesktopNodeChainSOCKSMembers(selection.Control, profiles, nodeChainSelectedReferences(selection.Nodes), "local")
	if err != nil || selection.EntryMode != resolved[0].Mode || selection.ExitMode != resolved[2].Mode ||
		selection.Base != desktopExternalEntryBase(resolved[0].Mode) || liveMeasurementProfileToken(selection.Entry) != liveMeasurementProfileToken(resolved[0].Profile) ||
		liveMeasurementProfileToken(selection.Exit) != liveMeasurementProfileToken(resolved[2].Profile) {
		return bad
	}
	_, meta, err := typed.source.ReadValidated()
	if err != nil || meta.SourceSHA256 != capture.source || !reflect.DeepEqual(meta.Physical, capture.entryPhysical) {
		return bad
	}
	return typed.validate(context.Background(), selection.Control, profiles)
}
