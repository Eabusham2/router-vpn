package main

import (
	"errors"
	"os/exec"
	"time"

	"router-vpn/internal/common"
)

// Keep the actual proved graph and its frozen credentials. Recompiling from
// current saved measurements would create another source identity and could
// accidentally rerun the user's saved Compare choice instead of restoring it.
func captureNativeMultihopRestore(a *app, command *exec.Cmd, graph activeMultihopGraph, control, entry, exit common.RouterProfile) (multihopSelection, error) {
	owner, err := capturedNativeMultihopRuntime(a, command, graph)
	if err != nil {
		return multihopSelection{}, err
	}
	selection := owner.selection
	if !nativeMultihopLiveProfilesCurrent(a, selection) {
		return multihopSelection{}, errors.New("previous multihop node sources were relinked before restoration")
	}
	if graph.Execution != "local" && graph.Execution != "server" ||
		mtuProfileSnapshotToken(control) != mtuProfileSnapshotToken(selection.Control) ||
		mtuProfileSnapshotToken(entry) != mtuProfileSnapshotToken(selection.Entry) ||
		mtuProfileSnapshotToken(exit) != mtuProfileSnapshotToken(selection.Exit) {
		return multihopSelection{}, errors.New("previous multihop profiles differ from the proved captured graph")
	}
	var capturedRelay *desktopRelayOwner
	if graph.Execution == "server" && nativeMultihopPacketExitMode(selection.ExitMode) {
		raw, found := desktopRelays.Load(a)
		relay, _ := raw.(*desktopRelayOwner)
		if !found || relay == nil {
			return multihopSelection{}, errors.New("previous WG/AWG server path has no owned lease")
		}
		relay.mu.Lock()
		valid := relay.command == command && relay.renewed && relay.packetCapabilityReady &&
			relay.request.EntryNodeID == selection.Entry.NodeProofID && relay.request.ExitID == selection.Exit.ID && relay.request.ExitMode == selection.ExitMode &&
			relay.expected.Request == relay.request && relay.expected.ExitNodeID == selection.Exit.NodeProofID && relay.expected.NodeID == selection.Entry.NodeProofID && relay.expected.ExpiresAt.After(time.Now()) &&
			relay.serverPacketPublic != "" && relay.request.ExpectedPacketPublicKey == relay.serverPacketPublic && relay.localPacketPublic == selection.Native.localPacketPublic[selection.ExitMode] && relay.localPacketPublic != relay.serverPacketPublic
		selection.serverPacketPublic = relay.serverPacketPublic
		if nativeMultihopPQExitMode(selection.ExitMode) {
			valid = valid && relay.validPQPin() && relay.localPQIdentity == selection.Native.localPQIdentity[selection.ExitMode]
			selection.serverPQIdentity = relay.serverPQIdentity
		}
		relay.mu.Unlock()
		if !valid {
			return multihopSelection{}, errors.New("previous WG/AWG server lease identity changed")
		}
		capturedRelay = relay
	}
	selection.restoreMTU, err = captureDesktopNodeRestoreMTU(owner.launch)
	if err != nil {
		return multihopSelection{}, err
	}
	current, err := capturedNativeMultihopRuntime(a, command, graph)
	if err != nil || current != owner || !nativeMultihopLiveProfilesCurrent(a, selection) {
		return multihopSelection{}, errors.New("multihop owner or node sources changed while capturing live MTU restoration")
	}
	if capturedRelay != nil {
		raw, present := desktopRelays.Load(a)
		capturedRelay.mu.Lock()
		current := present && raw == capturedRelay && capturedRelay.packetCapabilityReady && capturedRelay.serverPacketPublic == selection.serverPacketPublic && capturedRelay.expected.ExpiresAt.After(time.Now()) && capturedRelay.validPQPin() && capturedRelay.serverPQIdentity == selection.serverPQIdentity
		capturedRelay.mu.Unlock()
		if !current {
			return multihopSelection{}, errors.New("WG/AWG server owner changed while capturing live MTU restoration")
		}
	}
	selection.Control = common.CloneRouterProfile(selection.Control)
	selection.Entry = common.CloneRouterProfile(selection.Entry)
	selection.Exit = common.CloneRouterProfile(selection.Exit)
	return selection, nil
}

// The already-proved source stays frozen, but a same-ID relink must disqualify
// a new temporary-test restore capture. Check the actual catalog under its
// lock; an older caller snapshot alone cannot bless replacement credentials.
// The existing MTU identity excludes only the persisted EffectiveMTU value;
// restoration uses the owned live readback, never that saved measurement.
func nativeMultihopLiveProfilesCurrent(a *app, selection multihopSelection) bool {
	if a == nil || selection.Native == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, captured := range []common.RouterProfile{selection.Control, selection.Entry, selection.Exit} {
		current, ok := a.profileByIDLocked(captured.ID)
		if !ok || mtuProfileSnapshotToken(current) != mtuProfileSnapshotToken(captured) {
			return false
		}
	}
	return true
}
