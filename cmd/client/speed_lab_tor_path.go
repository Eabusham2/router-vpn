package main

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"router-vpn/internal/common"
)

// This preparation belongs to one temporary-test transaction. It retains the
// original stored source separately from the approved temporary overrides;
// neither native preflight nor a failed trial may rewrite the previous owner.
type speedLabTorPreparation struct {
	selection      *desktopTorSelection
	command        *exec.Cmd
	prelaunch      *torBridgePrelaunch
	sourceToken    string
	operation      context.Context
	temporary      *speedLabTemporaryOwner
	owned          bool
	request        externalProfileConnectRequest
	selectedBefore string
	selectedAfter  string
}

func speedLabTorRequest(q speedLabRequest, profile common.RouterProfile) externalProfileConnectRequest {
	// Unlike primary Connect, the Speed Lab dialog has an explicit Direct
	// choice represented by an empty entry. Do not revive the node's saved hop.
	entryID := strings.TrimSpace(q.EntryID)
	direct := entryID == ""
	return externalProfileConnectRequest{ProfileID: profile.ID, EntryID: entryID, EntryMode: q.EntryMode, Base: q.Base, Direct: &direct, Execution: q.Execution}
}

func (prepared *speedLabTorPreparation) releaseUnused() error {
	if prepared == nil || prepared.prelaunch == nil || prepared.command != nil && prepared.command.Process != nil {
		return nil
	}
	err := prepared.prelaunch.cleanup()
	prepared.prelaunch.close()
	return err
}

func (prepared *speedLabTorPreparation) current(a *app, applied bool) error {
	if prepared == nil || prepared.selection == nil || prepared.prelaunch == nil || prepared.command == nil || prepared.operation == nil {
		return errors.New("Tor Speed Lab has no captured prepared operation")
	}
	if prepared.operation.Err() != nil {
		return errConnectionOperationCancelled
	}
	launch := prepared.prelaunch.workspace
	if launch == nil || launch.tor == nil || prepared.temporary == nil || launch.tor.network == "" || launch.tor.network != prepared.temporary.network || launch.tor.network != launch.tor.currentNetworkIdentity() {
		return errors.New("Tor Speed Lab preparation belongs to a changed physical network")
	}
	a.mu.Lock()
	raw, owned := speedLabTemporaryOwners.Load(a)
	current := !a.closing && a.connectionContext == prepared.operation && owned == prepared.owned &&
		(!owned || raw == prepared.temporary && a.speedLabOwnerCurrentLocked(prepared.temporary) && a.cmd == prepared.temporary.runtime)
	profile, exists := a.profileByIDLocked(prepared.selection.profile.ID)
	token := prepared.sourceToken
	selected := prepared.selectedBefore
	if applied {
		token = prepared.selection.profileToken
		selected = prepared.selectedAfter
	}
	current = current && exists && desktopTorSourceIdentityToken(profile) == token && a.profiles.SelectedID == selected
	a.mu.Unlock()
	if !current {
		return errors.New("Tor Speed Lab preparation belongs to a replaced operation, runtime or private source")
	}
	return prepared.selection.predecessor.current(a)
}

func (a *app) prepareSpeedLabTorPathWithRuntime(q speedLabRequest, profile common.RouterProfile, restored *speedLabTorRestore, driver desktopTorConnectRuntime) (*speedLabTorPreparation, error) {
	a.mu.Lock()
	original, exists := a.profileByIDLocked(profile.ID)
	original = cloneRouterProfile(original)
	operation := a.connectionContext
	selected := a.profiles.SelectedID
	rawOwner, owned := speedLabTemporaryOwners.Load(a)
	owner, _ := rawOwner.(*speedLabTemporaryOwner)
	a.mu.Unlock()
	if !exists || operation == nil || !owned || owner == nil || liveMeasurementProfileToken(speedLabProfileOverrides(original, q)) != liveMeasurementProfileToken(profile) {
		return nil, errors.New("Tor Speed Lab preview does not belong to the captured node and temporary policy")
	}
	before := a.speedLabTorPrelaunchCheck(original)
	var selection *desktopTorSelection
	var err error
	if restored == nil {
		lookup := driver.lookup
		if lookup == nil {
			lookup = desktopTorEndpointLookup
		}
		selection, err = captureDesktopTorSelection(a, original, speedLabTorRequest(q, original), lookup)
		if err == nil {
			selection.policy = speedLabProfileOverrides(selection.policy, q)
			selection.profile = cloneRouterProfile(profile)
			selection.profileToken = desktopTorSourceIdentityToken(profile)
		}
	} else {
		selection, err = restored.selectionFor(a, profile, q)
	}
	if err != nil {
		return nil, err
	}
	if driver.capability == nil {
		driver.capability = torBridgeRuntimeCapability
	}
	if capability := driver.capability(); !capability.Supported {
		return nil, errors.New(capability.Reason)
	}
	command, prelaunch, err := prepareTorBridgeCommandWithRuntime(a, selection.policy, profile, selection.predecessor, driver)
	if err != nil {
		return nil, err
	}
	prepared := &speedLabTorPreparation{selection: selection, command: command, prelaunch: prelaunch, sourceToken: desktopTorSourceIdentityToken(original), operation: operation, temporary: owner, owned: owned, request: speedLabTorRequest(q, profile)}
	prepared.selectedBefore, prepared.selectedAfter = selected, profile.ID
	if restored != nil {
		prepared.selectedAfter = selected
	}
	if err := before(); err != nil {
		return nil, errors.Join(err, prepared.releaseUnused())
	}
	if err := prepared.current(a, false); err != nil {
		return nil, errors.Join(err, prepared.releaseUnused())
	}
	return prepared, nil
}

func (a *app) startPreparedSpeedLabTorPath(q speedLabRequest, profile common.RouterProfile, prepared *speedLabTorPreparation) (path speedLabPath, failure error) {
	defer func() { failure = errors.Join(failure, prepared.releaseUnused()) }()
	if err := prepared.current(a, true); err != nil {
		return path, err
	}
	if !reflect.DeepEqual(prepared.request, speedLabTorRequest(q, profile)) {
		return path, errors.New("Tor temporary path request changed after native preparation")
	}
	selection := prepared.selection
	if liveMeasurementProfileToken(profile) != liveMeasurementProfileToken(selection.profile) {
		return path, errors.New("Tor temporary profile changed after native preparation")
	}
	base := "tor"
	if selection.predecessor != nil {
		base = desktopExternalEntryBase(selection.predecessor.mode)
	}
	sessionTrackerFor(a).declareRequest("speed-lab:external", base)
	if err := a.speedLabStopRuntime(true); err != nil {
		return path, err
	}
	check := a.speedLabTorPrelaunchCheck(profile)
	current := func() error {
		if err := prepared.current(a, true); err != nil {
			return err
		}
		if err := selection.current(a); err != nil {
			return err
		}
		return check()
	}
	if err := prepared.prelaunch.start(current); err != nil {
		return path, err
	}
	command, launch := prepared.command, prepared.prelaunch.workspace
	a.mu.Lock()
	a.cmd = command
	a.state.Connected, a.state.Phase, a.state.LastError = false, "speed-lab:external:proving-tor", ""
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode, a.state.Base, a.state.RouterID = "external-node", "external-node", "external-tor-bridge", base, profile.ID
	a.mu.Unlock()
	if err := a.speedLabOwnRuntime(command); err != nil {
		return path, err
	}
	if err := prepared.current(a, true); err != nil {
		return path, err
	}
	if _, err := a.proveTorBridgeExit(); err != nil {
		return path, err
	}
	if err := prepared.current(a, true); err != nil {
		return path, err
	}
	if err := a.desktopTorCurrent(launch); err != nil {
		return path, err
	}
	a.mu.Lock()
	if a.cmd != command || selection.currentLocked(a) != nil {
		a.mu.Unlock()
		return path, errors.New("Tor Speed Lab proof belongs to a replaced native owner")
	}
	a.state.Connected, a.state.Phase = true, "connected"
	captureDesktopMTUBaselineLocked(a, launch)
	a.mu.Unlock()
	a.monitorDesktopTorRuntime(launch)
	if _, err := waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond); err != nil {
		return path, err
	}
	path = speedLabPath{Scope: "temporary", Topology: "external", Temporary: true, NodeID: profile.ID, NodeName: profile.Name, ExitID: profile.ID, ExitName: profile.Name, RuntimeMode: "external-tor-bridge", LogicalMode: "external-node", Base: base, ExternalProtocol: "tor-bridge", Execution: "local", StartedAt: launch.tor.started, Description: "temporary captured Tor path with fresh dynamic exit, selected DNS and native interface proof"}
	if entry := selection.predecessor; entry != nil {
		path.EntryID, path.EntryName, path.EntryMode = entry.entry.ID, entry.entry.Name, entry.mode
	}
	return path, nil
}

func (a *app) startSpeedLabTorRestoreWithRuntime(plan speedLabRestorePlan, driver desktopTorConnectRuntime) error {
	profile, err := a.speedLabTorRestoreProfile(plan)
	if err != nil {
		return err
	}
	prepared, err := a.prepareSpeedLabTorPathWithRuntime(plan.request, profile, plan.tor, driver)
	if err != nil {
		return err
	}
	_, err = a.startPreparedSpeedLabTorPath(plan.request, profile, prepared)
	if err != nil {
		return err
	}
	return a.restoreSpeedLabTorMTU(plan)
}
