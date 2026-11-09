package main

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
)

// This preparation belongs to one temporary-test transaction. It retains the
// original stored source separately from the approved temporary overrides;
// neither native preflight nor a failed trial may rewrite the previous owner.
type speedLabTorPreparation struct {
	comparison     *speedLabTorComparisonPreparation
	selection      *desktopTorSelection
	command        *exec.Cmd
	prelaunch      *torBridgePrelaunch
	sourceToken    string
	operation      context.Context
	intent         context.Context
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
	return externalProfileConnectRequest{ProfileID: profile.ID, EntryID: entryID, EntryMode: q.EntryMode, Base: q.Base, Direct: &direct, Execution: q.Execution, ComparisonRequestID: q.ComparisonRequestID}
}

func (prepared *speedLabTorPreparation) releaseUnused() error {
	if prepared != nil && prepared.comparison != nil {
		var failure error
		for _, candidate := range prepared.comparison.paths {
			failure = errors.Join(failure, candidate.releaseUnused())
		}
		return failure
	}
	if prepared == nil || prepared.prelaunch == nil || prepared.command != nil && prepared.command.Process != nil {
		return nil
	}
	err := prepared.prelaunch.cleanup()
	prepared.prelaunch.close()
	return err
}

func (prepared *speedLabTorPreparation) current(a *app, applied bool) error {
	return prepared.currentContext(context.Background(), a, applied)
}

func (prepared *speedLabTorPreparation) currentContext(ctx context.Context, a *app, applied bool) error {
	if ctx == nil || prepared == nil || prepared.operation == nil {
		return errors.New("Tor Speed Lab has no original preparation caller")
	}
	work, finish, err := desktopTorChoiceCaller(prepared.operation, prepared.intent)
	if err != nil {
		return err
	}
	defer finish()
	ctx, finishCall, err := desktopTorChoiceCaller(work, ctx)
	if err != nil {
		return err
	}
	defer finishCall()
	if prepared != nil && prepared.comparison != nil {
		for _, candidate := range prepared.comparison.paths {
			if err := candidate.currentContext(ctx, a, applied); err != nil {
				return err
			}
		}
	}
	if prepared == nil || prepared.selection == nil || prepared.prelaunch == nil || prepared.command == nil || prepared.operation == nil {
		return errors.New("Tor Speed Lab has no captured prepared operation")
	}
	if prepared.operation.Err() != nil {
		return errConnectionOperationCancelled
	}
	launch := prepared.prelaunch.workspace
	if launch == nil || launch.tor == nil || prepared.temporary == nil || launch.tor.network == "" || launch.tor.network != prepared.temporary.network {
		return errors.New("Tor Speed Lab preparation belongs to a changed physical network")
	}
	network, err := launch.tor.currentNetworkIdentityContext(ctx)
	if err != nil || network != launch.tor.network {
		return errors.Join(err, errors.New("Tor Speed Lab physical observation changed"))
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
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
	current = current && exists && desktopTorSourceIdentityToken(profile) == token && desktopTorOperationCurrentLocked(a, prepared.operation, selected) == nil
	a.mu.Unlock()
	if !current {
		return errors.New("Tor Speed Lab preparation belongs to a replaced operation, runtime or private source")
	}
	return prepared.selection.predecessor.currentContext(ctx, a)
}

func (a *app) prepareSpeedLabTorPathWithRuntime(q speedLabRequest, profile common.RouterProfile, restored *speedLabTorRestore, driver desktopTorConnectRuntime) (*speedLabTorPreparation, error) {
	caller, err := captureDesktopTorCaller(a, driver.operation, driver.requestContext)
	if err != nil {
		return nil, err
	}
	defer caller.finish()
	driver.operation = caller.operation
	return a.prepareSpeedLabTorPathWithRuntimeContext(caller.work, q, profile, restored, driver)
}

func (a *app) prepareSpeedLabTorPathWithRuntimeContext(ctx context.Context, q speedLabRequest, profile common.RouterProfile, restored *speedLabTorRestore, driver desktopTorConnectRuntime) (*speedLabTorPreparation, error) {
	if ctx == nil || driver.operation == nil {
		return nil, errors.New("Tor Speed Lab preparation has no original caller and operation")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	original, exists := a.profileByIDLocked(profile.ID)
	original = cloneRouterProfile(original)
	operation := driver.operation
	selected := a.profiles.SelectedID
	rawOwner, owned := speedLabTemporaryOwners.Load(a)
	owner, _ := rawOwner.(*speedLabTemporaryOwner)
	operationErr := desktopTorOperationCurrentLocked(a, operation, selected)
	a.mu.Unlock()
	if operationErr != nil || !exists || operation == nil || !owned || owner == nil || liveMeasurementProfileToken(speedLabProfileOverrides(original, q)) != liveMeasurementProfileToken(profile) {
		return nil, errors.New("Tor Speed Lab preview does not belong to the captured node and temporary policy")
	}
	if restored == nil {
		execution, err := desktopTorRequestedExecution(original, speedLabTorRequest(q, original))
		if err != nil {
			return nil, err
		}
		if execution == "auto" {
			return a.prepareSpeedLabTorComparisonContext(ctx, q, profile, driver)
		}
	}
	before, err := a.speedLabTorPrelaunchCheckContext(ctx, operation, original)
	if err != nil {
		return nil, err
	}
	var selection *desktopTorSelection
	if restored == nil {
		lookup := driver.lookup
		if lookup == nil {
			lookup = desktopTorEndpointLookup
		}
		selection, err = captureDesktopTorSelectionContext(ctx, a, original, speedLabTorRequest(q, original), lookup)
		if err == nil {
			selection.policy = speedLabProfileOverrides(selection.policy, q)
			selection.profile = cloneRouterProfile(profile)
			selection.profileToken = desktopTorSourceIdentityToken(profile)
		}
	} else {
		selection, err = restored.selectionForContext(ctx, a, profile, q)
	}
	if err != nil {
		return nil, err
	}
	selection.adoption = driver.requestContext
	if driver.capability == nil {
		driver.capability = func() standardExitCapability { return desktopTorPolicyRuntimeCapabilityContext(ctx, selection.policy) }
	}
	if capability := driver.capability(); !capability.Supported {
		return nil, errors.New(capability.Reason)
	}
	command, prelaunch, err := prepareTorBridgeCommandWithRuntimeContext(ctx, a, selection.policy, profile, selection.predecessor, driver)
	if err != nil {
		return nil, err
	}
	prepared := &speedLabTorPreparation{selection: selection, command: command, prelaunch: prelaunch, sourceToken: desktopTorSourceIdentityToken(original), operation: operation, intent: driver.requestContext, temporary: owner, owned: owned, request: speedLabTorRequest(q, profile)}
	prepared.selectedBefore, prepared.selectedAfter = selected, profile.ID
	if restored != nil {
		prepared.selectedAfter = selected
	}
	if err := before(); err != nil {
		return nil, errors.Join(err, prepared.releaseUnused())
	}
	if err := prepared.currentContext(ctx, a, false); err != nil {
		return nil, errors.Join(err, prepared.releaseUnused())
	}
	return prepared, nil
}

func (a *app) startPreparedSpeedLabTorPath(q speedLabRequest, profile common.RouterProfile, prepared *speedLabTorPreparation) (path speedLabPath, failure error) {
	defer func() { failure = errors.Join(failure, prepared.releaseUnused()) }()
	if prepared == nil {
		return path, errors.New("Tor Speed Lab start has no original preparation")
	}
	ctx, finish, err := desktopTorChoiceCaller(prepared.operation, prepared.intent)
	if err != nil {
		return path, err
	}
	defer finish()
	if err := prepared.currentContext(ctx, a, true); err != nil {
		return path, err
	}
	if !reflect.DeepEqual(prepared.request, speedLabTorRequest(q, profile)) {
		return path, errors.New("Tor temporary path request changed after native preparation")
	}
	selection := prepared.selection
	if liveMeasurementProfileToken(profile) != liveMeasurementProfileToken(selection.profile) {
		return path, errors.New("Tor temporary profile changed after native preparation")
	}
	if prepared.comparison != nil {
		return a.startPreparedSpeedLabTorComparison(q, profile, prepared)
	}
	base := "tor"
	if selection.predecessor != nil {
		base = desktopExternalEntryBase(selection.predecessor.mode)
	}
	sessionTrackerFor(a).declareRequest("speed-lab:external", base)
	if err := a.speedLabStopRuntime(true); err != nil {
		return path, err
	}
	check, err := a.speedLabTorPrelaunchCheckContext(ctx, prepared.operation, profile)
	if err != nil {
		return path, err
	}
	current := func() error {
		if err := prepared.currentContext(ctx, a, true); err != nil {
			return err
		}
		if err := selection.currentContext(ctx, a); err != nil {
			return err
		}
		return check()
	}
	if err := prepared.prelaunch.startContext(ctx, current); err != nil {
		return path, err
	}
	command, launch := prepared.command, prepared.prelaunch.workspace
	a.mu.Lock()
	a.cmd = command
	a.state.Connected, a.state.Phase, a.state.LastError = false, "speed-lab:external:proving-tor", ""
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode, a.state.Base, a.state.RouterID = "external-node", "external-node", launch.mode, base, profile.ID
	a.mu.Unlock()
	if err := a.speedLabOwnRuntime(command); err != nil {
		return path, err
	}
	if err := prepared.currentContext(ctx, a, true); err != nil {
		return path, err
	}
	if _, err := a.proveTorBridgeExitContext(ctx, launch); err != nil {
		return path, err
	}
	if err := prepared.currentContext(ctx, a, true); err != nil {
		return path, err
	}
	if err := a.desktopTorCurrentContext(ctx, launch); err != nil {
		return path, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return path, err
	}
	if ctx.Err() != nil || desktopTorOperationCurrentLocked(a, prepared.operation, prepared.selectedAfter) != nil || a.cmd != command || selection.currentLocked(a) != nil {
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
	path = speedLabPath{Scope: "temporary", Topology: "external", Temporary: true, NodeID: profile.ID, NodeName: profile.Name, ExitID: profile.ID, ExitName: profile.Name, RuntimeMode: launch.mode, LogicalMode: "external-node", Base: base, ExternalProtocol: profile.External.Protocol, Execution: desktopTorExecution(launch.tor.expected.Execution), StartedAt: launch.tor.started, Description: "temporary captured Tor path with fresh dynamic exit, selected DNS and native interface proof"}
	if entry := selection.predecessor; entry != nil {
		path.EntryID, path.EntryName, path.EntryMode = entry.entry.ID, entry.entry.Name, entry.mode
	}
	return path, nil
}

func (a *app) startSpeedLabTorRestoreWithRuntime(plan speedLabRestorePlan, driver desktopTorConnectRuntime) error {
	return a.startSpeedLabTorRestoreWithRuntimeContext(a.connectionOperationContextOrBackground(), plan, driver)
}

func (a *app) startSpeedLabTorRestoreWithRuntimeContext(ctx context.Context, plan speedLabRestorePlan, driver desktopTorConnectRuntime) error {
	if ctx == nil {
		return errors.New("Tor restoration has no original cleanup operation")
	}
	// The restoration coordinator has already installed its separate captured
	// cleanup operation. The cancelled HTTP test cannot own this restoration.
	caller, err := captureDesktopTorCaller(a, ctx, nil)
	if err != nil {
		return err
	}
	defer caller.finish()
	driver.operation, driver.requestContext = caller.operation, nil
	profile, err := a.speedLabTorRestoreProfileContext(caller.work, plan)
	if err != nil {
		return err
	}
	prepared, err := a.prepareSpeedLabTorPathWithRuntimeContext(caller.work, plan.request, profile, plan.tor, driver)
	if err != nil {
		return err
	}
	_, err = a.startPreparedSpeedLabTorPath(plan.request, profile, prepared)
	if err != nil {
		return err
	}
	return a.restoreSpeedLabTorMTU(plan)
}
