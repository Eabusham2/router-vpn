package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/routechoice"
)

// A temporary imported entry uses the independently paired final as its policy
// owner. Retain both originals, the approved overrides and the checked native
// launch before stopping the current VPN. The launch is consumed only once;
// startup may not compile another graph from mutable selected-node state.
type speedLabMultihopPreparation struct {
	mu             sync.Mutex
	app            *app
	dns            activeDNSRuntimeIdentity
	selection      multihopSelection
	launch         *desktopNodeLaunch
	request        []byte
	sources        map[string]string
	selected       string
	operation      context.Context
	caller         context.Context
	owner          *speedLabTemporaryOwner
	network        string
	readNetwork    func(context.Context) (string, error)
	launchDigest   [32]byte
	metadataDigest [32]byte
	applied        bool
	consumed       bool
}

type speedLabMultihopPreparationRuntime struct {
	capture   func(context.Context, *app, multihopSelection, []string) (multihopSelection, error)
	preflight func(context.Context, *app, multihopSelection, *desktopExecutionDescriptor) (*desktopNodeLaunch, error)
	network   func(context.Context) (string, error)
}

// The paired-node catalog and each imported source have different authority.
// A generic union would let an imported protocol masquerade as a paired mode,
// or offer Server/Compare without an independently authenticated entry relay.
func speedLabMultihopNodeCapabilities(profile common.RouterProfile) ([]string, []string, []string) {
	if profile.External == nil && (profile.NodeKind == "" || profile.NodeKind == "router-vpn") {
		return desktopMultihopEntryModes(), desktopMultihopExitModes(), []string{"local", "server", "auto"}
	}
	if profile.NodeKind != "external" || profile.External == nil || !desktopImportedEntryProtocol(profile.External.Protocol) || !retainedNativeMultihopSelected() {
		return []string{}, []string{}, []string{}
	}
	var finals []string
	for _, mode := range desktopMultihopExitModes() {
		if desktopImportedFinalMode(mode) {
			finals = append(finals, mode)
		}
	}
	return []string{profile.External.Protocol}, finals, []string{"local"}
}

func (prepared *speedLabMultihopPreparation) releaseUnused() error {
	if prepared == nil {
		return nil
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	return prepared.retireUnstartedLocked()
}

// Staging registers one exact private DNS input before process startup. Retire
// that identity with an unstarted launch; a replacement runtime is never cleared.
func (prepared *speedLabMultihopPreparation) retireUnstartedLocked() error {
	if prepared.launch != nil && (prepared.launch.command == nil || prepared.launch.command.Process == nil) && prepared.app != nil && prepared.dns.Config != "" {
		activeDNSRuntimeIdentities.CompareAndDelete(prepared.app, prepared.dns)
	}
	return retireUnstartedNativeMultihop(prepared.launch)
}

func (a *app) prepareSpeedLabImportedMultihop(ctx context.Context, q speedLabRequest) (*speedLabMultihopPreparation, error) {
	return a.prepareSpeedLabImportedMultihopWithRuntime(ctx, q, speedLabMultihopPreparationRuntime{})
}

func (a *app) prepareSpeedLabImportedMultihopWithRuntime(ctx context.Context, q speedLabRequest, driver speedLabMultihopPreparationRuntime) (*speedLabMultihopPreparation, error) {
	if ctx == nil {
		return nil, errors.New("temporary multihop requires its original caller")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	store := cloneRouterProfileStore(a.profiles)
	operation := a.connectionContext
	raw, owned := speedLabTemporaryOwners.Load(a)
	owner, _ := raw.(*speedLabTemporaryOwner)
	a.mu.Unlock()
	entry, exists := profileByID(store.Profiles, strings.TrimSpace(q.EntryID))
	if !exists {
		return nil, errors.New("temporary multihop entry is not linked")
	}
	if entry.External == nil && entry.NodeKind != "external" {
		return nil, nil // The paired-node resolver retains its own mode contract.
	}
	if !retainedNativeMultihopSelected() {
		return nil, errors.New("temporary imported entry requires the installed native multihop runtime")
	}
	if operation == nil || operation.Err() != nil || !owned || owner == nil {
		return nil, errors.New("temporary imported entry has no captured Speed Lab owner")
	}
	selected, selectedOK := profileByID(store.Profiles, store.SelectedID)
	final, finalOK := profileByID(store.Profiles, strings.TrimSpace(q.ExitID))
	if !selectedOK || !finalOK || entry.ID == final.ID {
		return nil, errors.New("temporary imported entry requires its selected source and a different linked paired final")
	}
	// Overrides belong to the final's DNS, protection and packet policy. The
	// imported entry keeps its complete original transport and credentials.
	originalFinal := cloneRouterProfile(final)
	// Base selects the entry path; it does not override the paired final's
	// saved preference. Keep the original request for validation and identity.
	policyRequest := q
	policyRequest.Base = ""
	final = speedLabProfileOverrides(final, policyRequest)
	profiles := cloneRouterProfileStore(store).Profiles
	for i := range profiles {
		if profiles[i].ID == final.ID {
			profiles[i] = cloneRouterProfile(final)
		}
	}
	selection, err := a.resolveSpeedLabTemporaryMultihop(q, selected, entry, profiles)
	if err != nil {
		return nil, err
	}
	if driver.capture == nil {
		driver.capture = captureNativeMultihopForAppContext
	}
	if driver.preflight == nil {
		driver.preflight = preflightOwnedNativeMultihopCommandContext
	}
	if driver.network == nil {
		driver.network = physicalNetworkIdentityContext
	}
	request, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	prepared := &speedLabMultihopPreparation{app: a, selection: selection, request: request, selected: store.SelectedID,
		operation: operation, caller: ctx, owner: owner, network: owner.network, readNetwork: driver.network, sources: map[string]string{}}
	for _, profile := range []common.RouterProfile{selected, entry, originalFinal} {
		prepared.sources[profile.ID] = liveMeasurementProfileToken(profile)
	}
	if err := prepared.current(ctx, a, false); err != nil {
		return nil, err
	}
	prepared.selection, err = driver.capture(ctx, a, selection, []string{selection.ExitMode})
	if err == nil {
		err = prepared.current(ctx, a, false)
	}
	if err == nil && (prepared.selection.Native == nil || !prepared.selection.Native.imported || prepared.selection.Native.validate(prepared.selection) != nil) {
		err = errors.New("temporary imported entry lost its complete native capture")
	}
	if err == nil {
		prepared.launch, err = driver.preflight(ctx, a, prepared.selection, nil)
	}
	if err == nil {
		err = prepared.current(ctx, a, false)
	}
	if err == nil && (prepared.launch == nil || !prepared.launch.importedEntry || prepared.launch.profileID != final.ID || prepared.launch.policyProfileID != final.ID || len(prepared.launch.config) == 0 || len(prepared.launch.metadata) == 0) {
		err = errors.New("temporary imported entry preflight did not retain its paired final policy")
	}
	if err != nil {
		return nil, errors.Join(err, prepared.releaseUnused())
	}
	prepared.launchDigest, prepared.metadataDigest = sha256.Sum256(prepared.launch.config), sha256.Sum256(prepared.launch.metadata)
	return prepared, nil
}

func (prepared *speedLabMultihopPreparation) currentLocked(a *app, applied bool) error {
	if prepared.operation.Err() != nil || prepared.caller.Err() != nil || a.closing ||
		a.connectionContext != prepared.operation || a.connectionCancelIntent == prepared.operation || !a.speedLabOwnerCurrentLocked(prepared.owner) || a.cmd != prepared.owner.runtime {
		return errors.New("temporary imported entry lost its original caller, operation or runtime")
	}
	selected := prepared.selected
	if applied {
		selected = prepared.selection.Control.ID
	}
	if a.profiles.SelectedID != selected {
		return errors.New("temporary imported entry belongs to another selected profile")
	}
	for id, token := range prepared.sources {
		if applied && id == prepared.selection.Control.ID {
			token = liveMeasurementProfileToken(prepared.selection.Control)
		}
		profile, exists := a.profileByIDLocked(id)
		if !exists || liveMeasurementProfileToken(profile) != token {
			return errors.New("temporary imported entry or paired final source changed after capture")
		}
	}
	return nil
}

func (prepared *speedLabMultihopPreparation) current(ctx context.Context, a *app, applied bool) error {
	if ctx == nil || prepared == nil || prepared.caller == nil || prepared.operation == nil || prepared.owner == nil || prepared.readNetwork == nil {
		return errors.New("temporary imported entry has no complete captured operation")
	}
	if err := errors.Join(ctx.Err(), prepared.caller.Err(), prepared.operation.Err()); err != nil {
		return err
	}
	network, err := prepared.readNetwork(ctx)
	if err != nil || network == "" || network != prepared.network || network != prepared.owner.network {
		return errors.Join(err, errors.New("temporary imported entry belongs to a changed physical network"))
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	return errors.Join(prepared.currentLocked(a, applied), ctx.Err())
}

func (prepared *speedLabMultihopPreparation) apply(ctx context.Context, a *app, q speedLabRequest) (multihopSelection, error) {
	request, err := json.Marshal(q)
	if err != nil || prepared == nil || !reflect.DeepEqual(request, prepared.request) {
		return multihopSelection{}, errors.New("temporary imported multihop request changed after preparation")
	}
	if err := desktopnetwork.LockContext(ctx, &prepared.mu); err != nil {
		return multihopSelection{}, err
	}
	defer prepared.mu.Unlock()
	if prepared.applied || prepared.consumed {
		return multihopSelection{}, errors.New("temporary imported preparation was already consumed")
	}
	if err := prepared.current(ctx, a, false); err != nil {
		return multihopSelection{}, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return multihopSelection{}, err
	}
	defer a.mu.Unlock()
	if err := prepared.currentLocked(a, false); err != nil {
		return multihopSelection{}, err
	}
	if !prepared.owner.mutated || a.cmd != nil {
		return multihopSelection{}, errors.New("temporary imported entry cannot replace the undrained previous VPN")
	}
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == prepared.selection.Control.ID {
			a.profiles.Profiles[i] = cloneRouterProfile(prepared.selection.Control)
		}
	}
	a.profiles.SelectedID = prepared.selection.Control.ID
	a.state.RouterID = prepared.selection.Control.ID
	if q.DAITA != nil {
		a.state.DAITA = *q.DAITA
	}
	if q.Jumbo != nil {
		a.state.Jumbo = *q.Jumbo
	}
	prepared.applied = true
	return prepared.selection, nil
}

func (prepared *speedLabMultihopPreparation) stage(ctx context.Context, a *app, selection multihopSelection, candidate routechoice.Candidate) (*desktopNodeLaunch, error) {
	if err := desktopnetwork.LockContext(ctx, &prepared.mu); err != nil {
		return nil, err
	}
	defer prepared.mu.Unlock()
	if !prepared.applied || prepared.consumed || prepared.launch == nil || candidate.Execution != routechoice.Local ||
		candidate.EntryID != prepared.selection.Entry.ID || candidate.ExitID != prepared.selection.Exit.ID || candidate.Transport != prepared.selection.ExitMode ||
		selection.Native != prepared.selection.Native || selection.Native == nil || selection.Native.validate(selection) != nil ||
		sha256.Sum256(prepared.launch.config) != prepared.launchDigest || sha256.Sum256(prepared.launch.metadata) != prepared.metadataDigest {
		return nil, errors.New("temporary imported launch no longer matches its checked Local graph")
	}
	if err := prepared.current(ctx, a, true); err != nil {
		return nil, err
	}
	prepared.consumed = true
	if err := stageOwnedNativeMultihopInputs(a, selection, prepared.launch); err != nil {
		return prepared.launch, errors.Join(err, prepared.retireUnstartedLocked())
	}
	config, err := runtimeConfigUnderPrivateRun(a, filepath.Join(prepared.launch.directory, "sing-box.json"))
	if err != nil {
		return prepared.launch, errors.Join(err, prepared.retireUnstartedLocked())
	}
	if err := prepared.current(ctx, a, true); err != nil {
		return prepared.launch, errors.Join(err, prepared.retireUnstartedLocked())
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return prepared.launch, errors.Join(err, prepared.retireUnstartedLocked())
	}
	if err := errors.Join(prepared.currentLocked(a, true), ctx.Err()); err != nil {
		a.mu.Unlock()
		return prepared.launch, errors.Join(err, prepared.retireUnstartedLocked())
	}
	err = registerNativeMultihopDNSRuntime(a, selection, prepared.launch.command)
	if err == nil {
		prepared.dns = activeDNSRuntimeIdentity{ProfileID: selection.Exit.ID, RuntimeID: selection.ExitMode, Config: config, ImportedEntry: true}
	}
	a.mu.Unlock()
	if err != nil {
		return prepared.launch, errors.Join(err, prepared.retireUnstartedLocked())
	}
	if err := prepared.current(ctx, a, true); err != nil {
		return prepared.launch, errors.Join(err, prepared.retireUnstartedLocked())
	}
	return prepared.launch, nil
}
