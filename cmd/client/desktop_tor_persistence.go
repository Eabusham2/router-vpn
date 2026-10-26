package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"router-vpn/internal/common"
)

// The native capture remains immutable. Only a successfully saved choice may
// replace the host's accepted saved-profile identity, exactly once and only for
// this proved session. Readers never accept both the previous and saved token.
type desktopTorCommittedChoice struct {
	profileToken string
	nodeID       string
	sessionID    string
	sourceSHA256 string
}

func (owner *desktopTorRuntime) sourceIdentityToken() string {
	if owner == nil {
		return ""
	}
	if choice := owner.committedChoice.Load(); choice != nil {
		if choice.nodeID != owner.expected.NodeID || choice.sessionID != owner.expected.SessionID || choice.sourceSHA256 != owner.expected.SourceSHA256 {
			return ""
		}
		return choice.profileToken
	}
	return owner.profileToken
}

type desktopTorChoiceAdoption struct {
	launch    *desktopNodeLaunch
	choice    *desktopTorCommittedChoice
	operation context.Context
	selected  string
	startup   startupSelection
}

func desktopTorOperationCurrentLocked(a *app, operation context.Context, selected string) error {
	if a == nil || a.closing || operation == nil || operation.Err() != nil || a.connectionContext != operation || a.profiles.SelectedID != selected {
		return errors.New("Tor connection operation or selected node changed")
	}
	return nil
}

func desktopTorChoiceRuntimeCurrentLocked(a *app, launch *desktopNodeLaunch) bool {
	if launch == nil || launch.tor == nil || launch.command == nil || a.cmd != launch.command || a.state.Connected || a.state.RouterID != launch.profileID || a.state.Mode != "external-node" || a.state.LogicalMode != "external-node" || a.state.RuntimeMode != "external-tor-bridge" || launch.tor.network == "" || launch.tor.network != launch.tor.currentNetworkIdentity() {
		return false
	}
	base := "tor"
	if entry := launch.tor.predecessor; entry != nil {
		base = desktopExternalEntryBase(entry.mode)
	}
	return a.state.Base == base
}

// Only these already-proved graph fields are persisted. Runtime-derived Home
// DNS, resolved addresses, credentials, Start assets and MTU history must not be
// copied out of the launch policy into the reusable private node.
func desktopTorSavedChoiceProfile(current common.RouterProfile, selection *desktopTorSelection, launch *desktopNodeLaunch) (common.RouterProfile, error) {
	if selection == nil || launch == nil || launch.tor == nil || current.ID != selection.profile.ID || current.ID != launch.profileID || selection.profileToken != desktopTorSourceIdentityToken(current) || launch.tor.profileToken != selection.profileToken || launch.tor.predecessor != selection.predecessor || selection.policy.ID != current.ID {
		return common.RouterProfile{}, errors.New("Tor saved choice lost its captured private source")
	}
	policy, entry, expected := selection.policy, selection.predecessor, launch.tor.expected
	if policy.MultihopExecution != "local" || policy.MultihopEnabled != (entry != nil) || expected.NodeID != current.ID {
		return common.RouterProfile{}, errors.New("Tor saved choice differs from its proved native execution")
	}
	updated := cloneRouterProfile(current)
	updated.MultihopEnabled, updated.MultihopExecution = entry != nil, "local"
	updated.MultihopEntryID, updated.MultihopExitID, updated.MultihopEntryMode = "", "", ""
	if entry == nil {
		if expected.EntryID != "" || expected.EntryMode != "" || policy.MultihopEntryID != "" || policy.MultihopExitID != "" || policy.MultihopEntryMode != "" {
			return common.RouterProfile{}, errors.New("Direct Tor cannot save an unrelated entry choice")
		}
	} else {
		if policy.MultihopEntryID != entry.entry.ID || policy.MultihopExitID != current.ID || policy.MultihopEntryMode != entry.mode || expected.EntryID != entry.entry.ID || expected.EntryMode != entry.mode || expected.EntryAssetsSHA256 != entry.assetsSHA256 {
			return common.RouterProfile{}, errors.New("Tor saved entry differs from its proved private graph")
		}
		updated.MultihopEntryID, updated.MultihopExitID, updated.MultihopEntryMode = entry.entry.ID, current.ID, entry.mode
	}
	return updated, nil
}

var errDesktopTorChoiceSave = errors.New("Tor proved path choice could not be saved")

func (a *app) commitDesktopTorChoice(selection *desktopTorSelection, launch *desktopNodeLaunch, q externalProfileConnectRequest, startup *startupPolicyCapture, operation context.Context, selected, actualIP string) (*desktopTorChoiceAdoption, error) {
	if selection == nil || launch == nil || launch.tor == nil {
		return nil, errors.New("Tor choice has no captured native owner")
	}
	proof, err := a.readDesktopTorProof(launch)
	if err != nil {
		return nil, err
	}
	if proof.Proof.IP != actualIP {
		return nil, errors.New("Tor saved choice cannot borrow another public-exit result")
	}
	if err := selection.current(a); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	registered, present := desktopNodeOwners.Load(a)
	current, found := a.profileByIDLocked(selection.profile.ID)
	if desktopTorOperationCurrentLocked(a, operation, selected) != nil || !present || registered != launch || !desktopTorChoiceRuntimeCurrentLocked(a, launch) || !found || launch.tor.committedChoice.Load() != nil || selection.currentLocked(a) != nil || a.validateExternalProfileExpectedProfilesLocked(q, selection.profile) != nil || startup != nil && startup.currentLocked(a) != nil {
		return nil, errors.New("Tor source, request or operation changed before saving its proved choice")
	}
	updated, err := desktopTorSavedChoiceProfile(current, selection, launch)
	if err != nil {
		return nil, err
	}
	entry, mode := common.RouterProfile{}, ""
	if selection.predecessor != nil {
		entry, mode = selection.predecessor.entry, selection.predecessor.mode
	}
	source, err := startupExternalSourceToken(a, entry, mode)
	if err != nil || selection.predecessor != nil && source != selection.predecessor.assetsSHA256 {
		return nil, errors.New("Tor private entry source changed before saving its proved choice")
	}
	// The operation can be cancelled independently of app.mu while bounded
	// source files are read. Check it again immediately before the disk write.
	if err := desktopTorOperationCurrentLocked(a, operation, selected); err != nil {
		return nil, err
	}
	previous := cloneRouterProfileStore(a.profiles)
	updated.UseCount++
	updated.LastUsedAt, updated.PublicIP = time.Now().UTC().Format(time.RFC3339), actualIP
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == updated.ID {
			a.profiles.Profiles[i] = updated
			break
		}
	}
	if err := a.persistProfilesLocked(); err != nil {
		// atomicWritePrivate reports failures only before its successful rename.
		// Thus this rollback does not claim to undo a completed durable write.
		a.rollbackProfilesLocked(previous)
		return nil, fmt.Errorf("%w: %v", errDesktopTorChoiceSave, err)
	}
	choice := &desktopTorCommittedChoice{profileToken: desktopTorSourceIdentityToken(updated), nodeID: updated.ID, sessionID: launch.tor.expected.SessionID, sourceSHA256: launch.tor.expected.SourceSHA256}
	launch.tor.committedChoice.Store(choice)
	last := &startupExternalSelection{Protocol: "tor-bridge", Direct: entry.ID == "", SourceToken: source, Execution: "local", EntryMode: mode}
	if entry.ID != "" {
		last.EntryID, last.EntryToken = entry.ID, startupExternalProfileToken(entry)
	}
	return &desktopTorChoiceAdoption{launch: launch, choice: choice, operation: operation, selected: selected,
		startup: startupSelection{RouterID: updated.ID, RuntimeMode: "external-tor-bridge", LogicalMode: "external-node", Base: a.state.Base,
			ProfileToken: startupExternalProfileToken(updated), UpdatedAt: time.Now().UTC(), External: last}}, nil
}

func (saved *desktopTorChoiceAdoption) currentLocked(a *app) error {
	if saved == nil || saved.launch == nil || saved.launch.tor == nil || saved.choice == nil {
		return errors.New("Tor saved choice has no captured adoption owner")
	}
	if err := desktopTorOperationCurrentLocked(a, saved.operation, saved.selected); err != nil {
		return err
	}
	launch := saved.launch
	registered, present := desktopNodeOwners.Load(a)
	profile, found := a.profileByIDLocked(launch.profileID)
	if !present || registered != launch || !desktopTorChoiceRuntimeCurrentLocked(a, launch) || launch.tor.committedChoice.Load() != saved.choice || launch.tor.sourceIdentityToken() != saved.choice.profileToken || !found || desktopTorSourceIdentityToken(profile) != saved.choice.profileToken || launch.tor.entryCurrentLocked(a) != nil || desktopNodeProcessExited(launch) {
		return errors.New("Tor saved choice lost its proved native process or private source")
	}
	if entry := launch.tor.predecessor; entry != nil {
		source, err := startupExternalSourceToken(a, entry.entry, entry.mode)
		if err != nil || source != entry.assetsSHA256 {
			return errors.New("Tor private entry source changed after saving its proved choice")
		}
	}
	return nil
}

// A post-save failure must keep the newly persisted choice and report that it
// was saved. It may retire only this runtime, never pretend to roll disk state
// back to the previous choice or adopt a stale native proof.
func (saved *desktopTorChoiceAdoption) adopt(a *app) (desktopTorProof, error) {
	if saved == nil || saved.launch == nil {
		return desktopTorProof{}, errors.New("Tor has no saved choice to adopt")
	}
	_, err := a.readDesktopTorProof(saved.launch)
	if err != nil {
		return desktopTorProof{}, err
	}
	a.mu.Lock()
	if err := saved.currentLocked(a); err != nil {
		a.mu.Unlock()
		return desktopTorProof{}, err
	}
	if err := a.saveStartupSelection(saved.startup); err != nil {
		a.mu.Unlock()
		return desktopTorProof{}, fmt.Errorf("proved Tor Startup Last record could not be saved: %w", err)
	}
	a.mu.Unlock()
	// The durable write can take time. Re-read the real native proof after it,
	// then perform one final captured-operation check before Connected.
	proof, err := a.readDesktopTorProof(saved.launch)
	if err != nil {
		return desktopTorProof{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := saved.currentLocked(a); err != nil {
		return desktopTorProof{}, err
	}
	a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""
	captureDesktopMTUBaselineLocked(a, saved.launch)
	return proof, nil
}
