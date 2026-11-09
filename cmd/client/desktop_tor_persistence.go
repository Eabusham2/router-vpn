package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
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
	intent    context.Context
}

func desktopTorOperationCurrentLocked(a *app, operation context.Context, selected string) error {
	if a == nil || a.closing || operation == nil || operation.Err() != nil || a.connectionContext != operation || a.connectionCancelIntent == operation || a.profiles.SelectedID != selected {
		return errors.New("Tor connection operation or selected node changed")
	}
	return nil
}

func desktopTorChoiceRuntimeCurrentLocked(ctx context.Context, a *app, launch *desktopNodeLaunch) bool {
	if ctx == nil || ctx.Err() != nil || launch == nil || launch.tor == nil || launch.command == nil || a.cmd != launch.command || a.state.Connected || a.state.RouterID != launch.profileID || a.state.Mode != "external-node" || a.state.LogicalMode != "external-node" || !desktopTorRuntimeID(launch.mode) || a.state.RuntimeMode != launch.mode || launch.tor.network == "" {
		return false
	}
	network, err := launch.tor.currentNetworkIdentityContext(ctx)
	if err != nil || network != launch.tor.network || ctx.Err() != nil {
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
	execution := desktopTorExecution(expected.Execution)
	if execution == "" || desktopTorExecution(policy.MultihopExecution) != execution || execution == "server" && (entry == nil || entry.native == nil || !entry.native.IsRouter()) || policy.MultihopEnabled != (entry != nil) || expected.NodeID != current.ID {
		return common.RouterProfile{}, errors.New("Tor saved choice differs from its proved native execution")
	}
	updated := cloneRouterProfile(current)
	updated.MultihopEnabled, updated.MultihopExecution = entry != nil, execution
	if selection.preference == "auto" {
		if entry == nil || entry.native == nil || !entry.native.IsRouter() {
			return common.RouterProfile{}, errors.New("Tor Compare preference requires its proved private Router path")
		}
		updated.MultihopExecution = "auto"
	} else if selection.preference != "" && selection.preference != execution {
		return common.RouterProfile{}, errors.New("Tor saved preference differs from its captured execution")
	}
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
	ctx, finish, err := desktopTorChoiceCaller(operation, selection.adoption)
	if err != nil {
		return nil, err
	}
	defer finish()
	requested, err := desktopTorRequestedExecution(selection.profile, q)
	if err != nil || selection.preference != "" && requested != selection.preference {
		return nil, errors.New("Tor saved execution preference changed after the request was captured")
	}
	proof, err := a.readDesktopTorProofContext(ctx, launch)
	if err != nil {
		return nil, err
	}
	if proof.Proof.IP != actualIP {
		return nil, errors.New("Tor saved choice cannot borrow another public-exit result")
	}
	if err := selection.currentContext(ctx, a); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	registered, present := desktopNodeOwners.Load(a)
	current, found := a.profileByIDLocked(selection.profile.ID)
	if desktopTorOperationCurrentLocked(a, operation, selected) != nil || !present || registered != launch || !desktopTorChoiceRuntimeCurrentLocked(ctx, a, launch) || !found || launch.tor.committedChoice.Load() != nil || selection.currentLocked(a) != nil || a.validateExternalProfileExpectedProfilesLocked(q, selection.profile) != nil || startup != nil && startup.currentLocked(a) != nil {
		return nil, errors.Join(ctx.Err(), errors.New("Tor source, request or operation changed before saving its proved choice"))
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
	if err := errors.Join(ctx.Err(), desktopTorOperationCurrentLocked(a, operation, selected)); err != nil {
		return nil, err
	}
	if selection.adoption != nil && selection.adoption.Err() != nil {
		return nil, errors.New("Tor comparison was cancelled before saving its proved choice")
	}
	currentWrite := func() error {
		if failure := errors.Join(ctx.Err(), desktopTorOperationCurrentLocked(a, operation, selected)); failure != nil {
			return failure
		}
		if selection.adoption != nil && selection.adoption.Err() != nil {
			return selection.adoption.Err()
		}
		actual, err := startupExternalSourceToken(a, entry, mode)
		if err != nil || actual != source {
			return errors.Join(err, errors.New("Tor private entry source changed before the durable rename"))
		}
		if !desktopTorChoiceRuntimeCurrentLocked(ctx, a, launch) || desktopNodeProcessExited(launch) {
			return errors.Join(ctx.Err(), errors.New("Tor native path changed before the durable rename"))
		}
		return errors.Join(ctx.Err(), operation.Err())
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
	if err := a.persistDesktopTorChoiceProfilesContext(ctx, currentWrite); err != nil {
		// atomicWritePrivate reports failures only before its successful rename.
		// Thus this rollback does not claim to undo a completed durable write.
		a.rollbackProfilesLocked(previous)
		return nil, fmt.Errorf("%w: %v", errDesktopTorChoiceSave, err)
	}
	choice := &desktopTorCommittedChoice{profileToken: desktopTorSourceIdentityToken(updated), nodeID: updated.ID, sessionID: launch.tor.expected.SessionID, sourceSHA256: launch.tor.expected.SourceSHA256}
	launch.tor.committedChoice.Store(choice)
	last := &startupExternalSelection{Protocol: updated.External.Protocol, Direct: entry.ID == "", SourceToken: source, Execution: desktopTorExecution(launch.tor.expected.Execution), EntryMode: mode}
	if entry.ID != "" {
		last.EntryID, last.EntryToken = entry.ID, startupExternalProfileToken(entry)
	}
	return &desktopTorChoiceAdoption{launch: launch, choice: choice, operation: operation, selected: selected, intent: selection.adoption,
		startup: startupSelection{RouterID: updated.ID, RuntimeMode: launch.mode, LogicalMode: "external-node", Base: a.state.Base,
			ProfileToken: startupExternalProfileToken(updated), UpdatedAt: time.Now().UTC(), External: last}}, nil
}

func (saved *desktopTorChoiceAdoption) currentLocked(ctx context.Context, a *app) error {
	if saved == nil || saved.launch == nil || saved.launch.tor == nil || saved.choice == nil {
		return errors.New("Tor saved choice has no captured adoption owner")
	}
	if ctx == nil {
		return errors.New("Tor saved choice has no original caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if saved.intent != nil && saved.intent.Err() != nil {
		return errors.New("Tor saved choice belongs to a cancelled comparison")
	}
	if err := desktopTorOperationCurrentLocked(a, saved.operation, saved.selected); err != nil {
		return err
	}
	launch := saved.launch
	registered, present := desktopNodeOwners.Load(a)
	profile, found := a.profileByIDLocked(launch.profileID)
	if !present || registered != launch || !desktopTorChoiceRuntimeCurrentLocked(ctx, a, launch) || launch.tor.committedChoice.Load() != saved.choice || launch.tor.sourceIdentityToken() != saved.choice.profileToken || !found || desktopTorSourceIdentityToken(profile) != saved.choice.profileToken || launch.tor.entryCurrentLocked(a) != nil || desktopNodeProcessExited(launch) {
		return errors.Join(ctx.Err(), errors.New("Tor saved choice lost its proved native process or private source"))
	}
	if entry := launch.tor.predecessor; entry != nil {
		source, err := startupExternalSourceToken(a, entry.entry, entry.mode)
		if err != nil || source != entry.assetsSHA256 {
			return errors.New("Tor private entry source changed after saving its proved choice")
		}
	}
	return errors.Join(ctx.Err(), saved.operation.Err())
}

// A post-save failure must keep the newly persisted choice and report that it
// was saved. It may retire only this runtime, never pretend to roll disk state
// back to the previous choice or adopt a stale native proof.
func (saved *desktopTorChoiceAdoption) adopt(a *app) (desktopTorProof, error) {
	if saved == nil || saved.launch == nil {
		return desktopTorProof{}, errors.New("Tor has no saved choice to adopt")
	}
	ctx, finish, err := desktopTorChoiceCaller(saved.operation, saved.intent)
	if err != nil {
		return desktopTorProof{}, err
	}
	defer finish()
	_, err = a.readDesktopTorProofContext(ctx, saved.launch)
	if err != nil {
		return desktopTorProof{}, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return desktopTorProof{}, err
	}
	if err := saved.currentLocked(ctx, a); err != nil {
		a.mu.Unlock()
		return desktopTorProof{}, err
	}
	if err := a.saveDesktopTorChoiceStartupContext(ctx, saved); err != nil {
		a.mu.Unlock()
		return desktopTorProof{}, fmt.Errorf("proved Tor Startup Last record could not be saved: %w", err)
	}
	a.mu.Unlock()
	// The durable write can take time. Re-read the real native proof after it,
	// then perform one final captured-operation check before Connected.
	proof, err := a.readDesktopTorProofContext(ctx, saved.launch)
	if err != nil {
		return desktopTorProof{}, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return desktopTorProof{}, err
	}
	defer a.mu.Unlock()
	if err := saved.currentLocked(ctx, a); err != nil {
		return desktopTorProof{}, err
	}
	a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""
	captureDesktopMTUBaselineLocked(a, saved.launch)
	return proof, nil
}

// The shorter user intent and original connection transaction both own this
// admission. Combining them does not renew either deadline or detach a reader.
// The returned cancellation is local to this save/adoption attempt; the saved
// record retains the original contexts for its next distinct phase.
func desktopTorChoiceCaller(operation, intent context.Context) (context.Context, context.CancelFunc, error) {
	if operation == nil {
		return nil, nil, errors.New("Tor choice has no original connection operation")
	}
	if err := operation.Err(); err != nil {
		return nil, nil, err
	}
	if intent == nil || intent == operation {
		return operation, func() {}, nil
	}
	if err := intent.Err(); err != nil {
		return nil, nil, err
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline, ok := operation.Deadline(); ok {
		ctx, cancel = context.WithDeadline(intent, deadline)
	} else {
		ctx, cancel = context.WithCancel(intent)
	}
	stop := context.AfterFunc(operation, cancel)
	finish := func() { stop(); cancel() }
	if err := errors.Join(operation.Err(), ctx.Err()); err != nil {
		finish()
		return nil, nil, err
	}
	return ctx, finish, nil
}

func (a *app) persistDesktopTorChoiceProfilesContext(ctx context.Context, current func() error) error {
	if ctx == nil || current == nil {
		return errors.New("Tor choice persistence has no original admission")
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return current()
	}
	if err := check(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(a.profiles, "", "  ")
	if err != nil {
		return err
	}
	_, err = atomicWritePrivateChecked(a.cfg.ProfilesFile, append(body, '\n'), check)
	return err
}

func (a *app) saveDesktopTorChoiceStartupContext(ctx context.Context, saved *desktopTorChoiceAdoption) error {
	if ctx == nil || saved == nil {
		return errors.New("Tor Startup Last has no original admission")
	}
	check := func() error { return saved.currentLocked(ctx, a) }
	if err := check(); err != nil {
		return err
	}
	path := a.startupStatePath()
	if path == "" {
		return nil
	}
	if !validStartupProfileToken(saved.startup.ProfileToken) {
		return errors.New("last-good startup state requires one exact profile/path-policy token")
	}
	body, err := json.MarshalIndent(saved.startup, "", "  ")
	if err != nil {
		return err
	}
	_, err = atomicWritePrivateChecked(path, append(body, '\n'), check)
	return err
}
