//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync/atomic"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// One transaction retains the actual parent, journal, launched engine and
// baseline creator. Journal and channel values only compare those owners.
// The application owns the connection-operation lock around construction and
// succession; a superseded/cancelled request cannot create or admit a source.
type desktopLinuxNodeTransaction struct {
	stopRequested atomic.Bool
	gate          chan struct{}
	parent        *desktopLinuxNodeParentCapture
	journal       *desktopLinuxNodeJournal
	process       *desktopLinuxNodeProcess
	bootstrap     *linuxprocess.Bootstrap
	control       *linuxprotection.NodeControl
	policy        *mobilemultihop.DesktopNodePolicy
	operation     context.Context
	selection     linuxprotection.NodeSelection
	engine        linuxprocess.Observation
	engineState   linuxprotection.ProcessRecord
	profileID     string
	revision      string
	network       string
	options       [3]bool

	predecessor, successor *desktopLinuxNodeTransaction
	previous               linuxprotection.JournalState
	head                   linuxprotection.JournalSelection
	pending                *linuxprotection.JournalRecord
	baseline               *mobiletor.DesktopLinuxNodeBaseline
	created                *mobiletor.DesktopLinuxNodeCreationRecord
	prepared               *linuxprotection.NodePreparedRecord
	retirement             *linuxprotection.NodeRetirementRecord

	complete, served, admitted, retiring  bool
	nativeCommitted, engineJoined         bool
	baselineReleased                      bool
	retired, superseded, closed, released bool
	exitCode                              uint32
	exitError                             error
}

func sameDesktopLinuxParentCapture(a, b *desktopLinuxNodeParentCapture) bool {
	return a != nil && b != nil && a.app == b.app && a.parent == b.parent && a.controller == b.controller &&
		a.record == b.record && a.lifetime == b.lifetime
}

func desktopLinuxParentObservationMatches(observed linuxprocess.Observation, parent linuxprotection.ParentRecord) bool {
	return observed.BootID == parent.BootID && observed.ProcessID == parent.ProcessID && observed.ProcProcessID == parent.ProcProcessID &&
		observed.StartTicks == parent.StartTicks && linuxprotection.NativeObject(observed.Image) == parent.Image &&
		linuxprotection.NativeObject(observed.NetworkNamespace) == parent.NetworkNamespace &&
		linuxprotection.NativeObject(observed.PIDNamespace) == parent.PIDNamespace
}

// The original Witness already proved privileged task credentials. ProcParentID
// belongs to its retained procfs view; ParentProcessID uses the actual caller's
// PID namespace, checked against that same captured parent observation.
func desktopLinuxObservedProcess(observed, parent linuxprocess.Observation) (linuxprotection.ProcessRecord, error) {
	if observed.Validate() != nil || parent.Validate() != nil || observed.ProcParentID != parent.ProcProcessID {
		return linuxprotection.ProcessRecord{}, errors.New("Linux journal process lost its actual retained parent observation")
	}
	record := linuxprotection.ProcessRecord{BootID: observed.BootID, ProcessID: observed.ProcessID, ProcProcessID: observed.ProcProcessID,
		ParentProcessID: parent.ProcessID, StartTicks: observed.StartTicks, Image: linuxprotection.NativeObject(observed.Image),
		NetworkNamespace: linuxprotection.NativeObject(observed.NetworkNamespace), PIDNamespace: linuxprotection.NativeObject(observed.PIDNamespace)}
	return record, record.Validate()
}

func newDesktopLinuxNodeTransaction(operation context.Context, parent *desktopLinuxNodeParentCapture, journal *desktopLinuxNodeJournal,
	process *desktopLinuxNodeProcess, policy *mobilemultihop.DesktopNodePolicy,
	predecessor *desktopLinuxNodeTransaction) (*desktopLinuxNodeTransaction, error) {
	if operation == nil || operation.Err() != nil || parent == nil || parent.Current(operation) != nil || journal == nil || process == nil ||
		!sameDesktopLinuxParentCapture(parent, journal.parent) || !sameDesktopLinuxParentCapture(parent, process.parent) ||
		policy == nil || policy.Validate() != nil || !process.Started() || process.command == nil {
		return nil, errors.New("Linux Node transaction requires its original accepted app, journal and created engine")
	}
	meta := policy.Metadata()
	if meta.TargetOS != "linux" {
		return nil, errors.New("Linux Node transaction cannot reinterpret another platform's sealed policy")
	}
	selection := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
		ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	if selection.Validate() != nil {
		return nil, errors.New("Linux Node transaction lost its complete selected native policy")
	}
	parent.app.mu.Lock()
	profile, exists := parent.app.profileByIDLocked(meta.ProfileID)
	parent.app.mu.Unlock()
	if !exists {
		return nil, errors.New("Linux Node transaction lost its original saved profile")
	}
	input, err := policy.OriginalProfile().LaunchInput()
	if err != nil {
		return nil, err
	}
	var envelope struct {
		ProfileJSON string `json:"profile_json"`
	}
	var captured common.RouterProfile
	if json.Unmarshal([]byte(input), &envelope) != nil || json.Unmarshal([]byte(envelope.ProfileJSON), &captured) != nil ||
		validateDesktopOwnedNodeSourceProfile(profile, captured.Endpoint, input) != nil {
		return nil, errors.New("Linux Node transaction substituted private input from another saved profile")
	}
	t := &desktopLinuxNodeTransaction{gate: make(chan struct{}, 1), parent: parent, journal: journal, process: process,
		policy: policy, operation: operation, selection: selection, profileID: meta.ProfileID,
		revision: desktopOwnedNodeProfileToken(profile), network: physicalNetworkIdentity(),
		options: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, predecessor: predecessor}
	p := parent.parent
	select {
	case <-operation.Done():
		return nil, operation.Err()
	case <-p.gate:
	}
	if err := p.currentLocked(true); err != nil {
		p.gate <- struct{}{}
		return nil, err
	}
	if p.dependents == nil {
		p.dependents = make(map[ownedDesktopNodeParent]struct{})
	}
	p.dependents[t] = struct{}{}
	p.gate <- struct{}{}
	defer func() { t.gate <- struct{}{} }()
	if err := t.accepted(operation); err != nil {
		return t, err
	}
	t.bootstrap, err = process.Bootstrap(operation)
	if err != nil {
		return t, err
	}
	observed, engine, err := t.bootstrap.Observations(operation)
	if err != nil || !desktopLinuxParentObservationMatches(observed, parent.record) || engine.ProcessID != process.command.Process.Pid {
		return t, errors.Join(err, errors.New("Linux Node journal substituted its original native launcher relationship"))
	}
	t.engine, t.engineState = engine, linuxprotection.ProcessRecord{}
	t.engineState, err = desktopLinuxObservedProcess(engine, observed)
	if err != nil {
		return t, err
	}
	t.control, err = linuxprotection.NewNodeParentControl(operation, t.bootstrap, selection)
	if err != nil {
		return t, err
	}
	if predecessor != nil {
		if err := predecessor.enter(operation); err != nil {
			return t, err
		}
		defer func() { predecessor.gate <- struct{}{} }()
		if !predecessor.retired || !predecessor.engineJoined || predecessor.closed || predecessor.superseded || predecessor.successor != nil ||
			predecessor.baseline == nil || predecessor.journal != journal || !sameDesktopLinuxParentCapture(predecessor.parent, parent) {
			return t, errors.New("Linux Node successor lost its original joined predecessor capability")
		}
		if err := predecessor.baseline.ObserveClosed(operation); err != nil {
			return t, err
		}
	}
	t.head, err = journal.Snapshot(operation)
	if err != nil || t.head.Incomplete || t.head.Record.Phase != "settled" || t.head.Record.Committed.Engine != nil ||
		t.head.Record.Controller != parent.record {
		return t, errors.Join(err, errors.New("Linux Node transaction requires its exact settled joined journal"))
	}
	if predecessor == nil {
		if t.head.Record.Committed.Target != nil || mobiletor.ReadDesktopLinuxProtectionAbsence(operation) != nil {
			return t, errors.New("Linux Node initial transaction has no independent native absence")
		}
	} else if t.head.SHA256 != predecessor.head.SHA256 || t.head.Record.Committed.Target == nil ||
		!reflect.DeepEqual(t.head.Record.Committed, predecessor.head.Record.Committed) {
		return t, errors.New("Linux Node successor changed its original predecessor checkpoint")
	}
	t.previous = linuxprotection.CloneState(t.head.Record.Committed)
	if err := t.accepted(operation); err != nil {
		return t, err
	}
	if predecessor != nil {
		predecessor.successor = t
	}
	t.complete = true
	return t, nil
}

func (t *desktopLinuxNodeTransaction) enter(ctx context.Context) error {
	if t == nil || ctx == nil || ctx.Err() != nil || t.gate == nil {
		return errors.New("Linux Node transaction has no live captured operation")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.gate:
		if ctx.Err() != nil {
			t.gate <- struct{}{}
			return ctx.Err()
		}
		return nil
	}
}

// accepted is never used to authorize cleanup. Retirement keeps its original
// native owners when the saved profile, network, request or command changes.
func (t *desktopLinuxNodeTransaction) accepted(ctx context.Context) error {
	if t == nil || ctx == nil || ctx.Err() != nil || t.operation == nil || t.operation.Err() != nil || t.stopRequested.Load() || t.retiring || t.retired || t.closed ||
		t.policy == nil || t.policy.Validate() != nil || t.network == "" || physicalNetworkIdentity() != t.network {
		return errors.New("Linux Node preparation lost its accepted captured policy or network")
	}
	if err := t.parent.Current(ctx); err != nil {
		return err
	}
	a := t.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, exists := a.profileByIDLocked(t.profileID)
	if err := a.checkCapturedConnectionOperationLocked(t.operation); err != nil || !exists || a.cmd != t.process.command ||
		a.state.RouterID != t.profileID || a.state.RuntimeMode != t.policy.Metadata().Mode ||
		desktopOwnedNodeProfileToken(profile) != t.revision ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != t.options ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != t.options {
		return errors.Join(err, errors.New("Linux Node preparation belongs to another saved profile, request or command"))
	}
	return nil
}

func (t *desktopLinuxNodeTransaction) nextRecord() linuxprotection.JournalRecord {
	next := linuxprotection.CloneRecord(t.head.Record)
	next.Sequence++
	next.PreviousSHA256 = t.head.SHA256
	return next
}

func sameDesktopLinuxJournalSelection(actual linuxprotection.JournalSelection, wanted linuxprotection.JournalRecord) bool {
	first, err := linuxprotection.CanonicalJournalRecord(actual.Record)
	second, otherErr := linuxprotection.CanonicalJournalRecord(wanted)
	digest, digestErr := linuxprotection.JournalRecordSHA256(second)
	return err == nil && otherErr == nil && digestErr == nil && !actual.Incomplete &&
		actual.SHA256 == digest && actual.Slot == int((wanted.Sequence-1)%2) && bytes.Equal(first, second)
}

// Retain the exact next record before its first write. A returned durable
// selection is preserved even if cancellation wins its final parent readback;
// an unknown/partial append can retry only these same bytes.
func (t *desktopLinuxNodeTransaction) appendRecord(ctx context.Context, next linuxprotection.JournalRecord) error {
	if t.pending != nil {
		return errors.New("Linux Node transaction still owns another pending durable record")
	}
	if err := linuxprotection.CheckJournalTransition(t.head.Record, next); err != nil {
		return err
	}
	copy := linuxprotection.CloneRecord(next)
	t.pending = &copy
	return t.flushPending(ctx)
}

func (t *desktopLinuxNodeTransaction) flushPending(ctx context.Context) error {
	if t.pending == nil {
		return nil
	}
	next := *t.pending
	selected, readErr := t.snapshotJournal(ctx)
	if readErr == nil && sameDesktopLinuxJournalSelection(selected, next) {
		t.head, t.pending = selected, nil
		return ctx.Err()
	}
	if readErr == nil && !sameDesktopLinuxJournalSelection(selected, t.head.Record) {
		return errors.New("Linux Node pending append was replaced by another durable transaction")
	}
	saved, err := t.appendJournal(ctx, next)
	if sameDesktopLinuxJournalSelection(saved, next) {
		t.head, t.pending = saved, nil
		return err
	}
	return errors.Join(err, errors.New("Linux Node transaction retained an unacknowledged exact durable append"))
}

func (t *desktopLinuxNodeTransaction) checkHead(ctx context.Context) error {
	if t.pending != nil {
		return errors.New("Linux Node mutation cannot pass a pending durable append")
	}
	selected, err := t.snapshotJournal(ctx)
	if err != nil || !sameDesktopLinuxJournalSelection(selected, t.head.Record) {
		return errors.Join(err, errors.New("Linux Node mutation changed its exact original journal head"))
	}
	return nil
}

func (t *desktopLinuxNodeTransaction) createBaseline(ctx context.Context, capture mobiletor.DesktopSocketCapture) (mobiletor.DesktopLinuxNodeCreationRecord, error) {
	if err := t.accepted(ctx); err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	if err := t.checkHead(ctx); err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	if t.baseline != nil || t.created != nil || capture.SessionID != t.selection.SessionID || capture.SourceSHA256 != t.selection.SourceSHA256 ||
		t.head.Record.Phase != "settled" || !reflect.DeepEqual(t.head.Record.Committed, t.previous) {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, errors.New("Linux Node creation lost its unused original captured intent")
	}
	next := t.nextRecord()
	next.Phase = "intent"
	next.Intent = &linuxprotection.JournalIntent{Action: "prepare", RequestID: t.selection.SessionID, ProfileID: t.profileID,
		ProfileRevision: t.revision, ResultProfileRevision: t.revision,
		Preparation: &linuxprotection.JournalPreparation{Capture: capture, HomeLAN: t.selection.HomeLAN,
			ConfigSHA256: t.selection.ConfigSHA256, Policy: t.selection.Policy, Engine: t.engineState}}
	if err := t.appendRecord(ctx, next); err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	if err := t.accepted(ctx); err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	// Once this captured bounded native operation enters, a user cancellation
	// prevents admission but does not erase its result or durable receipt.
	var err error
	t.baseline, err = mobiletor.NewDesktopLinuxNodeBaseline(ctx, capture, t.selection.HomeLAN)
	if err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	created, err := t.baseline.Created(ctx)
	if err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	t.created = &created
	next = t.nextRecord()
	next.Intent.Preparation.Created = &created
	if err := t.appendRecord(ctx, next); err != nil {
		return mobiletor.DesktopLinuxNodeCreationRecord{}, err
	}
	return created, t.accepted(ctx)
}

func (t *desktopLinuxNodeTransaction) candidate(prepared linuxprotection.NodePreparedRecord) (linuxprotection.JournalState, error) {
	guardian, err := desktopLinuxObservedProcess(prepared.Guardian.Guardian, prepared.Guardian.Engine)
	if err != nil {
		return linuxprotection.JournalState{}, err
	}
	engine := t.engineState
	state := linuxprotection.JournalState{ProfileID: t.profileID, ProfileRevision: t.revision, Engine: &engine,
		Target: &linuxprotection.ProtectionTarget{Native: prepared.Protection, Guardian: guardian,
			ConfigSHA256: t.selection.ConfigSHA256, Policy: t.selection.Policy}}
	return state, state.Validate()
}

func (t *desktopLinuxNodeTransaction) admitSource(ctx context.Context, prepared linuxprotection.NodePreparedRecord) error {
	if err := t.accepted(ctx); err != nil {
		return err
	}
	if err := t.checkHead(ctx); err != nil {
		return err
	}
	if prepared.Validate() != nil || t.baseline == nil || t.created == nil || t.prepared != nil ||
		prepared.Guardian.Engine != t.engine || prepared.Policy != t.selection.Policy || !t.created.MatchesPrepared(prepared.Protection) ||
		t.head.Record.Phase != "intent" || t.head.Record.Intent.Action != "prepare" || t.head.Record.Intent.Preparation.Created == nil ||
		*t.head.Record.Intent.Preparation.Created != *t.created {
		return errors.New("Linux Node admission substituted its original engine, creation receipt or prepare intent")
	}
	copy := prepared
	t.prepared = &copy
	if err := t.baseline.BindPrepared(ctx, prepared.Protection); err != nil {
		return err
	}
	candidate, err := t.candidate(prepared)
	if err != nil {
		return err
	}
	next := t.nextRecord()
	next.Intent.Action, next.Intent.Candidate = "successor", candidate
	if err := t.appendRecord(ctx, next); err != nil {
		return err
	}
	if err := t.accepted(ctx); err != nil {
		return err
	}
	if t.predecessor != nil {
		if err := t.predecessor.enter(ctx); err != nil {
			return err
		}
		defer func() { t.predecessor.gate <- struct{}{} }()
		if t.predecessor.successor != t || t.predecessor.superseded || t.predecessor.baseline == nil {
			return errors.New("Linux Node admission lost its reserved original predecessor")
		}
		if err := t.predecessor.baseline.Supersede(ctx, t.baseline); err != nil {
			return err
		}
	}
	t.nativeCommitted = true
	next = t.nextRecord()
	next.Phase, next.Intent, next.Committed = "settled", nil, candidate
	if err := t.appendRecord(ctx, next); err != nil {
		return err
	}
	return t.accepted(ctx)
}

// Use the original bounded engine dialogue context, not the user's cancelled
// request, so a captured refusal and source join can finish. The callbacks
// independently check that original request before creation and admission.
func (t *desktopLinuxNodeTransaction) ServePreparation(ctx context.Context) error {
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer func() { t.gate <- struct{}{} }()
	if !t.complete || t.served || t.control == nil || t.closed {
		return errors.New("Linux Node transaction has no unused complete original preparation")
	}
	t.served = true
	err := t.control.ServePreparation(ctx, t.createBaseline, t.admitSource)
	if err == nil {
		t.admitted = true
	}
	return err
}
