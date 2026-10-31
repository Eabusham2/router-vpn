package windowsprotection

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"time"

	"router-vpn/internal/mobiletor"
)

// JournalRecoveryResult describes a durable handover, not a reusable native
// capability. A nonzero result accompanied by an error preserves the actual
// written checkpoint but never admits a connection. Observed is separate from
// Selection because an accepted Off remains pending until its captured result
// profile is actually saved, even when its native absence has been proved.
type JournalRecoveryResult struct {
	Selection JournalSelection
	Observed  JournalState
}

type journalRecoveryBackend interface {
	verify(context.Context) error
	retire(context.Context) error
	append(context.Context, JournalRecord) (JournalSelection, error)
	close() error
	finish(context.Context, *JournalRecovery) error
}

type journalRecoveryObservation interface {
	Run(context.Context) error
	Close(context.Context) error
}

// JournalRecovery is created only by the native locked ProtectionJournal.
// It owns immutable process/BFE candidates and one exact durable handover.
// Run is synchronous; Close revokes its callback context before joining it.
// Neither method sends signals to recorded PIDs or deletes unknown state.
type JournalRecovery struct {
	head        JournalSelection
	controller  Controller
	requestID   string
	candidates  []JournalState
	backend     journalRecoveryBackend
	observation journalRecoveryObservation
	gate        chan struct{}
	lifetime    context.Context
	cancel      context.CancelFunc
	closing     atomic.Bool
	selected    int
	adoption    *JournalRecord
	durable     *JournalRecoveryResult
	observed    bool
	finished    bool
}

func cloneJournalSelection(selection JournalSelection) JournalSelection {
	selection.Record = cloneJournalRecord(selection.Record)
	return selection
}

func cloneJournalRecoveryResult(result JournalRecoveryResult) JournalRecoveryResult {
	result.Selection = cloneJournalSelection(result.Selection)
	result.Observed = cloneJournalState(result.Observed)
	return result
}

func newJournalRecovery(head JournalSelection, controller Controller, requestID string, backend journalRecoveryBackend,
	observe func([]*mobiletor.DesktopWindowsProtectionTarget, func(context.Context, int) error) (journalRecoveryObservation, error)) (*JournalRecovery, error) {
	raw, err := CanonicalJournalRecord(head.Record)
	if err != nil || head.Incomplete || head.Slot < 0 || head.Slot > 1 || uint64(head.Slot) != (head.Record.Sequence-1)%2 ||
		controller.Validate() != nil || controller == head.Record.Controller || !lowerHex(requestID, 32) || backend == nil || observe == nil {
		return nil, errors.New("Windows recovery requires its intact captured native journal owner")
	}
	digest, err := JournalRecordSHA256(raw)
	if err != nil || digest != head.SHA256 || requireJournalProfileBindings(head.Record) != nil {
		return nil, errors.New("Windows recovery lost its exact bound journal digest")
	}
	if _, err := journalRecoveryProcesses(head.Record); err != nil {
		return nil, err
	}
	candidates, err := JournalRecoveryCandidates(head.Record)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	owner := &JournalRecovery{head: cloneJournalSelection(head), controller: controller, requestID: requestID, candidates: candidates,
		backend: backend, gate: make(chan struct{}, 1), lifetime: lifetime, cancel: cancel, selected: -1}
	targets := make([]*mobiletor.DesktopWindowsProtectionTarget, len(candidates))
	for index, candidate := range candidates {
		targets[index] = cloneJournalState(candidate).Target
	}
	owner.observation, err = observe(targets, owner.acknowledge)
	if err == nil && owner.observation == nil {
		err = errors.New("Windows journal recovery captured no native observation owner")
	}
	return owner, err // a partial observation remains owned and must be closed
}

func (owner *JournalRecovery) result() JournalRecoveryResult {
	if owner.durable == nil {
		return JournalRecoveryResult{}
	}
	return cloneJournalRecoveryResult(*owner.durable)
}

// acknowledge runs synchronously inside the retained native read transaction.
// The first observed index freezes the append before any file I/O. A failed
// flush never authorizes another recorded candidate or request on a retry.
func (owner *JournalRecovery) acknowledge(ctx context.Context, matched int) error {
	if owner.closing.Load() || ctx == nil || ctx.Err() != nil || matched < 0 || matched >= len(owner.candidates) {
		return errors.New("Windows journal recovery callback lost its captured live outcome")
	}
	if err := owner.backend.verify(ctx); err != nil {
		return err
	}
	if owner.selected >= 0 && owner.selected != matched {
		return errors.New("Windows journal recovery cannot replace its first observed outcome")
	}
	if owner.adoption == nil {
		next, err := deriveJournalRecoveryTransition(owner.head.Record, owner.controller, owner.requestID, matched)
		if err != nil {
			return err
		}
		owner.selected, owner.adoption = matched, &next
	}
	selection, appendErr := owner.backend.append(ctx, cloneJournalRecord(*owner.adoption))
	wanted, err := CanonicalJournalRecord(*owner.adoption)
	if err != nil {
		return err
	}
	digest, _ := JournalRecordSHA256(wanted)
	actual, err := CanonicalJournalRecord(selection.Record)
	if err == nil && !selection.Incomplete && selection.Slot == 1-owner.head.Slot && selection.SHA256 == digest && bytes.Equal(actual, wanted) {
		result := JournalRecoveryResult{Selection: cloneJournalSelection(selection), Observed: cloneJournalState(owner.adoption.Adoption.Observed)}
		owner.durable = &result
	} else {
		return errors.Join(appendErr, errors.New("Windows journal recovery did not acknowledge its exact durable handover"))
	}
	return errors.Join(appendErr, ctx.Err())
}

// Run independently retires every recorded process before observing BFE.
// It returns an admitted result only after the observer, old read-only process
// references and retained-head readback have all joined successfully. Repeated
// calls retry exact pending work; a prior durable write is never fabricated as
// proof that the native snapshot or cleanup succeeded.
func (owner *JournalRecovery) Run(ctx context.Context) (JournalRecoveryResult, error) {
	if owner == nil || ctx == nil || owner.backend == nil || owner.observation == nil {
		return JournalRecoveryResult{}, errors.New("Windows journal recovery has no complete native owner")
	}
	if err := ctx.Err(); err != nil {
		return JournalRecoveryResult{}, err
	}
	if owner.closing.Load() {
		return JournalRecoveryResult{}, errors.New("Windows journal recovery is retiring")
	}
	select {
	case <-ctx.Done():
		return JournalRecoveryResult{}, ctx.Err()
	case <-owner.lifetime.Done():
		return JournalRecoveryResult{}, errors.New("Windows journal recovery is retiring")
	case owner.gate <- struct{}{}:
	}
	defer func() { <-owner.gate }()
	if owner.closing.Load() {
		return owner.result(), errors.New("Windows journal recovery is retiring")
	}
	if owner.finished {
		return owner.result(), nil
	}
	request, cancel := context.WithTimeout(ctx, 20*time.Second)
	stop := context.AfterFunc(owner.lifetime, cancel)
	defer func() { stop(); cancel() }()
	if err := owner.backend.verify(request); err != nil {
		return owner.result(), err
	}
	if !owner.observed {
		if err := owner.backend.retire(request); err != nil {
			return owner.result(), err
		}
		if err := owner.observation.Run(request); err != nil {
			return owner.result(), err
		}
		if owner.durable == nil {
			return JournalRecoveryResult{}, errors.New("Windows journal recovery observation omitted its durable callback")
		}
		owner.observed = true
	}
	if err := owner.observation.Close(request); err != nil {
		return owner.result(), err
	}
	if err := owner.backend.close(); err != nil {
		return owner.result(), err
	}
	if err := request.Err(); err != nil {
		return owner.result(), err
	}
	if err := owner.backend.finish(request, owner); err != nil {
		return owner.result(), err
	}
	owner.finished = true
	return owner.result(), request.Err()
}

// Close abandons admission, cancels an entered callback, then joins all native
// resources. It preserves both durable slots, including an uncertain append.
// An abandoned owner never silently releases ordinary write authority; its
// journal must also close before a fresh controller can reconcile the files.
func (owner *JournalRecovery) Close(ctx context.Context) error {
	if owner == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("Windows journal recovery close requires its captured context")
	}
	owner.closing.Store(true)
	owner.cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case owner.gate <- struct{}{}:
	}
	defer func() { <-owner.gate }()
	var failure error
	if owner.observation != nil {
		failure = owner.observation.Close(ctx)
	}
	if owner.backend != nil {
		failure = errors.Join(failure, owner.backend.close())
	}
	return errors.Join(failure, ctx.Err())
}
