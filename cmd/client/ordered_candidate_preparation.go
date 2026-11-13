package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
)

// The preparation is a separate, finite purpose: measure saved SS candidates
// using one complete saved Local graph, retire that graph, then permit an
// explicit profile save. It cannot represent an ordinary connection, a draft
// prefix without its final node, or automatic connection adoption.
type orderedCandidatePreparationRequest struct {
	RequestID    string
	Position     int
	CandidateIDs []string
	Samples      int
}

type orderedCandidatePreparation struct {
	app               *app
	control           *viaEntryControl
	owner             *viaEntryOwner
	operation         context.Context
	cancel            context.CancelFunc
	request           orderedCandidatePreparationRequest
	selection         multihopSelection
	inventory         *desktopNodeChainCandidateCatalog // source-only capture; no connected identity
	state             state
	revision, network string
	observeNetwork    func(context.Context) (string, error)
	mu                sync.Mutex // lifecycle; if both are needed, acquire before app.mu
	launch            *desktopNodeLaunch
	runtime           *orderedCandidatePreparedRuntime
	workerDone        <-chan struct{}
	pending           error
	releaseLease      func()
	down              bool
	nativeDown        bool
	workspaceDown     bool
	windowsRelease    *orderedCandidateWindowsRelease
	finishOnce        sync.Once
	finishError       error
	invalidated       atomic.Bool
}

// Synchronous callers own the entire batch lifetime, including cleanup. The
// public 202 route uses the explicit lifetime-aware admission below so ending
// its response cannot revoke the retained native worker.
func beginOrderedCandidatePreparation(ctx context.Context, a *app, q orderedCandidatePreparationRequest) (*orderedCandidatePreparation, error) {
	return beginOrderedCandidatePreparationWithNetwork(ctx, a, q, physicalNetworkIdentityContext)
}

// Only the physical-inventory boundary is supplied by portable tests. Complete
// saved graph/source compilation and candidate eligibility use shipping code.
func beginOrderedCandidatePreparationWithNetwork(ctx context.Context, a *app, q orderedCandidatePreparationRequest,
	observe func(context.Context) (string, error)) (result *orderedCandidatePreparation, failure error) {
	return beginOrderedCandidatePreparationWithLifetime(ctx, ctx, a, q, observe)
}

// A 202 response has a separate bounded, registered worker lifetime. Admission
// still uses its request deadline; ending that response cannot revoke the
// original background worker, while explicit Cancel/Stop retains its join.
func beginOrderedCandidatePreparationWithLifetime(ctx, lifetime context.Context, a *app, q orderedCandidatePreparationRequest,
	observe func(context.Context) (string, error)) (result *orderedCandidatePreparation, failure error) {
	if ctx == nil || ctx.Err() != nil || lifetime == nil || lifetime.Err() != nil || a == nil || observe == nil || !validViaEntryRequestID(q.RequestID) ||
		q.Samples != 50 || q.Position < 0 || q.Position > 7 || len(q.CandidateIDs) < 1 || len(q.CandidateIDs) > hopmeasure.CandidateMaximumTargets {
		return nil, errors.New("temporary candidates require an original caller, saved IDs and exactly 50 samples")
	}
	seen := map[string]bool{}
	for _, id := range q.CandidateIDs {
		if !validProfileID(id) || seen[id] {
			return nil, errors.New("temporary candidate IDs must be distinct saved sources")
		}
		seen[id] = true
	}
	if !a.operationMu.TryLock() {
		return nil, errors.New("another operation owns candidate preparation")
	}
	transferred := false
	defer func() {
		if !transferred {
			a.operationMu.Unlock()
		}
	}()
	c := viaEntryControlFor(a)
	release, err := a.lockCandidatePublicationContext(ctx, c)
	if err != nil {
		return nil, err
	}
	c.pruneNoncesLocked()
	_, repeated := c.seen[q.RequestID]
	if repeated || len(c.seen) >= 1024 || c.owner != nil && (c.owner.running || !c.owner.drained) || !orderedCandidatePreparationIdleLocked(a) {
		release()
		return nil, errors.New("temporary candidate admission is not idle, was cancelled, or still owns cleanup")
	}
	control, found := a.profileByIDLocked(a.profiles.SelectedID)
	if !found || !control.MultihopEnabled || control.MultihopExecution != "local" || len(control.MultihopNodes) < 2 {
		release()
		return nil, errors.New("temporary candidates require the selected complete saved Local graph")
	}
	control = cloneRouterProfile(control)
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	revision, err := a.candidateCatalogRevisionLocked()
	initial := a.state
	release()
	if err != nil {
		return nil, err
	}
	network, err := observe(ctx)
	if err != nil || network == "" {
		return nil, errors.Join(err, errors.New("temporary candidate physical network is unavailable"))
	}
	selection, err := resolveDesktopNodeChainSelection(control, profiles, control.MultihopNodes, "local")
	if err != nil {
		return nil, err
	}
	selection, err = captureNativeNodeChainSelection(ctx, clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		return nil, err
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	// This socket-free projection exists only to compile the original candidate
	// inventory. It has no host, process, tracker or ready proof and cannot pass
	// the connected catalog/currentness gates.
	sourceLaunch, err := newDesktopNodeChainLaunch(selection, session, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	inventory, err := captureDesktopNodeChainCandidateSources(ctx, a, sourceLaunch, q.Position, q.CandidateIDs)
	if err != nil {
		return nil, err
	}
	if inventory.revision != revision {
		return nil, errors.New("saved candidate catalog changed during preparation")
	}
	if err = selection.Native.chain.validate(ctx, control, profiles); err != nil {
		return nil, err
	}
	currentNetwork, err := observe(ctx)
	if err != nil || currentNetwork != network {
		return nil, errors.Join(err, errors.New("physical network changed during candidate preparation"))
	}
	release, err = a.lockCandidatePublicationContext(ctx, c)
	if err != nil {
		return nil, err
	}
	defer release()
	c.pruneNoncesLocked()
	_, repeated = c.seen[q.RequestID]
	currentRevision, err := a.candidateCatalogRevisionLocked()
	if err != nil || ctx.Err() != nil || lifetime.Err() != nil || repeated || len(c.seen) >= 1024 ||
		c.owner != nil && (c.owner.running || !c.owner.drained) || !orderedCandidatePreparationIdleLocked(a) ||
		a.state != initial || currentRevision != revision || !selection.Native.chain.profilesCurrent(control, a.profiles.Profiles) {
		return nil, errors.Join(err, ctx.Err(), errors.New("temporary candidate capture changed before original admission"))
	}
	operation, cancel := context.WithCancel(lifetime)
	q.CandidateIDs = append([]string(nil), q.CandidateIDs...)
	p := &orderedCandidatePreparation{app: a, control: c, operation: operation, cancel: cancel, request: q,
		selection: selection, inventory: inventory, state: initial, revision: revision, network: network, observeNetwork: observe}
	p.owner = &viaEntryOwner{id: q.RequestID, cancel: cancel, done: make(chan struct{}), running: true, preparation: p}
	p.owner.cleanup = p.retire
	c.owner, c.seen[q.RequestID] = p.owner, time.Now()
	a.candidatePreparation, a.connectionContext, a.connectionCancel = p, operation, cancel
	transferred = true
	return p, nil
}

func orderedCandidatePreparationIdleLocked(a *app) bool {
	if a == nil || a.controllerClosingLocked() || a.candidatePreparation != nil || a.connectionContext != nil ||
		a.cmd != nil || profileSettingsBusy(a.state.Connected, a.state.Phase) {
		return false
	}
	if _, ok := nativeMultihopOwners.Load(a); ok {
		return false
	}
	if _, ok := desktopNodeOwners.Load(a); ok {
		return false
	}
	if _, ok := activeMultihopGraphs.Load(a); ok {
		return false
	}
	if _, ok := desktopRelays.Load(a); ok {
		return false
	}
	if _, ok := speedLabTemporaryOwners.Load(a); ok {
		return false
	}
	return true
}

func (p *orderedCandidatePreparation) sourceCurrent(ctx context.Context) (failure error) {
	defer func() {
		if failure != nil && p != nil {
			p.invalidate()
		}
	}()
	if ctx == nil || p == nil || p.app == nil || p.operation == nil || p.operation.Err() != nil || p.observeNetwork == nil {
		return errors.New("temporary candidate preparation lost its original purpose")
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return err
	}
	err := p.currentLocked()
	p.app.mu.Unlock()
	if err != nil {
		return err
	}
	if err := p.savedSourcesCurrent(ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return err
	}
	defer p.app.mu.Unlock()
	return errors.Join(p.currentLocked(), ctx.Err())
}

// Shared immutable source inventory checks for running and detached-DOWN
// observations. Each caller separately validates its concrete owner boundary.
func (p *orderedCandidatePreparation) savedSourcesCurrent(ctx context.Context) error {
	if ctx == nil || p == nil || p.app == nil || p.inventory == nil || p.selection.Native == nil ||
		p.selection.Native.chain == nil || p.observeNetwork == nil {
		return errors.New("candidate saved source observation lost its original capture")
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return err
	}
	profiles := cloneRouterProfileStore(p.app.profiles).Profiles
	p.app.mu.Unlock()
	if err := p.selection.Native.chain.validate(ctx, p.selection.Control, profiles); err != nil {
		return err
	}
	// Re-capture only source inventory. No connected identity is manufactured.
	current, err := captureDesktopNodeChainCandidateSources(ctx, p.app, p.inventory.launch, p.request.Position, p.request.CandidateIDs)
	if err != nil || current.inventory != p.inventory.inventory || !reflect.DeepEqual(current.assets, p.inventory.assets) {
		return errors.Join(err, errors.New("temporary candidate original saved inventory changed"))
	}
	for i, file := range current.files {
		if i >= len(p.inventory.files) || !sameDesktopCandidateSourceFile(file, p.inventory.files[i]) {
			return errors.New("temporary candidate saved source file was replaced")
		}
	}
	if len(current.files) != len(p.inventory.files) {
		return errors.New("temporary candidate source file inventory changed")
	}
	network, err := p.observeNetwork(ctx)
	if err != nil || network != p.network {
		return errors.Join(err, errors.New("temporary candidate original physical network changed"))
	}
	return ctx.Err()
}

func (p *orderedCandidatePreparation) currentLocked() (failure error) {
	defer func() {
		if failure != nil && p != nil {
			p.invalidate()
		}
	}()
	if p == nil || p.app == nil || p.operation == nil || p.app.candidatePreparation != p ||
		p.invalidated.Load() || p.app.checkCapturedConnectionOperationLocked(p.operation) != nil || p.app.state.Connected ||
		p.selection.Native == nil || p.selection.Native.chain == nil {
		return errors.New("temporary candidate original owner was cancelled or replaced")
	}
	revision, err := p.app.candidateCatalogRevisionLocked()
	if err != nil || revision != p.revision || !p.selection.Native.chain.profilesCurrent(p.selection.Control, p.app.profiles.Profiles) {
		return errors.Join(err, errors.New("temporary candidate original saved graph changed"))
	}
	if [3]bool{p.app.state.DAITA, p.app.state.Jumbo, p.app.state.Socks} != [3]bool{p.state.DAITA, p.state.Jumbo, p.state.Socks} {
		return errors.New("temporary candidate original Home options changed")
	}
	if p.launch == nil && (p.app.state != p.state || p.app.cmd != nil) {
		return errors.New("temporary candidate original idle Home identity changed before binding")
	}
	return nil
}

// Once observed, a mismatch is permanent even if the values later return. A
// pair of physical inventory reads alone does not claim to observe unreported
// network events; runtime integration must retain the native cohort observer.
func (p *orderedCandidatePreparation) invalidate() {
	p.invalidated.Store(true)
	if p.cancel != nil {
		p.cancel()
	}
}

func sameDesktopCandidateSourceFile(a, b desktopCandidateSourceFile) bool {
	return a.path == b.path && os.SameFile(a.info, b.info) && a.info.Mode() == b.info.Mode() &&
		a.info.Size() == b.info.Size() && a.info.ModTime().Equal(b.info.ModTime())
}
