package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
)

// This observation never satisfies a connected catalog. It retains the actual
// full-graph launch, native proof, reader and separately owned physical observer
// for one finite preparation, including its later DOWN/result-review boundary.
type orderedCandidatePreparedRuntime struct {
	preparation *orderedCandidatePreparation
	cohort      *desktopnetwork.Tracker
	stopCohort  context.CancelFunc
	transition  bool
	receipt     *desktopnetwork.DesktopNetworkReceipt
	graph       activeMultihopGraph
	graphSet    bool
	owner       *nativeMultihopRuntime
	catalog     *desktopNodeChainCandidateCatalog
	live        desktopNodeMTURecord
}

// The caller retains the preparation on every error and invokes its original
// cleanup. No high-level Connect route is used: usage/startup persistence and
// ordinary Connected adoption do not belong to this finite purpose.
func (p *orderedCandidatePreparation) startRuntime(ctx context.Context) (*orderedCandidatePreparedRuntime, error) {
	if err := p.sourceCurrent(ctx); err != nil {
		return nil, err
	}
	if err := p.holdLease(ctx); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &p.mu); err != nil {
		return nil, err
	}
	if p.runtime != nil || p.launch != nil || p.nativeDown || p.down {
		p.mu.Unlock()
		return nil, errors.New("candidate runtime requires its unused original preparation")
	}
	lifetime, stop := context.WithCancel(context.Background())
	r := &orderedCandidatePreparedRuntime{preparation: p, stopCohort: stop}
	p.runtime = r // Retain even a partially opened observer before any native effect.
	p.mu.Unlock()
	var err error
	r.cohort, err = desktopnetwork.OpenWithLifetime(ctx, lifetime, nil)
	if err != nil {
		return r, err
	}
	if err := p.sourceCurrent(ctx); err != nil {
		return r, err
	}
	launch, err := preflightOwnedNativeMultihopCommandForPurpose(ctx, p.app, p.selection, nil, p)
	if err != nil {
		return r, err
	}
	if launch != p.launch || launch == nil || launch.chain == nil || launch.chain.preparation != p ||
		(launch.ownedNode == nil && !desktopMultihopPlatformLaunch(launch)) {
		return r, errors.New("candidate runtime lost its original concrete platform launch")
	}
	if err := p.app.guardDesktopOwnedNodeTransitionContext(ctx, launch); err != nil {
		return r, err
	}
	if err := p.sourceCurrent(ctx); err != nil {
		return r, err
	}
	if err := r.cohort.Begin(ctx, nil); err != nil {
		return r, err
	}
	r.transition = true
	if err := stageOwnedNativeMultihopCommandContext(ctx, p.app, p.selection, launch); err != nil {
		return r, err
	}
	if desktopMultihopPlatformLaunch(launch) {
		err = startDesktopMultihopPlatform(ctx, p.app, p.selection, launch)
	} else {
		if err = desktopnetwork.LockContext(ctx, &p.app.mu); err == nil {
			err = p.app.publishDesktopCapturedMultihopStartLocked(p.operation, launch, p.selection)
			p.app.mu.Unlock()
		}
	}
	if err != nil {
		return r, err
	}
	r.graph, err = publishDesktopMultihopPlatformGraph(ctx, p.app, launch, p.selection, "local")
	if err != nil {
		return r, err
	}
	r.graphSet = true
	if err := bindNativeMultihopRuntimeContext(ctx, p.app, launch, p.selection, p.network); err != nil {
		return r, err
	}
	raw, found := nativeMultihopOwners.Load(p.app)
	r.owner, _ = raw.(*nativeMultihopRuntime)
	if !found || r.owner == nil || r.owner.launch != launch || r.owner.graph != r.graph {
		return r, errors.New("candidate graph binding lost its original native owner")
	}
	if !desktopMultihopPlatformLaunch(launch) {
		if err := startDesktopCapturedMultihopOwned(ctx, p.operation, p.app, launch); err != nil {
			return r, err
		}
	}
	if err := proveDesktopNodeChainContext(ctx, p.app, p.selection, launch.command); err != nil {
		return r, err
	}
	if desktopMultihopPlatformLaunch(launch) {
		if err := activateDesktopMultihopPlatform(ctx, launch); err != nil {
			return r, err
		}
	}
	if err := desktopNodeChainCurrent(ctx, p.app, launch); err != nil {
		return r, err
	}
	r.live, err = readDesktopNodeMTUContext(ctx, launch)
	if err != nil || r.live.Active || r.live.Failure != "" {
		return r, errors.Join(err, errors.New("candidate preparation has no idle original native reader"))
	}
	r.receipt, err = parseDesktopCohortReceipt(r.live.NetworkReceipt, r.live.Interface, r.live.Index, r.live.MTU)
	if err != nil {
		return r, err
	}
	if err := r.cohort.RecordContext(ctx, *r.receipt); err != nil {
		return r, err
	}
	if err := r.cohort.End(ctx, r.receipt); err != nil {
		return r, err
	}
	r.transition = false
	r.catalog, err = captureDesktopNodeChainCandidateSources(ctx, p.app, launch, p.request.Position, p.request.CandidateIDs)
	if err != nil || !orderedCandidateSameInventory(p.inventory, r.catalog) {
		return r, errors.Join(err, errors.New("candidate runtime changed its admitted saved inventory"))
	}
	if err := p.sourceCurrent(ctx); err != nil {
		return r, err
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return r, err
	}
	_, err = orderedCandidateLaunchPurposeLocked(p.app, launch)
	if err == nil && p.app.cmd != launch.command {
		err = errors.New("candidate testing publication lost its original native command")
	}
	if err == nil {
		p.app.state.Connected, p.app.state.Phase, p.app.state.LastError = false, "candidate:testing", ""
	}
	p.app.mu.Unlock()
	if err != nil {
		return r, err
	}
	return r, r.current(ctx)
}

func orderedCandidateSameInventory(a, b *desktopNodeChainCandidateCatalog) bool {
	if a == nil || b == nil || a.revision != b.revision || a.inventory != b.inventory ||
		!reflect.DeepEqual(a.assets, b.assets) || !reflect.DeepEqual(a.profiles, b.profiles) || len(a.files) != len(b.files) {
		return false
	}
	for i := range a.files {
		if !sameDesktopCandidateSourceFile(a.files[i], b.files[i]) {
			return false
		}
	}
	return true
}

func (r *orderedCandidatePreparedRuntime) current(ctx context.Context) error {
	if r == nil || r.preparation == nil {
		return errors.New("temporary candidate observation lost its original purpose")
	}
	if err := r.preparation.sourceCurrent(ctx); err != nil {
		return err
	}
	if err := desktopNodeChainCurrent(ctx, r.preparation.app, r.preparation.launch); err != nil {
		return err
	}
	return r.pulseCurrent(ctx)
}

func (r *orderedCandidatePreparedRuntime) pulseCurrent(ctx context.Context) (failure error) {
	defer func() {
		if failure != nil && r != nil && r.preparation != nil {
			r.preparation.invalidate()
		}
	}()
	if ctx == nil || ctx.Err() != nil || r == nil || r.preparation == nil || r.cohort == nil ||
		r.catalog == nil || r.owner == nil || r.receipt == nil || r.transition {
		return errors.New("candidate observation lacks its complete original native receipt")
	}
	p, c := r.preparation, r.catalog
	if owner, ok := nativeMultihopOwners.Load(p.app); !ok || owner != r.owner || r.owner.launch != p.launch ||
		c.launch != p.launch || p.launch == nil || p.launch.chain == nil || p.launch.chain.preparation != p {
		return errors.New("candidate observation belongs to another native launch")
	}
	if graph, ok := getActiveMultihopGraph(p.app); !ok || graph != r.graph {
		return errors.New("candidate observation changed its original full graph")
	}
	if err := r.cohort.CurrentContext(ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return err
	}
	err := p.currentLocked()
	if err == nil && (p.app.cmd != p.launch.command || p.app.state.Phase != "candidate:testing") {
		err = errors.New("candidate observation lost its separate testing presentation")
	}
	p.app.mu.Unlock()
	if err != nil {
		return err
	}
	for _, file := range c.files {
		info, err := os.Lstat(file.path)
		if err != nil || !sameDesktopCandidateSourceFile(file, desktopCandidateSourceFile{file.path, info}) {
			return errors.New("candidate observation lost an original saved source file")
		}
	}
	for _, asset := range c.assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		files, err := readDesktopNodeAssets(c.launch.root, asset.id, asset.mode)
		valid := err == nil && viaEntryAssetDigest(files) == asset.digest
		clearViaEntryAssets(files)
		if !valid {
			return errors.New("candidate observation changed its original saved assets")
		}
	}
	live, err := readDesktopNodeMTUContext(ctx, p.launch)
	if err != nil || !orderedCandidateSameReader(r.live, live) {
		return errors.Join(err, errors.New("candidate observation changed its original native reader"))
	}
	return ctx.Err()
}

func orderedCandidateSameReader(a, b desktopNodeMTURecord) bool {
	return a.Session == b.Session && a.Config == b.Config && a.Path == b.Path && a.Reader == b.Reader &&
		a.Interface == b.Interface && a.Index == b.Index && a.MTU == b.MTU && a.NetworkReceipt == b.NetworkReceipt &&
		!b.Active && b.Failure == ""
}

// Synchronous batch: the operation context cannot outlive its handler. Each
// retained child still executes exactly fifty connections and proves its own
// result/drain; a failed drain is delivered to the original preparation join.
func (p *orderedCandidatePreparation) measureRuntime(ctx context.Context, r *orderedCandidatePreparedRuntime,
	completed func(string, hopmeasure.CandidateStatus, error)) (failure error) {
	if r == nil || r != p.runtime || r.preparation != p || completed == nil {
		return errors.New("candidate batch lost its exact prepared observation")
	}
	if err := r.current(ctx); err != nil {
		return err
	}
	joined, err := p.beginWorker(ctx)
	if err != nil {
		return err
	}
	var pending error
	defer func() { joined(pending) }()
	for _, id := range p.request.CandidateIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := exchangeDesktopNodeChainCandidateObserved(ctx, r.catalog, id, r.current, r.pulseCurrent)
		completed(id, status, err)
		if errors.Is(err, errDesktopNodeChainMeasurementPending) {
			pending = err
			return err
		}
		if err := r.current(ctx); err != nil {
			return err
		}
	}
	return r.current(ctx)
}

// Review expiry uses the measured receipts' original finite deadline. It does
// not refresh a native receipt or extend the worker's request budget.
func orderedCandidateResultExpiry(results []hopmeasure.CandidateStatus) time.Time {
	var expiry time.Time
	for _, result := range results {
		at := time.UnixMilli(result.ExpiresAt)
		if expiry.IsZero() || at.Before(expiry) {
			expiry = at
		}
	}
	return expiry
}
