package mobilemultihop

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/routechoice"
)

// Selection epochs reject away-and-back changes during directly tagged proof I/O.
// Native admission establishes a nonzero epoch before runtime trials.
type NodeChainExecutionSelectionEpochEngine interface {
	SelectionEpochContext(context.Context) (uint64, error)
}

type NodeChainExecutionProgress struct {
	NodeChainProgress
	Comparison routechoice.Result `json:"comparison"`
}

// The runtime owns proofs and exact remote attempts; the host owns the one
// original native Box/TUN. Each trial is immutable and cannot be replaced
// until its original application, proof, control and server owners join.
type NodeChainExecutionRuntime struct {
	mu                   sync.Mutex
	projection           *NodeChainExecutionProjection
	engine               NodeChainExecutionEngine
	identity             NodeChainIdentity
	lifetime             context.Context
	cancel               context.CancelFunc
	runDone, watchDone   chan struct{}
	started, retired     atomic.Bool
	closed               bool
	measurementHolds     int
	lastCaptures         int
	healthObservations   int
	readbackObservations int
	active               *nodeChainExecutionTrial
	progress             NodeChainExecutionProgress
	checkedAt            time.Time
	restore              *NodeChainExecutionRestoreCapture
	mtuPause             *nodeChainExecutionMTUResumeState
	mtuResume            *nodeChainExecutionMTUResumeState
	lastPlan             *nodeChainExecutionLastPlanState
	testTLS              *tls.Config
}

type nodeChainExecutionTrial struct {
	mu                         sync.Mutex
	runtime                    *NodeChainExecutionRuntime
	execution, tag, target, id string
	selectionEpoch             uint64
	lifetime                   context.Context
	cancel                     context.CancelFunc
	proofIO, controlIO         *nodeChainExecutionIO
	attempt                    *nodeChainExecutionAttempt
	closeGate                  chan struct{}
	closed                     bool
	checkedAt                  time.Time
	prefixes                   []NodeChainPrefixProgress
}

func NewNodeChainExecutionRuntime(projection *NodeChainExecutionProjection, engine NodeChainExecutionEngine) (*NodeChainExecutionRuntime, error) {
	if projection.validateCapture() != nil || engine == nil {
		return nil, nodeChainExecutionError
	}
	if _, ok := engine.(NodeChainExecutionSelectionEpochEngine); !ok {
		return nil, nodeChainExecutionError
	}
	return &NodeChainExecutionRuntime{projection: projection, engine: engine, progress: NodeChainExecutionProgress{NodeChainProgress: NodeChainProgress{Stage: "pending", Execution: projection.Execution(), Prefixes: []NodeChainPrefixProgress{}}}}, nil
}

func (r *NodeChainExecutionRuntime) identityMatches(identity NodeChainIdentity) bool {
	return nodeChainIdentityText(identity.EngineID) && nodeChainIdentityText(identity.SessionID) && nodeChainIdentityText(identity.NetworkID) && identity.SourceSHA256 == r.projection.SourceSHA256() && identity.ConfigSHA256 == r.projection.ConfigSHA256()
}

func (r *NodeChainExecutionRuntime) current(ctx context.Context, trial *nodeChainExecutionTrial, selected bool) error {
	if r == nil || ctx == nil || ctx.Err() != nil || r.retired.Load() || r.projection.validateCapture() != nil {
		return nodeChainExecutionError
	}
	r.mu.Lock()
	identity, active := r.identity, r.active
	r.mu.Unlock()
	if !r.identityMatches(identity) || trial != nil && (active != trial || trial.lifetime.Err() != nil) {
		return nodeChainExecutionError
	}
	observed, err := r.engine.ObserveChainContext(ctx)
	if err != nil {
		return err
	}
	if observed != identity {
		return nodeChainExecutionError
	}
	if selected {
		if trial == nil {
			return nodeChainExecutionError
		}
		tag, err := r.engine.SelectedContext(ctx)
		if err != nil {
			return err
		}
		if tag != trial.tag {
			return nodeChainExecutionError
		}
		epoch, err := r.engine.(NodeChainExecutionSelectionEpochEngine).SelectionEpochContext(ctx)
		if err != nil {
			return err
		}
		if epoch == 0 || epoch != trial.selectionEpoch {
			return nodeChainExecutionError
		}
	}
	r.mu.Lock()
	valid := r.identity == identity && (trial == nil || r.active == trial) && !r.closed
	r.mu.Unlock()
	if !valid || r.retired.Load() || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	return nil
}

func (r *NodeChainExecutionRuntime) candidate(execution string) routechoice.Candidate {
	p := r.projection.policy
	return routechoice.Candidate{Execution: routechoice.Execution(execution), Transport: "ordered-node-chain", EntryID: p.local.proofs[0].ProfileID, ExitID: p.local.proofs[len(p.local.proofs)-1].ProfileID}
}

type nodeChainExecutionDriver struct{ r *NodeChainExecutionRuntime }

func (d nodeChainExecutionDriver) Open(ctx context.Context, c routechoice.Candidate) (routechoice.Session, error) {
	return d.OpenTarget(ctx, c, Targets[0])
}
func (d nodeChainExecutionDriver) OpenTarget(ctx context.Context, c routechoice.Candidate, target string) (routechoice.Session, error) {
	return d.r.open(ctx, c, target)
}

func (r *NodeChainExecutionRuntime) open(ctx context.Context, c routechoice.Candidate, target string) (routechoice.Session, error) {
	if c != r.candidate(string(c.Execution)) || c.Execution != routechoice.Local && c.Execution != routechoice.Server || !nodeChainExecutionTarget(target) {
		return nil, nodeChainExecutionError
	}
	if err := r.current(ctx, nil, false); err != nil {
		return nil, err
	}
	proofs, err := r.projection.ProofInventory(string(c.Execution))
	if err != nil {
		return nil, err
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(r.lifetime)
	s := &nodeChainExecutionTrial{runtime: r, execution: string(c.Execution), tag: proofs[len(proofs)-1].Tag, target: target, id: id, lifetime: lifetime, cancel: cancel, closeGate: make(chan struct{}, 1)}
	s.closeGate <- struct{}{}
	r.mu.Lock()
	if r.active != nil || r.retired.Load() {
		r.mu.Unlock()
		cancel()
		return nil, errors.New("previous ordered execution owner is not joined")
	}
	r.active = s
	r.mu.Unlock()
	if err := r.engine.RevokeApplicationContext(ctx); err != nil {
		return s, err
	}
	open, err := r.engine.ApplicationOpenContext(ctx)
	if err != nil || open {
		return s, errors.Join(err, nodeChainExecutionError)
	}
	if err := r.current(ctx, s, false); err != nil {
		return s, err
	}
	if err := r.engine.SelectContext(ctx, s.tag); err != nil {
		return s, err
	}
	s.selectionEpoch, err = r.engine.(NodeChainExecutionSelectionEpochEngine).SelectionEpochContext(ctx)
	if err != nil || s.selectionEpoch == 0 {
		return s, errors.Join(err, nodeChainExecutionError)
	}
	if err := r.current(ctx, s, true); err != nil {
		return s, err
	}
	entry := r.projection.policy.local.nodes[0]
	api, token := predecessorText(entry.profile, "router_api"), predecessorText(entry.profile, "api_token")
	current := func(call context.Context) error { return r.current(call, s, true) }
	s.proofIO, err = newNodeChainExecutionIO(proofs[0].Tag, api, token, r.engine.Dial, current)
	if err != nil {
		return s, err
	}
	s.controlIO, err = newNodeChainExecutionIO(proofs[0].Tag, api, token, r.engine.Dial, current)
	if err != nil {
		return s, err
	}
	context.AfterFunc(s.lifetime, func() { s.proofIO.cancel(); s.controlIO.cancel() })
	if s.execution == "server" {
		if err = s.acquire(ctx); err != nil {
			return s, err
		}
	}
	if err = s.proveComplete(ctx); err != nil {
		return s, err
	}
	return s, nil
}

// Run uses the original native owner's lifetime. Comparison keeps one
// approved target and the shared formula, closes every trial, then repeats
// both winner measurements. Server reacquisition always uses a fresh attempt.
func (r *NodeChainExecutionRuntime) Run(parent context.Context) (failure error) {
	if r == nil || parent == nil || r.projection.validateCapture() != nil {
		return nodeChainExecutionError
	}
	r.mu.Lock()
	if r.retired.Load() || !r.started.CompareAndSwap(false, true) {
		r.mu.Unlock()
		return nodeChainExecutionError
	}
	lifetime, cancel := context.WithCancel(parent)
	r.lifetime, r.cancel = lifetime, cancel
	r.runDone = make(chan struct{})
	done := r.runDone
	r.progress.Stage = "verifying"
	r.mu.Unlock()
	defer func() {
		if failure != nil {
			r.retire("Captured ordered execution did not complete proof")
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			_ = r.engine.RevokeApplicationContext(cleanup)
			r.mu.Lock()
			active := r.active
			r.mu.Unlock()
			if active != nil {
				failure = errors.Join(failure, active.Close(cleanup))
			}
		}
		close(done)
	}()
	ctx, finish := context.WithTimeout(lifetime, 2*time.Minute)
	identity, err := r.engine.ObserveChainContext(ctx)
	if err != nil || !r.identityMatches(identity) {
		finish()
		return errors.Join(err, nodeChainExecutionError)
	}
	if r.restore != nil && r.mtuResume == nil && (identity.EngineID == r.restore.identity.EngineID || identity.SessionID == r.restore.identity.SessionID) {
		finish()
		return nodeChainExecutionError
	}
	if r.mtuResume != nil {
		if err := r.validateMTUResumeContext(ctx, identity); err != nil {
			finish()
			return err
		}
	}
	if r.lastPlan != nil {
		if err := r.validateLastContext(ctx, identity); err != nil {
			finish()
			return err
		}
	}
	r.mu.Lock()
	r.identity = identity
	r.mu.Unlock()
	finish()
	if err := r.current(lifetime, nil, false); err != nil {
		return err
	}
	options := routechoice.Options{Targets: append([]string(nil), Targets...), StartupTimeout: 2 * time.Minute, ProbeTimeout: 2500 * time.Millisecond, CleanupTimeout: 10 * time.Second, Preferred: routechoice.Local, Notify: r.event}
	var result routechoice.Result
	var active routechoice.Session
	if r.projection.Execution() == "auto" && r.restore == nil && r.lastPlan == nil {
		result, active, err = routechoice.Compare(lifetime, []routechoice.Candidate{r.candidate("local"), r.candidate("server")}, nodeChainExecutionDriver{r}, options)
	} else {
		execution, target := r.projection.Execution(), Targets[0]
		if r.restore != nil {
			execution, target = r.restore.execution, r.restore.result.Target
		}
		if r.lastPlan != nil {
			execution, target = r.lastPlan.last.record.Execution, r.lastPlan.last.record.Target
		}
		candidate := r.candidate(execution)
		startup, stop := context.WithTimeout(lifetime, options.StartupTimeout)
		active, err = r.open(startup, candidate, target)
		stop()
		if err == nil {
			var measurement routechoice.Measurement
			measurement, err = r.measureSelected(lifetime, active, candidate, target)
			if err == nil {
				result = routechoice.Result{Target: target, Winner: &candidate, Final: &measurement}
				if r.restore != nil {
					result.Measurements = append([]routechoice.Measurement(nil), r.restore.result.Measurements...)
				}
			}
		}
	}
	if err != nil {
		return err
	}
	s, ok := active.(*nodeChainExecutionTrial)
	if !ok || s == nil || result.Winner == nil || result.Final == nil || !result.Final.Eligible {
		return routechoice.ErrNoWinner
	}
	activation, stop := context.WithTimeout(s.lifetime, 5*time.Second)
	defer stop()
	if err = s.Verify(activation); err != nil {
		return err
	}
	if err = r.current(activation, s, true); err != nil {
		return err
	}
	if err = r.engine.OpenApplicationContext(activation, identity, s.tag); err != nil {
		return err
	}
	open, err := r.engine.ApplicationOpenContext(activation)
	if err != nil || !open {
		return errors.Join(err, nodeChainExecutionError)
	}
	if err = r.current(activation, s, true); err != nil {
		return err
	}
	s.mu.Lock()
	checkedAt, prefixes := s.checkedAt, append([]NodeChainPrefixProgress(nil), s.prefixes...)
	s.mu.Unlock()
	r.mu.Lock()
	if r.retired.Load() || activation.Err() != nil || r.active != s {
		r.mu.Unlock()
		return nodeChainExecutionError
	}
	r.checkedAt = checkedAt
	r.progress = NodeChainExecutionProgress{NodeChainProgress: NodeChainProgress{Stage: "selected", Complete: true, Ready: true, Execution: s.execution, Prefixes: prefixes, DNSProven: true, PublicProven: true}, Comparison: cloneNodeChainExecutionResult(result)}
	r.watchDone = make(chan struct{})
	watch := r.watchDone
	r.mu.Unlock()
	go r.watch(s, lifetime, watch)
	return nil
}

func (r *NodeChainExecutionRuntime) measureSelected(ctx context.Context, s routechoice.Session, c routechoice.Candidate, target string) (routechoice.Measurement, error) {
	probe, stop := context.WithTimeout(ctx, 2500*time.Millisecond)
	err := s.Verify(probe)
	stop()
	if err != nil {
		return routechoice.Measurement{}, err
	}
	probe, stop = context.WithTimeout(ctx, 2500*time.Millisecond)
	last, err := s.ProbeLast(probe)
	stop()
	if err != nil {
		return routechoice.Measurement{}, err
	}
	probe, stop = context.WithTimeout(ctx, 2500*time.Millisecond)
	external, err := s.ProbeExternal(probe, target)
	stop()
	if err != nil {
		return routechoice.Measurement{}, err
	}
	return routechoice.Score(c, last, external)
}

func (r *NodeChainExecutionRuntime) event(event routechoice.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired.Load() {
		return
	}
	r.progress.Stage = event.Stage
	if event.Candidate.Valid() {
		r.progress.Execution = string(event.Candidate.Execution)
	}
}
func cloneNodeChainExecutionResult(result routechoice.Result) routechoice.Result {
	raw, _ := json.Marshal(result)
	var copied routechoice.Result
	_ = json.Unmarshal(raw, &copied)
	return copied
}
func (r *NodeChainExecutionRuntime) Progress() NodeChainExecutionProgress {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.progress
	result.Prefixes = append([]NodeChainPrefixProgress(nil), result.Prefixes...)
	result.Comparison = cloneNodeChainExecutionResult(result.Comparison)
	if r.retired.Load() || r.closed || r.checkedAt.IsZero() || time.Since(r.checkedAt) > r.proofLifetime() {
		result.Ready = false
	}
	return result
}
func (r *NodeChainExecutionRuntime) proofLifetime() time.Duration {
	return time.Duration(15+5*len(r.projection.policy.local.nodes)) * time.Second
}
func (r *NodeChainExecutionRuntime) retire(message string) {
	r.retired.Store(true)
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
	}
	r.progress.Ready = false
	r.progress.Complete = true
	if message != "" {
		r.progress.Stage = "failed"
		r.progress.Failure = message
	}
	r.mu.Unlock()
}

func (r *NodeChainExecutionRuntime) watch(s *nodeChainExecutionTrial, lifetime context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var failure error
	for failure == nil {
		select {
		case <-lifetime.Done():
			failure = lifetime.Err()
		case <-s.lifetime.Done():
			failure = s.lifetime.Err()
		case <-ticker.C:
			s.mu.Lock()
			expires := s.checkedAt.Add(r.proofLifetime())
			s.mu.Unlock()
			ctx, cancel := context.WithDeadline(lifetime, expires)
			failure = s.renewAndProve(ctx)
			cancel()
			if failure == nil {
				s.mu.Lock()
				at, prefixes := s.checkedAt, append([]NodeChainPrefixProgress(nil), s.prefixes...)
				s.mu.Unlock()
				r.mu.Lock()
				if !r.retired.Load() && r.active == s {
					r.checkedAt = at
					r.progress.Prefixes = prefixes
				}
				r.mu.Unlock()
			}
		}
	}
	r.retire("Captured ordered execution owner or proof expired")
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = r.engine.RevokeApplicationContext(cleanup)
	_ = s.Close(cleanup)
}

func (r *NodeChainExecutionRuntime) HealthyContext(ctx context.Context) (failure error) {
	if r == nil || ctx == nil {
		return nodeChainExecutionError
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	// An observation belongs only to its original live runtime. Once retired,
	// even its failure cleanup must not touch a same-Box resumed owner.
	if r.retired.Load() || r.closed {
		r.mu.Unlock()
		return nodeChainExecutionError
	}
	r.healthObservations++
	s, ready, at := r.active, r.progress.Ready, r.checkedAt
	r.mu.Unlock()
	defer func() {
		if failure != nil && ctx.Err() == nil {
			r.retire("Captured ordered execution observation failed")
			failure = errors.Join(failure, r.engine.RevokeApplicationContext(ctx))
		}
		// Include late failure cleanup in the join. Close cannot acknowledge
		// this runtime while any original native observation/revoke can return.
		r.mu.Lock()
		r.healthObservations--
		r.mu.Unlock()
	}()
	if !ready || s == nil || at.IsZero() || time.Since(at) > r.proofLifetime() {
		return nodeChainExecutionError
	}
	if err := r.current(ctx, s, true); err != nil {
		return err
	}
	open, err := r.engine.ApplicationOpenContext(ctx)
	if err != nil || !open {
		return errors.Join(err, nodeChainExecutionError)
	}
	return s.cachedReady(ctx)
}

// CloseContext cancels admission first, joins the original Run/watch handles,
// and retires the exact retained trial. Failure keeps every original handle
// for retry and never claims the host's native Box or TUN has been closed.
func (r *NodeChainExecutionRuntime) CloseContext(ctx context.Context) error {
	if r == nil || ctx == nil {
		return nodeChainExecutionError
	}
	r.mu.Lock()
	alreadyClosed := r.closed
	r.mu.Unlock()
	if alreadyClosed {
		return ctx.Err()
	}
	r.retire("")
	revokeErr := r.engine.RevokeApplicationContext(ctx)
	r.mu.Lock()
	run, watch := r.runDone, r.watchDone
	r.mu.Unlock()
	for _, done := range []chan struct{}{run, watch} {
		if done != nil {
			select {
			case <-done:
			case <-ctx.Done():
				return errors.Join(revokeErr, ctx.Err())
			}
		}
	}
	r.mu.Lock()
	s := r.active
	r.mu.Unlock()
	if s != nil {
		if err := s.Close(ctx); err != nil {
			return errors.Join(revokeErr, err)
		}
	}
	// A cancelled entered native callback may finish after the first revoke.
	// Its original caller is cancelled; verify the final joined barrier too.
	revokeErr = errors.Join(revokeErr, r.engine.RevokeApplicationContext(ctx))
	open, err := r.engine.ApplicationOpenContext(ctx)
	if revokeErr != nil || err != nil || open || ctx.Err() != nil {
		return errors.Join(revokeErr, err, ctx.Err(), nodeChainExecutionError)
	}
	r.mu.Lock()
	if r.healthObservations != 0 {
		r.mu.Unlock()
		return errors.New("original ordered health observation has not joined")
	}
	if r.readbackObservations != 0 {
		r.mu.Unlock()
		return errors.New("original ordered TUN observation has not joined")
	}
	if r.measurementHolds != 0 {
		r.mu.Unlock()
		return errors.New("original ordered measurement activity has not joined")
	}
	if r.lastCaptures != 0 {
		r.mu.Unlock()
		return errors.New("original ordered Last capture has not joined")
	}
	r.closed = true
	r.progress.Ready = false
	r.progress.Stage = "closed"
	r.mu.Unlock()
	return nil
}

func (s *nodeChainExecutionTrial) Identity() string {
	s.runtime.mu.Lock()
	identity := s.runtime.identity
	s.runtime.mu.Unlock()
	raw, _ := json.Marshal([]any{identity, s.execution, s.id})
	return externalDigest(raw)
}
func (s *nodeChainExecutionTrial) IdentityContext(ctx context.Context) (string, error) {
	if err := s.runtime.current(ctx, s, true); err != nil {
		return "", err
	}
	return s.Identity(), nil
}
func (s *nodeChainExecutionTrial) cachedReady(ctx context.Context) error {
	s.mu.Lock()
	closed, at, attempt := s.closed, s.checkedAt, s.attempt
	s.mu.Unlock()
	if closed || at.IsZero() || time.Since(at) > s.runtime.proofLifetime() || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	if s.execution == "server" && (attempt == nil || !attempt.fresh()) {
		return nodeChainExecutionError
	}
	return nil
}
func (s *nodeChainExecutionTrial) Verify(ctx context.Context) error {
	if err := s.runtime.current(ctx, s, true); err != nil {
		return err
	}
	if err := s.cachedReady(ctx); err != nil {
		return err
	}
	if s.execution == "server" {
		if err := s.status(ctx, true); err != nil {
			return err
		}
	}
	return s.runtime.current(ctx, s, true)
}

func (s *nodeChainExecutionTrial) Close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return nodeChainExecutionError
	}
	s.cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closeGate:
	}
	defer func() { s.closeGate <- struct{}{} }()
	s.mu.Lock()
	closed, attempt := s.closed, s.attempt
	s.mu.Unlock()
	if closed {
		return ctx.Err()
	}
	s.runtime.mu.Lock()
	sameOwner := s.runtime.active == s
	s.runtime.mu.Unlock()
	if !sameOwner {
		return nodeChainExecutionError
	}
	revokeErr := s.runtime.engine.RevokeApplicationContext(ctx)
	// The tombstone is sent before waiting on a potentially late original PUT.
	// Even its positive reply cannot waive either local original I/O join.
	var stopErr error
	if attempt != nil {
		stopErr = attempt.stopOriginal(ctx)
	}
	var proofErr, controlErr error
	if s.proofIO != nil {
		proofErr = s.proofIO.close(ctx)
	}
	if s.controlIO != nil {
		controlErr = s.controlIO.close(ctx)
	}
	var renewErr error
	if attempt != nil {
		renewErr = attempt.joinRenew(ctx)
	}
	if err := errors.Join(revokeErr, stopErr, proofErr, controlErr, renewErr, ctx.Err()); err != nil {
		return err
	}
	if attempt != nil {
		attempt.discardStopped()
	}
	s.mu.Lock()
	s.closed = true
	s.checkedAt = time.Time{}
	s.mu.Unlock()
	s.runtime.mu.Lock()
	if s.runtime.active == s {
		s.runtime.active = nil
	}
	s.runtime.mu.Unlock()
	return nil
}

// Restore retains the already-proved execution choice and original target.
// It requires positive original cleanup and a fresh native owner; Run repeats
// that choice's proofs/probes but never runs comparison/ranking again.
type NodeChainExecutionRestoreCapture struct {
	owner      *NodeChainExecutionRuntime
	projection *NodeChainExecutionProjection
	identity   NodeChainIdentity
	execution  string
	result     routechoice.Result
}

func (r *NodeChainExecutionRuntime) CaptureRestoreContext(ctx context.Context) (NodeChainExecutionRestoreCapture, error) {
	if err := r.HealthyContext(ctx); err != nil {
		return NodeChainExecutionRestoreCapture{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired.Load() || !r.progress.Ready || r.progress.Comparison.Winner == nil || ctx.Err() != nil {
		return NodeChainExecutionRestoreCapture{}, nodeChainExecutionError
	}
	return NodeChainExecutionRestoreCapture{r, r.projection, r.identity, r.progress.Execution, cloneNodeChainExecutionResult(r.progress.Comparison)}, nil
}
func NewNodeChainExecutionRestoreRuntime(capture NodeChainExecutionRestoreCapture, engine NodeChainExecutionEngine) (*NodeChainExecutionRuntime, error) {
	if capture.owner == nil || capture.projection.validateCapture() != nil || capture.result.Winner == nil || string(capture.result.Winner.Execution) != capture.execution || !nodeChainExecutionTarget(capture.result.Target) {
		return nil, nodeChainExecutionError
	}
	capture.owner.mu.Lock()
	closed := capture.owner.closed && capture.owner.active == nil && capture.owner.identity == capture.identity && capture.owner.projection == capture.projection
	capture.owner.mu.Unlock()
	if !closed {
		return nil, errors.New("original ordered execution cleanup is not joined")
	}
	runtime, err := NewNodeChainExecutionRuntime(capture.projection, engine)
	if err != nil {
		return nil, err
	}
	capture.result = cloneNodeChainExecutionResult(capture.result)
	runtime.restore = &capture
	return runtime, nil
}

// Source returns private restore handoff only after original runtime and remote
// cleanup joined. The platform must also join its original native Box/TUN
// before constructing the replacement preparation owner.
func (c NodeChainExecutionRestoreCapture) Source() (string, error) {
	if c.owner == nil || c.projection.validateCapture() != nil {
		return "", nodeChainExecutionError
	}
	c.owner.mu.Lock()
	closed := c.owner.closed && c.owner.active == nil && c.owner.identity == c.identity && c.owner.projection == c.projection
	c.owner.mu.Unlock()
	if !closed {
		return "", nodeChainExecutionError
	}
	return c.projection.Source(), nil
}
