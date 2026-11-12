package mobilemultihop

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"router-vpn/internal/routechoice"
)

// Native admission must prove its retained manager transaction, exact old
// reader retirement and actual replacement readback. A binding grants no
// caller-created reader, requested MTU, effective MTU or replacement engine.
type NodeChainExecutionMTUResumeEngine interface {
	AdmitExecutionMTUResumeContext(context.Context, NodeChainExecutionMTUResumeBinding) error
}

// A value copy retains the same private owner and nonce. It is process-owned
// authority, not a serialized restore receipt. Failed pause/close retries keep
// this exact value until every original proof, remote and measurement joins.
type NodeChainExecutionMTUResumeBinding struct {
	state *nodeChainExecutionMTUResumeState
}

type nodeChainExecutionMTUResumeState struct {
	owner          *NodeChainExecutionRuntime
	projection     *NodeChainExecutionProjection
	engine         NodeChainExecutionEngine
	identity       NodeChainIdentity
	nonce          string
	execution      string
	selectedTag    string
	selectionEpoch uint64
	tunTag         string
	result         routechoice.Result
	mu             sync.Mutex
	admitting      bool
	resume         *NodeChainExecutionRuntime
}

func (b NodeChainExecutionMTUResumeBinding) Identity() NodeChainIdentity {
	if b.state == nil {
		return NodeChainIdentity{}
	}
	return b.state.identity
}

// Identity strings are observations, not native pointer authority. A resume
// adapter must also own the exact engine retained by the original runtime.
func (b NodeChainExecutionMTUResumeBinding) OwnsEngine(engine NodeChainExecutionEngine) bool {
	if b.state == nil || engine == nil {
		return false
	}
	value := reflect.ValueOf(engine)
	return value.Kind() == reflect.Pointer && !value.IsNil() && b.state.engine == engine
}
func (b NodeChainExecutionMTUResumeBinding) Nonce() string {
	if b.state == nil {
		return ""
	}
	return b.state.nonce
}
func (b NodeChainExecutionMTUResumeBinding) SelectedTag() string {
	if b.state == nil {
		return ""
	}
	return b.state.selectedTag
}
func (b NodeChainExecutionMTUResumeBinding) SelectionEpoch() uint64 {
	if b.state == nil {
		return 0
	}
	return b.state.selectionEpoch
}
func (b NodeChainExecutionMTUResumeBinding) TUNTag() string {
	if b.state == nil {
		return ""
	}
	return b.state.tunTag
}
func (b NodeChainExecutionMTUResumeBinding) MTUPlan() (NodeChainMTUPlan, error) {
	if b.state == nil || !proofID.MatchString(b.state.nonce) {
		return NodeChainMTUPlan{}, nodeChainExecutionError
	}
	bound, err := b.state.projection.MTUPlan()
	if err != nil || bound.TUNTag != b.state.tunTag {
		return NodeChainMTUPlan{}, errors.Join(err, nodeChainExecutionError)
	}
	return bound, nil
}

func (b NodeChainExecutionMTUResumeBinding) ValidateClosedContext(ctx context.Context) error {
	if ctx == nil {
		return nodeChainExecutionError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s := b.state
	if s == nil || s.owner == nil || s.engine == nil || !proofID.MatchString(s.nonce) || s.selectionEpoch == 0 ||
		s.projection.validateCapture() != nil || s.result.Winner == nil || string(s.result.Winner.Execution) != s.execution ||
		!nodeChainExecutionTarget(s.result.Target) || !s.owner.identityMatches(s.identity) {
		return nodeChainExecutionError
	}
	proofs, err := s.projection.ProofInventory(s.execution)
	if err != nil || len(proofs) < 2 || proofs[len(proofs)-1].Tag != s.selectedTag || s.tunTag != s.projection.transition.TUNTag {
		return errors.Join(err, nodeChainExecutionError)
	}
	if err := externalObservationLock(ctx, &s.owner.mu); err != nil {
		return err
	}
	closed := s.owner.mtuPause == s && s.owner.closed && s.owner.active == nil && s.owner.measurementHolds == 0 &&
		s.owner.identity == s.identity && s.owner.projection == s.projection
	s.owner.mu.Unlock()
	if !closed {
		return errors.New("original ordered MTU pause cleanup has not joined")
	}
	return ctx.Err()
}

// Native Change uses this stronger check before a new mutation or rollback.
// It cannot replace the reader while an earlier resumed attempt or activity
// still owns the same Box, even when the initial pause is already closed.
func (b NodeChainExecutionMTUResumeBinding) ValidateTransitionContext(ctx context.Context) error {
	if err := b.ValidateClosedContext(ctx); err != nil {
		return err
	}
	s := b.state
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return err
	}
	resume, admitting := s.resume, s.admitting
	s.mu.Unlock()
	if admitting {
		return errors.New("ordered MTU resume admission remains owned")
	}
	return s.resumeClosed(ctx, resume)
}

func (s *nodeChainExecutionMTUResumeState) resumeClosed(ctx context.Context, resume *NodeChainExecutionRuntime) error {
	if resume == nil {
		return ctx.Err()
	}
	if err := externalObservationLock(ctx, &resume.mu); err != nil {
		return err
	}
	closed := resume.closed && resume.active == nil && resume.measurementHolds == 0 &&
		resume.identity == s.identity && resume.projection == s.projection && resume.mtuResume == s
	resume.mu.Unlock()
	if !closed {
		return errors.New("previous ordered MTU resume cleanup has not joined")
	}
	return ctx.Err()
}

func (r *NodeChainExecutionRuntime) PauseMTUContext(ctx context.Context) (NodeChainExecutionMTUResumeBinding, error) {
	if r == nil || ctx == nil {
		return NodeChainExecutionMTUResumeBinding{}, nodeChainExecutionError
	}
	if err := ctx.Err(); err != nil {
		return NodeChainExecutionMTUResumeBinding{}, err
	}
	if _, ok := r.engine.(NodeChainExecutionMTUResumeEngine); !ok {
		return NodeChainExecutionMTUResumeBinding{}, nodeChainExecutionError
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return NodeChainExecutionMTUResumeBinding{}, err
	}
	s := r.mtuPause
	r.mu.Unlock()
	if s != nil {
		return NodeChainExecutionMTUResumeBinding{s}, r.CloseContext(ctx)
	}
	capture, err := r.CaptureRestoreContext(ctx)
	if err != nil {
		// Another pause may have retained the one original capsule while its
		// close invalidated this concurrent health observation.
		if lockErr := externalObservationLock(ctx, &r.mu); lockErr != nil {
			return NodeChainExecutionMTUResumeBinding{}, errors.Join(err, lockErr)
		}
		s = r.mtuPause
		r.mu.Unlock()
		if s != nil {
			return NodeChainExecutionMTUResumeBinding{s}, r.CloseContext(ctx)
		}
		return NodeChainExecutionMTUResumeBinding{}, err
	}
	bound, err := r.projection.MTUPlan()
	if err != nil {
		return NodeChainExecutionMTUResumeBinding{}, err
	}
	nonce, err := randomHex(32)
	if err != nil {
		return NodeChainExecutionMTUResumeBinding{}, err
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return NodeChainExecutionMTUResumeBinding{}, err
	}
	s = r.mtuPause
	if s == nil {
		if r.retired.Load() || r.closed || !r.progress.Ready || r.active == nil || r.identity != capture.identity || r.active.selectionEpoch == 0 || ctx.Err() != nil {
			r.mu.Unlock()
			return NodeChainExecutionMTUResumeBinding{}, nodeChainExecutionError
		}
		s = &nodeChainExecutionMTUResumeState{owner: r, projection: r.projection, engine: r.engine, identity: r.identity,
			nonce: nonce, execution: capture.execution, selectedTag: r.active.tag, selectionEpoch: r.active.selectionEpoch,
			tunTag: bound.TUNTag, result: cloneNodeChainExecutionResult(capture.result)}
		r.mtuPause = s
	}
	r.mu.Unlock()
	return NodeChainExecutionMTUResumeBinding{s}, r.CloseContext(ctx)
}

// NewNodeChainExecutionMTUResumeRuntime keeps the same original Box and already
// proved execution choice. A fresh Server request is acquired only by Run,
// after original cleanup and actual native reader succession were admitted.
func NewNodeChainExecutionMTUResumeRuntime(ctx context.Context, binding NodeChainExecutionMTUResumeBinding) (*NodeChainExecutionRuntime, error) {
	if err := binding.ValidateClosedContext(ctx); err != nil {
		return nil, err
	}
	s := binding.state
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return nil, err
	}
	if s.admitting {
		s.mu.Unlock()
		return nil, nodeChainExecutionError
	}
	previous := s.resume
	s.admitting = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.admitting = false; s.mu.Unlock() }()
	if err := s.resumeClosed(ctx, previous); err != nil {
		return nil, err
	}
	engine, ok := s.engine.(NodeChainExecutionMTUResumeEngine)
	if !ok {
		return nil, nodeChainExecutionError
	}
	if err := engine.AdmitExecutionMTUResumeContext(ctx, binding); err != nil {
		return nil, err
	}
	if err := binding.ValidateClosedContext(ctx); err != nil {
		return nil, err
	}
	runtime, err := NewNodeChainExecutionRuntime(s.projection, s.engine)
	if err != nil {
		return nil, err
	}
	runtime.restore = &NodeChainExecutionRestoreCapture{s.owner, s.projection, s.identity, s.execution, cloneNodeChainExecutionResult(s.result)}
	runtime.identity, runtime.mtuResume = s.identity, s
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return nil, err
	}
	if s.resume != previous || ctx.Err() != nil {
		s.mu.Unlock()
		return nil, nodeChainExecutionError
	}
	s.resume = runtime
	s.mu.Unlock()
	return runtime, nil
}

func (r *NodeChainExecutionRuntime) validateMTUResumeContext(ctx context.Context, identity NodeChainIdentity) error {
	s := r.mtuResume
	if s == nil || identity != s.identity || r.projection != s.projection || r.restore == nil || r.restore.owner != s.owner {
		return nodeChainExecutionError
	}
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return err
	}
	claimed := s.resume == r && !s.admitting
	s.mu.Unlock()
	if !claimed {
		return nodeChainExecutionError
	}
	binding := NodeChainExecutionMTUResumeBinding{s}
	if err := binding.ValidateClosedContext(ctx); err != nil {
		return err
	}
	engine, ok := s.engine.(NodeChainExecutionMTUResumeEngine)
	if !ok {
		return nodeChainExecutionError
	}
	return engine.AdmitExecutionMTUResumeContext(ctx, binding)
}
