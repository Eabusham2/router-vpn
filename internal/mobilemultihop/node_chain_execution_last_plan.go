package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"
)

// A LastPlan can only be produced by fresh discovery on one retained entry.
// It owns no native Box, but binds the exact original discovery close and new
// frontend credentials to the one projected graph the host may adopt.
type NodeChainExecutionLastPlan struct {
	state *nodeChainExecutionLastPlanState
}

type nodeChainExecutionLastPlanState struct {
	owner        *NodeChainExecutionDiscoveryOwner
	last         NodeChainExecutionLast
	projection   *NodeChainExecutionProjection
	identity     NodeChainIdentity
	discoverySHA string
	seal         string
	mu           sync.Mutex
	runtime      *NodeChainExecutionRuntime
}

func (s *nodeChainExecutionLastPlanState) captureSeal() string {
	if s == nil || s.projection == nil {
		return ""
	}
	raw, err := json.Marshal([]any{"routervpn-node-chain-execution-last-plan-v1", s.last.raw, s.identity, s.discoverySHA,
		s.projection.SourceSHA256(), s.projection.ConfigSHA256()})
	if err != nil {
		return ""
	}
	return externalDigest(raw)
}

func (p NodeChainExecutionLastPlan) validate() error {
	s := p.state
	if s == nil || s.owner == nil || s.seal == "" || s.captureSeal() != s.seal || s.last.validateProjection(s.projection) != nil ||
		s.owner.prep != s.projection.preparation {
		return nodeChainExecutionError
	}
	s.owner.mu.Lock()
	valid := s.owner.planned && s.owner.identity == s.identity && externalDigest([]byte(s.owner.raw)) == s.discoverySHA
	s.owner.mu.Unlock()
	if !valid {
		return nodeChainExecutionError
	}
	return nil
}

func (p NodeChainExecutionLastPlan) Projection() (*NodeChainExecutionProjection, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p.state.projection, nil
}

func (p NodeChainExecutionLastPlan) RequireJoinedContext(ctx context.Context) error {
	if ctx == nil {
		return nodeChainExecutionError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	io := p.state.owner.io
	if !io.closed.Load() {
		return errors.New("original Last discovery has not closed")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-io.gate:
	}
	defer func() { io.gate <- struct{}{} }()
	io.mu.Lock()
	joined := io.pending == nil
	io.mu.Unlock()
	if !joined {
		return errors.New("original Last discovery I/O has not joined")
	}
	return ctx.Err()
}

func (o *NodeChainExecutionDiscoveryOwner) PlanLastContext(ctx context.Context, last NodeChainExecutionLast) (NodeChainExecutionLastPlan, error) {
	if o == nil || ctx == nil || last.ValidatePreparation(o.prep) != nil {
		return NodeChainExecutionLastPlan{}, nodeChainExecutionError
	}
	if err := o.io.observe(ctx); err != nil {
		return NodeChainExecutionLastPlan{}, err
	}
	o.mu.Lock()
	raw, planned, identity := o.raw, o.planned, o.identity
	o.mu.Unlock()
	if raw == "" || planned {
		return NodeChainExecutionLastPlan{}, nodeChainExecutionError
	}
	discovery, err := parseNodeChainExecutionDiscovery(raw, o.prep.local.proofs[0].NodeID, time.Now())
	if err != nil || discovery.Challenge.Peer != last.record.Peer || discovery.FirstPort != last.record.FirstPort || discovery.LastPort != last.record.LastPort {
		return NodeChainExecutionLastPlan{}, nodeChainExecutionError
	}
	matched := false
	for _, descriptor := range discovery.Sources {
		if reflect.DeepEqual(descriptor, last.record.Descriptor) {
			matched = true
		}
	}
	if !matched {
		return NodeChainExecutionLastPlan{}, nodeChainExecutionError
	}
	policy, err := o.prep.policyForDiscovery(last.record.Descriptor, discovery, last.record.Port)
	if err != nil {
		return NodeChainExecutionLastPlan{}, err
	}
	projection, err := o.prep.BindExecution(policy)
	if err != nil || last.validateProjection(projection) != nil {
		return NodeChainExecutionLastPlan{}, nodeChainExecutionError
	}
	if err := o.io.observe(ctx); err != nil {
		return NodeChainExecutionLastPlan{}, err
	}
	s := &nodeChainExecutionLastPlanState{owner: o, last: last, projection: projection, identity: identity, discoverySHA: externalDigest([]byte(raw))}
	s.seal = s.captureSeal()
	o.mu.Lock()
	if o.io.closed.Load() || ctx.Err() != nil || o.raw != raw || o.planned || o.identity != identity {
		o.mu.Unlock()
		return NodeChainExecutionLastPlan{}, nodeChainExecutionError
	}
	o.planned = true
	o.mu.Unlock()
	plan := NodeChainExecutionLastPlan{s}
	return plan, plan.validate()
}

// No prior process or live cleanup handle is reconstructed from a saved Last
// record. The exact fresh plan must first join discovery; Run then proves its
// adopted original preparation Box and repeats the saved choice's live probes.
func NewNodeChainExecutionLastRuntime(ctx context.Context, plan NodeChainExecutionLastPlan, engine NodeChainExecutionEngine) (*NodeChainExecutionRuntime, error) {
	if err := plan.RequireJoinedContext(ctx); err != nil {
		return nil, err
	}
	runtime, err := NewNodeChainExecutionRuntime(plan.state.projection, engine)
	if err != nil {
		return nil, err
	}
	s := plan.state
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.runtime != nil || ctx.Err() != nil {
		return nil, errors.New("Last plan already belongs to its original runtime")
	}
	runtime.lastPlan = s
	s.runtime = runtime
	return runtime, nil
}

func (r *NodeChainExecutionRuntime) validateLastContext(ctx context.Context, identity NodeChainIdentity) error {
	s := r.lastPlan
	if s == nil || r.projection != s.projection {
		return nodeChainExecutionError
	}
	plan := NodeChainExecutionLastPlan{s}
	if err := plan.RequireJoinedContext(ctx); err != nil {
		return err
	}
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return err
	}
	owned := s.runtime == r
	s.mu.Unlock()
	expected := s.identity
	expected.SourceSHA256, expected.ConfigSHA256 = s.projection.SourceSHA256(), s.projection.ConfigSHA256()
	if !owned || identity != expected {
		return nodeChainExecutionError
	}
	return ctx.Err()
}
