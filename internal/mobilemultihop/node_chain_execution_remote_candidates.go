package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/hopmeasure"
)

// This owner observes the already-selected complete execution and the original
// catalog. It cannot rerun Compare or substitute an ordinary Local owner.
type NodeChainExecutionRemoteCandidateOwner interface {
	NodeChainExecutionMeasurementOwner
	CandidateInventoryCurrentContext(context.Context, string) error
}

type NodeChainExecutionRemoteCandidatePlan struct {
	self          *NodeChainExecutionRemoteCandidatePlan
	runtime       *NodeChainExecutionRuntime
	projection    *NodeChainExecutionProjection
	trial         *nodeChainExecutionTrial
	identity      NodeChainIdentity
	engine        NodeChainExecutionEngine
	packet        *NodeChainCandidatePlan
	capture, seal string
}

func (r *NodeChainExecutionRuntime) NewRemoteCandidatePlanContext(ctx context.Context, position int, inventory string) (*NodeChainExecutionRemoteCandidatePlan, error) {
	if ctx == nil || r == nil || position < 1 || r.engine == nil || !reflect.TypeOf(r.engine).Comparable() {
		return nil, nodeChainExecutionError
	}
	if err := r.HealthyContext(ctx); err != nil {
		return nil, err
	}
	r.mu.Lock()
	trial, identity := r.active, r.identity
	r.mu.Unlock()
	if trial == nil || trial.execution != "server" {
		return nil, nodeChainExecutionError
	}
	if _, ok := r.engine.(NodeChainExecutionCandidateStopEngine); !ok {
		return nil, nodeChainExecutionError
	}
	// The original family compiler retains every source member and private
	// identity. Only an actual paired WG/AWG prefix can acquire TCP timing.
	packet, err := r.projection.newPacketCandidatePlan(position, inventory)
	if err != nil {
		return nil, err
	}
	descriptor := r.projection.policy.Descriptor()
	if position >= len(descriptor.Members) || descriptor.Members[position-1].NodeKind != "" || !NodeChainPrefixMode(descriptor.Members[position-1].Mode) {
		return nil, nodeChainExecutionError
	}
	p := &NodeChainExecutionRemoteCandidatePlan{runtime: r, projection: r.projection, trial: trial, identity: identity, engine: r.engine, packet: packet}
	p.self = p
	raw, _ := json.Marshal([]any{"routervpn-node-chain-remote-candidate-v1", identity, trial.id, trial.execution, trial.tag, trial.selectionEpoch, packet.capture})
	p.capture = externalDigest(raw)
	clear(raw)
	p.seal = p.digest()
	return p, p.current(ctx)
}
func (p *NodeChainExecutionRemoteCandidatePlan) digest() string {
	if p == nil || p.packet == nil || p.projection == nil {
		return ""
	}
	raw, _ := json.Marshal([]any{p.projection.SourceSHA256(), p.projection.ConfigSHA256(), p.identity, p.trial.id, p.trial.execution, p.trial.tag, p.trial.selectionEpoch, p.packet.capture, p.packet.digest(), p.capture})
	defer clear(raw)
	return externalDigest(raw)
}
func (p *NodeChainExecutionRemoteCandidatePlan) current(ctx context.Context) error {
	if p == nil || p.self != p || ctx == nil || p.runtime == nil || p.projection == nil || p.projection.policy == nil || p.trial == nil || p.packet == nil || p.packet.chain != p.projection.policy.local || p.packet.validate() != nil || p.seal == "" || p.seal != p.digest() || p.runtime.projection != p.projection || p.engine == nil || p.runtime.engine == nil || !reflect.TypeOf(p.engine).Comparable() || !reflect.TypeOf(p.runtime.engine).Comparable() || p.runtime.engine != p.engine || p.trial.execution != "server" {
		return nodeChainExecutionError
	}
	p.runtime.mu.Lock()
	same := p.runtime.active == p.trial && p.runtime.identity == p.identity
	p.runtime.mu.Unlock()
	if !same {
		return nodeChainExecutionError
	}
	return p.runtime.current(ctx, p.trial, true)
}
func (p *NodeChainExecutionRemoteCandidatePlan) CaptureSHA256() string {
	if p == nil || p.self != p || p.seal != p.digest() {
		return ""
	}
	return p.capture
}
func (p *NodeChainExecutionRemoteCandidatePlan) Metadata() string {
	if p.CaptureSHA256() == "" {
		return ""
	}
	var meta map[string]any
	if json.Unmarshal([]byte(p.packet.Metadata()), &meta) != nil {
		return ""
	}
	meta["capture_sha256"] = p.capture
	meta["source_sha256"] = p.projection.SourceSHA256()
	meta["config_sha256"] = p.projection.ConfigSHA256()
	meta["preparation_source_sha256"] = p.projection.preparation.SourceSHA256()
	meta["preparation_config_sha256"] = p.projection.preparation.ConfigSHA256()
	meta["requested_execution"] = p.projection.policy.source.Execution
	meta["execution"] = p.trial.execution
	meta["selection_epoch"] = p.trial.selectionEpoch
	raw, _ := json.Marshal(meta)
	return string(raw)
}
func (p *NodeChainExecutionRemoteCandidatePlan) NewMeasurementContext(ctx context.Context, owner NodeChainExecutionRemoteCandidateOwner) (*NodeChainExecutionRemoteCandidateMeasurement, error) {
	if owner == nil || p.current(ctx) != nil {
		return nil, nodeChainExecutionError
	}
	base := &nodeChainExecutionMeasurementEngine{runtime: p.runtime, projection: p.projection, owner: owner, identity: p.identity, trial: p.trial}
	e := &nodeChainExecutionRemoteCandidateEngine{plan: p, owner: owner, base: base}
	service, err := hopmeasure.NewCapturedPrefixCandidatesContext(ctx, e, hopmeasure.CandidatePrefix{Position: p.packet.prefix.Position, ID: p.packet.prefix.ProfileID, Tag: p.packet.prefix.Tag, CaptureSHA256: p.capture}, p.packet.targets, NodeChainInputLimit)
	if err != nil {
		return nil, err
	}
	result := &NodeChainExecutionRemoteCandidateMeasurement{service: service, engine: e}
	result.self = result
	return result, nil
}

type nodeChainExecutionRemoteCandidateEngine struct {
	plan      *NodeChainExecutionRemoteCandidatePlan
	owner     NodeChainExecutionRemoteCandidateOwner
	base      *nodeChainExecutionMeasurementEngine
	mu        sync.Mutex
	target    hopmeasure.CandidateTarget
	operation *nodeChainExecutionRemoteOperation
	invalid   atomic.Bool
}

func (e *nodeChainExecutionRemoteCandidateEngine) current(ctx context.Context) error {
	if e == nil || ctx == nil || e.invalid.Load() {
		return hopmeasure.ErrStale
	}
	err := e.plan.current(ctx)
	if err == nil {
		err = e.owner.CandidateInventoryCurrentContext(ctx, e.plan.capture)
	}
	if err == nil {
		err = e.base.current(ctx)
	}
	if err != nil && ctx.Err() == nil {
		e.invalid.Store(true)
	}
	return err
}
func (e *nodeChainExecutionRemoteCandidateEngine) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	value, _ := e.IdentityContext(ctx)
	return value
}
func (e *nodeChainExecutionRemoteCandidateEngine) IdentityContext(ctx context.Context) (string, error) {
	if err := e.current(ctx); err != nil {
		return "", err
	}
	return e.plan.capture, nil
}
func (e *nodeChainExecutionRemoteCandidateEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if err := e.current(ctx); err != nil {
		return nil, err
	}
	e.mu.Lock()
	target := e.target
	e.mu.Unlock()
	if target.ID == "" {
		return nil, nodeChainExecutionError
	}
	op := newNodeChainExecutionRemoteOperation(ctx, e, target)
	release, err := e.base.beginMeasurementContext(ctx, op.close)
	if err != nil {
		op.cancel()
		close(op.ready)
		return release, err
	}
	e.mu.Lock()
	e.operation = op
	e.mu.Unlock()
	err = op.initialize(ctx)
	return release, err
}
func (e *nodeChainExecutionRemoteCandidateEngine) VerifyMeasurement(ctx context.Context) error {
	if err := e.current(ctx); err != nil {
		return err
	}
	e.mu.Lock()
	op := e.operation
	e.mu.Unlock()
	// Constructor verification precedes any active request. Start installs its
	// exact operation before the fifty-sample service performs the first check.
	if op == nil {
		return nil
	}
	return op.verify(ctx)
}
func (e *nodeChainExecutionRemoteCandidateEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	e.mu.Lock()
	op := e.operation
	e.mu.Unlock()
	if op == nil || tag != e.plan.packet.prefix.Tag || address != op.target.Address {
		return nil, nodeChainExecutionError
	}
	return op.dial(ctx, address)
}

type NodeChainExecutionRemoteCandidateMeasurement struct {
	self    *NodeChainExecutionRemoteCandidateMeasurement
	service *hopmeasure.CandidateService
	engine  *nodeChainExecutionRemoteCandidateEngine
}

func (m *NodeChainExecutionRemoteCandidateMeasurement) Start(request, candidate string) error {
	return m.StartContext(context.Background(), request, candidate)
}
func (m *NodeChainExecutionRemoteCandidateMeasurement) StartContext(ctx context.Context, request, candidate string) error {
	if m == nil || m.self != m || ctx == nil {
		return nodeChainExecutionError
	}
	e := m.engine
	e.base.mu.Lock()
	if e.base.starting || e.base.scope != nil || e.base.closed.Load() {
		e.base.mu.Unlock()
		return errors.New("original remote candidate cleanup remains owned")
	}
	var target hopmeasure.CandidateTarget
	for _, row := range e.plan.packet.targets {
		if row.ID == candidate {
			target = row
			break
		}
	}
	if target.ID == "" {
		e.base.mu.Unlock()
		return nodeChainExecutionError
	}
	e.base.starting = true
	e.base.nextID = request
	e.base.mu.Unlock()
	defer func() { e.base.mu.Lock(); e.base.starting = false; e.base.nextID = ""; e.base.mu.Unlock() }()
	e.mu.Lock()
	e.target = target
	e.operation = nil
	e.mu.Unlock()
	return m.service.StartContext(ctx, request, candidate)
}
func (m *NodeChainExecutionRemoteCandidateMeasurement) Cancel(id string) {
	if m != nil && m.self == m {
		m.service.Cancel(id)
	}
}
func (m *NodeChainExecutionRemoteCandidateMeasurement) Drain(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.DrainTimeout)
	defer cancel()
	return m.DrainContext(ctx, id)
}
func (m *NodeChainExecutionRemoteCandidateMeasurement) DrainContext(ctx context.Context, id string) error {
	if m == nil || m.self != m || ctx == nil {
		return nodeChainExecutionError
	}
	if err := m.service.Drain(id); err != nil {
		return err
	}
	return m.engine.base.drainScope(ctx, id)
}
func (m *NodeChainExecutionRemoteCandidateMeasurement) Invalidate() {
	if m != nil && m.self == m {
		m.engine.invalid.Store(true)
		m.engine.base.closed.Store(true)
		m.service.Invalidate()
		m.engine.base.retireScope()
	}
}
func (m *NodeChainExecutionRemoteCandidateMeasurement) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.DrainTimeout)
	defer cancel()
	return m.CloseContext(ctx)
}
func (m *NodeChainExecutionRemoteCandidateMeasurement) CloseContext(ctx context.Context) error {
	if m == nil || m.self != m || ctx == nil {
		return nodeChainExecutionError
	}
	m.Invalidate()
	return errors.Join(m.service.CloseContext(ctx), m.engine.base.drainScope(ctx, ""))
}
func (m *NodeChainExecutionRemoteCandidateMeasurement) StatusJSON() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	return m.StatusContextJSON(ctx)
}
func (m *NodeChainExecutionRemoteCandidateMeasurement) StatusContextJSON(ctx context.Context) string {
	if m == nil || m.self != m {
		return "{}"
	}
	var state hopmeasure.CandidateStatus
	if json.Unmarshal([]byte(m.service.StatusContextJSON(ctx)), &state) != nil {
		return "{}"
	}
	m.engine.base.mu.Lock()
	pending := m.engine.base.scope != nil || m.engine.base.starting
	m.engine.base.mu.Unlock()
	if pending {
		state.Drained = false
		if state.Complete && state.Failure == "" {
			state.Complete = false
			state.Stage = "draining"
		}
		if state.Complete || state.Stage == "draining" {
			state.Results = []hopmeasure.Result{}
		}
	}
	raw, _ := json.Marshal(state)
	return string(raw)
}

// Keep the original service request deadline; neither a new status call nor a
// new sample is allowed to extend the server's ninety-second authority.
func remoteCandidateDeadline(ctx context.Context, lease time.Time) time.Time {
	deadline := time.Now().Add(hopmeasure.RequestTimeout)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if lease.Before(deadline) {
		deadline = lease
	}
	return deadline
}
