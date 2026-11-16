package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"

	"router-vpn/internal/hopmeasure"
)

// Entry candidates borrow the already selected execution. They cannot open a
// Local path, rerun Compare, or obtain the private generic chain's authority.
type NodeChainExecutionCandidateOwner interface {
	NodeChainExecutionMeasurementOwner
	CandidateInventoryCurrentContext(context.Context, string) error
}

type NodeChainExecutionCandidatePlan struct {
	self          *NodeChainExecutionCandidatePlan
	runtime       *NodeChainExecutionRuntime
	native        NodeChainExecutionEngine
	projection    *NodeChainExecutionProjection
	preparation   *NodeChainExecutionPreparation
	trial         *nodeChainExecutionTrial
	identity      NodeChainIdentity
	plan          *NodeChainCandidatePlan
	capture, seal string
}

func (r *NodeChainExecutionRuntime) NewEntryCandidatePlanContext(ctx context.Context, position int, inventory string) (*NodeChainExecutionCandidatePlan, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || position != 0 || r.projection == nil || r.projection.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	r.mu.Lock()
	trial, identity := r.active, r.identity
	r.mu.Unlock()
	if trial == nil || trial.runtime != r || r.engine == nil || !reflect.TypeOf(r.engine).Comparable() {
		return nil, hopmeasure.ErrStale
	}
	if err := r.HealthyContext(ctx); err != nil {
		return nil, err
	}
	plan, err := r.projection.policy.local.newPacketCandidatePlan(position, inventory)
	if err != nil {
		return nil, err
	}
	p := &NodeChainExecutionCandidatePlan{runtime: r, native: r.engine, projection: r.projection,
		preparation: r.projection.preparation, trial: trial, identity: identity, plan: plan}
	p.self = p
	p.capture = p.digest()
	p.seal = p.capture
	if err := p.current(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *NodeChainExecutionCandidatePlan) digest() string {
	if p == nil || p.plan == nil || p.projection == nil || p.preparation == nil || p.trial == nil {
		return ""
	}
	raw, _ := json.Marshal([]any{"routervpn-selected-execution-entry-candidates-v1", p.identity,
		p.trial.id, p.trial.execution, p.trial.tag, p.trial.selectionEpoch,
		p.projection.SourceSHA256(), p.projection.ConfigSHA256(), p.preparation.SourceSHA256(),
		p.preparation.ConfigSHA256(), p.preparation.Execution(), p.plan.digest()})
	defer clear(raw)
	return externalDigest(raw)
}

func (p *NodeChainExecutionCandidatePlan) validate() error {
	if p == nil || p.self != p || p.runtime == nil || p.trial == nil || p.trial.runtime != p.runtime ||
		p.projection == nil || p.preparation == nil || p.plan == nil || p.plan.validate() != nil ||
		p.projection.validateCapture() != nil || p.projection.preparation != p.preparation ||
		p.plan.chain != p.projection.policy.local || p.plan.prefix.Position != 0 ||
		p.capture == "" || p.capture != p.seal || p.seal != p.digest() {
		return hopmeasure.ErrStale
	}
	r := p.runtime
	r.mu.Lock()
	valid := r.engine != nil && reflect.TypeOf(r.engine).Comparable() && r.projection == p.projection && r.engine == p.native && r.active == p.trial &&
		r.identity == p.identity && !r.closed && !r.retired.Load()
	r.mu.Unlock()
	if !valid {
		return hopmeasure.ErrStale
	}
	return nil
}

func (p *NodeChainExecutionCandidatePlan) current(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || p.validate() != nil {
		return hopmeasure.ErrStale
	}
	if err := p.runtime.HealthyContext(ctx); err != nil {
		return err
	}
	if err := p.runtime.current(ctx, p.trial, true); err != nil {
		return err
	}
	return p.validate()
}

func (p *NodeChainExecutionCandidatePlan) CaptureSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.capture
}

func (p *NodeChainExecutionCandidatePlan) Metadata() string {
	if p.validate() != nil {
		return ""
	}
	var metadata map[string]any
	if json.Unmarshal([]byte(p.plan.Metadata()), &metadata) != nil {
		return ""
	}
	metadata["capture_sha256"] = p.capture
	metadata["source_sha256"], metadata["config_sha256"] = p.projection.SourceSHA256(), p.projection.ConfigSHA256()
	metadata["preparation_source_sha256"], metadata["preparation_config_sha256"] = p.preparation.SourceSHA256(), p.preparation.ConfigSHA256()
	metadata["requested_execution"], metadata["execution"], metadata["selection_epoch"] = p.preparation.Execution(), p.trial.execution, p.trial.selectionEpoch
	raw, _ := json.Marshal(metadata)
	return string(raw)
}

func (p *NodeChainExecutionCandidatePlan) NewMeasurementContext(ctx context.Context, owner NodeChainExecutionCandidateOwner) (*NodeChainExecutionCandidateMeasurement, error) {
	if owner == nil || p.current(ctx) != nil {
		return nil, hopmeasure.ErrStale
	}
	base := &nodeChainExecutionMeasurementEngine{runtime: p.runtime, owner: owner, identity: p.identity, trial: p.trial}
	e := &nodeChainExecutionEntryCandidateEngine{base: base, plan: p, owner: owner}
	service, err := hopmeasure.NewPrefixCandidatesContext(ctx, e, hopmeasure.CandidatePrefix{
		Position: 0, ID: p.plan.prefix.ProfileID, Tag: p.plan.prefix.Tag, CaptureSHA256: p.capture}, p.plan.targets)
	if err != nil {
		return nil, err
	}
	s := &NodeChainExecutionCandidateMeasurement{engine: e, service: service}
	s.self = s
	return s, nil
}

type nodeChainExecutionEntryCandidateEngine struct {
	base  *nodeChainExecutionMeasurementEngine
	plan  *NodeChainExecutionCandidatePlan
	owner NodeChainExecutionCandidateOwner
}

func (e *nodeChainExecutionEntryCandidateEngine) current(ctx context.Context) error {
	if err := e.plan.current(ctx); err != nil {
		return err
	}
	if err := e.base.current(ctx); err != nil {
		return err
	}
	if err := e.owner.CandidateInventoryCurrentContext(ctx, e.plan.capture); err != nil {
		return err
	}
	if err := e.base.current(ctx); err != nil {
		return err
	}
	return e.plan.validate()
}
func (e *nodeChainExecutionEntryCandidateEngine) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	id, _ := e.IdentityContext(ctx)
	return id
}
func (e *nodeChainExecutionEntryCandidateEngine) IdentityContext(ctx context.Context) (string, error) {
	if err := e.current(ctx); err != nil {
		return "", err
	}
	return e.plan.capture, nil
}
func (e *nodeChainExecutionEntryCandidateEngine) VerifyMeasurement(ctx context.Context) error {
	if err := e.current(ctx); err != nil {
		return err
	}
	return e.base.VerifyMeasurement(ctx)
}
func (e *nodeChainExecutionEntryCandidateEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if err := e.current(ctx); err != nil {
		return nil, err
	}
	release, err := e.base.BeginMeasurementContext(ctx)
	if err != nil || release == nil {
		return release, errors.Join(err, nodeChainExecutionError)
	}
	return release, e.current(ctx)
}
func (e *nodeChainExecutionEntryCandidateEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if err := e.current(ctx); err != nil {
		return nil, err
	}
	allowed := false
	for _, target := range e.plan.plan.targets {
		allowed = allowed || address == target.Address
	}
	if tag != e.plan.plan.prefix.Tag || !allowed {
		return nil, hopmeasure.ErrStale
	}
	e.base.mu.Lock()
	scope := e.base.scope
	e.base.mu.Unlock()
	if scope == nil {
		return nil, hopmeasure.ErrStale
	}
	call, finish, err := scope.io.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	connection, dialErr := e.plan.native.Dial(call, tag, address)
	var keepErr error
	if connection != nil {
		connection, keepErr = scope.io.keep(connection)
	}
	currentErr := e.current(call)
	if connection == nil || dialErr != nil || keepErr != nil || currentErr != nil || call.Err() != nil {
		if owned, ok := connection.(*leaseStopConn); ok {
			owned.startClose()
		}
		return connection, errors.Join(dialErr, keepErr, currentErr, call.Err(), nodeChainExecutionError)
	}
	return connection, nil
}

// The wrapper retains the exact leaseStopIO scope through failed Drain/Close.
// It deliberately does not expose a raw CandidateService to a host.
type NodeChainExecutionCandidateMeasurement struct {
	self    *NodeChainExecutionCandidateMeasurement
	engine  *nodeChainExecutionEntryCandidateEngine
	service *hopmeasure.CandidateService
}

func (s *NodeChainExecutionCandidateMeasurement) valid() bool {
	return s != nil && s.self == s && s.engine != nil && s.service != nil
}
func (s *NodeChainExecutionCandidateMeasurement) Start(id, candidate string) error {
	return s.StartContext(context.Background(), id, candidate)
}
func (s *NodeChainExecutionCandidateMeasurement) StartContext(ctx context.Context, id, candidate string) error {
	if !s.valid() {
		return hopmeasure.ErrStale
	}
	bridge := &NodeChainExecutionMeasurement{engine: s.engine.base}
	return bridge.start(ctx, id, func() error { return s.service.StartContext(ctx, id, candidate) })
}
func (s *NodeChainExecutionCandidateMeasurement) Cancel(id string) {
	if s.valid() {
		s.service.Cancel(id)
	}
}
func (s *NodeChainExecutionCandidateMeasurement) Drain(id string) error {
	if !s.valid() {
		return hopmeasure.ErrStale
	}
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.DrainTimeout)
	defer cancel()
	if err := s.service.Drain(id); err != nil {
		return err
	}
	return s.engine.base.drainScope(ctx, id)
}
func (s *NodeChainExecutionCandidateMeasurement) Invalidate() {
	if s.valid() {
		s.engine.base.closed.Store(true)
		s.service.Invalidate()
		s.engine.base.retireScope()
	}
}
func (s *NodeChainExecutionCandidateMeasurement) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.DrainTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}
func (s *NodeChainExecutionCandidateMeasurement) CloseContext(ctx context.Context) error {
	if !s.valid() || ctx == nil {
		return hopmeasure.ErrStale
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.Invalidate()
	err := s.service.CloseContext(ctx)
	return errors.Join(err, s.engine.base.drainScope(ctx, ""))
}
func (s *NodeChainExecutionCandidateMeasurement) StatusJSON() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	return s.StatusContextJSON(ctx)
}
func (s *NodeChainExecutionCandidateMeasurement) StatusContextJSON(ctx context.Context) string {
	if !s.valid() {
		return "{}"
	}
	var state hopmeasure.CandidateStatus
	if json.Unmarshal([]byte(s.service.StatusContextJSON(ctx)), &state) != nil {
		return "{}"
	}
	s.engine.base.mu.Lock()
	pending := s.engine.base.scope != nil || s.engine.base.starting
	s.engine.base.mu.Unlock()
	nodeChainExecutionCandidateMaskPending(&state, pending)
	raw, _ := json.Marshal(state)
	return string(raw)
}

func nodeChainExecutionCandidateMaskPending(state *hopmeasure.CandidateStatus, pending bool) {
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
}
