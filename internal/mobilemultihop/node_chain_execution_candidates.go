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
	localInterior bool
}

// DesktopTypedEntryCandidateDescription contains only the chooser's public
// metadata. It carries no runtime, private destination, grant or dial method.
type DesktopTypedEntryCandidateDescription struct{ metadata, capture string }

func (d *DesktopTypedEntryCandidateDescription) Metadata() string {
	if d == nil {
		return ""
	}
	return d.metadata
}
func (d *DesktopTypedEntryCandidateDescription) CaptureSHA256() string {
	if d == nil {
		return ""
	}
	return d.capture
}

// DescribeDesktopTypedEntryCandidate compiles the original typed policy's
// physical entry. The native child separately binds its own selected trial
// and proof to a live candidate plan before issuing a measurement grant.
func (p *NodeChainExecutionPreparation) DescribeDesktopTypedEntryCandidate(socks *DesktopNodeChainSOCKSPolicy, connect *DesktopNodeChainCONNECTPolicy, position int, inventory string) (*DesktopTypedEntryCandidateDescription, error) {
	if p == nil || position != 0 || (socks == nil) == (connect == nil) || p.validateCapture() != nil ||
		socks != nil && (p.socks == nil || p.socks.desktop == nil || p.socks.desktop.original != socks || p.socks.local != p.local) ||
		connect != nil && (p.connect == nil || p.connect.desktop == nil || p.connect.desktop.original != connect || p.connect.local != p.local) {
		return nil, nodeChainExecutionError
	}
	plan, err := p.local.newPacketCandidatePlan(0, inventory)
	if err != nil {
		return nil, err
	}
	meta := plan.Metadata()
	if meta == "" {
		return nil, nodeChainExecutionError
	}
	return &DesktopTypedEntryCandidateDescription{metadata: meta, capture: plan.CaptureSHA256()}, nil
}

// Connected candidates borrow the original selected construction. A schema-six
// packet stop can traverse preceding imports, but an imported stream itself
// cannot attest to the destination's TCP handshake.
func (p *NodeChainExecutionProjection) newPacketCandidatePlan(position int, inventory string) (*NodeChainCandidatePlan, error) {
	if p == nil || p.policy == nil || p.policy.local == nil || p.policy.local.CandidatePrefixMeasurement(position) != hopmeasure.CandidateTCPMeasurement {
		return nil, nodeChainExecutionError
	}

	if binding := p.policy.multiple; binding != nil {
		if p.preparation.multiple != binding || binding.preparation != p.preparation ||
			binding.local != p.policy.local || binding.owners != p.policy.local.importedNodes {
			return nil, nodeChainExecutionError
		}
		return binding.local.NewMultipleImportedCandidatePlan(position, inventory)
	}
	return p.policy.local.newPacketCandidatePlan(position, inventory)
}

// SupportsCompareLocalResponseCandidate describes a source before Compare runs.
// Only an already selected Local trial can create the live plan or dial.
func (p *NodeChainExecutionPreparation) SupportsCompareLocalResponseCandidate(position int) bool {
	if p == nil || p.validateCapture() != nil || p.Execution() != "auto" {
		return false
	}
	if p.multiple != nil {
		private, eligible := p.local.selectedStreamLayout()
		finalPrefix := len(p.local.proofs) - 2
		insert := private == 0 && len(p.local.proofs) < NodeChainExtendedLocalMaximumNodes && position > 0 && position < finalPrefix
		return eligible && p.multiple.local == p.local && p.multiple.owners == p.local.importedNodes &&
			(position == finalPrefix || insert) &&
			p.local.CandidatePrefixMeasurement(position) == hopmeasure.CandidatePrivateResponseMeasurement
	}
	return p.local.compareLocalResponsePrefix(position)
}

func (c *NodeChain) compareLocalResponsePrefix(position int) bool {
	return c != nil && position == 1 && len(c.proofs) == 3 && c.importedMiddle != nil && c.importedMiddle.hostname == nil &&
		c.importedMiddle.policy != nil && c.nodes[0] != nil && c.nodes[1] == nil && c.nodes[2] != nil &&
		c.proofs[0].Mode == "wg" && c.proofs[0].StartLayer == "off" &&
		c.proofs[1].Mode == "shadowsocks" && c.proofs[1].NodeKind == "external" &&
		c.proofs[2].Mode == "shadowsocks" && c.proofs[2].StartLayer == "off" &&
		c.CandidatePrefixMeasurement(position) == hopmeasure.CandidatePrivateResponseMeasurement
}

func (r *NodeChainExecutionRuntime) NewEntryCandidatePlanContext(ctx context.Context, position int, inventory string) (*NodeChainExecutionCandidatePlan, error) {
	return r.newExecutionCandidatePlanContext(ctx, position, inventory, false)
}

// NewLocalCandidatePlanContext borrows only the already selected Local winner.
// It does not open a Local graph or rerun Compare. Interior packet admission
// still belongs to the original family's packet candidate compiler.
func (r *NodeChainExecutionRuntime) NewLocalCandidatePlanContext(ctx context.Context, position int, inventory string) (*NodeChainExecutionCandidatePlan, error) {
	return r.newExecutionCandidatePlanContext(ctx, position, inventory, true)
}

func (r *NodeChainExecutionRuntime) newExecutionCandidatePlanContext(ctx context.Context, position int, inventory string, localInterior bool) (*NodeChainExecutionCandidatePlan, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || (!localInterior && position != 0) || (localInterior && position <= 0) || r.projection == nil || r.projection.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	r.mu.Lock()
	trial, identity := r.active, r.identity
	r.mu.Unlock()
	if trial == nil || trial.runtime != r || r.engine == nil || !reflect.TypeOf(r.engine).Comparable() {
		return nil, hopmeasure.ErrStale
	}
	if localInterior && (trial.execution != "local" || position >= len(r.projection.policy.local.nodes)-1) {
		return nil, nodeChainExecutionError
	}
	if err := r.HealthyContext(ctx); err != nil {
		return nil, err
	}
	var plan *NodeChainCandidatePlan
	var err error
	if localInterior && r.projection.preparation.SupportsCompareLocalResponseCandidate(position) {
		original := r.projection.policy.local
		binding := r.projection.preparation.multiple
		if binding == nil {
			if !original.compareLocalResponsePrefix(position) {
				return nil, nodeChainExecutionError
			}
		} else if original != binding.local || r.projection.policy.multiple != binding || original.importedNodes != binding.owners {
			return nil, nodeChainExecutionError
		}
		plan, err = original.NewCandidatePlan(position, inventory)
		if err == nil {
			// The plan excludes prefix identities. A separately named route
			// preserves the unmeasured suffix as well, including its final.
			for _, response := range plan.responses {
				for _, member := range original.proofs[position+1:] {
					if response.Target.ID == member.ProfileID || response.NodeID == member.NodeID {
						return nil, nodeChainExecutionError
					}
				}
			}
		}
	} else {
		plan, err = r.projection.newPacketCandidatePlan(position, inventory)
	}
	if err != nil {
		return nil, err
	}
	p := &NodeChainExecutionCandidatePlan{runtime: r, native: r.engine, projection: r.projection,
		preparation: r.projection.preparation, trial: trial, identity: identity, plan: plan, localInterior: localInterior}
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
	kind := "routervpn-selected-execution-entry-candidates-v1"
	if p.plan.measurement == hopmeasure.CandidatePrivateResponseMeasurement {
		kind = "routervpn-selected-compare-local-private-response-candidates-v1"
	} else if p.localInterior {
		kind = "routervpn-selected-execution-local-interior-candidates-v1"
	}
	raw, _ := json.Marshal([]any{kind, p.identity,
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
		p.plan.chain != p.projection.policy.local || !p.validPosition() ||
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

// Entry and Local-interior plans share ownership, not admission. The sealed
// kind and original packet plan prevent either constructor from widening the other.
func (p *NodeChainExecutionCandidatePlan) validPosition() bool {
	if p.plan.measurement == hopmeasure.CandidatePrivateResponseMeasurement {
		return p.localInterior && p.trial.execution == "local" && p.preparation.SupportsCompareLocalResponseCandidate(p.plan.prefix.Position)
	}
	if p.localInterior {
		return p.trial.execution == "local" && p.plan.prefix.Position > 0 && p.plan.prefix.Position < len(p.plan.chain.nodes)-1
	}
	return p.plan.prefix.Position == 0
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
	base := &nodeChainExecutionMeasurementEngine{runtime: p.runtime, projection: p.projection, owner: owner, identity: p.identity, trial: p.trial}
	e := &nodeChainExecutionEntryCandidateEngine{base: base, plan: p, owner: owner}
	var service *hopmeasure.CandidateService
	var err error
	if p.plan.measurement == hopmeasure.CandidatePrivateResponseMeasurement {
		service, err = p.plan.newService(ctx, e, p.capture)
	} else {
		service, err = hopmeasure.NewCapturedPrefixCandidatesContext(ctx, e, hopmeasure.CandidatePrefix{
			Position: p.plan.prefix.Position, ID: p.plan.prefix.ProfileID, Tag: p.plan.prefix.Tag, CaptureSHA256: p.capture}, p.plan.targets, NodeChainInputLimit)
	}
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
