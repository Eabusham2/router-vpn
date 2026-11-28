package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sync"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// The original Local preparation remains the native Config/physical/DNS owner.
// This separate interface can read only source-bound entry control/front tuples.
type NodeChainCandidateAppendExecutionOwner interface {
	NodeChainCandidatePreparationOwner
	AppendExecutionEngineContext(context.Context, *NodeChainCandidatePreparation) (NodeChainCandidateAppendExecutionEngine, error)
}
type NodeChainCandidateAppendExecutionEngine interface {
	ObservePreparationContext(context.Context) (NodeChainIdentity, error)
	DialAppendExecutionContext(context.Context, *NodeChainCandidateAppendExecutionDialRequest) (net.Conn, error)
}
type NodeChainCandidateAppendExecutionDialRequest struct {
	self         *NodeChainCandidateAppendExecutionDialRequest
	runtime      *NodeChainCandidateAppendExecutionRuntime
	preparation  *NodeChainCandidatePreparation
	reader       NodeChainCandidateAppendExecutionEngine
	tag, address string
	lease        *nodeChainAppendExecutionLease
	retirement   *nodeChainAppendExecutionRetirement
}

func (q *NodeChainCandidateAppendExecutionDialRequest) Read(ctx context.Context, reader NodeChainCandidateAppendExecutionEngine, preparation *NodeChainCandidatePreparation) (string, string, error) {
	if q == nil || q.self != q || q.runtime == nil || q.reader != reader || q.preparation != preparation || q.runtime.preparation.original != preparation || q.runtime.nativeCurrent(ctx, q.retirement != nil) != nil {
		return "", "", errNodeChainAppendExecution
	}
	if q.retirement != nil && (q.retirement.runtime != q.runtime || q.retirement.valid() != nil) {
		return "", "", errNodeChainAppendExecution
	}
	p := q.runtime.preparation.policy
	first := p.original.proofs[0]
	api, err := privateAPI(predecessorText(p.original.prefixNode(0).profile, "router_api"))
	if err != nil || q.tag != first.Tag {
		return "", "", errNodeChainAppendExecution
	}
	if q.address != api.Host {
		if q.retirement != nil || q.lease == nil || q.lease.runtime != q.runtime || !q.lease.frontCurrent() || q.address != q.lease.front {
			return "", "", errNodeChainAppendExecution
		}
	}
	return q.tag, q.address, nil
}

type NodeChainCandidateAppendExecutionProgress struct {
	Stage                  string                    `json:"stage"`
	Purpose                string                    `json:"purpose"`
	RequestedExecution     string                    `json:"requested_execution"`
	Prepared               bool                      `json:"prepared"`
	Prefixes               []NodeChainPrefixProgress `json:"prefixes"`
	ApplicationOpen        bool                      `json:"application_open"`
	DNSOpen                bool                      `json:"dns_open"`
	ExecutionSourceSHA256  string                    `json:"execution_source_sha256"`
	ExecutionCaptureSHA256 string                    `json:"execution_capture_sha256"`
}
type NodeChainCandidateAppendExecutionDiscovery struct {
	Schema                           int               `json:"schema"`
	Purpose                          string            `json:"purpose"`
	ExecutionSourceSHA256            string            `json:"execution_source_sha256"`
	ExecutionCaptureSHA256           string            `json:"execution_capture_sha256"`
	OriginalSourceSHA256             string            `json:"original_source_sha256"`
	OriginalPreparationSourceSHA256  string            `json:"original_preparation_source_sha256"`
	OriginalPreparationCaptureSHA256 string            `json:"original_preparation_capture_sha256"`
	ConfigSHA256                     string            `json:"config_sha256"`
	RequestedExecution               string            `json:"requested_execution"`
	DescriptorSHA256                 string            `json:"descriptor_sha256"`
	RegistrySHA256                   string            `json:"registry_sha256"`
	Identity                         NodeChainIdentity `json:"identity"`
	Prepared                         bool              `json:"prepared"`
	ApplicationOpen                  bool              `json:"application_open"`
	DNSOpen                          bool              `json:"dns_open"`
	ObservedAt                       int64             `json:"observed_at"`
}
type nodeChainAppendExecutionRuntimeCapture struct {
	Source                  string                                  `json:"source"`
	LocalPreparationSource  string                                  `json:"local_preparation_source"`
	LocalPreparationCapture string                                  `json:"local_preparation_capture"`
	Identity                NodeChainIdentity                       `json:"identity"`
	Discovery               multihoprelay.NodeChainPrefixDiscovery  `json:"discovery"`
	Descriptor              multihoprelay.NodeChainPrefixDescriptor `json:"descriptor"`
	Proposal                struct {
		Nonce string `json:"nonce"`
		Port  int    `json:"port"`
	} `json:"proposal"`
	PrefixSelection *multihoprelay.NodeChainPrefixSelectionReceipt `json:"prefix_selection,omitempty"`
}
type NodeChainCandidateAppendExecutionRuntime struct {
	self                              *NodeChainCandidateAppendExecutionRuntime
	preparation                       *NodeChainCandidateAppendExecutionPreparation
	owner                             NodeChainCandidateAppendExecutionOwner
	local                             *NodeChainCandidatePreparationRuntime
	engine                            NodeChainCandidateAppendExecutionEngine
	identity                          NodeChainIdentity
	mu                                sync.Mutex
	started, retired, closed          bool
	lifetime                          context.Context
	cancel                            context.CancelFunc
	startDone                         chan struct{}
	stage, capture                    string
	captured                          nodeChainAppendExecutionRuntimeCapture
	descriptor                        multihoprelay.NodeChainPrefixDescriptor
	discovery                         multihoprelay.NodeChainPrefixDiscovery
	control                           *nodeChainExecutionIO
	prefixSelection                   *nodeChainAppendExecutionSelection
	service                           *hopmeasure.CandidateService
	active                            *nodeChainAppendExecutionRun
	pending                           map[*nodeChainAppendExecutionLease]bool
	holds                             map[*nodeChainAppendExecutionHold]bool
	closeGate                         chan struct{}
	resultRequest, winning, selection string
}

func NewNodeChainCandidateAppendExecutionRuntime(preparation *NodeChainCandidateAppendExecutionPreparation, owner NodeChainCandidateAppendExecutionOwner) (*NodeChainCandidateAppendExecutionRuntime, error) {
	if preparation.validate() != nil || owner == nil {
		return nil, errNodeChainAppendExecution
	}
	local, err := NewNodeChainCandidatePreparationRuntime(preparation.original, owner)
	if err != nil {
		return nil, err
	}
	r := &NodeChainCandidateAppendExecutionRuntime{preparation: preparation, owner: owner, local: local, stage: "pending-prefix-proof", pending: make(map[*nodeChainAppendExecutionLease]bool), holds: make(map[*nodeChainAppendExecutionHold]bool), closeGate: make(chan struct{}, 1)}
	r.self = r
	return r, nil
}
func (r *NodeChainCandidateAppendExecutionRuntime) nativeCurrent(ctx context.Context, retirement bool) error {
	if r == nil || r.self != r || ctx == nil || ctx.Err() != nil || r.preparation.validate() != nil {
		return errNodeChainAppendExecution
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	engine, identity, alive := r.engine, r.identity, r.started && !r.closed && (retirement || !r.retired && r.lifetime != nil && r.lifetime.Err() == nil)
	r.mu.Unlock()
	if !alive || engine == nil || !reflect.TypeOf(engine).Comparable() {
		return errNodeChainAppendExecution
	}
	actual, err := r.owner.AppendExecutionEngineContext(ctx, r.preparation.original)
	if err != nil || actual != engine {
		return errors.Join(err, errNodeChainAppendExecution)
	}
	observed, err := engine.ObservePreparationContext(ctx)
	if err != nil || observed != identity {
		return errors.Join(err, errNodeChainAppendExecution)
	}
	if !retirement {
		observed, err = r.owner.ObservePreparationContext(ctx)
		if err != nil || observed != identity {
			return errors.Join(err, errNodeChainAppendExecution)
		}
	}
	if identity.SourceSHA256 != r.preparation.original.sourceSHA || identity.ConfigSHA256 != r.preparation.original.configSHA {
		return errNodeChainAppendExecution
	}
	return ctx.Err()
}
func (r *NodeChainCandidateAppendExecutionRuntime) dialControl(ctx context.Context, tag, address string, lease *nodeChainAppendExecutionLease, retirement *nodeChainAppendExecutionRetirement) (net.Conn, error) {
	if r.nativeCurrent(ctx, retirement != nil) != nil {
		return nil, errNodeChainAppendExecution
	}
	r.mu.Lock()
	reader := r.engine
	r.mu.Unlock()
	q := &NodeChainCandidateAppendExecutionDialRequest{runtime: r, preparation: r.preparation.original, reader: reader, tag: tag, address: address, lease: lease, retirement: retirement}
	q.self = q
	if _, _, err := q.Read(ctx, reader, q.preparation); err != nil {
		return nil, err
	}
	original, err := reader.DialAppendExecutionContext(ctx, q)
	after := r.nativeCurrent(ctx, retirement != nil)
	return original, errors.Join(err, after, ctx.Err())
}
func (r *NodeChainCandidateAppendExecutionRuntime) newControl() (*nodeChainExecutionIO, error) {
	original := r.preparation.original
	node := original.prefixNode(0)
	tag := original.proofs[0].Tag
	dial := func(ctx context.Context, actual, address string) (net.Conn, error) {
		return r.dialControl(ctx, actual, address, nil, nil)
	}
	current := func(ctx context.Context) error {
		if err := r.nativeCurrent(ctx, false); err != nil {
			return err
		}
		return r.local.VerifyMeasurement(ctx)
	}
	return newNodeChainExecutionIO(tag, predecessorText(node.profile, "router_api"), predecessorText(node.profile, "api_token"), dial, current)
}
func (r *NodeChainCandidateAppendExecutionRuntime) StartContext(parent context.Context) (failure error) {
	if r == nil || r.self != r || parent == nil {
		return errNodeChainAppendExecution
	}
	if err := externalObservationLock(parent, &r.mu); err != nil {
		return err
	}
	if r.started || r.retired {
		r.mu.Unlock()
		return errNodeChainAppendExecution
	}
	r.started = true
	r.lifetime, r.cancel = context.WithCancel(parent)
	r.startDone = make(chan struct{})
	done := r.startDone
	lifetime := r.lifetime
	r.mu.Unlock()
	defer close(done)
	defer func() {
		if failure != nil {
			r.mu.Lock()
			r.stage = "append-execution-failed"
			r.retired = true
			r.mu.Unlock()
			r.cancel()
		}
	}()
	if err := r.local.StartContext(lifetime); err != nil {
		return err
	}
	engine, err := r.owner.AppendExecutionEngineContext(lifetime, r.preparation.original)
	if err != nil || engine == nil || !reflect.TypeOf(engine).Comparable() {
		return errors.Join(err, errNodeChainAppendExecution)
	}
	identity, err := engine.ObservePreparationContext(lifetime)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.engine, r.identity = engine, identity
	r.stage = "pending-prefix-discovery"
	r.mu.Unlock()
	if err = r.nativeCurrent(lifetime, false); err != nil {
		return err
	}
	control, err := r.newControl()
	r.mu.Lock()
	r.control = control
	r.mu.Unlock()
	if err != nil {
		return err
	}
	bounded, finish := context.WithTimeout(lifetime, 8*time.Second)
	defer finish()
	discovery, descriptor, err := r.initialDiscovery(bounded)
	if err != nil {
		return err
	}
	nonce, err := randomHex(32)
	if err != nil {
		return err
	}
	capture := nodeChainAppendExecutionRuntimeCapture{Source: r.preparation.Source(), LocalPreparationSource: r.preparation.original.source, LocalPreparationCapture: r.preparation.original.capture, Identity: identity, Discovery: discovery, Descriptor: descriptor}
	r.mu.Lock()
	prefixSelection := r.prefixSelection
	r.mu.Unlock()
	if prefixSelection != nil {
		receipt, ok := prefixSelection.receipt()
		if !ok {
			return errNodeChainAppendExecution
		}
		capture.PrefixSelection = &receipt
	}
	capture.Proposal.Nonce = nonce
	// The proposal stays bound to the captured range. A later lease uses a fresh
	// acquisition identity; a collision is refusal, never an unreviewed port retry.
	capture.Proposal.Port = discovery.FirstPort
	digest, err := nodeChainAppendExecutionDigest("routervpn-append-execution-capture-v1", capture)
	if err != nil {
		return err
	}
	if err = r.nativeCurrent(bounded, false); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired || lifetime.Err() != nil {
		return errNodeChainAppendExecution
	}
	r.discovery, r.descriptor, r.captured, r.capture = discovery, descriptor, capture, digest
	r.stage = "append-execution-prepared"
	return nil
}
func (r *NodeChainCandidateAppendExecutionRuntime) fetchDiscovery(ctx context.Context) (multihoprelay.NodeChainPrefixDiscovery, multihoprelay.NodeChainPrefixDescriptor, error) {
	fail := func() (multihoprelay.NodeChainPrefixDiscovery, multihoprelay.NodeChainPrefixDescriptor, error) {
		return multihoprelay.NodeChainPrefixDiscovery{}, multihoprelay.NodeChainPrefixDescriptor{}, errNodeChainAppendExecution
	}
	r.mu.Lock()
	control := r.control
	prefixSelection := r.prefixSelection
	r.mu.Unlock()
	if control == nil {
		return fail()
	}
	raw, err := control.exchangePrefix(ctx, "GET", nil)
	if err != nil {
		return multihoprelay.NodeChainPrefixDiscovery{}, multihoprelay.NodeChainPrefixDescriptor{}, err
	}
	discovery, err := multihoprelay.DecodeNodeChainPrefixDiscovery(raw)
	if err != nil || discovery.Challenge.ExpiresAt <= time.Now().Unix() {
		return fail()
	}
	var descriptor multihoprelay.NodeChainPrefixDescriptor
	matches := 0
	for _, value := range discovery.Prefixes {
		if r.preparation.policy.matchesDescriptor(value) {
			descriptor = value.Clone()
			matches++
		}
	}
	if matches != 1 || descriptor.EntryNodeID != r.preparation.policy.localMembers[0].NodeID || discovery.NodeID != descriptor.EntryNodeID {
		return fail()
	}
	if prefixSelection != nil && !prefixSelection.matches(discovery, descriptor) {
		return fail()
	}
	return discovery, descriptor, nil
}
func (r *NodeChainCandidateAppendExecutionRuntime) HealthyContext(ctx context.Context) error {
	if err := r.nativeCurrent(ctx, false); err != nil {
		return err
	}
	if err := r.local.HealthyContext(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	valid := r.stage == "append-execution-prepared" && r.capture != "" && !r.retired
	captured, digest := r.captured, r.capture
	r.mu.Unlock()
	actual, err := nodeChainAppendExecutionDigest("routervpn-append-execution-capture-v1", captured)
	if err != nil || !valid || actual != digest || captured.Source != r.preparation.Source() || captured.LocalPreparationCapture != r.preparation.original.capture || captured.LocalPreparationSource != r.preparation.original.source {
		return errNodeChainAppendExecution
	}
	return ctx.Err()
}
func (r *NodeChainCandidateAppendExecutionRuntime) VerifyMeasurement(ctx context.Context) error {
	if err := r.HealthyContext(ctx); err != nil {
		return err
	}
	if err := r.local.VerifyMeasurement(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	active := r.active
	r.mu.Unlock()
	if active != nil {
		return active.verify(ctx)
	}
	return ctx.Err()
}
func (r *NodeChainCandidateAppendExecutionRuntime) Progress() NodeChainCandidateAppendExecutionProgress {
	if r == nil {
		return NodeChainCandidateAppendExecutionProgress{Stage: "append-execution-failed", Purpose: multihoprelay.NodeChainPrefixPurpose, Prefixes: []NodeChainPrefixProgress{}}
	}
	local := r.local.Progress()
	r.mu.Lock()
	defer r.mu.Unlock()
	stage := r.stage
	prepared := stage == "append-execution-prepared" && !r.retired && local.Prepared
	if stage == "append-execution-prepared" && !prepared {
		stage = "append-execution-failed"
	}
	prefixes := append([]NodeChainPrefixProgress{}, local.Prefixes...)
	return NodeChainCandidateAppendExecutionProgress{Stage: stage, Purpose: multihoprelay.NodeChainPrefixPurpose, RequestedExecution: r.preparation.Execution(), Prepared: prepared, Prefixes: prefixes, ExecutionSourceSHA256: r.preparation.SourceSHA256(), ExecutionCaptureSHA256: r.capture}
}
func (r *NodeChainCandidateAppendExecutionRuntime) CaptureSHA256() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.capture
}
func (r *NodeChainCandidateAppendExecutionRuntime) DiscoveryContext(ctx context.Context) (NodeChainCandidateAppendExecutionDiscovery, error) {
	if err := r.VerifyMeasurement(ctx); err != nil {
		return NodeChainCandidateAppendExecutionDiscovery{}, err
	}
	r.mu.Lock()
	capture, identity, descriptor := r.capture, r.identity, r.descriptor
	r.mu.Unlock()
	digest, err := descriptor.Digest()
	if err != nil {
		return NodeChainCandidateAppendExecutionDiscovery{}, err
	}
	p := r.preparation
	return NodeChainCandidateAppendExecutionDiscovery{Schema: 1, Purpose: multihoprelay.NodeChainPrefixPurpose, ExecutionSourceSHA256: p.SourceSHA256(), ExecutionCaptureSHA256: capture, OriginalSourceSHA256: p.OriginalSourceSHA256(), OriginalPreparationSourceSHA256: p.original.sourceSHA, OriginalPreparationCaptureSHA256: p.original.capture, ConfigSHA256: p.ConfigSHA256(), RequestedExecution: p.Execution(), DescriptorSHA256: digest, RegistrySHA256: digest, Identity: identity, Prepared: true, ObservedAt: time.Now().UnixMilli()}, nil
}
func (r *NodeChainCandidateAppendExecutionRuntime) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	v, _ := r.IdentityContext(ctx)
	return v
}
func (r *NodeChainCandidateAppendExecutionRuntime) IdentityContext(ctx context.Context) (string, error) {
	if err := r.VerifyMeasurement(ctx); err != nil {
		return "", err
	}
	r.mu.Lock()
	identity, capture := r.identity, r.capture
	r.mu.Unlock()
	raw, err := json.Marshal([]any{identity, capture})
	return string(raw), err
}

// VerifyMeasurementIdentityContext uses IdentityContext's complete fresh
// VerifyMeasurement traversal and returns the identity from that observation.
// It carries no result from an earlier boundary or from a status reader.
func (r *NodeChainCandidateAppendExecutionRuntime) VerifyMeasurementIdentityContext(ctx context.Context) (string, error) {
	return r.IdentityContext(ctx)
}

type nodeChainAppendExecutionHold struct {
	release   func()
	requested bool
}

func (r *NodeChainCandidateAppendExecutionRuntime) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if err := r.VerifyMeasurement(ctx); err != nil {
		return nil, err
	}
	release, err := r.local.BeginMeasurementContext(ctx)
	if err != nil || release == nil {
		if release != nil {
			release()
		}
		return nil, errors.Join(err, errNodeChainAppendExecution)
	}
	hold := &nodeChainAppendExecutionHold{release: release}
	r.mu.Lock()
	r.holds[hold] = true
	valid := !r.retired && !r.closed && ctx.Err() == nil
	if !valid {
		hold.requested = true
	}
	r.mu.Unlock()
	if !valid {
		r.releaseJoinedHolds()
		return nil, errNodeChainAppendExecution
	}
	return func() {
		r.mu.Lock()
		if r.holds[hold] {
			hold.requested = true
		}
		r.mu.Unlock()
		r.releaseJoinedHolds()
	}, nil
}
func (r *NodeChainCandidateAppendExecutionRuntime) releaseJoinedHolds() {
	r.mu.Lock()
	if r.active != nil || len(r.pending) != 0 {
		r.mu.Unlock()
		return
	}
	var releases []func()
	for hold := range r.holds {
		if hold.requested {
			releases = append(releases, hold.release)
			delete(r.holds, hold)
		}
	}
	r.mu.Unlock()
	for _, release := range releases {
		release()
	}
}
func (r *NodeChainCandidateAppendExecutionRuntime) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errNodeChainAppendExecution
}
func (r *NodeChainCandidateAppendExecutionRuntime) AppendExecutionResponseDepth(position int, id, tag string) int {
	p := r.preparation
	if p.validate() != nil || position != p.original.position || p.original.proofs[position].ProfileID != id || p.original.proofs[position].Tag != tag {
		return 0
	}
	return len(p.original.proofs)
}
func (r *NodeChainCandidateAppendExecutionRuntime) AppendExecutionResponseTarget(position int, id, tag string, target hopmeasure.CandidateTarget) bool {
	if r.AppendExecutionResponseDepth(position, id, tag) == 0 {
		return false
	}
	for _, source := range r.preparation.original.candidates.responses {
		if source.Target == target {
			return true
		}
	}
	return false
}
func (r *NodeChainCandidateAppendExecutionRuntime) NewMeasurementContext(ctx context.Context) (*hopmeasure.CandidateService, error) {
	if err := r.VerifyMeasurement(ctx); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.service != nil {
		r.mu.Unlock()
		return nil, errNodeChainAppendExecution
	}
	r.mu.Unlock()
	p := r.preparation.original
	proof := p.proofs[p.position]
	service, err := hopmeasure.NewAppendExecutionResponseRunContext(ctx, r, hopmeasure.CandidatePrefix{Position: p.position, ID: proof.ProfileID, Tag: proof.Tag, CaptureSHA256: r.CaptureSHA256()}, p.candidates.targets, NodeChainInputLimit, r, r.openResponseRun)
	if service != nil {
		r.mu.Lock()
		if r.service == nil {
			r.service = service
		} else {
			r.mu.Unlock()
			_ = service.CloseContext(ctx)
			return nil, errNodeChainAppendExecution
		}
		r.mu.Unlock()
	}
	return service, err
}
func (r *NodeChainCandidateAppendExecutionRuntime) StatusContextJSON(ctx context.Context) string {
	if r == nil || ctx == nil {
		return ""
	}
	r.mu.Lock()
	service := r.service
	r.mu.Unlock()
	if service == nil {
		return ""
	}
	raw := service.StatusContextJSON(ctx)
	var state map[string]any
	if json.Unmarshal([]byte(raw), &state) != nil {
		return ""
	}
	request, _ := state["request_id"].(string)
	r.mu.Lock()
	bound, winning, selection, capture := r.resultRequest, r.winning, r.selection, r.capture
	joined := r.active == nil && len(r.pending) == 0
	r.mu.Unlock()
	if request == "" {
		return ""
	}
	state["purpose"] = multihoprelay.NodeChainPrefixPurpose
	state["source_sha256"] = r.preparation.OriginalSourceSHA256()
	state["execution_source_sha256"] = r.preparation.SourceSHA256()
	state["execution_capture_sha256"] = capture
	state["requested_execution"] = r.preparation.Execution()
	state["winning_execution"] = ""
	if state["results"] == nil {
		state["results"] = []any{}
	}
	if complete, _ := state["complete"].(bool); complete && !joined {
		state["complete"] = false
		state["drained"] = false
		state["stage"] = "draining"
		state["results"] = []any{}
	}
	if request == bound {
		state["winning_execution"] = winning
		if r.preparation.Execution() == "auto" && selection != "" {
			var selected any
			if json.Unmarshal([]byte(selection), &selected) == nil {
				state["selection"] = selected
			}
		}
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return ""
	}
	return string(encoded)
}
func (r *NodeChainCandidateAppendExecutionRuntime) SelectionContextJSON(ctx context.Context) string {
	if r == nil || ctx == nil || r.preparation.Execution() != "auto" {
		return ""
	}
	raw := r.StatusContextJSON(ctx)
	var state struct {
		Selection json.RawMessage `json:"selection"`
	}
	if json.Unmarshal([]byte(raw), &state) != nil {
		return ""
	}
	return string(state.Selection)
}
func (r *NodeChainCandidateAppendExecutionRuntime) Cancel() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.retired = true
	if r.stage != "append-execution-failed" {
		r.stage = "append-execution-retired"
	}
	service, cancel := r.service, r.cancel
	r.mu.Unlock()
	if service != nil {
		service.Invalidate()
	}
	if cancel != nil {
		cancel()
	}
}
func (r *NodeChainCandidateAppendExecutionRuntime) CloseContext(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errNodeChainAppendExecution
	}
	select {
	case r.closeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-r.closeGate }()
	r.Cancel()
	r.mu.Lock()
	done, service := r.startDone, r.service
	r.mu.Unlock()
	if service != nil {
		if err := service.CloseContext(ctx); err != nil {
			return err
		}
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.mu.Lock()
	active := r.active
	leases := make([]*nodeChainAppendExecutionLease, 0, len(r.pending))
	for lease := range r.pending {
		leases = append(leases, lease)
	}
	control := r.control
	prefixSelection := r.prefixSelection
	r.mu.Unlock()
	if active != nil {
		if err := active.closeContext(ctx); err != nil {
			return err
		}
	}
	for _, lease := range leases {
		if err := lease.close(ctx); err != nil {
			return err
		}
	}
	if prefixSelection != nil {
		if err := prefixSelection.close(ctx); err != nil {
			return err
		}
	}
	if control != nil {
		if err := control.close(ctx); err != nil {
			return err
		}
	}
	r.releaseJoinedHolds()
	r.mu.Lock()
	holds := len(r.holds)
	r.mu.Unlock()
	if holds != 0 {
		return errNodeChainAppendExecution
	}
	if err := r.local.CloseContext(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return ctx.Err()
}

// Drain retries only the already-retained request after the service's original
// worker has joined. Remote cleanup may keep the Local activity hold pending.
func (r *NodeChainCandidateAppendExecutionRuntime) DrainContext(ctx context.Context, request string) error {
	if r == nil || ctx == nil || request == "" {
		return errNodeChainAppendExecution
	}
	r.mu.Lock()
	service, active := r.service, r.active
	r.mu.Unlock()
	if service == nil {
		return errNodeChainAppendExecution
	}
	if err := service.Drain(request); err != nil {
		return err
	}
	var state struct {
		Request string `json:"request_id"`
	}
	if json.Unmarshal([]byte(service.StatusContextJSON(ctx)), &state) != nil || state.Request != request {
		return errNodeChainAppendExecution
	}
	if active != nil {
		if active.request != request {
			return errNodeChainAppendExecution
		}
		if err := active.closeContext(ctx); err != nil {
			return err
		}
	}
	r.releaseJoinedHolds()
	r.mu.Lock()
	joined := r.active == nil && len(r.pending) == 0 && len(r.holds) == 0
	r.mu.Unlock()
	if !joined {
		return errNodeChainAppendExecution
	}
	return ctx.Err()
}

// The desktop bridge observes the same retained Local proof runtime. This does
// not construct another preparation, select a lane or grant complete readiness.
func (r *NodeChainCandidateAppendExecutionRuntime) OriginalRuntime() *NodeChainCandidatePreparationRuntime {
	if r == nil || r.self != r || r.preparation.validate() != nil {
		return nil
	}
	return r.local
}

// Native IPC may retire one original per-request service and then construct the
// next. Failed remote cleanup retains the exact service, runtime and holds.
func (r *NodeChainCandidateAppendExecutionRuntime) ReleaseMeasurementContext(ctx context.Context, service *hopmeasure.CandidateService) error {
	if r == nil || ctx == nil || service == nil {
		return errNodeChainAppendExecution
	}
	select {
	case r.closeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-r.closeGate }()
	r.mu.Lock()
	same := r.service == service && !r.closed
	r.mu.Unlock()
	if !same {
		return errNodeChainAppendExecution
	}
	if err := service.CloseContext(ctx); err != nil {
		return err
	}
	r.releaseJoinedHolds()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.service != service || r.active != nil || len(r.pending) != 0 || len(r.holds) != 0 || ctx.Err() != nil {
		return errNodeChainAppendExecution
	}
	r.service = nil
	return nil
}
