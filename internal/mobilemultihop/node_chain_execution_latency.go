package mobilemultihop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sync"

	"router-vpn/internal/hopmeasure"
)

// NodeChainExecutionLatency borrows the original execution measurement owner.
// It keeps the selected trial and its activity/IO cleanup; it cannot create a
// new route, rerun Compare, or expose the underlying hopmeasure.Service.
type NodeChainExecutionLatency struct {
	self        *NodeChainExecutionLatency
	measurement *NodeChainExecutionMeasurement
	service     *hopmeasure.OrderedLatencyService
	capture     string
	mu          sync.Mutex
	closed      bool
	request     string
	scope       *nodeChainExecutionMeasurementScope
}

type nodeChainExecutionLatencyHop struct {
	NodeID   string `json:"node_id"`
	Position int    `json:"position"`
	Role     string `json:"role"`
	Kind     string `json:"kind"`
}

// NewLatencyBenchmarkContext attaches a facade only after the actual selected
// execution and the host's original measurement association both validate.
// Source/config belong to that projection, never caller-supplied physical or
// preparation digests. The generation includes the selected trial and epoch.
func (s *NodeChainExecutionMeasurement) NewLatencyBenchmarkContext(ctx context.Context, validate func(context.Context) error) (*NodeChainExecutionLatency, error) {
	if s == nil || s.self != s || s.service == nil || s.engine == nil || validate == nil || ctx == nil {
		return nil, nodeChainExecutionError
	}
	if err := s.engine.current(ctx); err != nil {
		return nil, err
	}
	p := s.engine.runtime.projection
	proofs, err := p.ProofInventory(s.engine.trial.execution)
	if err != nil {
		return nil, err
	}
	identity, err := s.engine.IdentityContext(ctx)
	if err != nil {
		return nil, err
	}
	hops := make([]nodeChainExecutionLatencyHop, len(proofs))
	for position, proof := range proofs {
		role, kind := "intermediate", "private-node"
		if position == 0 {
			role = "entry"
		} else if position == len(proofs)-1 {
			role = "exit"
		}
		if position == 1 && p.policy.local.importedMiddle != nil {
			kind = "public-path"
		}
		hops[position] = nodeChainExecutionLatencyHop{proof.ProfileID, position, role, kind}
	}
	digest := sha256.Sum256([]byte(identity))
	capture, err := json.Marshal(struct {
		Schema           int                            `json:"schema"`
		SourceSHA256     string                         `json:"source_sha256"`
		ConfigSHA256     string                         `json:"config_sha256"`
		GenerationSHA256 string                         `json:"generation_sha256"`
		Execution        string                         `json:"selected_execution"`
		Nodes            []nodeChainExecutionLatencyHop `json:"nodes"`
	}{1, p.SourceSHA256(), p.ConfigSHA256(), hex.EncodeToString(digest[:]), s.engine.trial.execution, hops})
	if err != nil {
		return nil, err
	}
	service, err := hopmeasure.NewOrderedLatencyValidatedContext(ctx, s.service, p.SourceSHA256(), p.ConfigSHA256(), func(call context.Context) error {
		if s.self != s || s.engine.current(call) != nil {
			return nodeChainExecutionError
		}
		return validate(call)
	})
	if err != nil {
		return nil, err
	}
	value := &NodeChainExecutionLatency{measurement: s, service: service, capture: string(capture)}
	value.self = value
	return value, nil
}

func (s *NodeChainExecutionLatency) original() bool {
	return s != nil && s.self == s && s.measurement != nil && s.measurement.self == s.measurement && s.service != nil
}

func (s *NodeChainExecutionLatency) CaptureJSON() string {
	if !s.original() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return ""
	}
	defer s.mu.Unlock()
	if s.closed || s.measurement.engine.current(ctx) != nil {
		return ""
	}
	return s.capture
}

func (s *NodeChainExecutionLatency) Start(request, nodeID string) error {
	return s.StartContext(context.Background(), request, nodeID)
}

func (s *NodeChainExecutionLatency) StartContext(ctx context.Context, request, nodeID string) error {
	if !s.original() || ctx == nil {
		return nodeChainExecutionError
	}
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if s.closed {
		return nodeChainExecutionError
	}
	return s.measurement.start(ctx, request, func() error {
		s.request, s.scope = request, nil
		err := s.service.StartContext(ctx, request, nodeID)
		e := s.measurement.engine
		e.mu.Lock()
		if e.scope != nil && e.scope.id == request {
			s.scope = e.scope
		}
		e.mu.Unlock()
		return err
	})
}

func (s *NodeChainExecutionLatency) Cancel(request string) {
	if s.original() {
		s.service.Cancel(request)
	}
}

func (s *NodeChainExecutionLatency) Drain(request string) error {
	if !s.original() {
		return nodeChainExecutionError
	}
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.DrainTimeout)
	defer cancel()
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if request != s.request {
		return errors.New("execution latency drain belongs to another request")
	}
	if err := s.service.DrainContext(ctx, request); err != nil {
		return err
	}
	return s.measurement.engine.drainCapturedScope(ctx, s.scope)
}

func executionLatencyScopeJoined(scope *nodeChainExecutionMeasurementScope) bool {
	if scope == nil {
		return true
	}
	select {
	case <-scope.joined:
		return true
	default:
		return false
	}
}

func (s *NodeChainExecutionLatency) StatusJSON() string {
	if !s.original() {
		return "{}"
	}
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return "{}"
	}
	defer s.mu.Unlock()
	if !executionLatencyScopeJoined(s.scope) {
		// Calling the facade here could commit its pending result before the
		// stronger original execution activity has finished releasing. This
		// also applies after a cancelled or failed facade close: worker-only
		// retirement is not proof that the retained native activity joined.
		var state hopmeasure.Status
		_ = json.Unmarshal([]byte(s.measurement.StatusContextJSON(ctx)), &state)
		if state.Request != s.request {
			state = hopmeasure.Status{Request: s.request}
		}
		state.Stage, state.Complete, state.Drained = "draining", false, false
		state.Results = []hopmeasure.Result{}
		raw, _ := json.Marshal(state)
		return string(raw)
	}
	raw := s.service.StatusJSON()
	var state hopmeasure.Status
	if !s.closed && json.Unmarshal([]byte(raw), &state) == nil && state.Complete && state.Drained && state.Stage == "complete" && state.Failure == "" && len(state.Results) == 1 && state.Results[0].Ready {
		// The generic facade can retain a completed worker after a later
		// adoption proof fails. Execution must not expose that row as current:
		// require its committed receipt and a fresh selected-path proof.
		var saved hopmeasure.OrderedLatencyReceipt
		p := s.measurement.engine.runtime.projection
		if json.Unmarshal([]byte(s.service.CommittedJSON(state.Results[0].ID)), &saved) != nil || saved.Request != state.Request ||
			saved.NodeID != state.Results[0].ID || saved.SourceSHA256 != p.SourceSHA256() || saved.ConfigSHA256 != p.ConfigSHA256() ||
			!reflect.DeepEqual(saved.Result, state.Results[0]) || s.measurement.engine.VerifyMeasurement(ctx) != nil {
			state.Stage, state.Failure = "invalidated", "Original selected execution proof is unavailable"
			state.Results = []hopmeasure.Result{}
			result, _ := json.Marshal(state)
			return string(result)
		}
	}
	return raw
}

func (s *NodeChainExecutionLatency) SavedJSON(nodeID string) string {
	if !s.original() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return ""
	}
	defer s.mu.Unlock()
	if s.closed || !executionLatencyScopeJoined(s.scope) {
		return s.service.CommittedJSON(nodeID)
	}
	return s.service.SavedJSON(nodeID)
}

func (s *NodeChainExecutionLatency) Invalidate() {
	if !s.original() {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.service.Invalidate()
	s.mu.Unlock()
}

func (s *NodeChainExecutionLatency) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.DrainTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}

func (s *NodeChainExecutionLatency) CloseContext(ctx context.Context) error {
	if !s.original() || ctx == nil {
		return nodeChainExecutionError
	}
	if err := externalObservationLock(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	s.closed = true
	if err := s.service.CloseContext(ctx); err != nil {
		return err
	}
	// The service is borrowed. Close joins only this facade's retained scope;
	// a later throughput worker may already have acquired the host service.
	return s.measurement.engine.drainCapturedScope(ctx, s.scope)
}
