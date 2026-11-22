package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"math"

	"router-vpn/internal/hopmeasure"
)

// NodeChainExecutionMeasurement retains the native activity and any failed
// original close beyond the underlying measurement worker. Its cleanup/readback
// methods must be used together; a raw service is deliberately not exposed.
type NodeChainExecutionMeasurement struct {
	self    *NodeChainExecutionMeasurement
	service *hopmeasure.Service
	engine  *nodeChainExecutionMeasurementEngine
}

func (s *NodeChainExecutionMeasurement) start(ctx context.Context, id string, work func() error) error {
	if s == nil || ctx == nil || work == nil {
		return nodeChainExecutionError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e := s.engine
	e.mu.Lock()
	if e.closed.Load() || e.starting || e.scope != nil {
		e.mu.Unlock()
		return errors.New("ordered measurement admission or cleanup remains owned")
	}
	e.starting, e.nextID = true, id
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.starting, e.nextID = false, ""; e.mu.Unlock() }()
	return work()
}

func (s *NodeChainExecutionMeasurement) Start(id string, size int) error {
	return s.StartContext(context.Background(), id, size)
}
func (s *NodeChainExecutionMeasurement) StartContext(ctx context.Context, id string, size int) error {
	return s.start(ctx, id, func() error { return s.service.StartContext(ctx, id, size) })
}
func (s *NodeChainExecutionMeasurement) StartLatency(id, exitID string) error {
	return s.StartLatencyContext(context.Background(), id, exitID)
}
func (s *NodeChainExecutionMeasurement) StartLatencyContext(ctx context.Context, id, exitID string) error {
	return s.start(ctx, id, func() error { return s.service.StartLatencyContext(ctx, id, exitID) })
}
func (s *NodeChainExecutionMeasurement) StartResponse(id, exitID string) error {
	return s.StartResponseContext(context.Background(), id, exitID)
}
func (s *NodeChainExecutionMeasurement) StartResponseContext(ctx context.Context, id, exitID string) error {
	return s.start(ctx, id, func() error { return s.service.StartResponseContext(ctx, id, exitID) })
}
func (s *NodeChainExecutionMeasurement) Cancel(id string) {
	if s != nil {
		s.service.Cancel(id)
	}
}
func (s *NodeChainExecutionMeasurement) Drain(id string) error {
	if s == nil {
		return nodeChainExecutionError
	}
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.DrainTimeout)
	defer cancel()
	if err := s.service.Drain(id); err != nil {
		return err
	}
	return s.engine.drainScope(ctx, id)
}
func (s *NodeChainExecutionMeasurement) Invalidate() {
	if s != nil {
		s.engine.closed.Store(true)
		s.service.Invalidate()
		s.engine.retireScope()
	}
}
func (s *NodeChainExecutionMeasurement) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.DrainTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}
func (s *NodeChainExecutionMeasurement) CloseContext(ctx context.Context) error {
	if s == nil || ctx == nil {
		return nodeChainExecutionError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.Invalidate()
	workErr := s.service.CloseContext(ctx)
	return errors.Join(workErr, s.engine.drainScope(ctx, ""))
}
func (s *NodeChainExecutionMeasurement) StatusJSON() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	return s.StatusContextJSON(ctx)
}
func (s *NodeChainExecutionMeasurement) StatusContextJSON(ctx context.Context) string {
	if s == nil {
		return "{}"
	}
	var state hopmeasure.Status
	if json.Unmarshal([]byte(s.service.StatusContextJSON(ctx)), &state) != nil {
		return "{}"
	}
	s.engine.mu.Lock()
	pending := s.engine.scope != nil || s.engine.starting
	s.engine.mu.Unlock()
	if pending {
		state.Drained = false
		if state.Complete && state.Failure == "" {
			state.Complete, state.Stage = false, "draining"
		}
		if state.Complete || state.Stage == "draining" {
			state.Results = []hopmeasure.Result{}
		}
	}
	raw, _ := json.Marshal(state)
	return string(raw)
}

// CompletedThroughputContext returns only a joined, complete upload and download
// from every original selected prefix. Candidate and HTTP50 results have
// different schemas and cannot be adopted as transferred bytes.
func (s *NodeChainExecutionMeasurement) CompletedThroughputContext(ctx context.Context, request, capture string, size int) (hopmeasure.Status, error) {
	var state hopmeasure.Status
	if size != 8<<20 || request == "" || s.VerifySelectedCaptureContext(ctx, capture) != nil {
		return state, nodeChainExecutionError
	}
	if json.Unmarshal([]byte(s.StatusContextJSON(ctx)), &state) != nil || state.Request != request || !state.Complete || !state.Drained ||
		state.Stage != "complete" || state.Failure != "" {
		return hopmeasure.Status{}, nodeChainExecutionError
	}
	selected := s.engine.trial.execution
	projection := s.engine.runtime.projection
	proofs, err := projection.ProofInventory(selected)
	if err != nil || len(proofs) < 2 || len(state.Results) != len(proofs) {
		return hopmeasure.Status{}, errors.Join(err, nodeChainExecutionError)
	}
	transfer := func(t *hopmeasure.Transfer) bool {
		return t != nil && t.Bytes == int64(size) && t.Seconds > 0 && t.Seconds <= hopmeasure.RequestTimeout.Seconds() &&
			t.Mbps > 0 && math.Abs(t.Mbps-8*float64(t.Bytes)/t.Seconds/1e6) < 0.0011
	}
	for position, row := range state.Results {
		role := "intermediate"
		if position == 0 {
			role = "entry"
		} else if position == len(proofs)-1 {
			role = "exit"
		}
		kind := "private-node"
		if projection.policy.importedPublicAt(position) {
			kind = "public-path"
		}
		if proofs[position].Position != position || row.ID != proofs[position].ProfileID || row.Role != role || row.Kind != kind ||
			!row.Ready || row.Failure != "" || row.Idle == nil || row.Idle.Samples != 6 ||
			row.Benchmark != nil || row.Response != nil || !transfer(row.Download) || !transfer(row.Upload) {
			return hopmeasure.Status{}, nodeChainExecutionError
		}
	}
	return state, s.engine.current(ctx)
}
