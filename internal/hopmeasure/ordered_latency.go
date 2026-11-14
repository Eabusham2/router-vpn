package hopmeasure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// OrderedLatencyReceipt is a historical measurement of one captured prefix.
// It is not path readiness, ICMP RTT, candidate reachability or throughput.
// GenerationSHA256 binds the original native identity without exporting it.
type OrderedLatencyReceipt struct {
	Schema           int    `json:"schema"`
	SourceSHA256     string `json:"source_sha256"`
	ConfigSHA256     string `json:"config_sha256"`
	GenerationSHA256 string `json:"generation_sha256"`
	Position         int    `json:"position"`
	NodeID           string `json:"node_id"`
	Request          string `json:"request_id"`
	MeasuredAt       int64  `json:"measured_at"`
	Result           Result `json:"result"`
}

// OrderedLatencyService can select only a hop already validated by the strict
// ordered constructor. It shares the original worker, cancellation, drain and
// native measurement exclusion; it cannot acquire a new route or endpoint.
type OrderedLatencyService struct {
	self                       *OrderedLatencyService
	service                    *Service
	source, config, generation string
	saved                      map[string]string // original service.mu; immutable serialized receipts
	pending                    *OrderedLatencyReceipt
	operation                  *measurementAdmission // original service.mu; exact borrowed worker
	closed                     bool                  // facade only, never the host service
}

func NewOrderedLatencyContext(ctx context.Context, service *Service, sourceSHA256, configSHA256 string) (*OrderedLatencyService, error) {
	return newOrderedLatencyContext(ctx, service, sourceSHA256, configSHA256, nil)
}

// NewOrderedLatencyValidatedContext checks the retained typed host before any
// facade is attached. Failure returns no resource, including on gomobile ABIs
// that discard a nonnil result when an error is returned. The callback runs
// without service.mu and cannot replace the mandatory original service checks.
func NewOrderedLatencyValidatedContext(ctx context.Context, service *Service, sourceSHA256, configSHA256 string, validate func(context.Context) error) (*OrderedLatencyService, error) {
	if validate == nil {
		return nil, errors.New("ordered latency host validation is missing")
	}
	return newOrderedLatencyContext(ctx, service, sourceSHA256, configSHA256, validate)
}
func newOrderedLatencyContext(ctx context.Context, service *Service, sourceSHA256, configSHA256 string, validate func(context.Context) error) (*OrderedLatencyService, error) {
	if ctx == nil || service == nil || !nodeID.MatchString(sourceSHA256) || !nodeID.MatchString(configSHA256) {
		return nil, errors.New("ordered latency requires its captured source")
	}
	if _, ok := service.engine.(CandidateEngine); !ok {
		return nil, errors.New("ordered latency requires original bounded native observation and exclusion")
	}
	if err := service.valid(ctx); err != nil {
		return nil, err
	}
	if validate != nil {
		if err := validate(ctx); err != nil {
			return nil, err
		}
	}
	if err := lockOrderedLatencyService(ctx, service); err != nil {
		return nil, err
	}
	defer service.mu.Unlock()
	if !service.ordered || service.closed || service.pending != nil || service.orderedLatency != nil || ctx.Err() != nil {
		return nil, errors.New("ordered latency requires an unused original ordered owner")
	}
	if service.done != nil {
		select {
		case <-service.done:
		default:
			return nil, errors.New("original measurement worker has not drained")
		}
	}
	digest := sha256.Sum256([]byte(service.identity))
	value := &OrderedLatencyService{service: service, source: sourceSHA256, config: configSHA256, generation: hex.EncodeToString(digest[:]), saved: make(map[string]string)}
	value.self = value
	service.orderedLatency = value
	return value, nil
}
func (o *OrderedLatencyService) originalContext(ctx context.Context) error {
	if o == nil || o.self != o || o.service == nil || ctx == nil {
		return errors.New("original ordered latency owner is unavailable")
	}
	if err := o.lockContext(ctx); err != nil {
		return err
	}
	defer o.service.mu.Unlock()
	if !o.service.ordered || o.service.orderedLatency != o || o.closed {
		return errors.New("original ordered latency owner is unavailable")
	}
	return ctx.Err()
}
func (o *OrderedLatencyService) Start(request, hopID string) error {
	return o.StartContext(context.Background(), request, hopID)
}
func (o *OrderedLatencyService) StartContext(ctx context.Context, request, hopID string) error {
	if err := o.originalContext(ctx); err != nil {
		return err
	}
	if err := o.adoptJoined(ctx); err != nil {
		return err
	}
	for position, hop := range o.service.hops {
		if hop.ID == hopID {
			return o.service.startContextOwned(ctx, request, func(work context.Context) { o.run(work, request, position, hop) }, o)
		}
	}
	return errors.New("latency hop is outside the original ordered inventory")
}

// Cancel never forwards a string-only cancellation to the shared service:
// another worker may have reused that ID after the original request joined.
func (o *OrderedLatencyService) Cancel(request string) {
	if o == nil || o.self != o || o.service == nil {
		return
	}
	s := o.service
	s.mu.Lock()
	defer s.mu.Unlock()
	if op := o.operation; op != nil && op.id == request {
		o.cancelLocked(op)
	}
}
func (o *OrderedLatencyService) cancelLocked(op *measurementAdmission) {
	if op == nil {
		return
	}
	s := o.service
	op.cancel()
	if o.pending != nil && o.pending.Request == op.id {
		o.pending = nil
	}
	if !s.closed && s.done == op.done && s.state.Request == op.id {
		s.state = Status{Request: op.id, Stage: "cancelled", Complete: true, Failure: "Measurement cancelled", Results: []Result{}}
	}
}
func (o *OrderedLatencyService) Drain(request string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DrainTimeout)
	defer cancel()
	return o.DrainContext(ctx, request)
}

func (o *OrderedLatencyService) DrainContext(ctx context.Context, request string) error {
	if o == nil || o.self != o || o.service == nil || ctx == nil {
		return ErrStale
	}
	s := o.service
	if err := o.lockContext(ctx); err != nil {
		return err
	}
	op := o.operation
	s.mu.Unlock()
	if op == nil || op.id != request {
		return errors.New("ordered latency drain belongs to another request")
	}
	return orderedLatencyJoin(ctx, op)
}
func orderedLatencyJoin(ctx context.Context, op *measurementAdmission) error {
	if op == nil {
		return ctx.Err()
	}
	select {
	case <-op.done:
		return nil
	default:
	}
	select {
	case <-op.done:
		return nil
	case <-ctx.Done():
		select {
		case <-op.done:
			return nil
		default:
			return errors.Join(ctx.Err(), errors.New("ordered latency original worker has not drained"))
		}
	}
}
func (o *OrderedLatencyService) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), DrainTimeout)
	defer cancel()
	return o.CloseContext(ctx)
}

// Close retires only this borrowed facade. Timeout retains the same token and
// attachment for retry; host throughput and its original service stay owned.
func (o *OrderedLatencyService) CloseContext(ctx context.Context) error {
	if o == nil || o.self != o || o.service == nil || ctx == nil {
		return ErrStale
	}
	s := o.service
	if err := o.lockContext(ctx); err != nil {
		return err
	}
	o.closed = true
	op := o.operation
	o.cancelLocked(op)
	s.mu.Unlock()
	if err := orderedLatencyJoin(ctx, op); err != nil {
		return err
	}
	if err := o.lockContext(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if o.operation != op {
		return ErrStale
	}
	if s.orderedLatency == o {
		s.orderedLatency = nil
	}
	return ctx.Err()
}
func (o *OrderedLatencyService) lockContext(ctx context.Context) error {
	return lockOrderedLatencyService(ctx, o.service)
}
func lockOrderedLatencyService(ctx context.Context, service *Service) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if service.mu.TryLock() {
			if err := ctx.Err(); err != nil {
				service.mu.Unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (o *OrderedLatencyService) Invalidate() {
	if o == nil || o.self != o || o.service == nil {
		return
	}
	s := o.service
	s.mu.Lock()
	defer s.mu.Unlock()
	o.closed = true
	o.cancelLocked(o.operation)
}
func (o *OrderedLatencyService) StatusJSON() string {
	if o == nil || o.self != o || o.service == nil {
		return "{}"
	}
	s := o.service
	fallback := func(op *measurementAdmission) string {
		state := Status{Stage: "idle", Complete: true, Drained: true, Results: []Result{}}
		if op != nil {
			state.Request = op.id
			state.Stage = "retired"
			select {
			case <-op.done:
			default:
				state.Drained = false
			}
		}
		raw, _ := json.Marshal(state)
		return string(raw)
	}
	s.mu.Lock()
	op := o.operation
	current := op != nil && !o.closed && s.orderedLatency == o && s.done == op.done && s.state.Request == op.id
	s.mu.Unlock()
	if !current {
		return fallback(op)
	}
	raw := s.StatusJSON()
	ctx, cancel := context.WithTimeout(context.Background(), ObservationTimeout)
	defer cancel()
	o.adoptJoined(ctx)
	s.mu.Lock()
	current = o.operation == op && !o.closed && s.orderedLatency == o && s.done == op.done && s.state.Request == op.id
	s.mu.Unlock()
	if !current {
		return fallback(op)
	}
	return raw
}

// SavedJSON remains historical after cancellation or native invalidation. Only
// a complete successful fifty-sample worker replaces it. A host may persist
// this receipt, but must never use it as current proof or another path's score.
func (o *OrderedLatencyService) SavedJSON(hopID string) string {
	if o == nil || o.self != o || o.service == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), ObservationTimeout)
	defer cancel()
	o.adoptJoined(ctx)
	return o.CommittedJSON(hopID)
}

// CommittedJSON reads already committed history without observing the native
// path or adopting a pending result. A stronger native wrapper uses it while
// its original socket or activity release is still joining.
func (o *OrderedLatencyService) CommittedJSON(hopID string) string {
	if o == nil || o.self != o || o.service == nil {
		return ""
	}
	o.service.mu.Lock()
	defer o.service.mu.Unlock()
	return o.saved[hopID]
}
func (o *OrderedLatencyService) run(ctx context.Context, request string, position int, hop Hop) {
	s := o.service
	verify := func() error {
		if boundary, ok := s.engine.(MeasurementBoundary); ok {
			if err := boundary.VerifyMeasurement(ctx); err != nil {
				return err
			}
		}
		return s.valid(ctx)
	}
	values := make([]float64, 0, LatencyBenchmarkSamples)
	failure := verify()
	for failure == nil && len(values) < LatencyBenchmarkSamples {
		if failure = verify(); failure != nil {
			break
		}
		if failure = s.phase(ctx, request, fmt.Sprintf("node %d: response %d/%d", position+1, len(values)+1, LatencyBenchmarkSamples)); failure != nil {
			break
		}
		value, err := s.prove(ctx, hop)
		if err != nil {
			failure = err
			break
		}
		if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			failure = errors.New("invalid original response interval")
			break
		}
		values = append(values, value)
	}
	boundary := verify()
	result := Result{ID: hop.ID, Role: hop.Role, Kind: hop.Kind, Label: hop.Label}
	if failure == nil && boundary == nil && len(values) == LatencyBenchmarkSamples {
		ordered := append([]float64(nil), values...)
		sort.Float64s(ordered)
		trim := len(ordered) / 10
		mean := 0.0
		for _, value := range ordered[trim : len(ordered)-trim] {
			mean += value
		}
		mean /= float64(len(ordered) - 2*trim)
		metric := "routed-private-response-including-connection"
		endpoint := "" // private API and credentials never enter a receipt
		if hop.Kind == "public-path" {
			metric = "routed-https-response-after-tls"
			endpoint = "https://" + PublicHost + "/__down?bytes=1"
		}
		result.Ready = true
		result.Benchmark = &LatencyBenchmark{Schema: 1, Measurement: metric, Endpoint: endpoint, Attempts: LatencyBenchmarkSamples, Failed: 0, Distribution: distribution(values), TrimmedMean: mean}
	} else {
		result.Failure = "No complete 50-sample ordered response benchmark; previous saved result unchanged"
	}
	finalError := s.valid(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Request != request || s.state.Complete || o.closed || s.orderedLatency != o || o.operation == nil || s.done != o.operation.done || o.operation.id != request {
		return
	}
	s.state.Complete = true
	s.state.Stage = "complete"
	if boundary != nil || ctx.Err() != nil || finalError != nil || s.closed || s.orderedLatency != o {
		s.state.Stage = "invalidated"
		s.state.Failure = "Captured ordered path changed or measurement was cancelled"
		s.state.Results = []Result{}
		return
	}
	s.state.Results = []Result{result}
	if !result.Ready {
		return
	}
	receipt := OrderedLatencyReceipt{Schema: 1, SourceSHA256: o.source, ConfigSHA256: o.config, GenerationSHA256: o.generation, Position: position, NodeID: hop.ID, Request: request, MeasuredAt: time.Now().UnixMilli(), Result: result}
	o.pending = &receipt
}

// Commit only after the original work, sockets and resource release have all
// joined. Cancel/stale/failure before that boundary cannot replace saved data.
func (o *OrderedLatencyService) adoptJoined(ctx context.Context) error {
	if ctx == nil {
		return errors.New("ordered latency receipt has no caller")
	}
	s := o.service
	if boundary, ok := s.engine.(MeasurementBoundary); ok {
		if err := boundary.VerifyMeasurement(ctx); err != nil {
			return err
		}
	}
	if err := s.valid(ctx); err != nil {
		return err
	}
	if err := o.lockContext(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	pending := o.pending
	if pending == nil || o.closed || s.closed || s.orderedLatency != o || o.operation == nil || s.done != o.operation.done || s.pending != nil || o.operation.id != pending.Request || s.state.Request != pending.Request || !s.state.Complete || s.state.Stage != "complete" || s.state.Failure != "" || len(s.state.Results) != 1 || !s.state.Results[0].Ready || ctx.Err() != nil {
		return ctx.Err()
	}
	if s.done == nil {
		return nil
	}
	select {
	case <-s.done:
	default:
		return nil
	}
	raw, err := json.Marshal(pending)
	if err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	o.saved[pending.NodeID] = string(raw)
	o.pending = nil
	return nil
}
