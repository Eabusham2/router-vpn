package hopmeasure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

const PathResponseSamples = 3
const PathResponseTimeout = 10 * time.Second

// PathResponse is a short live HTTPS response measurement on the already
// proved external path. It is separate from the durable fifty-sample benchmark
// and cannot enter direct-node TCP or ICMP rankings.
type PathResponse struct {
	Schema       int      `json:"schema"`
	Measurement  string   `json:"measurement"`
	Endpoint     string   `json:"endpoint"`
	Attempts     int      `json:"attempts"`
	Distribution *Latency `json:"distribution"`
}

// StartResponse accepts only the exit sealed into this retained native owner.
// DNS, endpoint, outbound, credentials and sample count are not caller inputs.
func (s *Service) StartResponse(id, exitID string) error {
	return s.StartResponseContext(context.Background(), id, exitID)
}

func (s *Service) StartResponseContext(ctx context.Context, id, exitID string) error {
	if s == nil || exitID == "" {
		return errors.New("a captured external exit is required")
	}
	for _, hop := range s.hops {
		if hop.ID == exitID && hop.Role == "exit" && hop.Kind == "public-path" && hop.Tag == "custom-exit" {
			return s.startContext(ctx, id, func(parent context.Context) {
				worker, cancel := context.WithTimeout(parent, PathResponseTimeout)
				defer cancel()
				s.runResponse(worker, id, hop)
			})
		}
	}
	return errors.New("live response belongs to the captured external exit")
}

func (s *Service) runResponse(ctx context.Context, id string, hop Hop) {
	verify := func() error {
		if boundary, ok := s.engine.(MeasurementBoundary); ok {
			if err := boundary.VerifyMeasurement(ctx); err != nil {
				return err
			}
		}
		return s.valid(ctx)
	}
	result := Result{ID: hop.ID, Role: hop.Role, Kind: hop.Kind, Label: hop.Label}
	boundaryFailure := verify()
	failure := boundaryFailure
	samples := make([]float64, 0, PathResponseSamples)
	if failure == nil {
		for len(samples) < PathResponseSamples {
			if failure = s.phase(ctx, id, fmt.Sprintf("exit: live HTTPS response %d/%d", len(samples)+1, PathResponseSamples)); failure != nil {
				break
			}
			value, err := s.provePublic(ctx, hop)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
				failure = errors.New("captured live HTTPS response failed")
				break
			}
			samples = append(samples, value)
		}
	}
	if boundaryFailure == nil {
		boundaryFailure = verify()
	}
	if failure == nil && boundaryFailure == nil && len(samples) == PathResponseSamples {
		result.Response = &PathResponse{Schema: 1, Measurement: "routed-https-response-after-tls",
			Endpoint: "https://" + PublicHost + "/__down?bytes=1", Attempts: PathResponseSamples, Distribution: distribution(samples)}
		result.Ready = true
	} else {
		// No partial score or raw native error may be published.
		result.Failure = "No complete current-path HTTPS response measurement"
	}
	finalError := s.valid(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Request != id || s.state.Complete {
		return
	}
	s.state.Complete = true
	s.state.Stage = "complete"
	if boundaryFailure != nil || ctx.Err() != nil || finalError != nil {
		s.state.Stage = "invalidated"
		s.state.Failure = "Session changed or live response measurement timed out"
		s.state.Results = []Result{}
		return
	}
	s.state.Results = []Result{result}
}

// StartOrderedResponseContext samples the retained private final and, when
// paired, the retained private entry. Imported entries have no private API.
func (s *Service) StartOrderedResponseContext(ctx context.Context, id string, samples int) error {
	if s == nil || !s.ordered || len(s.hops) < 2 || samples < 1 || samples > 10 {
		return errors.New("an ordered private path and 1–10 responses are required")
	}
	entry, exit := s.hops[0], s.hops[len(s.hops)-1]
	if entry.Role != "entry" || exit.Role != "exit" || (entry.Kind != "private-node" && entry.Kind != "public-path") || exit.Kind != "private-node" {
		return errors.New("ordered live responses require the original private final endpoint")
	}
	endpoints := []Hop{entry, exit}
	if entry.Kind == "public-path" {
		endpoints = endpoints[1:]
	}
	return s.startContext(ctx, id, func(parent context.Context) {
		worker, cancel := context.WithTimeout(parent, PathResponseTimeout)
		defer cancel()
		rows := make([]Result, 0, 2)
		verify := func() error {
			if boundary, ok := s.engine.(MeasurementBoundary); ok {
				if err := boundary.VerifyMeasurement(worker); err != nil {
					return err
				}
			}
			return s.valid(worker)
		}
		for _, hop := range endpoints {
			if verify() != nil || s.phase(worker, id, hop.Role+": live private response") != nil {
				break
			}
			measured, err := s.latency(worker, hop, samples)
			if err != nil || verify() != nil {
				break
			}
			rows = append(rows, Result{ID: hop.ID, Role: hop.Role, Kind: hop.Kind, Label: hop.Label, Ready: true,
				Response: &PathResponse{Schema: 1, Measurement: "routed-private-response-including-connection", Attempts: samples, Distribution: measured}})
		}
		valid := len(rows) == len(endpoints) && verify() == nil && worker.Err() == nil
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.state.Request != id || s.state.Complete {
			return
		}
		s.state.Complete = true
		if !valid {
			s.state.Stage = "invalidated"
			s.state.Failure = "The complete original private path could not be measured"
			s.state.Results = []Result{}
			return
		}
		s.state.Stage = "complete"
		s.state.Results = rows
	})
}

// OrderedResponseLatencies validates every original private endpoint, with a
// mandatory private final. An imported entry has no private response row.
func OrderedResponseLatencies(status Status, request string, samples int, endpoints [2]Hop) ([2]Latency, error) {
	var values [2]Latency
	bad := errors.New("incomplete ordered private response")
	if request == "" || samples < 1 || samples > 10 || status.Request != request || !status.Complete || !status.Drained || status.Stage != "complete" || status.Failure != "" {
		return values, bad
	}
	first := 0
	if endpoints[0].Kind == "public-path" {
		first = 1
	} else if endpoints[0].Kind != "private-node" {
		return values, bad
	}
	if endpoints[0].ID == "" || endpoints[0].ID == endpoints[1].ID || endpoints[1].Kind != "private-node" || len(status.Results) != len(endpoints)-first {
		return values, bad
	}
	for i := first; i < len(endpoints); i++ {
		row, original := status.Results[i-first], endpoints[i]
		role := "entry"
		if i == 1 {
			role = "exit"
		}
		r := row.Response
		if original.ID == "" || original.Label == "" || row.ID != original.ID || row.Label != original.Label || row.Kind != "private-node" || row.Role != role || !row.Ready ||
			row.Failure != "" || row.Idle != nil || row.Download != nil || row.Upload != nil || row.Benchmark != nil || r == nil || r.Schema != 1 ||
			r.Measurement != "routed-private-response-including-connection" || r.Endpoint != "" || r.Attempts != samples || r.Distribution == nil {
			return values, bad
		}
		d := r.Distribution
		if d.Samples != samples || d.Min > d.Median || d.Median > d.P90 || d.P90 > d.Max || math.IsNaN(d.Jitter) || math.IsInf(d.Jitter, 0) || d.Jitter < 0 || d.Jitter > d.Max-d.Min {
			return values, bad
		}
		for _, v := range []float64{d.Min, d.Median, d.Average, d.P90, d.Max} {
			if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || v > float64(PathResponseTimeout.Milliseconds()) || v < d.Min || v > d.Max {
				return values, bad
			}
		}
		values[i] = *d
	}
	return values, nil
}

// CompletedOrderedResponseContext rechecks the retained service and its exact
// joined native request. Its endpoint IDs and labels come from the same source
// that opened the private measurement sockets.
func (s *Service) CompletedOrderedResponseContext(ctx context.Context, request string, samples int) (Status, error) {
	var state Status
	if s == nil || !s.ordered || len(s.hops) < 2 || s.valid(ctx) != nil {
		return state, errors.New("ordered response owner unavailable")
	}
	if json.Unmarshal([]byte(s.StatusContextJSON(ctx)), &state) != nil {
		return Status{}, errors.New("invalid ordered response status")
	}
	_, err := OrderedResponseLatencies(state, request, samples, [2]Hop{s.hops[0], s.hops[len(s.hops)-1]})
	if err != nil {
		return Status{}, err
	}
	if err := s.valid(ctx); err != nil {
		return Status{}, err
	}
	return state, nil
}
