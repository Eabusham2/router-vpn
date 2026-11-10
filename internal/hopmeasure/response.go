package hopmeasure

import (
	"context"
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
