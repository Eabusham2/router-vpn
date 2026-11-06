package hopmeasure

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
)

const LatencyBenchmarkSamples = 50

// LatencyBenchmark describes HTTPS response time through one retained native
// exit. Preparation (selected DNS, TCP and TLS) precedes each timed request;
// this is neither ICMP RTT nor a response from the external VPN server itself.
type LatencyBenchmark struct {
	Schema       int      `json:"schema"`
	Measurement  string   `json:"measurement"`
	Endpoint     string   `json:"endpoint"`
	Attempts     int      `json:"attempts"`
	Failed       int      `json:"failed"`
	Distribution *Latency `json:"distribution"`
	TrimmedMean  float64  `json:"trimmed_mean_ms"`
}

// StartLatency can select only the exit already sealed into this native
// measurement owner. It accepts no endpoint, DNS, outbound or credentials.
func (s *Service) StartLatency(id, exitID string) error {
	return s.StartLatencyContext(context.Background(), id, exitID)
}

func (s *Service) StartLatencyContext(ctx context.Context, id, exitID string) error {
	if s == nil || exitID == "" {
		return errors.New("a captured external exit is required")
	}
	for _, hop := range s.hops {
		if hop.ID == exitID && hop.Role == "exit" && hop.Kind == "public-path" && hop.Tag == "custom-exit" {
			return s.startContext(ctx, id, func(ctx context.Context) { s.runLatency(ctx, id, hop) })
		}
	}
	return errors.New("latency benchmark belongs to the captured external exit")
}

func (s *Service) runLatency(ctx context.Context, id string, hop Hop) {
	verify := func() error {
		if boundary, ok := s.engine.(MeasurementBoundary); ok {
			if err := boundary.VerifyMeasurement(ctx); err != nil {
				return err
			}
		}
		return s.valid(ctx)
	}
	result := Result{ID: hop.ID, Role: hop.Role, Kind: hop.Kind, Label: hop.Label}
	samples := make([]float64, 0, LatencyBenchmarkSamples)
	boundaryFailure := verify()
	failure := boundaryFailure
	var probeFailure publicMeasurementFailure
	if failure == nil {
		for len(samples) < LatencyBenchmarkSamples {
			if failure = s.phase(ctx, id, fmt.Sprintf("exit: HTTPS response %d/%d", len(samples)+1, LatencyBenchmarkSamples)); failure != nil {
				break
			}
			value, err := s.provePublic(ctx, hop)
			if err != nil {
				failure = err
				// Only our fixed probe messages may explain a failed sample.
				// Never publish a native engine/proof error or a partial score.
				probeFailure, _ = err.(publicMeasurementFailure)
				break
			}
			if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
				failure = errors.New("captured HTTPS response failed")
				break
			}
			samples = append(samples, value)
		}
	}
	if boundaryFailure == nil {
		boundaryFailure = verify()
	}
	if failure == nil && boundaryFailure == nil && len(samples) == LatencyBenchmarkSamples {
		sorted := append([]float64(nil), samples...)
		sort.Float64s(sorted)
		trim := len(sorted) / 10
		mean := 0.0
		for _, value := range sorted[trim : len(sorted)-trim] {
			mean += value
		}
		mean /= float64(len(sorted) - 2*trim)
		result.Benchmark = &LatencyBenchmark{Schema: 1, Measurement: "routed-https-response-after-tls", Endpoint: "https://" + PublicHost + "/__down?bytes=1",
			Attempts: LatencyBenchmarkSamples, Failed: 0, Distribution: distribution(samples), TrimmedMean: mean}
		result.Ready = true
	} else {
		result.Failure = "No complete 50-sample HTTPS response benchmark; the previous saved result must remain unchanged"
		if probeFailure != "" {
			result.Failure += " (" + string(probeFailure) + ")"
		}
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
		s.state.Failure = "Session changed or latency measurement timed out"
		s.state.Results = []Result{}
		return
	}
	s.state.Results = []Result{result}
}
