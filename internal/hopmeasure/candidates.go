package hopmeasure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const CandidateReceiptLifetime = 120 * time.Second
const CandidateMaximumTargets = 64

// CandidateEngine must keep the original native path, catalog revision and MTU
// hold. A generic network dialer is deliberately insufficient for this API.
type CandidateEngine interface {
	Engine
	ContextEngine
	ContextMeasurementScope
	MeasurementBoundary
}

// CandidateTarget is private construction input from a validated source. Only
// its ID and source digest may appear in the public receipt, never its address.
type CandidateTarget struct {
	ID, SourceSHA256, Address string
}

type CandidatePrefix struct {
	Position      int
	ID, Tag       string
	CaptureSHA256 string
}

// CandidateStatus is a fresh TCP connection timing through one exact retained
// prefix. It is neither an ICMP result nor proof of the candidate's credentials.
type CandidateStatus struct {
	Status
	Schema                int    `json:"schema"`
	Measurement           string `json:"measurement"`
	PrefixPosition        int    `json:"prefix_position"`
	PrefixID              string `json:"prefix_id"`
	CaptureSHA256         string `json:"capture_sha256"`
	CandidateID           string `json:"candidate_id,omitempty"`
	CandidateSourceSHA256 string `json:"candidate_source_sha256,omitempty"`
	MeasuredAt            int64  `json:"measured_at,omitempty"`
	ExpiresAt             int64  `json:"expires_at,omitempty"`
}

type candidateCompletion struct {
	request, id, source string
	measured            time.Time
}

type CandidateService struct {
	service    *Service
	prefix     CandidatePrefix
	targets    []CandidateTarget
	completion candidateCompletion // protected by service.mu
}

func candidateText(value string) bool {
	if value == "" || len(value) > 128 || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func NewPrefixCandidatesContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget) (*CandidateService, error) {
	if ctx == nil || engine == nil || prefix.Position < 0 || prefix.Position > 7 ||
		!candidateText(prefix.ID) || !orderedPrefixTag.MatchString(prefix.Tag) ||
		!strings.HasPrefix(prefix.Tag, "routervpn-chain-"+strconv.Itoa(prefix.Position)+"-") ||
		!nodeID.MatchString(prefix.CaptureSHA256) || len(targets) == 0 || len(targets) > CandidateMaximumTargets {
		return nil, errors.New("candidate measurement requires its sealed original prefix and source inventory")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, target := range targets {
		host, port, err := net.SplitHostPort(target.Address)
		ip, ipErr := netip.ParseAddr(host)
		number, portErr := strconv.Atoi(port)
		if !candidateText(target.ID) || target.ID == prefix.ID || seen[target.ID] || !nodeID.MatchString(target.SourceSHA256) ||
			err != nil || ipErr != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() ||
			portErr != nil || number < 1 || number > 65535 || net.JoinHostPort(ip.String(), strconv.Itoa(number)) != target.Address {
			return nil, errors.New("candidate measurement requires exact captured literal TCP endpoints")
		}
		seen[target.ID] = true
	}
	if err := engine.VerifyMeasurement(ctx); err != nil {
		return nil, err
	}
	identity, err := observedIdentity(ctx, engine)
	if err != nil {
		return nil, err
	}
	service := &Service{engine: engine, identity: identity, state: Status{Stage: "idle", Results: []Result{}}}
	return &CandidateService{service: service, prefix: prefix, targets: append([]CandidateTarget(nil), targets...)}, nil
}

// Start accepts only a previously sealed candidate ID. Each result requires
// all fifty fresh connections within the existing complete request budget.
func (s *CandidateService) Start(request, candidateID string) error {
	return s.StartContext(context.Background(), request, candidateID)
}

func (s *CandidateService) StartContext(ctx context.Context, request, candidateID string) error {
	if s == nil || s.service == nil {
		return errors.New("candidate measurement has no retained owner")
	}
	for _, target := range s.targets {
		if target.ID == candidateID {
			return s.service.startContext(ctx, request, func(ctx context.Context) { s.run(ctx, request, target) })
		}
	}
	return errors.New("candidate is outside the original source inventory")
}

func (s *CandidateService) run(ctx context.Context, request string, target CandidateTarget) {
	service := s.service
	verify := func() error {
		if err := service.engine.(MeasurementBoundary).VerifyMeasurement(ctx); err != nil {
			return err
		}
		return service.valid(ctx)
	}
	result := Result{ID: target.ID, Role: "candidate", Kind: "tcp-connect", Label: fmt.Sprintf("TCP connection to candidate through node %d", s.prefix.Position+1)}
	samples := make([]float64, 0, LatencyBenchmarkSamples)
	boundaryFailure := verify()
	failure := boundaryFailure
	if failure == nil {
		for len(samples) < LatencyBenchmarkSamples {
			if failure = service.phase(ctx, request, fmt.Sprintf("candidate: TCP connection %d/%d", len(samples)+1, LatencyBenchmarkSamples)); failure != nil {
				break
			}
			probe, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			interval, clockErr := StartInterval()
			var connection net.Conn
			var dialErr error
			if clockErr == nil {
				connection, dialErr = service.engine.Dial(probe, s.prefix.Tag, target.Address)
			}
			elapsed, elapsedErr := interval.Milliseconds()
			var closeErr error
			if connection != nil {
				// A blocked native Close keeps the original worker and MTU hold.
				// Cancel/Close cannot publish a successful drain while it is pending.
				closeErr = connection.Close()
			}
			probeErr := probe.Err()
			cancel()
			failure = errors.Join(clockErr, dialErr, elapsedErr, closeErr, probeErr)
			if failure != nil || connection == nil || elapsed <= 0 || math.IsNaN(elapsed) || math.IsInf(elapsed, 0) {
				failure = errors.New("candidate TCP connection did not complete")
				break
			}
			if boundaryFailure = verify(); boundaryFailure != nil {
				break
			}
			samples = append(samples, elapsed)
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
		result.Benchmark = &LatencyBenchmark{Schema: 1, Measurement: "routed-tcp-connect", Attempts: LatencyBenchmarkSamples, Distribution: distribution(samples), TrimmedMean: mean}
		result.Ready = true
	} else {
		result.Failure = "No complete 50-sample TCP connection result; this candidate has no score"
	}
	finalError := service.valid(ctx)
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.state.Request != request || service.state.Complete {
		return
	}
	service.state.Complete, service.state.Stage = true, "complete"
	if boundaryFailure != nil || ctx.Err() != nil || finalError != nil {
		service.state.Stage, service.state.Failure = "invalidated", "Original prefix or candidate inventory changed, or the request expired"
		service.state.Results = []Result{}
		return
	}
	s.completion = candidateCompletion{request, target.ID, target.SourceSHA256, time.Now()}
	service.state.Results = []Result{result}
}

func (s *CandidateService) Cancel(request string)      { s.service.Cancel(request) }
func (s *CandidateService) Drain(request string) error { return s.service.Drain(request) }
func (s *CandidateService) Invalidate()                { s.service.Invalidate() }
func (s *CandidateService) Close() error               { return s.service.Close() }
func (s *CandidateService) CloseContext(ctx context.Context) error {
	return s.service.CloseContext(ctx)
}
func (s *CandidateService) StatusJSON() string {
	ctx, cancel := context.WithTimeout(context.Background(), ObservationTimeout)
	defer cancel()
	return s.StatusContextJSON(ctx)
}
func (s *CandidateService) StatusContextJSON(ctx context.Context) string {
	status := CandidateStatus{Schema: 1, Measurement: "routed-tcp-connect", PrefixPosition: s.prefix.Position, PrefixID: s.prefix.ID, CaptureSHA256: s.prefix.CaptureSHA256}
	_ = json.Unmarshal([]byte(s.service.StatusContextJSON(ctx)), &status.Status)
	s.service.mu.Lock()
	completion := s.completion
	current := status.Request == s.service.state.Request
	s.service.mu.Unlock()
	if !current {
		status.Status = Status{Request: status.Request, Stage: "invalidated", Complete: true, Failure: "Candidate request was replaced", Results: []Result{}}
	} else if status.Complete && !status.Drained {
		status.Complete, status.Stage, status.Results = false, "draining", []Result{}
	} else if status.Complete && status.Stage == "complete" && completion.request == status.Request {
		if time.Since(completion.measured) >= CandidateReceiptLifetime {
			status.Stage, status.Failure, status.Results = "expired", "Candidate result expired; retest the captured path", []Result{}
		} else {
			status.CandidateID, status.CandidateSourceSHA256 = completion.id, completion.source
			status.MeasuredAt, status.ExpiresAt = completion.measured.UnixMilli(), completion.measured.Add(CandidateReceiptLifetime).UnixMilli()
		}
	}
	raw, _ := json.Marshal(status)
	return string(raw)
}
