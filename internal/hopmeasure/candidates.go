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

var ErrCandidateNotRegistered = errors.New("paired candidate is not registered on the selected server")

const CandidateNotRegistered = "not-registered"

const (
	CandidateTCPMeasurement             = "routed-tcp-connect"
	CandidatePrivateResponseMeasurement = "routed-candidate-response"
	CandidatePublicResponseMeasurement  = "routed-public-candidate-response"
	CandidatePublicResponseEndpoint     = "https://1.1.1.1/cdn-cgi/trace"
)

// CandidateInventoryBytes bounds one native target frame. A retained source
// can contain multiple such frames.
const CandidateInventoryBytes = 64 << 10

func CandidateTargetsWithinBudget(targets []CandidateTarget) bool {
	return candidateTargetsWithinBytes(targets, CandidateInventoryBytes)
}

func candidateTargetsWithinBytes(targets []CandidateTarget, limit int) bool {
	if len(targets) == 0 {
		return false
	}
	bytes := 2
	for _, target := range targets {
		bytes += len(target.ID) + len(target.SourceSHA256) + len(target.Address) + 1
		if bytes > limit {
			return false
		}
	}
	raw, err := json.Marshal(targets)
	return err == nil && len(raw) <= limit
}

// CandidateEngine must keep the original native path, catalog revision and MTU
// hold. A generic network dialer is deliberately insufficient for this API.
type CandidateEngine interface {
	Engine
	ContextEngine
	ContextMeasurementScope
	MeasurementBoundary
}

// BoundaryIdentityCandidateEngine provides identity and complete measurement
// verification from the same fresh observation. It must perform every native,
// source, inventory, capture, lifetime and transport check of VerifyMeasurement
// before returning the corresponding identity, within the supplied caller.
// No observation may be reused across boundaries, requests or status reads.
// Engines without this contract retain separate boundary and identity checks.
type BoundaryIdentityCandidateEngine interface {
	CandidateEngine
	VerifyMeasurementIdentityContext(context.Context) (string, error)
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
	service                  *Service
	prefix                   CandidatePrefix
	targets                  []CandidateTarget
	response                 func(context.Context, CandidateTarget, func() error) error
	responseRun              func(context.Context, CandidateTarget) (CandidateResponseRun, error)
	publicResponse           func(context.Context, CandidateTarget, func() error, func() error) error
	registeredPublicResponse func(context.Context, CandidateTarget) (time.Duration, error)
	completion               candidateCompletion // protected by service.mu
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
	return newPrefixCandidatesContext(ctx, engine, prefix, targets, CandidateInventoryBytes, 8)
}

// NewCapturedPrefixCandidatesContext admits an in-process private source inventory.
// Each actual remote connection request still carries only its original selected target.
func NewCapturedPrefixCandidatesContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, sourceLimit int) (*CandidateService, error) {
	if sourceLimit <= 0 || sourceLimit > 40<<20 {
		return nil, errors.New("invalid captured candidate inventory bound")
	}
	return newPrefixCandidatesContext(ctx, engine, prefix, targets, sourceLimit, 8)
}

// NewCapturedResponseCandidatesContext owns one complete authenticated response per sample.
func NewCapturedResponseCandidatesContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, response func(context.Context, CandidateTarget, func() error) error) (*CandidateService, error) {
	if response == nil {
		return nil, errors.New("missing original candidate response owner")
	}
	service, err := NewCapturedPrefixCandidatesContext(ctx, engine, prefix, targets, limit)
	if err == nil {
		service.response = response
	}
	return service, err
}

// CandidateResponseRun retains one authenticated transport for this request.
// Each Respond opens a fresh stream and validates a fresh private challenge.
// Close joins the transport before any score or drained state is published.
type CandidateResponseRun interface {
	Respond(context.Context, func() error) error
	Close() error
}

func NewCapturedResponseRunContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, open func(context.Context, CandidateTarget) (CandidateResponseRun, error)) (*CandidateService, error) {
	if open == nil {
		return nil, ErrStale
	}
	service, err := NewCapturedPrefixCandidatesContext(ctx, engine, prefix, targets, limit)
	if err == nil {
		service.responseRun = open
	}
	return service, err
}

// ExtendedResponseCandidateAuthority binds a deep stream measurement to its
// sealed original imported route, selected proof, and candidate inventory.
type ExtendedResponseCandidateAuthority interface {
	ResponseCandidateDepth(position int, id, tag string) int
}

func NewExtendedResponseCandidatesContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, authority ExtendedResponseCandidateAuthority, response func(context.Context, CandidateTarget, func() error) error) (*CandidateService, error) {
	if authority == nil || response == nil || limit <= 0 || limit > 40<<20 {
		return nil, ErrStale
	}
	count := authority.ResponseCandidateDepth(prefix.Position, prefix.ID, prefix.Tag)
	if count <= 8 || count > 96 || prefix.Position < 1 || prefix.Position >= count-1 {
		return nil, ErrStale
	}
	service, err := newPrefixCandidatesContext(ctx, engine, prefix, targets, limit, count)
	if err == nil {
		service.response = response
	}
	return service, err
}

// NewExtendedResponseRunContext retains one native endpoint
// only when its original complete Local factory seals the deeper packet role.
// Ordinary captures and the imported-stream constructors keep their bounds.
func NewExtendedResponseRunContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, authority ExtendedResponseCandidateAuthority, open func(context.Context, CandidateTarget) (CandidateResponseRun, error)) (*CandidateService, error) {
	if authority == nil || open == nil || limit <= 0 || limit > 40<<20 {
		return nil, ErrStale
	}
	count := authority.ResponseCandidateDepth(prefix.Position, prefix.ID, prefix.Tag)
	if count <= 8 || count > 96 || prefix.Position < 0 || prefix.Position >= count-2 {
		return nil, ErrStale
	}
	service, err := newPrefixCandidatesContext(ctx, engine, prefix, targets, limit, count)
	if err == nil {
		service.responseRun = open
	}
	return service, err
}

// PublicResponseCandidateAuthority binds the public response target inventory
// to the exact original imported-exit route and selected imported prefix.
type PublicResponseCandidateAuthority interface {
	PublicResponseCandidateDepth(position int, id, tag string) int
}

func NewPublicResponseCandidatesContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, authority PublicResponseCandidateAuthority, response func(context.Context, CandidateTarget, func() error, func() error) error) (*CandidateService, error) {
	if authority == nil || response == nil || limit <= 0 || limit > 40<<20 {
		return nil, ErrStale
	}
	count := authority.PublicResponseCandidateDepth(prefix.Position, prefix.ID, prefix.Tag)
	if count < 3 || count > 96 || prefix.Position < 1 || prefix.Position >= count-1 {
		return nil, ErrStale
	}
	service, err := newPrefixCandidatesContext(ctx, engine, prefix, targets, limit, count)
	if err == nil {
		service.publicResponse = response
	}
	return service, err
}

// AppendPublicResponseCandidateAuthority reports the real retained prefix,
// not a complete route with an invented final. Its exact source/owner is
// checked by the native append preparation before this shared service opens.
type AppendPublicResponseCandidateAuthority interface {
	AppendPublicResponseCandidateDepth(position int, id, tag string) int
	AppendPublicResponseCandidateTarget(position int, id, tag string, target CandidateTarget) bool
}

func NewAppendPublicResponseCandidatesContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, authority AppendPublicResponseCandidateAuthority, response func(context.Context, CandidateTarget, func() error, func() error) error) (*CandidateService, error) {
	if authority == nil || response == nil || limit <= 0 || limit > 40<<20 {
		return nil, ErrStale
	}
	count := authority.AppendPublicResponseCandidateDepth(prefix.Position, prefix.ID, prefix.Tag)
	if count < 1 || count >= 96 || prefix.Position != count-1 {
		return nil, ErrStale
	}
	service, err := newPrefixCandidatesContextOwnedTargets(ctx, engine, prefix, targets, limit, count, func(target CandidateTarget) bool {
		return authority.AppendPublicResponseCandidateTarget(prefix.Position, prefix.ID, prefix.Tag, target)
	})
	if err == nil {
		service.publicResponse = response
	}
	return service, err
}

// NewRegisteredPublicResponseCandidatesContext retains the registered worker's
// authenticated post-TLS duration. Transport to its control front is outside
// the response timing interval, just as it is for the Local HTTPS owner.
func NewRegisteredPublicResponseCandidatesContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, authority PublicResponseCandidateAuthority, response func(context.Context, CandidateTarget) (time.Duration, error)) (*CandidateService, error) {
	if authority == nil || response == nil || limit <= 0 || limit > 40<<20 {
		return nil, ErrStale
	}
	count := authority.PublicResponseCandidateDepth(prefix.Position, prefix.ID, prefix.Tag)
	if count < 3 || count > 96 || prefix.Position < 1 || prefix.Position >= count-1 {
		return nil, ErrStale
	}
	s, err := newPrefixCandidatesContext(ctx, engine, prefix, targets, limit, count)
	if err == nil {
		s.registeredPublicResponse = response
	}
	return s, err
}

func (s *CandidateService) measurement() string {
	if s.publicResponse != nil || s.registeredPublicResponse != nil {
		return CandidatePublicResponseMeasurement
	}
	if s.response != nil || s.responseRun != nil {
		return CandidatePrivateResponseMeasurement
	}
	return CandidateTCPMeasurement
}

// Only the validated original all-paired Local factory can seal a deeper
// packet prefix. Ordinary clients retain the eight-position authorization.
type ExtendedPacketCandidateAuthority interface {
	PacketCandidateDepth(position int, id, tag string) int
}

func NewExtendedPacketCandidatesContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, authority ExtendedPacketCandidateAuthority) (*CandidateService, error) {
	if authority == nil || limit <= 0 || limit > 40<<20 {
		return nil, ErrStale
	}
	count := authority.PacketCandidateDepth(prefix.Position, prefix.ID, prefix.Tag)
	if count <= 8 || count > 96 || prefix.Position >= count-1 {
		return nil, ErrStale
	}
	return newPrefixCandidatesContext(ctx, engine, prefix, targets, limit, count)
}

func newPrefixCandidatesContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, depth int) (*CandidateService, error) {
	return newPrefixCandidatesContextOwnedTargets(ctx, engine, prefix, targets, limit, depth, nil)
}

func newPrefixCandidatesContextOwnedTargets(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, depth int, originalHostname func(CandidateTarget) bool) (*CandidateService, error) {
	if ctx == nil || engine == nil || prefix.Position < 0 || prefix.Position >= depth ||
		!candidateText(prefix.ID) || !orderedPrefixTag.MatchString(prefix.Tag) ||
		!strings.HasPrefix(prefix.Tag, "routervpn-chain-"+strconv.Itoa(prefix.Position)+"-") ||
		!nodeID.MatchString(prefix.CaptureSHA256) || !candidateTargetsWithinBytes(targets, limit) {
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
		literal := ipErr == nil && ip.Zone() == "" && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsMulticast() && net.JoinHostPort(ip.String(), strconv.Itoa(number)) == target.Address
		hostname := ipErr != nil && originalHostname != nil && originalHostname(target)
		if !candidateText(target.ID) || target.ID == prefix.ID || seen[target.ID] || !nodeID.MatchString(target.SourceSHA256) ||
			err != nil || portErr != nil || number < 1 || number > 65535 || !literal && !hostname {
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

// RegisteredPublicCandidateIntervalLimit bounds the original remote HTTPS
// observation and its serialized successful measurements.
const RegisteredPublicCandidateIntervalLimit = 2500 * time.Millisecond

func (s *CandidateService) run(ctx context.Context, request string, target CandidateTarget) {
	service := s.service
	verify := func() error {
		if engine, ok := service.engine.(BoundaryIdentityCandidateEngine); ok {
			return service.validWithIdentity(ctx, engine.VerifyMeasurementIdentityContext)
		}
		if err := service.engine.(MeasurementBoundary).VerifyMeasurement(ctx); err != nil {
			return err
		}
		return service.valid(ctx)
	}
	result := Result{ID: target.ID, Role: "candidate", Kind: "tcp-connect", Label: fmt.Sprintf("TCP connection to candidate through node %d", s.prefix.Position+1)}
	phase := "TCP connection"
	public := s.measurement() == CandidatePublicResponseMeasurement
	private := s.measurement() == CandidatePrivateResponseMeasurement
	if public {
		phase = "public exit HTTPS response"
		result.Kind = "public-exit-response"
		result.Label = fmt.Sprintf("Verified public exit HTTPS response through node %d and candidate", s.prefix.Position+1)
	} else if private {
		phase = "private agent response"
		result.Kind = "private-agent-response"
		result.Label = fmt.Sprintf("Authenticated candidate response through node %d", s.prefix.Position+1)
	}
	samples := make([]float64, 0, LatencyBenchmarkSamples)
	boundaryFailure := verify()
	failure := boundaryFailure
	var run CandidateResponseRun
	if failure == nil && s.responseRun != nil {
		run, failure = s.responseRun(ctx, target)
		if run == nil && failure == nil {
			failure = ErrStale
		}
	}
	if failure == nil {
		for len(samples) < LatencyBenchmarkSamples {
			if failure = service.phase(ctx, request, fmt.Sprintf("candidate: %s %d/%d", phase, len(samples)+1, LatencyBenchmarkSamples)); failure != nil {
				break
			}
			probe, cancel := context.WithTimeout(ctx, RegisteredPublicCandidateIntervalLimit)
			var interval Interval
			var clockErr error
			begin := func() error {
				interval, clockErr = StartInterval()
				return clockErr
			}
			if !public {
				_ = begin()
			}
			var connection net.Conn
			var dialErr, elapsedErr error
			elapsed := 0.0
			complete := func() error {
				elapsed, elapsedErr = interval.Milliseconds()
				return elapsedErr
			}
			if s.registeredPublicResponse != nil {
				var duration time.Duration
				duration, dialErr = s.registeredPublicResponse(probe, target)
				elapsed = float64(duration) / float64(time.Millisecond)
				if duration <= 0 || duration > RegisteredPublicCandidateIntervalLimit {
					elapsedErr = errMeasurementClock
				}
			} else if s.publicResponse != nil {
				dialErr = s.publicResponse(probe, target, begin, complete)
			} else if clockErr == nil && run != nil {
				dialErr = run.Respond(probe, complete)
			} else if clockErr == nil && s.response != nil {
				dialErr = s.response(probe, target, complete)
			} else if clockErr == nil {
				connection, dialErr = service.engine.Dial(probe, s.prefix.Tag, target.Address)
				_ = complete()
			}
			var closeErr error
			if connection != nil {
				// A blocked native Close keeps the original worker and MTU hold.
				// Cancel/Close cannot publish a successful drain while it is pending.
				closeErr = connection.Close()
			}
			probeErr := probe.Err()
			cancel()
			failure = errors.Join(clockErr, dialErr, elapsedErr, closeErr, probeErr)
			if failure != nil || connection == nil && !private && !public || elapsed <= 0 || math.IsNaN(elapsed) || math.IsInf(elapsed, 0) {
				if (s.response != nil || s.registeredPublicResponse != nil) && len(samples) == 0 && errors.Is(dialErr, ErrCandidateNotRegistered) && ctx.Err() == nil && probeErr == nil && clockErr == nil && closeErr == nil {
					result.CandidateDisposition = CandidateNotRegistered
					failure = ErrCandidateNotRegistered
				} else {
					failure = fmt.Errorf("candidate %s did not complete", phase)
				}
				break
			}
			if boundaryFailure = verify(); boundaryFailure != nil {
				break
			}
			samples = append(samples, elapsed)
		}
	}
	if run != nil {
		service.mu.Lock()
		if service.state.Request == request && !service.closed && !service.state.Complete && service.state.Failure == "" && service.state.Stage != "cancelled" && service.state.Stage != "invalidated" {
			// Only this original response worker can begin its own retirement.
			service.responseRetirementStarted = true
			service.state.Stage = "draining"
		}
		service.mu.Unlock()
		failure = errors.Join(failure, run.Close())
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
		result.Benchmark = &LatencyBenchmark{Schema: 1, Measurement: s.measurement(), Attempts: LatencyBenchmarkSamples, Distribution: distribution(samples), TrimmedMean: mean}
		if public {
			result.Benchmark.Endpoint = CandidatePublicResponseEndpoint
		}
		result.Ready = true
	} else {
		if result.CandidateDisposition == CandidateNotRegistered {
			result.Failure = ErrCandidateNotRegistered.Error()
		} else {
			result.Failure = fmt.Sprintf("No complete 50-sample %s result; this candidate has no score", phase)
		}
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
	status := CandidateStatus{Schema: 1, Measurement: s.measurement(), PrefixPosition: s.prefix.Position, PrefixID: s.prefix.ID, CaptureSHA256: s.prefix.CaptureSHA256}
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

// AppendExecutionResponseAuthority binds only a genuine unfinished prefix and
// its exact private inventory. It grants no complete-final or selected depth.
type AppendExecutionResponseAuthority interface {
	AppendExecutionResponseDepth(position int, id, tag string) int
	AppendExecutionResponseTarget(position int, id, tag string, target CandidateTarget) bool
}

func NewAppendExecutionResponseRunContext(ctx context.Context, engine CandidateEngine, prefix CandidatePrefix, targets []CandidateTarget, limit int, authority AppendExecutionResponseAuthority, open func(context.Context, CandidateTarget) (CandidateResponseRun, error)) (*CandidateService, error) {
	if authority == nil || open == nil || limit <= 0 || limit > 40<<20 {
		return nil, ErrStale
	}
	count := authority.AppendExecutionResponseDepth(prefix.Position, prefix.ID, prefix.Tag)
	if count < 1 || count > 95 || prefix.Position != count-1 {
		return nil, ErrStale
	}
	for _, target := range targets {
		if !authority.AppendExecutionResponseTarget(prefix.Position, prefix.ID, prefix.Tag, target) {
			return nil, ErrStale
		}
	}
	service, err := newPrefixCandidatesContext(ctx, engine, prefix, targets, limit, count)
	if err == nil {
		service.responseRun = open
	}
	return service, err
}
