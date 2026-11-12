// Package hopmeasure measures separately routed native hop paths. It has no
// default network dialer: only the captured engine may open probe connections.
package hopmeasure

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxBytes = 8 << 20

// RequestTimeout is the existing complete worker budget, including all fifty
// latency samples. Observers must not substitute a shorter sample-count budget.
const RequestTimeout = 90 * time.Second

// DrainTimeout bounds joining the original worker after completion or cancel.
const DrainTimeout = 5 * time.Second

var tokenID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var nodeID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ErrStale = errors.New("hop measurement session or selected route changed")

// Dial must use the captured native outbound, never an ordinary HTTP proxy or
// ambient network. Identity includes the selected exit and native generation.
type Engine interface {
	Identity() string
	Dial(context.Context, string, string) (net.Conn, error)
}

// ContextEngine observes the captured native owner within the original caller's
// lifetime. The compatibility Engine contract remains available for older
// owners; a context-capable owner must never fall back to its detached reader.
type ContextEngine interface {
	IdentityContext(context.Context) (string, error)
}

// MeasurementScope is implemented by native owners that share mutable packet
// resources with another controller. Its release is held through real worker
// and socket drain, including cancellation, rather than just status completion.
type MeasurementScope interface {
	BeginMeasurement() (release func(), err error)
}

// ContextMeasurementScope retains cancellation while acquiring the original
// native activity. A returned release is owned even when acquisition fails.
type ContextMeasurementScope interface {
	BeginMeasurementContext(context.Context) (release func(), err error)
}

// MeasurementBoundary observes any independently changing native transport
// before work and before publishing results. A cached health flag is not an
// adequate adoption boundary for a leased remote runtime.
type MeasurementBoundary interface {
	VerifyMeasurement(context.Context) error
}
type Hop struct {
	ID    string `json:"id"`
	Role  string `json:"role"`
	Tag   string `json:"tag"`
	API   string `json:"api"`
	Token string `json:"token"`
	Proof string `json:"proof"`
	Kind  string `json:"kind,omitempty"`
	Label string `json:"label,omitempty"`
}
type Latency struct {
	Samples int     `json:"samples"`
	Min     float64 `json:"min_ms"`
	Median  float64 `json:"median_ms"`
	Average float64 `json:"average_ms"`
	P90     float64 `json:"p90_ms"`
	Max     float64 `json:"max_ms"`
	Jitter  float64 `json:"jitter_ms"`
}
type Transfer struct {
	Bytes        int64    `json:"bytes"`
	Seconds      float64  `json:"seconds"`
	Mbps         float64  `json:"mbps"`
	Loaded       *Latency `json:"loaded,omitempty"`
	LoadedReason string   `json:"loaded_reason,omitempty"`
	Bufferbloat  *float64 `json:"bufferbloat_ms,omitempty"`
}
type Result struct {
	ID        string            `json:"node_id"`
	Role      string            `json:"role"`
	Kind      string            `json:"kind"`
	Label     string            `json:"label"`
	Ready     bool              `json:"ready"`
	Failure   string            `json:"failure,omitempty"`
	Idle      *Latency          `json:"idle,omitempty"`
	Download  *Transfer         `json:"download,omitempty"`
	Upload    *Transfer         `json:"upload,omitempty"`
	Benchmark *LatencyBenchmark `json:"benchmark,omitempty"`
	Response  *PathResponse     `json:"response,omitempty"`
}
type Status struct {
	Request  string   `json:"request_id"`
	Stage    string   `json:"stage"`
	Complete bool     `json:"complete"`
	Drained  bool     `json:"drained"`
	Failure  string   `json:"failure,omitempty"`
	Results  []Result `json:"results"`
}
type Service struct {
	mu       sync.Mutex
	hops     []Hop
	engine   Engine
	identity string
	closed   bool
	state    Status
	cancel   context.CancelFunc
	done     chan struct{}
	pending  *measurementAdmission
	// Unexported trusted-root seam for local TLS protocol/lifetime tests.
	publicTLS *tls.Config
}

type measurementAdmission struct {
	id     string
	cancel context.CancelFunc
	done   chan struct{}
}

// ObservationTimeout matches native identity observations. It applies only to
// contextless construction/status calls, not to an admitted measurement's
// existing complete 90-second request budget or five-second drain allowance.
const ObservationTimeout = 1500 * time.Millisecond

func New(engine Engine, hops []Hop) (*Service, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ObservationTimeout)
	defer cancel()
	return NewContext(ctx, engine, hops)
}

// NewContext captures identity without making the returned service's lifetime
// depend on the short-lived constructor caller.
func NewContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	return newContext(ctx, engine, hops, false)
}

// NewOrderedContext admits only the compiler's complete ordered private-node
// prefix inventory. Pair and imported-path constructors keep their old tags.
func NewOrderedContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	if len(hops) < 2 {
		return nil, errors.New("ordered measurement requires a complete node path")
	}
	return newContext(ctx, engine, hops, true)
}

func newContext(ctx context.Context, engine Engine, hops []Hop, ordered bool) (*Service, error) {
	if engine == nil || len(hops) < 1 || len(hops) > 8 {
		return nil, errors.New("a captured native path is required")
	}
	seen := map[string]bool{}
	proofs := map[string]bool{}
	copyHops := append([]Hop(nil), hops...)
	for index, h := range copyHops {
		if h.ID == "" || len(h.ID) > 128 || seen[h.ID] || strings.ContainsAny(h.ID, "\r\n\x00") {
			return nil, errors.New("invalid frozen hop identity")
		}
		if ordered {
			role := "intermediate"
			if index == 0 {
				role = "entry"
			} else if index == len(copyHops)-1 {
				role = "exit"
			}
			if h.Role != role || !orderedPrefixTag.MatchString(h.Tag) || !strings.HasPrefix(h.Tag, "routervpn-chain-"+strconv.Itoa(index)+"-") ||
				(h.Kind != "" && h.Kind != "private-node") || proofs[h.Proof] {
				return nil, errors.New("ordered measurement changed prefix order, role or node proof")
			}
			proofs[h.Proof] = true
		} else {
			if h.Tag != "proxy" && h.Tag != "entry-wg" && h.Tag != "routervpn-hop-entry" && h.Tag != "custom-exit" && h.Tag != "external-entry" {
				return nil, errors.New("unowned measurement route")
			}
			if h.Role != "entry" && h.Role != "exit" {
				return nil, errors.New("unowned measurement role")
			}
			if (h.Role == "exit") != (h.Tag == "proxy" || h.Tag == "custom-exit") {
				return nil, errors.New("hop role differs from native route")
			}
		}
		if h.Kind == "" {
			h.Kind = "private-node"
		}
		switch h.Kind {
		case "private-node":
			if !nodeID.MatchString(h.Proof) || h.Token == "" || len(h.Token) > 4096 || strings.ContainsAny(h.Token, "\r\n\x00") {
				return nil, errors.New("invalid captured private node proof")
			}
			if _, err := privateAPI(h.API); err != nil {
				return nil, err
			}
			if h.Label == "" {
				h.Label = "Router VPN " + h.Role + " private API"
			}
		case "public-path":
			if h.API != "" || h.Token != "" || h.Proof != "" || h.Tag != "custom-exit" && h.Tag != "external-entry" {
				return nil, errors.New("public path cannot claim a private node or unowned route")
			}
			if h.Label == "" {
				h.Label = "External " + h.Role + " → Cloudflare edge"
			}
		default:
			return nil, errors.New("unknown measurement kind")
		}
		if len(h.Label) > 160 || strings.ContainsAny(h.Label, "\r\n\x00") {
			return nil, errors.New("invalid measurement label")
		}
		copyHops[index] = h
		seen[h.ID] = true
	}
	identity, err := observedIdentity(ctx, engine)
	if err != nil {
		return nil, err
	}
	return &Service{hops: copyHops, engine: engine, identity: identity, state: Status{Stage: "idle", Results: []Result{}}}, nil
}

func observedIdentity(ctx context.Context, engine Engine) (string, error) {
	if ctx == nil {
		return "", errors.New("hop observation has no caller")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var identity string
	var err error
	if observer, ok := engine.(ContextEngine); ok {
		identity, err = observer.IdentityContext(ctx)
	} else {
		identity = engine.Identity()
	}
	if err != nil || ctx.Err() != nil {
		return "", errors.Join(err, ctx.Err())
	}
	if identity == "" {
		return "", ErrStale
	}
	return identity, nil
}
func privateAPI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("a private literal node API is required")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	p, e := strconv.Atoi(u.Port())
	if err != nil || e != nil || p < 1 || p > 65535 || ip.Zone() != "" || !ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return nil, errors.New("unsafe node measurement endpoint")
	}
	return u, nil
}
func (s *Service) valid(ctx context.Context) error {
	if ctx == nil {
		return errors.New("hop observation has no caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrStale
	}
	identity, err := observedIdentity(ctx, s.engine)
	if err != nil {
		return err
	}
	s.mu.Lock()
	closed = s.closed
	s.mu.Unlock()
	if closed || identity != s.identity {
		return ErrStale
	}
	return ctx.Err()
}
func (s *Service) Start(id string, size int) error {
	return s.StartContext(context.Background(), id, size)
}

func (s *Service) StartContext(ctx context.Context, id string, size int) error {
	if size < 64<<10 || size > MaxBytes {
		return errors.New("invalid bounded hop measurement request")
	}
	return s.startContext(ctx, id, func(ctx context.Context) { s.run(ctx, id, size) })
}

func (s *Service) start(id string, work func(context.Context)) error {
	return s.startContext(context.Background(), id, work)
}

func (s *Service) startContext(parent context.Context, id string, work func(context.Context)) error {
	if parent == nil || !tokenID.MatchString(id) || work == nil {
		return errors.New("invalid bounded hop measurement request")
	}
	ctx, cancel := context.WithTimeout(parent, RequestTimeout)
	op := &measurementAdmission{id: id, cancel: cancel, done: make(chan struct{})}
	accepted := false
	var release func()
	defer func() {
		if !accepted {
			cancel()
			if release != nil {
				release()
			}
			close(op.done)
			s.mu.Lock()
			if s.pending == op {
				s.pending = nil
			}
			s.mu.Unlock()
		}
	}()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrStale
	}
	if s.pending != nil {
		s.mu.Unlock()
		return errors.New("another hop measurement still owns this session")
	}
	if s.done != nil {
		select {
		case <-s.done:
		default:
			s.mu.Unlock()
			return errors.New("another hop measurement still owns this session")
		}
	}
	if id == s.state.Request {
		s.mu.Unlock()
		return errors.New("measurement request identifiers cannot be reused")
	}
	// Publish only cancellation/drain ownership before an external observation.
	// Rejected admission leaves the prior completed result unchanged.
	s.pending = op
	s.mu.Unlock()
	if err := s.valid(ctx); err != nil {
		return err
	}
	var err error
	if scoped, ok := s.engine.(ContextMeasurementScope); ok {
		release, err = scoped.BeginMeasurementContext(ctx)
	} else if scoped, ok := s.engine.(MeasurementScope); ok {
		release, err = scoped.BeginMeasurement()
	} else {
		release = func() {}
	}
	if err != nil || release == nil {
		return errors.Join(errors.New("native measurement resource is busy or retired"), ctx.Err())
	}
	if err := s.valid(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.pending != op {
		return ErrStale
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.pending = nil
	s.cancel = cancel
	s.done = op.done
	s.state = Status{Request: id, Stage: "starting", Results: []Result{}}
	accepted = true
	go func() { defer close(op.done); defer cancel(); defer release(); work(ctx) }()
	return nil
}
func (s *Service) Cancel(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil && id == s.pending.id {
		s.pending.cancel()
		return
	}
	if id == s.state.Request && s.cancel != nil {
		s.cancel()
		s.state = Status{Request: id, Stage: "cancelled", Complete: true, Failure: "Measurement cancelled", Results: []Result{}}
	}
}

// Drain joins only the named request. A cancellation acknowledgement is not
// proof that a late native dial, transfer or socket close has finished. Hosts
// keep the MTU measurement hold until this succeeds, including cancellation.
func (s *Service) Drain(id string) error {
	s.mu.Lock()
	done := s.done
	if s.pending != nil && id == s.pending.id {
		done = s.pending.done
	} else if id != s.state.Request {
		s.mu.Unlock()
		return errors.New("measurement drain belongs to another request")
	}
	s.mu.Unlock()
	if done == nil {
		return nil
	}
	timer := time.NewTimer(DrainTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("measurement request has not drained")
	}
}

// Invalidate cancels immediately; Close performs the bounded drain on teardown.
func (s *Service) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.pending != nil {
		s.pending.cancel()
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.state = Status{Request: s.state.Request, Stage: "invalidated", Complete: true, Failure: "Native path changed", Results: []Result{}}
}
func (s *Service) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), DrainTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}

// CloseContext cancels and joins the exact retained admission or worker within
// the original caller's lifetime. A timeout keeps every cleanup handle so a
// later original owner can retry; it never acknowledges an unfinished drain.
func (s *Service) CloseContext(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("hop measurement close has no original caller or service")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.mu.TryLock() {
			break
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.closed = true
	if s.pending != nil {
		s.pending.cancel()
	}
	if s.cancel != nil {
		s.cancel()
	}
	done := s.done
	if s.pending != nil {
		done = s.pending.done
	}
	s.state = Status{Request: s.state.Request, Stage: "invalidated", Complete: true, Failure: "Native path changed or closed", Results: []Result{}}
	s.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return errors.Join(ctx.Err(), errors.New("hop measurement teardown is still pending"))
		}
	}
	return ctx.Err()
}
func (s *Service) StatusJSON() string {
	ctx, cancel := context.WithTimeout(context.Background(), ObservationTimeout)
	defer cancel()
	return s.statusJSON(ctx)
}

// StatusContextJSON observes the original native owner within the caller lifetime.
func (s *Service) StatusContextJSON(ctx context.Context) string {
	return s.statusJSON(ctx)
}

func (s *Service) statusJSON(ctx context.Context) string {
	s.mu.Lock()
	request, done, pending := s.state.Request, s.done, s.pending
	observe := !s.closed && s.state.Stage != "cancelled" && s.state.Stage != "invalidated"
	s.mu.Unlock()
	var identity string
	var err error
	if observe {
		identity, err = observedIdentity(ctx, s.engine)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A late status read cannot invalidate a replacement admission, worker, or
	// cancellation. No native owner is ever queried while the status lock is held.
	if observe && !s.closed && s.state.Stage != "cancelled" && s.state.Stage != "invalidated" &&
		request == s.state.Request && done == s.done && pending == s.pending && (err != nil || identity != s.identity) {
		if s.cancel != nil {
			s.cancel()
		}
		if s.pending != nil {
			s.pending.cancel()
		}
		s.state = Status{Request: s.state.Request, Stage: "invalidated", Complete: true, Failure: "Selected native path changed", Results: []Result{}}
	}
	s.state.Drained = s.done == nil
	if s.done != nil {
		select {
		case <-s.done:
			s.state.Drained = true
		default:
		}
	}
	b, _ := json.Marshal(s.state)
	return string(b)
}
func (s *Service) phase(ctx context.Context, id, phase string) error {
	if err := s.valid(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Request != id || s.state.Complete {
		return context.Canceled
	}
	s.state.Stage = phase
	return nil
}
func (s *Service) run(ctx context.Context, id string, size int) {
	var boundaryError error
	verify := func() error {
		if boundary, ok := s.engine.(MeasurementBoundary); ok {
			if err := boundary.VerifyMeasurement(ctx); err != nil {
				return err
			}
		}
		return s.valid(ctx)
	}
	for _, h := range s.hops {
		if boundaryError = verify(); boundaryError != nil {
			break
		}
		if s.phase(ctx, id, h.Role+":idle") != nil {
			break
		}
		r := Result{ID: h.ID, Role: h.Role, Kind: h.Kind, Label: h.Label}
		idle, err := s.latency(ctx, h, 6)
		if err == nil {
			r.Idle = idle
			if s.phase(ctx, id, h.Role+":download") == nil {
				r.Download, err = s.transfer(ctx, h, size, false, idle)
			} else {
				err = context.Canceled
			}
			if err == nil {
				if s.phase(ctx, id, h.Role+":upload") == nil {
					r.Upload, err = s.transfer(ctx, h, size, true, idle)
				} else {
					err = context.Canceled
				}
			}
			if err == nil {
				_, err = s.prove(ctx, h)
			}
		}
		if err != nil {
			r = Result{ID: h.ID, Role: h.Role, Kind: h.Kind, Label: h.Label, Failure: "Routed identity, byte count, or transfer deadline failed"}
		} else {
			r.Ready = true
		}
		if boundaryError = verify(); boundaryError != nil {
			break
		}
		s.mu.Lock()
		if s.state.Request == id && !s.state.Complete {
			s.state.Results = append(s.state.Results, r)
		}
		s.mu.Unlock()
	}
	err := s.valid(ctx)
	if boundaryError != nil {
		err = boundaryError
	} else if err == nil {
		err = verify()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Request != id || s.state.Complete {
		return
	}
	s.state.Complete = true
	s.state.Stage = "complete"
	if err != nil {
		s.state.Stage = "invalidated"
		s.state.Failure = "Session changed or measurement timed out"
		s.state.Results = []Result{}
	}
}
func (s *Service) client(h Hop) *http.Client {
	transport := &privateMeasurementTransport{service: s, tag: h.Tag, connections: map[*privateMeasurementConn]struct{}{}}
	transport.Transport = &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second, DialContext: transport.dial}
	return &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("measurement redirects are forbidden") }}
}
func (s *Service) request(ctx context.Context, h Hop, path string, size int, upload bool) (*http.Response, measurementInstant, *http.Client, error) {
	return s.requestWithActivity(ctx, h, path, size, upload, nil)
}
func (s *Service) requestWithActivity(ctx context.Context, h Hop, path string, size int, upload bool, activity *transferActivity) (*http.Response, measurementInstant, *http.Client, error) {
	u, _ := privateAPI(h.API)
	u.Path = path
	if path == "/api/benchmark/download" {
		u.RawQuery = "bytes=" + strconv.Itoa(size)
	}
	method := http.MethodGet
	var reader io.Reader
	if upload {
		method = http.MethodPost
		reader = io.LimitReader(rand.Reader, int64(size))
		if activity != nil {
			reader = &activityReader{Reader: reader, activity: activity}
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { activity.finish() }})
		}
	}
	r, _ := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if upload {
		r.ContentLength = int64(size)
		r.Header.Set("Content-Type", "application/octet-stream")
	}
	r.Header.Set("Authorization", "Bearer "+h.Token)
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("Cache-Control", "no-store, no-transform")
	client := s.client(h)
	// Private-node response timing includes the captured request's connection
	// preparation, as before. Keep that boundary while using a clock that can
	// represent a short interval on every native platform.
	start, err := readMeasurementClock()
	if err != nil {
		client.CloseIdleConnections()
		return nil, start, client, errMeasurementClock
	}
	resp, err := client.Do(r)
	if err != nil {
		client.CloseIdleConnections()
		return nil, start, client, errors.New("routed measurement request failed")
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" {
		resp.Body.Close()
		client.CloseIdleConnections()
		return nil, start, client, errors.New("invalid measurement response")
	}
	return resp, start, client, nil
}
func (s *Service) prove(parent context.Context, h Hop) (float64, error) {
	if h.Kind == "public-path" {
		return s.provePublic(parent, h)
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	resp, start, client, err := s.request(ctx, h, "/health", 0, false)
	if err != nil {
		return 0, err
	}
	defer client.CloseIdleConnections()
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return 0, errors.New("invalid hop proof size")
	}
	var value struct {
		OK    bool   `json:"ok"`
		Node  string `json:"node_id"`
		Proof string `json:"proof"`
	}
	if strictJSON(data, &value) != nil || !value.OK || value.Node != h.Proof || value.Proof != "router-vpn-private-agent-v1" {
		return 0, errors.New("wrong hop proof")
	}
	if err = s.valid(ctx); err != nil {
		return 0, err
	}
	finish, err := readMeasurementClock()
	if err != nil {
		return 0, errMeasurementClock
	}
	elapsed, err := measurementSeconds(start, finish)
	if err != nil {
		return 0, errMeasurementClock
	}
	return elapsed * 1000, nil
}
func (s *Service) latency(ctx context.Context, h Hop, count int) (*Latency, error) {
	samples := make([]float64, 0, count)
	for i := 0; i < count; i++ {
		value, err := s.prove(ctx, h)
		if err != nil {
			return nil, err
		}
		samples = append(samples, value)
	}
	return distribution(samples), nil
}
func distribution(samples []float64) *Latency {
	if len(samples) == 0 {
		return nil
	}
	v := append([]float64(nil), samples...)
	sort.Float64s(v)
	total, jitter := 0.0, 0.0
	for i, n := range samples {
		total += n
		if i > 0 {
			jitter += math.Abs(n - samples[i-1])
		}
	}
	median := v[len(v)/2]
	if len(v)%2 == 0 {
		median = (v[len(v)/2-1] + median) / 2
	}
	if len(v) > 1 {
		jitter /= float64(len(v) - 1)
	}
	return &Latency{len(v), v[0], median, total / float64(len(v)), v[int(math.Ceil(float64(len(v))*.9))-1], v[len(v)-1], jitter}
}
func (s *Service) transfer(parent context.Context, h Hop, size int, upload bool, idle *Latency) (*Transfer, error) {
	if h.Kind == "public-path" {
		return s.transferPublic(parent, h, size, upload, idle)
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	activity := newTransferActivity()
	defer activity.finish()
	monitor, stop := context.WithCancel(ctx)
	defer stop()
	ch := make(chan loadedSampling, 1)
	go func() {
		ch <- sampleUnderLoad(monitor, activity, func(ctx context.Context) (float64, error) { return s.prove(ctx, h) })
	}()
	path := "/api/benchmark/download"
	if upload {
		path = "/api/benchmark/upload"
	}
	resp, start, client, err := s.requestWithActivity(ctx, h, path, size, upload, activity)
	if err != nil {
		stop()
		<-ch
		return nil, err
	}
	defer client.CloseIdleConnections()
	defer resp.Body.Close()
	var n int64
	if upload {
		data, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
		var ack struct {
			OK        bool    `json:"ok"`
			Direction string  `json:"direction"`
			Bytes     int64   `json:"bytes"`
			Receive   float64 `json:"server_receive_ms"`
			Peer      string  `json:"peer"`
			Proof     string  `json:"proof"`
		}
		if e != nil || len(data) > 4096 || strictJSON(data, &ack) != nil || !ack.OK || ack.Direction != "upload" || ack.Bytes != int64(size) || ack.Proof != "authenticated tunnel-peer private throughput sink" {
			err = errors.New("unproved upload byte count")
		} else {
			n = ack.Bytes
		}
	} else {
		if resp.ContentLength != int64(size) || resp.Header.Get("X-Routervpn-Benchmark") != "download-v1" || resp.Header.Get("X-Routervpn-Benchmark-Bytes") != strconv.Itoa(size) {
			err = errors.New("unproved download framing")
		} else {
			n, err = io.Copy(io.Discard, io.LimitReader(&activityReader{Reader: resp.Body, activity: activity, remaining: int64(size), finishOnBytes: true}, int64(size)+1))
			if n != int64(size) {
				err = errors.New("download byte count differs")
			}
		}
	}
	finish, clockErr := readMeasurementClock()
	elapsed, intervalErr := measurementSeconds(start, finish)
	activity.finish()
	stop()
	samples := <-ch
	if err != nil {
		return nil, errors.New("incomplete routed transfer")
	}
	if clockErr != nil || intervalErr != nil {
		return nil, errMeasurementClock
	}
	if err = s.valid(ctx); err != nil {
		return nil, err
	}
	result := &Transfer{Bytes: n, Seconds: elapsed, Mbps: float64(n) * 8 / elapsed / 1e6}
	if len(samples.values) > 0 && !samples.failed {
		result.Loaded = distribution(samples.values)
		delta := result.Loaded.Average - idle.Average
		result.Bufferbloat = &delta
	} else {
		result.LoadedReason = "Transfer finished before a complete loaded sample, or loaded probe failed"
	}
	return result, nil
}

// Small control/proof objects have unique keys, exact framing, and no unknown fields.
func strictJSON(data []byte, out any) error {
	bad := errors.New("invalid proof JSON")
	d := json.NewDecoder(bytes.NewReader(data))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return bad
	}
	keys := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		k, ok := key.(string)
		if e != nil || !ok || keys[k] {
			return bad
		}
		keys[k] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return bad
		}
	}
	if tok, e = d.Token(); e != nil || tok != json.Delim('}') {
		return bad
	}
	if _, e = d.Token(); e != io.EOF {
		return bad
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
