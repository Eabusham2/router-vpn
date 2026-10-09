// Package hopmeasure measures separately routed native hop paths. It has no
// default network dialer: only the captured engine may open probe connections.
package hopmeasure

import (
	"bytes"
	"context"
	"crypto/rand"
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

var tokenID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var nodeID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ErrStale = errors.New("hop measurement session or selected route changed")

// Dial must use the captured native outbound, never an ordinary HTTP proxy or
// ambient network. Identity includes the selected exit and native generation.
type Engine interface {
	Identity() string
	Dial(context.Context, string, string) (net.Conn, error)
}
type Hop struct {
	ID    string `json:"id"`
	Role  string `json:"role"`
	Tag   string `json:"tag"`
	API   string `json:"api"`
	Token string `json:"token"`
	Proof string `json:"proof"`
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
	ID       string    `json:"node_id"`
	Role     string    `json:"role"`
	Ready    bool      `json:"ready"`
	Failure  string    `json:"failure,omitempty"`
	Idle     *Latency  `json:"idle,omitempty"`
	Download *Transfer `json:"download,omitempty"`
	Upload   *Transfer `json:"upload,omitempty"`
}
type Status struct {
	Request  string   `json:"request_id"`
	Stage    string   `json:"stage"`
	Complete bool     `json:"complete"`
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
}

func New(engine Engine, hops []Hop) (*Service, error) {
	if engine == nil || engine.Identity() == "" || len(hops) < 1 || len(hops) > 8 {
		return nil, errors.New("a captured native path is required")
	}
	seen := map[string]bool{}
	copyHops := append([]Hop(nil), hops...)
	for _, h := range copyHops {
		if h.ID == "" || len(h.ID) > 128 || seen[h.ID] || !nodeID.MatchString(h.Proof) || h.Token == "" || len(h.Token) > 4096 || strings.ContainsAny(h.Token, "\r\n\x00") {
			return nil, errors.New("invalid frozen hop identity")
		}
		if h.Tag != "proxy" && h.Tag != "entry-wg" && h.Tag != "routervpn-hop-entry" {
			return nil, errors.New("unowned measurement route")
		}
		if h.Role != "entry" && h.Role != "exit" {
			return nil, errors.New("unowned measurement role")
		}
		if (h.Role == "exit") != (h.Tag == "proxy") {
			return nil, errors.New("hop role differs from native route")
		}
		if _, err := privateAPI(h.API); err != nil {
			return nil, err
		}
		seen[h.ID] = true
	}
	return &Service{hops: copyHops, engine: engine, identity: engine.Identity(), state: Status{Stage: "idle", Results: []Result{}}}, nil
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
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed || s.engine.Identity() != s.identity {
		return ErrStale
	}
	return nil
}
func (s *Service) Start(id string, size int) error {
	if !tokenID.MatchString(id) || size < 64<<10 || size > MaxBytes {
		return errors.New("invalid bounded hop measurement request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.engine.Identity() != s.identity {
		return ErrStale
	}
	if s.done != nil {
		select {
		case <-s.done:
		default:
			return errors.New("another hop measurement still owns this session")
		}
	}
	if id == s.state.Request {
		return errors.New("measurement request identifiers cannot be reused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	s.cancel = cancel
	s.done = make(chan struct{})
	done := s.done
	s.state = Status{Request: id, Stage: "starting", Results: []Result{}}
	go func() { defer close(done); defer cancel(); s.run(ctx, id, size) }()
	return nil
}
func (s *Service) Cancel(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == s.state.Request && s.cancel != nil {
		s.cancel()
		s.state = Status{Request: id, Stage: "cancelled", Complete: true, Failure: "Measurement cancelled", Results: []Result{}}
	}
}

// Invalidate cancels immediately; Close performs the bounded drain on teardown.
func (s *Service) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	s.state = Status{Stage: "invalidated", Complete: true, Failure: "Native path changed", Results: []Result{}}
}
func (s *Service) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	done := s.done
	s.state = Status{Stage: "invalidated", Complete: true, Failure: "Native path changed or closed", Results: []Result{}}
	s.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return errors.New("hop measurement teardown is still pending")
		}
	}
	return nil
}
func (s *Service) StatusJSON() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine.Identity() != s.identity {
		if s.cancel != nil {
			s.cancel()
		}
		s.state = Status{Stage: "invalidated", Complete: true, Failure: "Selected native path changed", Results: []Result{}}
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
	for _, h := range s.hops {
		if s.phase(ctx, id, h.Role+":idle") != nil {
			break
		}
		r := Result{ID: h.ID, Role: h.Role}
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
			r = Result{ID: h.ID, Role: h.Role, Failure: "Routed identity, byte count, or transfer deadline failed"}
		} else {
			r.Ready = true
		}
		if s.valid(ctx) != nil {
			break
		}
		s.mu.Lock()
		if s.state.Request == id && !s.state.Complete {
			s.state.Results = append(s.state.Results, r)
		}
		s.mu.Unlock()
	}
	err := s.valid(ctx)
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
	return &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, errors.New("invalid measurement transport")
			}
			if err := s.valid(ctx); err != nil {
				return nil, err
			}
			conn, err := s.engine.Dial(ctx, h.Tag, address)
			if err != nil {
				return nil, err
			}
			if err = s.valid(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("measurement redirects are forbidden") }}
}
func (s *Service) request(ctx context.Context, h Hop, path string, size int, upload bool) (*http.Response, time.Time, *http.Client, error) {
	return s.requestWithActivity(ctx, h, path, size, upload, nil)
}
func (s *Service) requestWithActivity(ctx context.Context, h Hop, path string, size int, upload bool, activity *transferActivity) (*http.Response, time.Time, *http.Client, error) {
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
	start := time.Now()
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
	return float64(time.Since(start).Nanoseconds()) / 1e6, nil
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
	elapsed := time.Since(start).Seconds()
	activity.finish()
	stop()
	samples := <-ch
	if err != nil || elapsed <= 0 {
		return nil, errors.New("incomplete routed transfer")
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
