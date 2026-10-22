package dnsmeasure

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const SampleTimeout = 5 * time.Second
const MeasurementTimeout = 75 * time.Second
const DrainTimeout = 5 * time.Second

var requestID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var profileID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var ErrStale = errors.New("DNS measurement no longer belongs to the proved native path")

// BeginMeasurement must retain the successful native proof and its exclusive
// activity scope until release. Its returned context follows proof retirement.
// SelectedDNS exchanges a fresh question through the captured actual DNS router
// with both local caches disabled, including its exact private Home entry route.
type Engine interface {
	Identity() string
	BeginMeasurement(context.Context) (context.Context, func(), error)
	Dial(context.Context, string) (net.Conn, error)
	SelectedDNS(context.Context) error
}

type Description struct {
	NodeID, SessionID, RouteLabel string
	Selected                      Endpoint
	IPv6Enabled                   bool
}
type Result struct {
	Endpoint
	Samples int      `json:"samples"`
	Failed  int      `json:"failed"`
	Ready   bool     `json:"ready"`
	Median  *float64 `json:"median_ms,omitempty"`
	Failure string   `json:"failure,omitempty"`
}
type Status struct {
	Schema          int      `json:"schema"`
	Request         string   `json:"request_id"`
	NodeID          string   `json:"node_id"`
	SessionID       string   `json:"session_id"`
	PublicTransport string   `json:"public_transport"`
	Stage           string   `json:"stage"`
	Complete        bool     `json:"complete"`
	Drained         bool     `json:"drained"`
	Failure         string   `json:"failure,omitempty"`
	Results         []Result `json:"results"`
}
type Service struct {
	mu          sync.Mutex
	engine      Engine
	identity    string
	description Description
	closed      bool
	used        map[string]bool
	state       Status
	cancel      context.CancelFunc
	done        chan struct{}
	connections map[*ownedConnection]struct{}
	// Trusted certificate seam is deliberately not part of the mobile API.
	testTLS *tls.Config
}

func New(engine Engine, description Description) (*Service, error) {
	if engine == nil || engine.Identity() == "" || !profileID.MatchString(description.NodeID) || !profileID.MatchString(description.SessionID) || !safeText(description.RouteLabel, 160) {
		return nil, errors.New("DNS measurement requires a captured proved native connection")
	}
	e := description.Selected
	if e.ID != "selected" || e.Kind != "selected" || !safeText(e.Name, 160) || !safeText(e.Address, 253) || e.Port < 1 || e.Port > 65535 || !safeText(e.Route, 128) || !safeText(e.RouteLabel, 160) {
		return nil, errors.New("selected DNS identity is incomplete")
	}
	if e.Transport != "udp" && e.Transport != "tcp" && e.Transport != "tls" && e.Transport != "https" && e.Transport != "h3" {
		return nil, errors.New("selected DNS transport is unknown")
	}
	if len(e.ServerName) > 253 || len(e.Path) > 2048 || strings.ContainsAny(e.ServerName+e.Path, "\r\n\x00") {
		return nil, errors.New("selected DNS endpoint is invalid")
	}
	s := &Service{engine: engine, identity: engine.Identity(), description: description, used: map[string]bool{}, connections: map[*ownedConnection]struct{}{}}
	s.state = s.status("", "", "idle")
	return s, nil
}
func safeText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}
func (s *Service) status(id, transport, stage string) Status {
	return Status{Schema: 1, Request: id, NodeID: s.description.NodeID, SessionID: s.description.SessionID, PublicTransport: transport, Stage: stage, Results: []Result{}}
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
func (s *Service) Start(id, transport string) error {
	if !requestID.MatchString(id) || transport != "tcp" && transport != "tls" && transport != "https" {
		return errors.New("DNS comparison requires a fresh nonce and TCP, DoT or DoH")
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
			return errors.New("DNS measurement still owns its native workers")
		}
	}
	if s.used[id] || len(s.used) >= 256 {
		return errors.New("DNS request was already used or its connection request budget is exhausted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), MeasurementTimeout)
	owned, release, err := s.engine.BeginMeasurement(ctx)
	if err != nil || owned == nil || release == nil || owned.Err() != nil || s.engine.Identity() != s.identity {
		cancel()
		if release != nil {
			release()
		}
		return errors.New("DNS measurement activity is busy or its proof retired")
	}
	s.used[id] = true
	s.cancel, s.done = cancel, make(chan struct{})
	done := s.done
	s.state = s.status(id, transport, "measuring")
	go func() {
		defer close(done)
		defer release()
		defer cancel()
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			tick := time.NewTicker(100 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-owned.Done():
					return
				case <-tick.C:
					if s.engine.Identity() != s.identity {
						cancel()
						return
					}
				}
			}
		}()
		s.run(owned, id, transport)
		cancel()
		<-watchDone
		// A failed or still-blocked native Close is not a successful drain.
		// Keep the proof activity and every remaining socket until real closure.
		for !s.drainConnections() {
			s.mu.Lock()
			s.state.Stage, s.state.Complete, s.state.Failure = "draining", true, "DNS socket cleanup is still pending"
			s.state.Results = []Result{}
			s.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}()
	return nil
}
func (s *Service) Cancel(id string) {
	if !requestID.MatchString(id) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Remember cancel-before-start, so a queued start cannot reopen this nonce.
	if len(s.used) < 256 {
		s.used[id] = true
	}
	if id == s.state.Request && s.cancel != nil {
		s.cancel()
		s.state.Stage, s.state.Complete, s.state.Failure = "cancelled", true, "DNS measurement cancelled"
		s.state.Results = []Result{}
	}
}
func (s *Service) Drain(id string) error {
	s.mu.Lock()
	if id != s.state.Request {
		// Cancel-before-start permanently retires this nonce. An older accepted
		// nonce can differ only after its previous workers actually drained.
		retired := requestID.MatchString(id) && (s.used[id] || s.closed || len(s.used) >= 256)
		s.mu.Unlock()
		if retired {
			return nil
		}
		return errors.New("DNS drain belongs to another request")
	}
	done := s.done
	s.mu.Unlock()
	return waitDrain(done)
}
func waitDrain(done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-time.After(DrainTimeout):
		return errors.New("DNS measurement workers have not drained")
	}
}
func (s *Service) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	s.state.Stage, s.state.Complete, s.state.Failure = "invalidated", true, "The captured native DNS path changed"
	s.state.Results = []Result{}
}
func (s *Service) Close() error {
	s.Invalidate()
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()
	return waitDrain(done)
}
func (s *Service) StatusJSON() string {
	if s.engine.Identity() != s.identity {
		s.Invalidate()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Drained = s.done == nil
	if s.done != nil {
		select {
		case <-s.done:
			s.state.Drained = true
		default:
		}
	}
	data, _ := json.Marshal(s.state)
	return string(data)
}
func (s *Service) run(ctx context.Context, id, transport string) {
	endpoints := append([]Endpoint{s.description.Selected}, candidates(transport, s.description.RouteLabel)...)
	results := make([]Result, len(endpoints))
	jobs := make(chan int, len(endpoints))
	for index := range endpoints {
		jobs <- index
	}
	close(jobs)
	var workers sync.WaitGroup
	for worker := 0; worker < Workers; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				endpoint := endpoints[index]
				row := Result{Endpoint: endpoint}
				if address, err := netip.ParseAddr(endpoint.Address); endpoint.Kind == "public" && err == nil && address.Is6() && !s.description.IPv6Enabled {
					row.Failed, row.Failure = Samples, "IPv6 is disabled for this captured connection"
					results[index] = row
					continue
				}
				values := []float64{}
				for sample := 0; sample < Samples; sample++ {
					if s.valid(ctx) != nil {
						break
					}
					value, err := s.sample(ctx, endpoint)
					if err == nil {
						values = append(values, value)
					}
				}
				row.Samples, row.Failed = len(values), Samples-len(values)
				if row.Failed == 0 {
					sort.Float64s(values)
					median := values[Samples/2]
					row.Median, row.Ready = &median, true
				} else {
					row.Failure = "No complete set of matching DNS answers on this captured route"
				}
				results[index] = row
			}
		}()
	}
	workers.Wait()
	err := s.valid(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Request != id || s.state.Complete {
		return
	}
	s.state.Stage, s.state.Complete = "complete", true
	if err != nil {
		s.state.Stage, s.state.Failure = "invalidated", "DNS measurement timed out or its native path changed"
		s.state.Results = []Result{}
	} else {
		s.state.Results = results
	}
}

// A context callback and the worker both join the same native Close. Errors
// retain the socket in the service; the activity cannot be released early.
type ownedConnection struct {
	net.Conn
	service *Service
	mu      sync.Mutex
	closed  bool
	stop    func() bool
	watch   chan struct{}
}

func (s *Service) own(ctx context.Context, raw net.Conn) *ownedConnection {
	c := &ownedConnection{Conn: raw, service: s, watch: make(chan struct{})}
	s.mu.Lock()
	s.connections[c] = struct{}{}
	s.mu.Unlock()
	c.stop = context.AfterFunc(ctx, func() { _ = c.closeSocket(); close(c.watch) })
	return c
}
func (c *ownedConnection) closeSocket() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if err := c.Conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		return err
	}
	c.closed = true
	return nil
}
func (c *ownedConnection) Close() error {
	err := c.closeSocket()
	if c.stop() {
		close(c.watch)
	}
	<-c.watch
	if err == nil {
		c.service.mu.Lock()
		delete(c.service.connections, c)
		c.service.mu.Unlock()
	}
	return err
}
func (s *Service) drainConnections() bool {
	s.mu.Lock()
	connections := make([]*ownedConnection, 0, len(s.connections))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	s.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.connections) == 0
}
