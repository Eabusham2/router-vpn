package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/multihoprelay"
)

// LeaseStopCapture is created only from the final authenticated acquisition
// proposal. Its private value fields include the challenge and cannot be
// replaced by a native adapter or a later selected profile.
type LeaseStopCapture struct {
	entryTag string
	target   string
	address  string
	token    string
	node     string
	proposal multihoprelay.Request
	body     string
}

func newLeaseStopCapture(meta Metadata, proposal multihoprelay.Request) (LeaseStopCapture, error) {
	var absent LeaseStopCapture
	target, err := privateAPI(meta.EntryAPI)
	if err != nil || !exactID.MatchString(meta.EntryTag) || !proofID.MatchString(meta.EntryNodeID) ||
		meta.EntryToken == "" || strings.ContainsAny(meta.EntryToken, "\r\n") || !exactID.MatchString(proposal.SessionID) {
		return absent, errors.New("server lease stop has no complete original capture")
	}
	body, err := json.Marshal(proposal)
	if err != nil || len(body) == 0 || len(body) > multihoprelay.MaxControlResponseBytes {
		return absent, errors.New("server lease stop proposal is not bounded")
	}
	target.Path = "/api/multihop/lease"
	return LeaseStopCapture{entryTag: meta.EntryTag, target: target.String(), address: target.Host,
		token: meta.EntryToken, node: meta.EntryNodeID, proposal: proposal, body: string(body)}, nil
}

// Route exposes only the fixed original route and literal API socket to the
// native factory. No caller can choose a route, address, method or request body
// when it later exercises the stop capability.
func (s LeaseStopCapture) Route() (string, string) { return s.entryTag, s.address }

type LeaseStop interface {
	Stop(context.Context) error
	Discard()
}

// Required is a fixed property of the original native factory. Legacy engines
// retain their existing path; a required factory must seal before any PUT.
type LeaseStopEngine interface {
	LeaseStopRequired() bool
	CaptureLeaseStop(context.Context, LeaseStopCapture) (LeaseStop, error)
}

type ownedLeaseStop struct {
	capture LeaseStopCapture
	dial    func(context.Context) (net.Conn, error)
	current func(context.Context) error
	discard func()
	gate    chan struct{}
	closed  atomic.Bool
	once    sync.Once
	pending *leaseStopIO // Serialized by gate, retained across an unsuccessful Stop.
	activeMu sync.Mutex
	active *leaseStopIO
}

// NewOwnedLeaseStop permits exactly one immutable DELETE operation. The native
// callbacks retain only the original entry adapter and independently verify
// its active identity or its acknowledged terminal data barrier.
func NewOwnedLeaseStop(capture LeaseStopCapture, dial func(context.Context) (net.Conn, error),
	current func(context.Context) error, discard func()) (LeaseStop, error) {
	if capture.entryTag == "" || capture.address == "" || capture.target == "" ||
		capture.token == "" || !proofID.MatchString(capture.node) ||
		!exactID.MatchString(capture.proposal.SessionID) || capture.body == "" ||
		dial == nil || current == nil || discard == nil {
		return nil, errors.New("server lease stop capability is incomplete")
	}
	owner := &ownedLeaseStop{capture: capture, dial: dial, current: current, discard: discard, gate: make(chan struct{}, 1)}
	owner.gate <- struct{}{}
	return owner, nil
}

func (s *ownedLeaseStop) Discard() {
	if s == nil { return }
	s.once.Do(func() {
		s.closed.Store(true)
		s.activeMu.Lock()
		active := s.active
		s.activeMu.Unlock()
		if active != nil { active.retire() }
		s.discard()
	})
}

func (s *ownedLeaseStop) Stop(ctx context.Context) (failure error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.closed.Load() {
		return errors.New("server lease stop capability is retired")
	}
	select {
	case <-ctx.Done(): return ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.closed.Load() { return errors.New("server lease stop capability is retired") }
	if s.pending != nil {
		if err := s.pending.wait(ctx); err != nil {
			return routedRequestFailure{"previous server stop stream is not joined",err}
		}
		s.pending = nil
		s.activeMu.Lock()
		s.active = nil
		s.activeMu.Unlock()
	}
	if err := s.current(ctx); err != nil { return err }
	operation := newLeaseStopIO(ctx)
	call,finish,err := operation.begin(ctx)
	if err != nil { operation.retire(); return err }
	s.pending = operation
	s.activeMu.Lock()
	s.active = operation
	s.activeMu.Unlock()
	defer func() {
		operation.retire()
		if err := operation.wait(ctx); err != nil {
			failure = errors.Join(failure,routedRequestFailure{"server stop stream cleanup is unverified",err})
			return
		}
		s.pending = nil
		s.activeMu.Lock()
		if s.active == operation { s.active = nil }
		s.activeMu.Unlock()
		if s.closed.Load() {
			failure = errors.Join(failure,errors.New("server stop capability retired during acknowledgement"))
		} else if failure == nil {
			failure = s.current(ctx)
		}
	}()
	if s.closed.Load() {
		finish()
		return errors.New("server lease stop capability is retired")
	}
	// The complete HTTP operation is retained, including body/transport close.
	// A blocked original write, read or Close cannot escape its caller's bound
	// or be silently replaced by a second cleanup request.
	done := make(chan error,1)
	go func() {
		defer finish()
		done <- s.exchange(call,operation)
	}()
	select {
	case <-ctx.Done(): return ctx.Err()
	case err := <-done: return err
	}
}

func (s *ownedLeaseStop) exchange(ctx context.Context, operation *leaseStopIO) error {
	transport := &http.Transport{Proxy:nil,DisableKeepAlives:true,TLSHandshakeTimeout:2500*time.Millisecond,
		DialContext:func(parent context.Context,network,address string)(net.Conn,error) {
			if network != "tcp" || address != s.capture.address || s.closed.Load() {
				return nil,errors.New("server lease stop changed its original socket")
			}
			call,finish,err := operation.begin(parent)
			if err != nil { return nil,err }
			defer finish()
			if err := s.current(call); err != nil { return nil,err }
			connection,dialErr := s.dial(call)
			var keepErr error
			if connection != nil { connection,keepErr = operation.keep(connection) }
			currentErr := s.current(call)
			if connection == nil || dialErr != nil || keepErr != nil || currentErr != nil || call.Err() != nil || s.closed.Load() {
				if owned,ok := connection.(*leaseStopConn); ok { owned.startClose() }
				return nil,errors.Join(dialErr,keepErr,currentErr,call.Err(),errors.New("server lease stop socket lost its original owner"))
			}
			return connection,nil
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport:transport,CheckRedirect:func(*http.Request,[]*http.Request)error{
		return errors.New("server lease stop cannot follow redirects")
	}}
	request,err := http.NewRequestWithContext(ctx,"DELETE",s.capture.target,strings.NewReader(s.capture.body))
	if err != nil { return errors.New("server lease stop request is invalid") }
	request.Header.Set("Cache-Control","no-store")
	request.Header.Set("Accept-Encoding","identity")
	request.Header.Set("Content-Type","application/json")
	request.Header.Set("Authorization","Bearer "+s.capture.token)
	response,err := client.Do(request)
	if err != nil { return routedRequestFailure{"server lease stop request failed",err} }
	limit := multihoprelay.LeaseResponseLimit("DELETE")
	data,readErr := io.ReadAll(io.LimitReader(response.Body,int64(limit)+1))
	closeErr := response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 { return controlError{response.StatusCode} }
	if readErr != nil || closeErr != nil || len(data) > limit {
		return errors.New("server lease stop acknowledgement is incomplete")
	}
	if err := s.current(ctx); err != nil { return err }
	if ctx.Err() != nil || s.closed.Load() { return errors.New("server lease stop owner retired during acknowledgement") }
	var receipt struct {
		Node string `json:"node_id"`
		Session string `json:"session_id"`
		Stopped bool `json:"stopped"`
	}
	if exactJSON(data,&receipt,limit) != nil || !receipt.Stopped ||
		receipt.Node != s.capture.node || receipt.Session != s.capture.proposal.SessionID {
		return errors.New("server lease stop acknowledgement is invalid")
	}
	return nil
}

func (c *Controller) sealLeaseStop(ctx context.Context) error {
	owner, required := c.engine.(LeaseStopEngine)
	if !required || !owner.LeaseStopRequired() { return nil }
	if c.leaseStop != nil { return errors.New("server lease stop is already captured") }
	capture, err := newLeaseStopCapture(c.meta, c.proposal)
	if err != nil { return err }
	stop, err := owner.CaptureLeaseStop(ctx, capture)
	if err != nil || stop == nil {
		if stop != nil { stop.Discard() }
		return errors.Join(err, errors.New("server lease requires its pre-acquisition stop capability"))
	}
	c.leaseStop, c.leaseStopCapture = stop, capture
	return nil
}
func (c *Controller) checkLeaseStop() error {
	owner, required := c.engine.(LeaseStopEngine)
	if !required || !owner.LeaseStopRequired() {
		if c.leaseStop != nil { return errors.New("server lease stop factory changed") }
		return nil
	}
	capture, err := newLeaseStopCapture(c.meta, c.proposal)
	if err != nil || c.leaseStop == nil || capture != c.leaseStopCapture {
		return errors.New("server lease changed its sealed original stop request")
	}
	return nil
}
func (c *Controller) discardLeaseStop() {
	if c.leaseStop != nil { c.leaseStop.Discard() }
	c.leaseStop = nil
	c.leaseStopCapture = LeaseStopCapture{}
}
