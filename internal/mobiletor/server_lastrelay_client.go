package mobiletor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

// ServerTorComparison retains the exact authenticated lease, full client Box
// identity, numeric external TLS anchor and remote native last-relay probe.
// Neither a server timestamp nor the duration of a control RPC is a score.
type ServerTorComparison struct {
	client        *ServerTorClient
	host          ComparisonCapture
	lease         multihoprelay.TorCapture
	target        string
	request       serverLastRelayRequest
	ctx           context.Context
	cancel        context.CancelFunc
	network       *Network
	roots         *x509.CertPool // nil in the exported production constructor
	mu            sync.Mutex
	closing       bool
	closed        bool
	preparing     bool
	prepared      bool
	verified      bool
	lastDone      bool
	externalDone  bool
	openIssued    bool
	remoteClosed  bool
	anchor        serverLastRelayAnchor
	pathAt, dnsAt time.Time
	until         time.Time
	timer         *time.Timer
	control       *Control
	probe         *LastRelayProbe
	external      *LastRelayExternalStream
	connections   []net.Conn
	holds         int
	operation     chan struct{}
	workers       sync.WaitGroup
	closeGate     chan struct{}
	drain         *serverLastRelayDrain
	stop          func() bool
}

// Construction claims one measurement owner but performs no network work.
// Every nonnil result, including an error result, must be retained until Close.
func (c *ServerTorClient) OpenLastRelay(parent context.Context, capture ComparisonCapture, target string) (Comparison, error) {
	owned, err := c.openLastRelay(parent, capture, target, nil)
	if owned == nil {
		return nil, err
	}
	return owned, err
}
func (c *ServerTorClient) openLastRelay(parent context.Context, capture ComparisonCapture, target string, roots *x509.CertPool) (*ServerTorComparison, error) {
	if c == nil || parent == nil || parent.Err() != nil || !c.Ready() || capture.Current == nil || capture.DNSProof == nil || !capture.Current() ||
		capture.OwnerID == "" || len(capture.OwnerID) > 512 || capture.SessionID == "" || len(capture.SessionID) > 256 || strings.ContainsAny(capture.OwnerID+capture.SessionID, "\x00\r\n") || !paddingHex(capture.SourceSHA256, 64) {
		return nil, errServerLastRelay
	}
	if _, err := serverLastRelayTarget(target); err != nil {
		return nil, err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, errServerLastRelay
	}
	ctx, cancel := context.WithCancel(c.ctx)
	s := &ServerTorComparison{client: c, host: capture, target: target, ctx: ctx, cancel: cancel, roots: roots,
		operation: make(chan struct{}, 1), closeGate: make(chan struct{}, 1)}
	c.mu.Lock()
	if c.comparison != nil || c.closing || !c.ready {
		c.mu.Unlock()
		cancel()
		return nil, errServerLastRelay
	}
	s.lease = c.capture(c.lease)
	s.request = serverLastRelayRequest{Schema: 1, OwnerID: s.lease.OwnerID, SessionID: c.session, SourceSHA256: c.policy.SourceSHA256(), RegistrySHA256: s.lease.RegistrySHA256, DNSPolicySHA256: c.policy.DNSPolicySHA256(), Handle: hex.EncodeToString(random[:]), Target: target}
	clear(random[:])
	c.comparison = s
	c.mu.Unlock()
	network, err := NewNetwork(context.WithoutCancel(c.ctx), func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != serverLastRelayAddress || !s.retained() || !c.current() {
			return nil, errServerLastRelay
		}
		return dialServerTorCommand(ctx, net.JoinHostPort(s.lease.Host, strconv.Itoa(s.lease.Port)), s.lease.Username, s.lease.Password, serverLastRelayAddress, serverLastRelayCommand, c.dial)
	}, nil)
	s.network = network
	if err != nil {
		s.Cancel()
		return s, err
	}
	s.stop = context.AfterFunc(c.ctx, s.Cancel)
	return s, nil
}

func (s *ServerTorComparison) retained() bool {
	if s == nil || s.client == nil {
		return false
	}
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.comparison == s && c.capture(c.lease) == s.lease && c.request == s.lease.Request && c.policy.SourceSHA256() == s.request.SourceSHA256
}

func (s *ServerTorComparison) current() bool {
	if s == nil || s.ctx.Err() != nil || !s.retained() || !s.client.Ready() || !s.host.Current() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closing && (s.until.IsZero() || time.Now().Before(s.until))
}

func (s *ServerTorComparison) begin(parent context.Context) (context.Context, func(), error) {
	if parent == nil || parent.Err() != nil || !s.current() {
		return nil, nil, errServerLastRelay
	}
	select {
	case s.operation <- struct{}{}:
	default:
		return nil, nil, errServerLastRelay
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		<-s.operation
		return nil, nil, errServerLastRelay
	}
	s.workers.Add(1)
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(s.ctx, cancel)
	return ctx, func() { stop(); cancel(); s.workers.Done(); <-s.operation }, nil
}

func (s *ServerTorComparison) newRequest(action, address string) (serverLastRelayRequest, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return serverLastRelayRequest{}, errServerLastRelay
	}
	r := s.request
	r.Action = action
	r.Address = address
	r.Nonce = hex.EncodeToString(nonce[:])
	clear(nonce[:])
	return r, r.validate()
}

// The control stream survives normal data cancellation so an issued native
// frame can finish. Every other request has its own bounded context/deadline;
// every nonnil connection is recorded before any framing or validation error.
func (s *ServerTorComparison) exchange(parent context.Context, action, address string) (net.Conn, serverLastRelayResponse, error) {
	var response serverLastRelayResponse
	if parent == nil || parent.Err() != nil || !s.retained() || action != "close" && !s.current() {
		return nil, response, errServerLastRelay
	}
	r, err := s.newRequest(action, address)
	if err != nil {
		return nil, response, err
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	stop := func() bool { return true }
	if action != "close" {
		stop = context.AfterFunc(s.ctx, cancel)
	}
	defer stop()
	connection, err := s.network.DialRetainedContext(ctx, "tcp", serverLastRelayAddress)
	if connection != nil {
		s.mu.Lock()
		s.connections = append(s.connections, connection)
		s.mu.Unlock()
	}
	if err != nil || connection == nil {
		return connection, response, errServerLastRelay
	}
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return connection, response, errServerLastRelay
	}
	interrupted := make(chan struct{})
	interrupt := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()); close(interrupted) })
	defer func() {
		if !interrupt() {
			<-interrupted
		}
	}()
	if action == "open" {
		s.mu.Lock()
		s.openIssued = true
		s.mu.Unlock()
	}
	if serverLastRelayWrite(connection, r) != nil || serverLastRelayRead(connection, &response) != nil || response.Request != r || ctx.Err() != nil || !s.retained() {
		return connection, response, errServerLastRelay
	}
	if action == "close" {
		if !response.Closed || response.Anchor != nil {
			return connection, response, errServerLastRelay
		}
	} else {
		if response.Closed || response.Anchor == nil || s.validateAnchor(*response.Anchor) != nil || !s.current() {
			return connection, response, errServerLastRelay
		}
	}
	if connection.SetDeadline(time.Time{}) != nil {
		return connection, response, errServerLastRelay
	}
	return connection, response, nil
}

func (s *ServerTorComparison) validateAnchor(anchor serverLastRelayAnchor) error {
	client, ec := netip.ParseAddrPort(anchor.Client)
	target, et := netip.ParseAddrPort(anchor.Target)
	want, _ := serverLastRelayTarget(s.target)
	digest := sha256.Sum256([]byte(s.client.session))
	if ec != nil || et != nil || client.String() != anchor.Client || !client.Addr().IsLoopback() || client.Port() == 0 || target != want || target.String() != anchor.Target || anchor.SessionSHA256 != hex.EncodeToString(digest[:]) {
		return errServerLastRelay
	}
	if _, err := validateLastRelayCapture(anchor.capture(s.lease.OwnerID, s.request.SourceSHA256), time.Now()); err != nil {
		return err
	}
	s.mu.Lock()
	before, prepared := s.anchor, s.anchor.AnchorStream != 0
	s.mu.Unlock()
	if prepared && before != anchor {
		return errServerLastRelay
	}
	return nil
}

func (s *ServerTorComparison) proveClient(ctx context.Context) error {
	if !s.current() || s.host.DNSProof(ctx) != nil {
		return errServerLastRelay
	}
	dns := time.Now()
	// Production always supplies nil roots, preserving platform trust and the
	// fixed check.torproject.org identity. The private constructor lets the
	// loopback integration test exercise that actual TLS path with its own CA.
	proof, err := proveWithRoots(ctx, s.host.SessionID, s.client.DialRetainedContext, s.roots)
	if err != nil || !proof.IsTor || proof.SessionID != s.host.SessionID || proof.CheckedAt.Before(dns) || !s.current() {
		return errServerLastRelay
	}
	s.mu.Lock()
	s.dnsAt, s.pathAt = dns, proof.CheckedAt
	s.mu.Unlock()
	return nil
}

func (s *ServerTorComparison) Prepare(parent context.Context) (failure error) {
	ctx, finish, err := s.begin(parent)
	if err != nil {
		return err
	}
	defer finish()
	defer func() {
		if failure != nil {
			s.Cancel()
		}
	}()
	s.mu.Lock()
	if s.preparing || s.prepared {
		s.mu.Unlock()
		return errServerLastRelay
	}
	s.preparing = true
	s.mu.Unlock()
	if err := s.proveClient(ctx); err != nil {
		return err
	}
	connection, response, err := s.exchange(ctx, "open", "")
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.anchor = *response.Anchor
	s.until = minTime(s.dnsAt.Add(lastRelayProofMaxAge), time.UnixMilli(s.anchor.DNSCheckedAt).Add(lastRelayProofMaxAge))
	s.timer = time.AfterFunc(time.Until(s.until), s.Cancel)
	s.mu.Unlock()
	// The idle external anchor must survive probe cancellation until native
	// CLOSE is acknowledged. Its entered TLS/HTTP I/O is still gated by
	// current(), and Cancel explicitly interrupts it whenever it can be active.
	external, err := newLastRelayExternalStream(context.WithoutCancel(s.ctx), connection, s.target, s.current, s.roots)
	s.mu.Lock()
	s.external = external
	s.mu.Unlock()
	if err != nil || external == nil {
		return errServerLastRelay
	}
	if external.Prepare(ctx) != nil {
		return errServerLastRelay
	}
	connection, _, err = s.exchange(ctx, "control", "")
	if err != nil {
		return err
	}
	control, err := NewControl(connection)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.control = control
	s.mu.Unlock()
	probe, err := NewLastRelayProbe(s.ctx, control, s)
	s.mu.Lock()
	s.probe = probe
	s.mu.Unlock()
	if err != nil || probe == nil {
		return errServerLastRelay
	}
	if err := s.verifyAnchor(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	s.prepared = true
	s.verified = true
	s.mu.Unlock()
	go s.watch()
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *ServerTorComparison) watch() {
	for {
		if !s.current() {
			s.Cancel()
			return
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-s.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *ServerTorComparison) Identity() string {
	if !s.current() {
		return ""
	}
	s.mu.Lock()
	anchor, ready := s.anchor, s.prepared
	s.mu.Unlock()
	if !ready {
		return ""
	}
	return capturedDigest([]byte(strings.Join([]string{s.host.OwnerID, s.host.SourceSHA256, s.host.SessionID, s.request.OwnerID, s.request.SourceSHA256, s.request.RegistrySHA256, s.request.DNSPolicySHA256, s.request.Handle, s.target, anchor.PathSHA256, strconv.FormatUint(anchor.AnchorStream, 10), strconv.FormatUint(uint64(anchor.Circuit), 10), anchor.ExitFingerprint}, "\x00")))
}

func (s *ServerTorComparison) verifyAnchor(ctx context.Context) error {
	connection, _, err := s.exchange(ctx, "verify", "")
	if connection != nil {
		if closeErr := connection.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errServerLastRelay
		}
	}
	return err
}

func (s *ServerTorComparison) Verify(parent context.Context) (failure error) {
	ctx, finish, err := s.begin(parent)
	if err != nil {
		return err
	}
	defer finish()
	defer func() {
		if failure != nil {
			s.Cancel()
		}
	}()
	s.mu.Lock()
	ready := s.prepared
	s.mu.Unlock()
	if !ready || s.proveClient(ctx) != nil || s.verifyAnchor(ctx) != nil {
		return errServerLastRelay
	}
	s.mu.Lock()
	s.verified = true
	s.mu.Unlock()
	return nil
}

func (s *ServerTorComparison) ProbeLast(parent context.Context) (elapsed time.Duration, failure error) {
	ctx, finish, err := s.begin(parent)
	if err != nil {
		return 0, err
	}
	defer finish()
	defer func() {
		if failure != nil {
			s.Cancel()
		}
	}()
	s.mu.Lock()
	ready, probe := s.prepared && s.verified && !s.lastDone && !s.externalDone, s.probe
	s.mu.Unlock()
	if !ready || probe == nil || s.verifyAnchor(ctx) != nil {
		return 0, errServerLastRelay
	}
	elapsed, err = probe.Run(ctx)
	if err != nil || !s.current() {
		return 0, errServerLastRelay
	}
	s.mu.Lock()
	s.lastDone = true
	s.mu.Unlock()
	return elapsed, nil
}

func (s *ServerTorComparison) ProbeExternal(parent context.Context, target string) (elapsed time.Duration, failure error) {
	ctx, finish, err := s.begin(parent)
	if err != nil {
		return 0, err
	}
	defer finish()
	defer func() {
		if failure != nil {
			s.Cancel()
		}
	}()
	s.mu.Lock()
	ready, external := s.prepared && s.verified && s.lastDone && !s.externalDone, s.external
	s.mu.Unlock()
	if !ready || target != s.target || external == nil || s.verifyAnchor(ctx) != nil {
		return 0, errServerLastRelay
	}
	elapsed, err = external.Measure(ctx, target)
	if err != nil || !s.current() || s.verifyAnchor(ctx) != nil {
		return 0, errServerLastRelay
	}
	s.mu.Lock()
	s.externalDone = true
	s.mu.Unlock()
	return elapsed, nil
}

// LastRelayAnchor methods. The remote native identities came from the exact
// retained SOCKS socket; independent client proof times are also required.
func (s *ServerTorComparison) Capture() (LastRelayAnchorCapture, error) {
	if !s.current() {
		return LastRelayAnchorCapture{}, errServerLastRelay
	}
	s.mu.Lock()
	anchor, path, dns := s.anchor, s.pathAt, s.dnsAt
	s.mu.Unlock()
	if anchor.AnchorStream == 0 {
		return LastRelayAnchorCapture{}, errServerLastRelay
	}
	capture := anchor.capture(s.lease.OwnerID, s.request.SourceSHA256)
	capture.PathCheckedAt = minTime(capture.PathCheckedAt, path)
	capture.DNSCheckedAt = minTime(capture.DNSCheckedAt, dns)
	if _, err := validateLastRelayCapture(capture, time.Now()); err != nil {
		return LastRelayAnchorCapture{}, err
	}
	return capture, nil
}

type serverLastRelayHold struct {
	owner *ServerTorComparison
	once  sync.Once
}

func (h *serverLastRelayHold) Close(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrLastRelayTeardown
	}
	h.once.Do(func() { h.owner.mu.Lock(); h.owner.holds--; h.owner.mu.Unlock() })
	return nil
}
func (s *ServerTorComparison) Retain() (LastRelayAnchorHold, error) {
	if !s.current() {
		return nil, errServerLastRelay
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.holds != 0 {
		return nil, errServerLastRelay
	}
	s.holds++
	return &serverLastRelayHold{owner: s}, nil
}
func (s *ServerTorComparison) DialProbe(ctx context.Context, address string) (net.Conn, error) {
	connection, _, err := s.exchange(ctx, "probe", address)
	return connection, err
}
func (s *ServerTorComparison) NativeJoined() bool {
	if s == nil || s.client == nil {
		return false
	}
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stoppedOwner == s.lease.OwnerID && c.request == s.lease.Request && !c.attempt
}

func (s *ServerTorComparison) Cancel() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closing = true
	s.cancel()
	if s.timer != nil {
		s.timer.Stop()
	}
	probe, external, lastDone := s.probe, s.external, s.lastDone
	s.mu.Unlock()
	if probe != nil {
		probe.Cancel()
	}
	// During the relay measurement the external anchor is idle but must stay
	// retained until native CLOSE drains. After that measurement, external
	// cancellation can interrupt its own active HTTP bytes immediately.
	if external != nil && (probe == nil || lastDone) {
		external.Cancel()
	}
}

func (s *ServerTorComparison) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return ErrLastRelayTeardown
	}
	s.Cancel()
	select {
	case s.closeGate <- struct{}{}:
		defer func() { <-s.closeGate }()
	case <-ctx.Done():
		return ErrLastRelayTeardown
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	if s.drain == nil {
		attempt := &serverLastRelayDrain{done: make(chan struct{})}
		s.drain = attempt
		go func() { attempt.err = s.closeOwned(); close(attempt.done) }()
	}
	attempt := s.drain
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return ErrLastRelayTeardown
	case <-attempt.done:
	}
	if attempt.err != nil {
		s.mu.Lock()
		s.drain = nil
		s.mu.Unlock()
		return ErrLastRelayTeardown
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.stop != nil {
		s.stop()
	}
	s.client.mu.Lock()
	if s.client.comparison == s {
		s.client.comparison = nil
	}
	s.client.mu.Unlock()
	return nil
}

func (s *ServerTorComparison) closeOwned() error {
	s.workers.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.mu.Lock()
	probe, external, issued := s.probe, s.external, s.openIssued
	s.mu.Unlock()
	if probe != nil {
		if err := probe.Close(ctx); err != nil {
			return err
		}
	}
	if external != nil {
		if err := external.Close(ctx); err != nil {
			return err
		}
	}
	s.mu.Lock()
	remoteClosed := s.remoteClosed
	holds := s.holds
	s.mu.Unlock()
	if holds != 0 {
		return ErrLastRelayTeardown
	}
	if issued && !remoteClosed && !s.NativeJoined() {
		connection, _, err := s.exchange(ctx, "close", "")
		if connection != nil {
			if closeErr := connection.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				err = errServerLastRelay
			}
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.remoteClosed = true
		s.mu.Unlock()
	}
	s.mu.Lock()
	connections := append([]net.Conn(nil), s.connections...)
	s.mu.Unlock()
	for _, connection := range connections {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}
	if s.network != nil {
		return s.network.Close(ctx)
	}
	return nil
}
