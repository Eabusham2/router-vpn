package mobiletor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

// ServerTorLastRelayOptions comes only from the no-TUN native lease owner. Dial
// is its tracked, expiry-gated final Tor SOCKS dialer; it must send the reserved
// one-use probe address directly to that SOCKS owner without DNS. Prove returns
// completed selected-DNS and exit proofs, not control or heartbeat timestamps.
type ServerTorLastRelayOptions struct {
	Dial                         DialContext
	Current                      func() bool
	Prove                        func(context.Context) (path, dns time.Time, failure error)
	NativeJoined                 func() bool
	SOCKSUsername, SOCKSPassword string
}

// ServerTorLastRelay retains one authenticated measurement at a time. It never
// computes either comparison operand: the client receives the real TLS and
// relay-local HTTP bytes and owns both request-to-response clocks.
type ServerTorLastRelay struct {
	ctx     context.Context
	cancel  context.CancelFunc
	control *Control
	capture multihoprelay.TorCapture
	options ServerTorLastRelayOptions
	mu      sync.Mutex
	closing bool
	active  *serverLastRelayHandle
	retired map[string]serverLastRelayRequest
}

type serverLastRelayHandle struct {
	owner        *ServerTorLastRelay
	request      serverLastRelayRequest
	ctx          context.Context
	cancel       context.CancelFunc
	network      *Network
	mu           sync.Mutex
	closing      bool
	closed       bool
	ready        bool
	controlUsed  bool
	probeUsed    bool
	issued       bool
	identity     LastRelayIdentity
	status       LastRelayStatus
	known        bool
	anchor       serverLastRelayAnchor
	until        time.Time
	timer        *time.Timer
	stop         func() bool
	connections  []net.Conn
	clients      []*serverLastRelaySocket
	nonces       map[string]struct{}
	workers      sync.WaitGroup
	operation    chan struct{}
	closeGate    chan struct{}
	closeAttempt *serverLastRelayDrain
}

func NewServerTorLastRelay(parent context.Context, session *ServerTorSession, capture multihoprelay.TorCapture, options ServerTorLastRelayOptions) (*ServerTorLastRelay, error) {
	if session == nil || session.owner == nil || session.policy == nil || session.owner.control == nil ||
		capture.Validate() != nil || capture.Source.SourceSHA256 != session.SourceSHA256() ||
		capture.Source.DNSPolicySHA256 != session.policy.DNSPolicySHA256() || capture.Source.ID != session.policy.ID() ||
		capture.Source.Mode != session.policy.Mode() || capture.Request.EntryNodeID != session.policy.EntryNodeID() {
		return nil, errServerLastRelay
	}
	current := options.Current
	if current == nil {
		return nil, errServerLastRelay
	}
	options.Current = func() bool { return session.Current() && current() }
	session.owner.operation.Lock()
	defer session.owner.operation.Unlock()
	if session.comparisonClaimed || session.owner.closed.Load() {
		return nil, errServerLastRelay
	}
	owner, err := newServerTorLastRelay(parent, session.owner.control, capture, options)
	if err != nil {
		return nil, err
	}
	session.comparisonClaimed = true
	return owner, nil
}

func newServerTorLastRelay(parent context.Context, control *Control, capture multihoprelay.TorCapture, options ServerTorLastRelayOptions) (*ServerTorLastRelay, error) {
	if parent == nil || parent.Err() != nil || control == nil || capture.Validate() != nil || options.Dial == nil ||
		options.Current == nil || options.Prove == nil || options.NativeJoined == nil ||
		!paddingHex(options.SOCKSUsername, 64) || !paddingHex(options.SOCKSPassword, 64) || options.SOCKSUsername == options.SOCKSPassword {
		return nil, errServerLastRelay
	}
	ctx, cancel := context.WithCancel(parent)
	return &ServerTorLastRelay{ctx: ctx, cancel: cancel, control: control, capture: capture, options: options, retired: make(map[string]serverLastRelayRequest)}, nil
}

func (o *ServerTorLastRelay) matches(r serverLastRelayRequest) bool {
	return r.validate() == nil && r.OwnerID == o.capture.OwnerID && r.SessionID == o.capture.Request.SessionID &&
		r.SourceSHA256 == o.capture.Source.SourceSHA256 && r.RegistrySHA256 == o.capture.RegistrySHA256 &&
		r.DNSPolicySHA256 == o.capture.Source.DNSPolicySHA256
}

func sameServerLastRelayHandle(a, b serverLastRelayRequest) bool {
	a.Action, b.Action, a.Nonce, b.Nonce, a.Address, b.Address = "", "", "", "", "", ""
	return a == b
}

func (o *ServerTorLastRelay) newHandle(r serverLastRelayRequest) (*serverLastRelayHandle, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, reused := o.retired[r.Handle]
	if o.closing || o.ctx.Err() != nil || o.active != nil || reused || len(o.retired) >= 64 || !o.options.Current() || o.options.NativeJoined() {
		return nil, errServerLastRelay
	}
	ctx, cancel := context.WithCancel(o.ctx)
	h := &serverLastRelayHandle{owner: o, request: r, ctx: ctx, cancel: cancel, until: time.Now().Add(30 * time.Second),
		nonces: map[string]struct{}{r.Nonce: {}}, operation: make(chan struct{}, 1), closeGate: make(chan struct{}, 1)}
	network, err := NewNetwork(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || !h.current() {
			return nil, errServerLastRelay
		}
		connection, err := o.options.Dial(ctx, network, address)
		if connection == nil {
			return nil, err
		}
		return &serverLastRelaySocket{Conn: connection, current: h.current}, err
	}, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	h.network = network
	h.stop = context.AfterFunc(o.ctx, h.Cancel)
	o.active = h
	go h.watch()
	return h, nil
}

func (h *serverLastRelayHandle) watch() {
	for {
		if !h.current() {
			h.Cancel()
			return
		}
		h.mu.Lock()
		until := h.until
		h.mu.Unlock()
		timer := time.NewTimer(min(100*time.Millisecond, time.Until(until)))
		select {
		case <-h.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (h *serverLastRelayHandle) current() bool {
	if h == nil || h.ctx.Err() != nil || h.owner.ctx.Err() != nil || !h.owner.options.Current() || h.owner.options.NativeJoined() {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.closing && time.Now().Before(h.until)
}

func (h *serverLastRelayHandle) enter(client net.Conn) (*serverLastRelaySocket, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing || h.ctx.Err() != nil || len(h.clients) >= 3 {
		return nil, errServerLastRelay
	}
	connection := &serverLastRelaySocket{Conn: client, current: h.current}
	h.clients = append(h.clients, connection)
	h.workers.Add(1)
	return connection, nil
}

func (h *serverLastRelayHandle) lock(ctx context.Context) error {
	select {
	case h.operation <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (h *serverLastRelayHandle) unlock() { <-h.operation }

// Serve is reachable only after exact front peer + credentials + private
// command admission. Every frame additionally binds the lease and a fresh
// challenge; no field selects an arbitrary local Tor controller or socket.
func (o *ServerTorLastRelay) Serve(parent context.Context, client net.Conn) error {
	if o == nil || parent == nil || client == nil {
		return errServerLastRelay
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if client.SetDeadline(deadline) != nil {
		return errServerLastRelay
	}
	var r serverLastRelayRequest
	if serverLastRelayRead(client, &r) != nil || !o.matches(r) {
		return errServerLastRelay
	}
	if r.Action == "open" {
		h, err := o.newHandle(r)
		if err != nil {
			return err
		}
		tracked, err := h.enter(client)
		if err != nil {
			h.Cancel()
			return err
		}
		defer h.workers.Done()
		defer h.Cancel()
		return h.open(ctx, r, tracked)
	}
	o.mu.Lock()
	h := o.active
	old, retired := o.retired[r.Handle]
	o.mu.Unlock()
	if retired {
		if r.Action != "close" || !sameServerLastRelayHandle(old, r) {
			return errServerLastRelay
		}
		return serverLastRelayWrite(client, serverLastRelayResponse{Request: r, Closed: true})
	}
	if h == nil || !sameServerLastRelayHandle(h.request, r) {
		return errServerLastRelay
	}
	h.mu.Lock()
	_, replayed := h.nonces[r.Nonce]
	if replayed || len(h.nonces) >= 64 {
		h.mu.Unlock()
		return errServerLastRelay
	}
	h.nonces[r.Nonce] = struct{}{}
	h.mu.Unlock()
	if r.Action == "close" {
		if err := h.Close(ctx); err != nil {
			return err
		}
		return serverLastRelayWrite(client, serverLastRelayResponse{Request: r, Closed: true})
	}
	if !h.current() {
		return errServerLastRelay
	}
	if r.Action == "verify" {
		if err := h.verify(ctx); err != nil {
			h.Cancel()
			return err
		}
		h.mu.Lock()
		anchor := h.anchor
		h.mu.Unlock()
		return serverLastRelayWrite(client, serverLastRelayResponse{Request: r, Anchor: &anchor})
	}
	tracked, err := h.enter(client)
	if err != nil {
		return err
	}
	defer h.workers.Done()
	if r.Action == "control" {
		defer h.Cancel()
		return h.serveControl(ctx, r, tracked)
	}
	if r.Action == "probe" {
		err := h.serveProbe(ctx, r, tracked)
		if err != nil {
			h.Cancel()
		}
		return err
	}
	return errServerLastRelay
}

func (h *serverLastRelayHandle) dial(ctx context.Context, address string) (net.Conn, error) {
	connection, err := h.network.DialRetainedContext(ctx, "tcp", address)
	if connection != nil {
		h.mu.Lock()
		h.connections = append(h.connections, connection)
		h.mu.Unlock()
	}
	if err != nil || !h.current() {
		return connection, errServerLastRelay
	}
	return connection, nil
}

func (h *serverLastRelayHandle) open(ctx context.Context, r serverLastRelayRequest, client net.Conn) error {
	path, dns, err := h.owner.options.Prove(ctx)
	now := time.Now()
	if err != nil || dns.IsZero() || path.Before(dns) || path.After(now) || !dns.Add(lastRelayProofMaxAge).After(now.Add(LastRelayMinTTL)) || !h.current() {
		return errServerLastRelay
	}
	h.mu.Lock()
	h.until = dns.Add(lastRelayProofMaxAge)
	h.timer = time.AfterFunc(time.Until(h.until), h.Cancel)
	h.mu.Unlock()
	address, _ := serverLastRelayTarget(r.Target)
	connection, err := h.dial(ctx, address.String())
	if err != nil || connection == nil {
		return errServerLastRelay
	}
	local, err := netip.ParseAddrPort(connection.LocalAddr().String())
	if err != nil {
		return errServerLastRelay
	}
	digest := sha256.Sum256([]byte(h.request.SessionID))
	locator := LastRelayAnchorLocator{SessionSHA256: hex.EncodeToString(digest[:]), SourceSHA256: h.request.SourceSHA256,
		SOCKSUsername: h.owner.options.SOCKSUsername, SOCKSPassword: h.owner.options.SOCKSPassword, Client: local, Target: address}
	located, err := h.owner.control.LookupLastRelayAnchor(ctx, locator)
	if err != nil || !h.current() {
		return errServerLastRelay
	}
	anchor := serverLastRelayAnchor{SessionSHA256: locator.SessionSHA256, AnchorStream: located.AnchorStream, Circuit: located.Circuit,
		ExitFingerprint: located.ExitFingerprint, PathSHA256: located.PathSHA256, SOCKSUsername: locator.SOCKSUsername, SOCKSPassword: locator.SOCKSPassword,
		Client: local.String(), Target: address.String(), PathCheckedAt: path.UnixMilli(), DNSCheckedAt: dns.UnixMilli()}
	if _, err := validateLastRelayCapture(anchor.capture(h.request.OwnerID, h.request.SourceSHA256), time.Now()); err != nil {
		return err
	}
	h.mu.Lock()
	h.anchor = anchor
	h.ready = true
	h.mu.Unlock()
	if serverLastRelayWrite(client, serverLastRelayResponse{Request: r, Anchor: &anchor}) != nil {
		return errServerLastRelay
	}
	return h.pump(client, connection)
}

func (h *serverLastRelayHandle) verify(ctx context.Context) error {
	if err := h.lock(ctx); err != nil {
		return err
	}
	defer h.unlock()
	return h.verifyLocked(ctx)
}
func (h *serverLastRelayHandle) verifyLocked(ctx context.Context) error {
	if !h.current() {
		return errServerLastRelay
	}
	h.mu.Lock()
	anchor, ready := h.anchor, h.ready
	h.mu.Unlock()
	if !ready {
		return errServerLastRelay
	}
	client, ec := netip.ParseAddrPort(anchor.Client)
	target, et := netip.ParseAddrPort(anchor.Target)
	if ec != nil || et != nil {
		return errServerLastRelay
	}
	actual, err := h.owner.control.LookupLastRelayAnchor(ctx, LastRelayAnchorLocator{SessionSHA256: anchor.SessionSHA256, SourceSHA256: h.request.SourceSHA256,
		SOCKSUsername: anchor.SOCKSUsername, SOCKSPassword: anchor.SOCKSPassword, Client: client, Target: target})
	if err != nil || actual.AnchorStream != anchor.AnchorStream || actual.Circuit != anchor.Circuit || actual.ExitFingerprint != anchor.ExitFingerprint || actual.PathSHA256 != anchor.PathSHA256 || !h.current() {
		return errServerLastRelay
	}
	return nil
}

func (h *serverLastRelayHandle) pump(client, remote net.Conn) error {
	if !h.current() {
		return errServerLastRelay
	}
	h.mu.Lock()
	until := h.until
	h.mu.Unlock()
	if client.SetDeadline(until) != nil || remote.SetDeadline(until) != nil {
		return errServerLastRelay
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(remote, client); _ = remote.Close(); _ = client.Close() }()
	_, _ = io.Copy(client, remote)
	_ = remote.Close()
	_ = client.Close()
	<-done
	return nil
}

func (h *serverLastRelayHandle) Cancel() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		return
	}
	h.closing = true
	h.cancel()
	if h.timer != nil {
		h.timer.Stop()
	}
	connections := append([]net.Conn(nil), h.connections...)
	for _, c := range h.clients {
		connections = append(connections, c)
	}
	h.mu.Unlock()
	for _, c := range connections {
		go func(c net.Conn) { _ = c.Close() }(c)
	}
}

func (h *serverLastRelayHandle) Close(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if ctx == nil {
		return ErrLastRelayTeardown
	}
	h.Cancel()
	select {
	case h.closeGate <- struct{}{}:
		defer func() { <-h.closeGate }()
	case <-ctx.Done():
		return ErrLastRelayTeardown
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	if h.closeAttempt == nil {
		attempt := &serverLastRelayDrain{done: make(chan struct{})}
		h.closeAttempt = attempt
		go func() { attempt.err = h.drain(); close(attempt.done) }()
	}
	attempt := h.closeAttempt
	h.mu.Unlock()
	select {
	case <-ctx.Done():
		return ErrLastRelayTeardown
	case <-attempt.done:
	}
	if attempt.err != nil {
		h.mu.Lock()
		h.closeAttempt = nil
		h.mu.Unlock()
		return ErrLastRelayTeardown
	}
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	if h.stop != nil {
		h.stop()
	}
	h.owner.mu.Lock()
	if h.owner.active == h {
		h.owner.active = nil
		h.owner.retired[h.request.Handle] = h.request
	}
	h.owner.mu.Unlock()
	return nil
}

func (h *serverLastRelayHandle) drain() error {
	h.mu.Lock()
	connections := append([]net.Conn(nil), h.connections...)
	for _, c := range h.clients {
		connections = append(connections, c)
	}
	h.mu.Unlock()
	for _, c := range connections {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			return err
		}
	}
	h.workers.Wait()
	// A late dial is retained before its worker returns. Re-read the list;
	// cancellation may have raced the first snapshot above.
	h.mu.Lock()
	connections = append([]net.Conn(nil), h.connections...)
	h.mu.Unlock()
	for _, c := range connections {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			return err
		}
	}
	if err := h.network.Close(context.Background()); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.lock(ctx); err != nil {
		return err
	}
	defer h.unlock()
	h.mu.Lock()
	issued, identity := h.issued, h.identity
	h.mu.Unlock()
	if !issued || h.owner.options.NativeJoined() {
		return nil
	}
	for {
		status, err := h.owner.control.CloseLastRelay(ctx, identity)
		if err != nil {
			if h.owner.options.NativeJoined() {
				return nil
			}
			return err
		}
		if !h.statusMatches(status) {
			return errServerLastRelay
		}
		if status.State == "stopped" {
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrLastRelayTeardown
		case <-timer.C:
		}
	}
}

func (o *ServerTorLastRelay) Cancel() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.closing = true
	o.cancel()
	h := o.active
	o.mu.Unlock()
	if h != nil {
		h.Cancel()
	}
}
func (o *ServerTorLastRelay) Close(ctx context.Context) error {
	if o == nil {
		return nil
	}
	o.Cancel()
	o.mu.Lock()
	h := o.active
	o.mu.Unlock()
	if h != nil {
		return h.Close(ctx)
	}
	return nil
}
