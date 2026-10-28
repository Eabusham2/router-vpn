package mobiletor

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

const lastRelayExternalBodyLimit = 8192

var errLastRelayExternal = errors.New("Tor external response lost its retained connection, selected target or native owner")

// LastRelayExternalStream owns one already-connected candidate SOCKS stream.
// It never dials, resolves, redirects or reconnects. The native adapter must
// independently bind its actual socket to its source, session, selected DNS,
// circuit and final relay before accepting either comparison measurement.
// Every nonnil result remains owned until Close succeeds, including errors.
type LastRelayExternalStream struct {
	ctx        context.Context
	cancel     context.CancelFunc
	current    func() bool
	raw        net.Conn
	tls        *tls.Conn
	target     string
	address    netip.AddrPort
	local      string
	mu         sync.Mutex
	preparing  bool
	prepared   bool
	measuring  bool
	closing    bool
	joined     bool
	workers    sync.WaitGroup
	ioWorkers  sync.WaitGroup
	attempt    *lastRelayExternalClose
	parentStop func() bool
}

type lastRelayExternalClose struct {
	done chan struct{}
	err  error
}

// NewLastRelayExternalStream prepares ownership only; no TLS or application
// bytes are sent here. The target is the one approved endpoint chosen for both
// candidates and their final recheck. Public DNS policy is not changed by these
// literal measurement endpoints.
func NewLastRelayExternalStream(parent context.Context, connection net.Conn, target string, current func() bool) (*LastRelayExternalStream, error) {
	return newLastRelayExternalStream(parent, connection, target, current, nil)
}

func newLastRelayExternalStream(parent context.Context, connection net.Conn, target string, current func() bool, roots *x509.CertPool) (*LastRelayExternalStream, error) {
	if connection == nil {
		return nil, errLastRelayExternal
	}
	validParent := parent != nil && parent.Err() == nil
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	s := &LastRelayExternalStream{ctx: ctx, cancel: cancel, raw: connection, target: target, current: current}
	if local := connection.LocalAddr(); local != nil {
		s.local = local.String()
	}
	if !validParent || current == nil || !current() {
		s.Cancel()
		return s, errLastRelayExternal
	}
	var host string
	switch target {
	case "https://1.1.1.1/cdn-cgi/trace":
		host = "1.1.1.1"
	case "https://1.0.0.1/cdn-cgi/trace":
		host = "1.0.0.1"
	default:
		s.Cancel()
		return s, errLastRelayExternal
	}
	s.address = netip.AddrPortFrom(netip.MustParseAddr(host), 443)
	// TLS is constructed here from the approved numeric peer. The public
	// entry point cannot inject trust roots, disable verification or choose a
	// different certificate identity. Tests supply only a private fixture CA.
	s.tls = tls.Client(&lastRelayExternalConnection{Conn: connection, owner: s}, &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots, NextProtos: []string{"http/1.1"},
	})
	s.parentStop = context.AfterFunc(parent, s.Cancel)
	if ctx.Err() != nil {
		s.Cancel()
		return s, errLastRelayExternal
	}
	return s, nil
}

func (s *LastRelayExternalStream) Target() string {
	if s == nil {
		return ""
	}
	return s.target
}

func (s *LastRelayExternalStream) TargetAddress() netip.AddrPort {
	if s == nil {
		return netip.AddrPort{}
	}
	return s.address
}

// LocalAddress is captured from the actual socket, never supplied by a caller.
// A Local Tor adapter additionally requires its exact loopback tuple when it
// asks the native controller to identify the anchored stream and circuit.
func (s *LastRelayExternalStream) LocalAddress() string {
	if s == nil {
		return ""
	}
	return s.local
}

func (s *LastRelayExternalStream) available() bool {
	if s == nil || s.ctx.Err() != nil || s.current == nil {
		return false
	}
	s.mu.Lock()
	valid := !s.closing && !s.joined
	s.mu.Unlock()
	return valid && s.current() && s.ctx.Err() == nil
}

// Healthy is a memory-only lifetime check, not a fresh DNS, circuit or peer
// proof. Native adapters must still verify their exact anchored path receipt.
func (s *LastRelayExternalStream) Healthy() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	prepared := s.prepared
	s.mu.Unlock()
	return prepared && s.available()
}

func (s *LastRelayExternalStream) operation(parent context.Context, limit time.Duration) (context.Context, func(), error) {
	if parent == nil || parent.Err() != nil || !s.available() {
		return nil, nil, errLastRelayExternal
	}
	until := time.Now().Add(limit)
	if deadline, ok := parent.Deadline(); ok && deadline.Before(until) {
		until = deadline
	}
	ctx, cancel := context.WithDeadline(s.ctx, until)
	stop := context.AfterFunc(parent, cancel)
	return ctx, func() { stop(); cancel() }, nil
}

// Prepare completes ordinary certificate-verified TLS on the retained stream.
// Handshake time is outside the two HTTP response operands. An ignored late
// handshake stays counted even after the caller is cancelled.
func (s *LastRelayExternalStream) Prepare(parent context.Context) error {
	ctx, release, err := s.operation(parent, 30*time.Second)
	if err != nil {
		return err
	}
	defer release()
	s.mu.Lock()
	if s.closing || s.preparing || s.prepared || s.tls == nil {
		s.mu.Unlock()
		return errLastRelayExternal
	}
	s.preparing = true
	s.workers.Add(1)
	s.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		defer s.workers.Done()
		deadline, _ := ctx.Deadline()
		err := s.raw.SetDeadline(deadline)
		if err == nil {
			err = s.tls.HandshakeContext(ctx)
		}
		state := s.tls.ConnectionState()
		if err != nil || ctx.Err() != nil || !s.available() || !state.HandshakeComplete || len(state.VerifiedChains) == 0 ||
			(state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1") {
			s.Cancel()
			done <- errLastRelayExternal
			return
		}
		if s.raw.SetDeadline(time.Time{}) != nil {
			s.Cancel()
			done <- errLastRelayExternal
			return
		}
		s.mu.Lock()
		if !s.closing && s.ctx.Err() == nil {
			s.prepared = true
		}
		prepared := s.prepared
		s.mu.Unlock()
		if !prepared {
			done <- errLastRelayExternal
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil || parent.Err() != nil || !s.available() {
			s.Cancel()
			return errLastRelayExternal
		}
		return nil
	case <-ctx.Done():
		s.Cancel()
		return errLastRelayExternal
	}
}

// Measure sends one new HTTP request over that same prepared TLS connection.
// The clock spans request write through the complete bounded response. TLS,
// control commands and cleanup are outside it; the caller deadline bounds the
// whole operation. Native circuit/path receipt checks remain the adapter's job.
func (s *LastRelayExternalStream) Measure(parent context.Context, target string) (time.Duration, error) {
	if s == nil {
		return 0, errLastRelayExternal
	}
	if target != s.target {
		s.Cancel()
		return 0, errLastRelayExternal
	}
	ctx, release, err := s.operation(parent, 10*time.Second)
	if err != nil {
		return 0, err
	}
	defer release()
	s.mu.Lock()
	if s.closing || !s.prepared || s.measuring {
		s.mu.Unlock()
		return 0, errLastRelayExternal
	}
	s.measuring = true
	s.workers.Add(1)
	s.mu.Unlock()
	type result struct {
		elapsed time.Duration
		err     error
	}
	done := make(chan result, 1)
	go func() {
		defer s.workers.Done()
		elapsed, err := s.measure(ctx)
		if err != nil {
			s.Cancel()
		}
		done <- result{elapsed, err}
	}()
	select {
	case result := <-done:
		if result.err != nil || parent.Err() != nil || !s.available() {
			s.Cancel()
			return 0, errLastRelayExternal
		}
		return result.elapsed, nil
	case <-ctx.Done():
		s.Cancel()
		return 0, errLastRelayExternal
	}
}

func (s *LastRelayExternalStream) measure(ctx context.Context) (time.Duration, error) {
	deadline, _ := ctx.Deadline()
	if s.raw.SetDeadline(deadline) != nil || !s.available() {
		return 0, errLastRelayExternal
	}
	parsed, err := url.Parse(s.target)
	if err != nil {
		return 0, errLastRelayExternal
	}
	request := &http.Request{Method: http.MethodGet, URL: parsed, Host: parsed.Host,
		ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Accept-Encoding": {"identity"}, "Cache-Control": {"no-cache"}}}
	started := time.Now()
	if err := request.Write(s.tls); err != nil {
		return 0, errLastRelayExternal
	}
	// Both headers and body have a wire budget. A server cannot keep a worker
	// parsing an unbounded header before the body limit is applied.
	reader := bufio.NewReader(io.LimitReader(s.tls, 2*lastRelayExternalBodyLimit+1))
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return 0, errLastRelayExternal
	}
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.Close ||
		response.Uncompressed || response.ContentLength > lastRelayExternalBodyLimit || response.Header.Get("Content-Encoding") != "" {
		_ = response.Body.Close()
		return 0, errLastRelayExternal
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, lastRelayExternalBodyLimit+1))
	elapsed := time.Since(started)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) == 0 || len(body) > lastRelayExternalBodyLimit ||
		ctx.Err() != nil || !s.available() || elapsed <= 0 || elapsed > 10*time.Second {
		return 0, errLastRelayExternal
	}
	if s.raw.SetDeadline(time.Time{}) != nil {
		return 0, errLastRelayExternal
	}
	return elapsed, nil
}

// Cancel freezes data immediately and starts only this stream's raw close.
// Completion remains separately observable and retryable through Close.
func (s *LastRelayExternalStream) Cancel() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closing = true
	s.cancel()
	s.startCloseLocked()
	s.mu.Unlock()
}

func (s *LastRelayExternalStream) startCloseLocked() {
	if s.joined || s.attempt != nil {
		return
	}
	attempt := &lastRelayExternalClose{done: make(chan struct{})}
	s.attempt = attempt
	go func() {
		err := s.raw.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			attempt.err = errors.New("Tor external stream close remains unconfirmed")
			close(attempt.done)
			return
		}
		// No new application or TLS operation can enter after closing. A raw
		// Close that returns before an in-flight Read unwinds is insufficient.
		s.workers.Wait()
		s.ioWorkers.Wait()
		if s.tls != nil {
			_ = s.tls.Close()
		}
		s.mu.Lock()
		s.joined = true
		s.mu.Unlock()
		close(attempt.done)
	}()
}

func (s *LastRelayExternalStream) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return errLastRelayExternal
	}
	s.Cancel()
	s.mu.Lock()
	attempt := s.attempt
	if s.joined {
		s.mu.Unlock()
		if s.parentStop != nil {
			s.parentStop()
		}
		return nil
	}
	select {
	case <-attempt.done:
		if attempt.err != nil {
			s.attempt = nil
			s.startCloseLocked()
			attempt = s.attempt
		}
	default:
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return errors.New("Tor external stream cleanup is still owned")
	case <-attempt.done:
		if attempt.err != nil {
			return attempt.err
		}
		if s.parentStop != nil {
			s.parentStop()
		}
		return nil
	}
}

type lastRelayExternalConnection struct {
	net.Conn
	owner *LastRelayExternalStream
}

func (c *lastRelayExternalConnection) begin() error {
	s := c.owner
	s.mu.Lock()
	if s.closing || s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.ioWorkers.Add(1)
	s.mu.Unlock()
	if !s.available() {
		s.ioWorkers.Done()
		return net.ErrClosed
	}
	return nil
}

func (c *lastRelayExternalConnection) Read(data []byte) (int, error) {
	if err := c.begin(); err != nil {
		return 0, err
	}
	defer c.owner.ioWorkers.Done()
	n, err := c.Conn.Read(data)
	if !c.owner.available() {
		return 0, net.ErrClosed
	}
	return n, err
}

func (c *lastRelayExternalConnection) Write(data []byte) (int, error) {
	if err := c.begin(); err != nil {
		return 0, err
	}
	defer c.owner.ioWorkers.Done()
	n, err := c.Conn.Write(data)
	if !c.owner.available() {
		return 0, net.ErrClosed
	}
	return n, err
}
