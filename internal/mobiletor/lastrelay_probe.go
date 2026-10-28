package mobiletor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const lastRelayProofMaxAge = 30 * time.Second

var ErrLastRelayTeardown = errors.New("last-relay probe teardown remains unconfirmed; retain its captured owner")

// LastRelayAnchorCapture must come from the running native owner and its
// actual open external SOCKS stream. No control echo, most-recent circuit,
// selected UI profile or cached latency can supply this independent capture.
// OwnerID names the immutable native instance, even if a profile is reused.
type LastRelayAnchorCapture struct {
	OwnerID, SessionSHA256, SourceSHA256 string
	AnchorStream                         uint64
	Circuit                              uint32
	ExitFingerprint, PathSHA256          string
	SOCKSUsername, SOCKSPassword         string
	PathCheckedAt, DNSCheckedAt          time.Time
}

// LastRelayAnchorHold is a retained reference to the same already-open anchor.
// Close releases this reference only, after the probe has drained. The path
// owner keeps its own anchor alive for the separate external measurement.
type LastRelayAnchorHold interface {
	Close(context.Context) error
}

// LastRelayAnchor is an internal integration boundary, not a graph-admission
// API. The native adapter must discover its exact retained SOCKS socket and
// circuit, capture the full running source independently, and bind all calls
// to that instance. Capture is a bounded memory-only read. DialProbe sends the
// reserved destination directly to that instance's isolated SOCKS connection;
// it must never resolve the private name or use an ordinary network fallback.
// NativeJoined refers only to this exact captured native process/resident,
// allowing cleanup after an ambiguous control reply has retired its socket.
// Implementing these adapters and authenticated Server transport is separate
// work; this prerequisite does not enable public Tor Compare.
type LastRelayAnchor interface {
	Capture() (LastRelayAnchorCapture, error)
	Retain() (LastRelayAnchorHold, error)
	DialProbe(context.Context, string) (net.Conn, error)
	NativeJoined() bool
}

type LastRelayProbe struct {
	control                        *Control
	anchor                         LastRelayAnchor
	hold                           LastRelayAnchorHold
	path                           LastRelayAnchorCapture
	ctx                            context.Context
	cancel                         context.CancelFunc
	network                        *Network
	mu                             sync.Mutex
	closeMu                        chan struct{}
	started, issued, known, closed bool
	done, watched                  chan struct{}
	identity                       LastRelayIdentity
	status                         LastRelayStatus
	until                          time.Time
	timer                          *time.Timer
	stream                         net.Conn
	streamClose                    chan struct{}
	streamCloseErr                 error
	nativeClose                    chan struct{}
	nativeCloseErr                 error
	elapsed                        time.Duration
	failure                        error
}

func validateLastRelayCapture(capture LastRelayAnchorCapture, now time.Time) (time.Time, error) {
	if capture.OwnerID == "" || len(capture.OwnerID) > 512 || strings.ContainsAny(capture.OwnerID, "\x00\r\n") ||
		!paddingHex(capture.SessionSHA256, 64) || !paddingHex(capture.SourceSHA256, 64) || capture.AnchorStream < 1 || capture.AnchorStream > math.MaxInt64 || capture.Circuit == 0 ||
		!paddingHex(capture.ExitFingerprint, 40) || capture.ExitFingerprint == strings.Repeat("0", 40) || !paddingHex(capture.PathSHA256, 64) ||
		!paddingHex(capture.SOCKSUsername, 32, 64) || !paddingHex(capture.SOCKSPassword, 64) ||
		capture.DNSCheckedAt.IsZero() || capture.PathCheckedAt.Before(capture.DNSCheckedAt) || capture.PathCheckedAt.After(now) ||
		!capture.DNSCheckedAt.Add(lastRelayProofMaxAge).After(now.Add(LastRelayMinTTL)) {
		return time.Time{}, errors.New("last-relay probe requires an independently captured live source, anchor and selected-DNS/path proof")
	}
	return capture.DNSCheckedAt.Add(lastRelayProofMaxAge), nil
}

func sameLastRelayAnchor(a, b LastRelayAnchorCapture) bool {
	return a.OwnerID == b.OwnerID && a.SessionSHA256 == b.SessionSHA256 && a.SourceSHA256 == b.SourceSHA256 &&
		a.AnchorStream == b.AnchorStream && a.Circuit == b.Circuit && a.ExitFingerprint == b.ExitFingerprint && a.PathSHA256 == b.PathSHA256 &&
		a.SOCKSUsername == b.SOCKSUsername && a.SOCKSPassword == b.SOCKSPassword
}

// Construction claims one controller and retains the existing anchor, but
// sends no control command, opens no probe socket and produces no measurement.
// Every non-nil returned probe must be retained until Close succeeds, including
// a constructor error, Run failure or expiration of the caller's deadline.
func NewLastRelayProbe(parent context.Context, control *Control, anchor LastRelayAnchor) (*LastRelayProbe, error) {
	if parent == nil || parent.Err() != nil || control == nil || control.conn == nil || anchor == nil || anchor.NativeJoined() {
		return nil, errors.New("last-relay probe requires its captured native controller and anchor")
	}
	capture, err := anchor.Capture()
	if err != nil {
		return nil, errors.New("last-relay native anchor capture is unavailable")
	}
	until, err := validateLastRelayCapture(capture, time.Now())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	p := &LastRelayProbe{control: control, anchor: anchor, path: capture, ctx: ctx, cancel: cancel, until: until,
		closeMu: make(chan struct{}, 1), done: make(chan struct{}), watched: make(chan struct{})}
	if !control.lastRelayProbe.CompareAndSwap(nil, p) {
		cancel()
		return nil, errors.New("last-relay controller already retains another probe")
	}
	hold, err := anchor.Retain()
	if hold == nil {
		cancel()
		p.releaseClaim()
		return nil, errors.New("last-relay anchor could not be retained")
	}
	p.hold = hold
	if err != nil {
		p.failure = errors.New("last-relay anchor retention returned an unfinished owner")
		cancel()
		return p, p.failure
	}
	p.network, err = NewNetwork(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		p.mu.Lock()
		identity := p.identity
		p.mu.Unlock()
		want, err := lastRelayExpectedAddress(identity)
		if err != nil || network != "tcp" || address != want || p.current() != nil {
			return nil, errors.New("last-relay dial escaped its one-use captured destination")
		}
		raw, err := p.anchor.DialProbe(ctx, address)
		if raw == nil {
			return nil, err
		}
		return &lastRelayProbeConnection{Conn: raw, probe: p}, err
	}, nil)
	if err != nil {
		// NewNetwork's arguments are validated above. Keep even an unexpected
		// failure reviewable through the retained probe instead of dropping hold.
		p.failure = err
		cancel()
		return p, err
	}
	if err := p.current(); err != nil {
		p.failure = err
		cancel()
		return p, err
	}
	return p, nil
}

func (p *LastRelayProbe) releaseClaim() {
	p.control.lastRelayProbe.CompareAndSwap(p, nil)
}

func (p *LastRelayProbe) currentAnchor() error {
	if p.anchor.NativeJoined() {
		return errors.New("last-relay captured native owner is already joined")
	}
	now := time.Now()
	capture, err := p.anchor.Capture()
	if err != nil || !sameLastRelayAnchor(p.path, capture) || capture.PathCheckedAt.Before(p.path.PathCheckedAt) || capture.DNSCheckedAt.Before(p.path.DNSCheckedAt) {
		return errors.New("last-relay running native source, anchor or completed proof changed")
	}
	if _, err := validateLastRelayCapture(capture, now); err != nil || !p.path.DNSCheckedAt.Add(lastRelayProofMaxAge).After(now) {
		return errors.New("last-relay captured path or selected-DNS proof expired")
	}
	return nil
}

func (p *LastRelayProbe) current() error {
	if p.ctx.Err() != nil {
		return errors.New("last-relay probe was cancelled")
	}
	p.mu.Lock()
	until := p.until
	p.mu.Unlock()
	if !until.After(time.Now()) {
		return errors.New("last-relay native grant expired")
	}
	return p.currentAnchor()
}

func (p *LastRelayProbe) record(status LastRelayStatus, sent time.Time) error {
	if status.Identity.SessionSHA256 != p.path.SessionSHA256 || status.Identity.SourceSHA256 != p.path.SourceSHA256 ||
		status.AnchorStream != p.path.AnchorStream || status.Circuit != p.path.Circuit || status.ExitFingerprint != p.path.ExitFingerprint || status.PathSHA256 != p.path.PathSHA256 {
		return errors.New("last-relay native receipt does not match the independently captured running anchor")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.known {
		if err := validateLastRelayProgress(p.status, status); err != nil {
			return err
		}
	}
	if status.State != "draining" && status.State != "stopped" {
		// The send instant conservatively excludes time spent waiting for the
		// controller. No STATUS read can extend an existing native grant.
		until := sent.Add(status.Expires)
		if until.Before(p.until) {
			p.until = until
			if p.timer != nil && p.ctx.Err() == nil {
				p.timer.Stop()
				p.timer = time.AfterFunc(time.Until(until), p.Cancel)
			}
		}
	}
	p.status, p.known = status, true
	return nil
}

// Framed control operations finish within their own bound even after normal
// probe cancellation. Cancelling a data read must not destroy the candidate's
// shared control stream and race another owner's cleanup.
func lastRelayCommandContext(until time.Time) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(2 * time.Second)
	if until.Before(deadline) {
		deadline = until
	}
	return context.WithDeadline(context.Background(), deadline)
}

func (p *LastRelayProbe) Cancel() {
	if p != nil && p.cancel != nil {
		p.cancel()
	}
}

func (p *LastRelayProbe) watch() {
	defer close(p.watched)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if p.current() != nil {
				p.Cancel()
				return
			}
		}
	}
}

// Run measures exactly one fresh client-origin HTTP request and full response
// after its dedicated BEGIN_DIR connection succeeds. It never reads a native
// RTT or includes connection/control setup, status or cleanup time.
// A driver may use its positive duration for routechoice.Session.ProbeLast;
// the independently selected external target and arithmetic remain separate.
func (p *LastRelayProbe) Run(ctx context.Context) (time.Duration, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return 0, errors.New("last-relay measurement requires its live caller")
	}
	p.mu.Lock()
	if p.started || p.closed || p.ctx.Err() != nil || p.failure != nil {
		p.mu.Unlock()
		return 0, errors.New("last-relay measurement belongs to a used or unavailable owner")
	}
	p.started = true
	if end, ok := ctx.Deadline(); ok && end.Before(p.until) {
		p.until = end
	}
	if limit := time.Now().Add(LastRelayMaxTTL); limit.Before(p.until) {
		p.until = limit
	}
	p.timer = time.AfterFunc(time.Until(p.until), p.Cancel)
	p.mu.Unlock()
	stop := context.AfterFunc(ctx, p.Cancel)
	defer stop()
	go p.watch()
	go p.work()
	select {
	case <-p.done:
	case <-ctx.Done():
		p.Cancel()
		return 0, ctx.Err()
	case <-p.ctx.Done():
		return 0, errors.New("last-relay measurement was cancelled or its captured owner expired")
	}
	p.mu.Lock()
	elapsed, failure := p.elapsed, p.failure
	p.mu.Unlock()
	if ctx.Err() != nil || p.current() != nil {
		failure = errors.New("last-relay measurement completed after cancellation or an ownership change")
	}
	cleanup, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := p.Close(cleanup); err != nil {
		return 0, errors.Join(failure, ErrLastRelayTeardown)
	}
	if failure != nil || elapsed <= 0 || ctx.Err() != nil || p.currentAnchor() != nil {
		return 0, errors.New("last-relay measurement did not retain a valid bounded response and current path")
	}
	return elapsed, nil
}

func (p *LastRelayProbe) work() {
	elapsed, err := p.measure()
	p.mu.Lock()
	p.elapsed, p.failure = elapsed, err
	p.mu.Unlock()
	close(p.done)
}

func (p *LastRelayProbe) measure() (time.Duration, error) {
	if err := p.current(); err != nil {
		return 0, err
	}
	p.mu.Lock()
	until := p.until
	p.mu.Unlock()
	command, cancel := lastRelayCommandContext(until)
	capability, err := p.control.LastRelayInfo(command)
	cancel()
	if err != nil || capability.GenerationHighWater == math.MaxInt64 || p.current() != nil {
		return 0, errors.New("last-relay native capability is unavailable or exhausted")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, errors.New("last-relay fresh nonce is unavailable")
	}
	identity := LastRelayIdentity{SessionSHA256: p.path.SessionSHA256, SourceSHA256: p.path.SourceSHA256, Generation: capability.GenerationHighWater + 1, Nonce: hex.EncodeToString(nonce[:])}
	clear(nonce[:])
	ttl := min(time.Until(until), LastRelayMaxTTL).Truncate(time.Millisecond)
	if ttl < LastRelayMinTTL {
		return 0, errors.New("last-relay capture has no bounded probe lifetime remaining")
	}
	p.mu.Lock()
	p.identity, p.issued = identity, true
	p.mu.Unlock()
	command, cancel = lastRelayCommandContext(until)
	sent := time.Now()
	status, err := p.control.CaptureLastRelay(command, identity, ttl, p.path.AnchorStream, p.path.SOCKSUsername, p.path.SOCKSPassword)
	cancel()
	if err != nil {
		return 0, errors.New("last-relay native capture was not acknowledged")
	}
	if err := p.record(status, sent); err != nil {
		return 0, err
	}
	if err := p.current(); err != nil {
		return 0, err
	}
	p.mu.Lock()
	until = p.until
	if p.timer != nil {
		p.timer.Stop()
	}
	if p.ctx.Err() == nil {
		p.timer = time.AfterFunc(time.Until(until), p.Cancel)
	}
	p.mu.Unlock()
	probeContext, cancelProbe := context.WithDeadline(p.ctx, until)
	defer cancelProbe()
	address, _ := lastRelayExpectedAddress(identity)
	connection, err := p.network.DialRetainedContext(probeContext, "tcp", address)
	p.mu.Lock()
	p.stream = connection
	p.mu.Unlock()
	if err != nil || connection == nil || p.current() != nil || probeContext.Err() != nil {
		return 0, errors.New("last-relay dedicated candidate socket was not admitted")
	}
	// Bind the actual assigned probe stream before any timed request. This
	// readback is outside the HTTP interval and proves that SOCKS success came
	// from the captured BEGIN_DIR CONNECTED, not another ordinary connection.
	command, cancel = lastRelayCommandContext(until)
	sent = time.Now()
	status, err = p.control.LastRelayStatus(command, identity)
	cancel()
	if err != nil {
		return 0, errors.New("last-relay connected socket lacks its native stream identity")
	}
	if err := p.record(status, sent); err != nil {
		return 0, err
	}
	if status.State != "connected" || status.Stream == 0 || status.RelayStream == 0 || status.RequestBytes != 0 || status.ResponseBytes != 0 || p.current() != nil {
		return 0, errors.New("last-relay connected stream was replaced or used before the timed request")
	}
	p.mu.Lock()
	until = p.until
	p.mu.Unlock()
	if err := connection.SetDeadline(until); err != nil {
		return 0, errors.New("last-relay candidate socket cannot enforce its deadline")
	}
	started := time.Now()
	if n, err := io.WriteString(connection, lastRelayRequest); err != nil || n != len(lastRelayRequest) {
		return 0, errors.New("last-relay bounded request did not reach its owned stream")
	}
	data, err := io.ReadAll(io.LimitReader(connection, LastRelayMaxResponseBytes+1))
	if err != nil || probeContext.Err() != nil || p.current() != nil || len(data) > LastRelayMaxResponseBytes {
		return 0, errors.New("last-relay real response failed, exceeded its bound or changed owner")
	}
	if err := validateLastRelayResponse(data); err != nil {
		return 0, err
	}
	elapsed := time.Since(started)
	if elapsed <= 0 || elapsed > LastRelayMaxTTL {
		return 0, errors.New("last-relay HTTP response interval exceeds its measurement bound")
	}
	command, cancel = lastRelayCommandContext(until)
	sent = time.Now()
	status, err = p.control.LastRelayStatus(command, identity)
	cancel()
	if err != nil {
		return 0, errors.New("last-relay response lacks its captured native stream receipt")
	}
	if err := p.record(status, sent); err != nil {
		return 0, err
	}
	if status.State != "ended" || status.EndReason != lastRelayEndDone || status.RequestBytes != uint32(len(lastRelayRequest)) ||
		status.ResponseBytes != uint32(len(data)) || status.Stream == 0 || status.RelayStream == 0 || p.current() != nil {
		return 0, errors.New("last-relay actual response and native circuit/stream accounting disagree")
	}
	return elapsed, nil
}

func validateLastRelayResponse(data []byte) error {
	bad := errors.New("last-relay stream did not return the real bounded relay-local robots response")
	if len(data) == 0 || len(data) > LastRelayMaxResponseBytes {
		return bad
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return bad
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 || response.ProtoMinor > 1 || response.ContentLength != int64(len(lastRelayRobots)) ||
		len(response.TransferEncoding) != 0 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return bad
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != lastRelayRobots {
		return bad
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		return bad
	}
	return nil
}

func (p *LastRelayProbe) closeStream(ctx context.Context) error {
	p.mu.Lock()
	connection := p.stream
	if connection == nil {
		p.mu.Unlock()
		return nil
	}
	if p.streamClose == nil {
		p.streamClose = make(chan struct{})
		done := p.streamClose
		go func() {
			err := connection.Close()
			p.mu.Lock()
			p.streamCloseErr = err
			p.mu.Unlock()
			close(done)
		}()
	}
	done := p.streamClose
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.streamCloseErr != nil {
		p.streamClose = nil
		return p.streamCloseErr
	}
	return nil
}

// The caller owns its wait deadline, while the issued control frame owns an
// independent fixed deadline. An interrupted wait never abandons a reply or
// causes a replacement caller to send a second CLOSE into the same stream.
func (p *LastRelayProbe) closeNative(ctx context.Context) error {
	joined := p.anchor.NativeJoined()
	p.mu.Lock()
	if (!p.issued || joined) && p.nativeClose == nil {
		p.mu.Unlock()
		return nil
	}
	if p.nativeClose == nil {
		p.nativeClose = make(chan struct{})
		done, identity := p.nativeClose, p.identity
		go func() {
			command, cancel := lastRelayCommandContext(time.Now().Add(2 * time.Second))
			sent := time.Now()
			status, err := p.control.CloseLastRelay(command, identity)
			cancel()
			if err == nil {
				err = p.record(status, sent)
				if err != nil {
					_ = p.control.Close()
				} else if status.State != "stopped" {
					err = ErrLastRelayTeardown
				}
			}
			p.mu.Lock()
			p.nativeCloseErr = err
			p.mu.Unlock()
			close(done)
		}()
	}
	done := p.nativeClose
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	p.mu.Lock()
	err := p.nativeCloseErr
	if err != nil {
		p.nativeClose = nil
	}
	p.mu.Unlock()
	if err != nil && p.anchor.NativeJoined() {
		return nil
	}
	return err
}

// Close cancels data immediately, then joins every issued operation, actual
// socket I/O, native stream and retained anchor reference. Timeout keeps this
// same object and controller claim intact for retry; it never stops a newer
// capture or accepts a merely closed control socket as a native drain.
func (p *LastRelayProbe) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		return ErrLastRelayTeardown
	}
	p.Cancel()
	select {
	case p.closeMu <- struct{}{}:
		defer func() { <-p.closeMu }()
	case <-ctx.Done():
		return ErrLastRelayTeardown
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	started, timer := p.started, p.timer
	p.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	if started {
		for _, done := range []<-chan struct{}{p.done, p.watched} {
			select {
			case <-done:
			case <-ctx.Done():
				return ErrLastRelayTeardown
			}
		}
	}
	if err := p.closeStream(ctx); err != nil {
		return ErrLastRelayTeardown
	}
	if p.network != nil {
		if err := p.network.Close(ctx); err != nil {
			return ErrLastRelayTeardown
		}
	}
	for {
		if ctx.Err() != nil {
			return ErrLastRelayTeardown
		}
		if err := p.closeNative(ctx); err == nil {
			break
		} else if !errors.Is(err, ErrLastRelayTeardown) {
			return ErrLastRelayTeardown
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrLastRelayTeardown
		case <-timer.C:
		}
	}
	if p.hold != nil {
		if err := p.hold.Close(ctx); err != nil {
			return ErrLastRelayTeardown
		}
	}
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.releaseClaim()
	return nil
}

// This wrapper lives inside the retained Network socket. A raw Close that
// returns before an entered Read/Write unwinds cannot release the network or
// the anchor; the actual operation remains counted until it has returned.
type lastRelayProbeConnection struct {
	net.Conn
	probe           *LastRelayProbe
	mu              sync.Mutex
	closeMu         sync.Mutex
	closing, closed bool
	workers         sync.WaitGroup
}

func (c *lastRelayProbeConnection) begin() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.probe.current() != nil {
		return net.ErrClosed
	}
	c.workers.Add(1)
	return nil
}

func (c *lastRelayProbeConnection) Read(buffer []byte) (int, error) {
	if err := c.begin(); err != nil {
		return 0, err
	}
	defer c.workers.Done()
	n, err := c.Conn.Read(buffer)
	if c.probe.current() != nil {
		return 0, net.ErrClosed
	}
	return n, err
}

func (c *lastRelayProbeConnection) Write(buffer []byte) (int, error) {
	if err := c.begin(); err != nil {
		return 0, err
	}
	defer c.workers.Done()
	n, err := c.Conn.Write(buffer)
	if c.probe.current() != nil {
		return 0, net.ErrClosed
	}
	return n, err
}

func (c *lastRelayProbeConnection) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closing = true
	c.mu.Unlock()
	if err := c.Conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		return err
	}
	c.workers.Wait()
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
