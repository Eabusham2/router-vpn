package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Control receipts and the native stream registry are explicit doubles here.
// Every positive response traverses a real loopback TCP socket. The separately
// compiled Tor fixture proves actual encrypted BEGIN_DIR/CONNECTED/DATA/END.
type lastRelayProbeFixture struct {
	t                                               *testing.T
	wire                                            *lastRelayControlWire
	mu                                              sync.Mutex
	path                                            LastRelayAnchorCapture
	fields                                          map[string]string
	expires                                         time.Time
	highwater                                       uint64
	holds, releases, dials, closes                  int
	joined, captureFailed, retainFailed, holdFailed bool
	nativeDone, forceDraining                       bool
	response                                        []byte
	responseDelay, captureDelay, dialDelay          time.Duration
	setupElapsed                                    time.Duration
	identity                                        LastRelayIdentity
	addresses                                       []string
	dialOverride                                    func(context.Context, string) (net.Conn, error)
	alter                                           func(string, string) string
	enteredCapture, releaseCapture                  chan struct{}
	enteredClose, releaseClose                      chan struct{}
	closeEntered                                    sync.Once
	enteredRead, releaseResponse                    chan struct{}
	listeners                                       []net.Listener
	servers                                         sync.WaitGroup
	anchor, anchorPeer                              net.Conn
}

func newLastRelayProbeFixture(t *testing.T) *lastRelayProbeFixture {
	t.Helper()
	now := time.Now().Add(-time.Second)
	f := &lastRelayProbeFixture{t: t, path: LastRelayAnchorCapture{OwnerID: "captured-native-instance", SessionSHA256: strings.Repeat("1", 64), SourceSHA256: strings.Repeat("2", 64),
		AnchorStream: 111, Circuit: 222, ExitFingerprint: strings.Repeat("4", 40), PathSHA256: strings.Repeat("5", 64), SOCKSUsername: strings.Repeat("a", 64), SOCKSPassword: strings.Repeat("b", 64), DNSCheckedAt: now, PathCheckedAt: now},
		response: []byte(fmt.Sprintf("HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(lastRelayRobots), lastRelayRobots))}
	f.anchor, f.anchorPeer = net.Pipe()
	f.wire = newLastRelayControlWire(t, f.control)
	t.Cleanup(func() {
		_ = f.anchor.Close()
		_ = f.anchorPeer.Close()
		f.mu.Lock()
		listeners := append([]net.Listener(nil), f.listeners...)
		f.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		done := make(chan struct{})
		go func() { f.servers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("real loopback probe fixture retained a server worker")
		}
	})
	return f
}

func (f *lastRelayProbeFixture) Capture() (LastRelayAnchorCapture, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.captureFailed {
		return LastRelayAnchorCapture{}, errors.New("captured native source changed")
	}
	return f.path, nil
}

type lastRelayTestHold struct {
	fixture *lastRelayProbeFixture
	closed  bool
}

func (h *lastRelayTestHold) Close(ctx context.Context) error {
	f := h.fixture
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil || f.holdFailed {
		return errors.New("anchor reference drain pending")
	}
	if !h.closed {
		h.closed = true
		f.holds--
		f.releases++
	}
	return nil
}
func (f *lastRelayProbeFixture) Retain() (LastRelayAnchorHold, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.holds++
	hold := &lastRelayTestHold{fixture: f}
	if f.retainFailed {
		return hold, errors.New("retained anchor failure")
	}
	return hold, nil
}
func (f *lastRelayProbeFixture) NativeJoined() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.joined
}

func (f *lastRelayProbeFixture) control(command string) string {
	parts := strings.Split(command, " ")
	if len(parts) < 2 || parts[0] != "ROUTERVPN_LASTRELAY" {
		return "512 invalid command\r\n"
	}
	if parts[1] == "CAPTURE" {
		f.mu.Lock()
		delay, entered, release := f.captureDelay, f.enteredCapture, f.releaseCapture
		f.mu.Unlock()
		started := time.Now()
		if entered != nil {
			close(entered)
		}
		if release != nil {
			<-release
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		f.mu.Lock()
		f.setupElapsed += time.Since(started)
		f.mu.Unlock()
	}
	if parts[1] == "CLOSE" {
		f.mu.Lock()
		entered, release := f.enteredClose, f.releaseClose
		f.mu.Unlock()
		if entered != nil {
			f.closeEntered.Do(func() { close(entered) })
		}
		if release != nil {
			<-release
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if parts[1] == "INFO" {
		return "250 " + lastRelayTestInfo(f.highwater) + "\r\n"
	}
	if parts[1] == "CAPTURE" {
		if len(parts) != 10 {
			return "512 invalid capture\r\n"
		}
		generation, _ := strconv.ParseUint(parts[4], 10, 64)
		ttl, _ := strconv.Atoi(parts[5])
		anchor, _ := strconv.ParseUint(parts[6], 10, 64)
		if generation <= f.highwater || anchor != f.path.AnchorStream || parts[7] != f.path.SOCKSUsername || parts[8] != f.path.SOCKSPassword {
			return "551 unavailable capture\r\n"
		}
		f.highwater = generation
		f.identity = LastRelayIdentity{SessionSHA256: parts[2], SourceSHA256: parts[3], Generation: generation, Nonce: parts[9]}
		f.fields = lastRelayTestFields(f.identity)
		f.expires = time.Now().Add(time.Duration(ttl) * time.Millisecond)
		f.nativeDone = false
		f.fields["anchor"] = strconv.FormatUint(f.path.AnchorStream, 10)
		f.fields["circuit"] = strconv.FormatUint(uint64(f.path.Circuit), 10)
		f.fields["exit"], f.fields["path_sha256"] = f.path.ExitFingerprint, f.path.PathSHA256
	} else {
		if len(parts) != 6 || f.fields == nil || parts[2] != f.identity.SessionSHA256 || parts[3] != f.identity.SourceSHA256 || parts[4] != strconv.FormatUint(f.identity.Generation, 10) || parts[5] != f.identity.Nonce {
			return "551 unavailable owner\r\n"
		}
		if parts[1] == "CLOSE" {
			f.closes++
			f.fields["reason"], f.fields["expires_ms"] = "controller", "0"
			f.fields["state"] = "stopped"
			if f.forceDraining || f.fields["stream"] != "0" && !f.nativeDone {
				f.fields["state"] = "draining"
			}
		}
	}
	if f.fields["state"] != "stopped" && f.fields["state"] != "draining" {
		remaining := time.Until(f.expires).Milliseconds()
		if remaining <= 0 {
			f.fields["state"], f.fields["reason"], f.fields["expires_ms"] = "stopped", "expired-or-path", "0"
		} else {
			f.fields["expires_ms"] = strconv.FormatInt(remaining, 10)
		}
	}
	reply := "250 " + lastRelayTestEncode(f.fields) + "\r\n"
	if f.alter != nil {
		reply = f.alter(command, reply)
	}
	return reply
}

func (f *lastRelayProbeFixture) DialProbe(ctx context.Context, address string) (net.Conn, error) {
	f.mu.Lock()
	want, err := lastRelayExpectedAddress(f.identity)
	if err != nil || address != want || f.fields["state"] != "armed" {
		f.mu.Unlock()
		return nil, errors.New("private capability was replaced or reused")
	}
	f.dials++
	f.addresses = append(f.addresses, address)
	f.fields["state"], f.fields["stream"], f.fields["relay_stream"] = "connecting", "333", "7"
	delay, override := f.dialDelay, f.dialOverride
	f.mu.Unlock()
	started := time.Now()
	if delay > 0 {
		time.Sleep(delay)
	}
	f.mu.Lock()
	f.setupElapsed += time.Since(started)
	f.mu.Unlock()
	if override != nil {
		f.mu.Lock()
		f.fields["state"] = "connected"
		f.mu.Unlock()
		return override(ctx, address)
	}
	return f.dialLoopback(ctx)
}

func (f *lastRelayProbeFixture) dialLoopback(ctx context.Context) (net.Conn, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.listeners = append(f.listeners, listener)
	f.mu.Unlock()
	connected := make(chan struct{})
	f.servers.Add(1)
	go func() {
		defer f.servers.Done()
		defer listener.Close()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = connection.Close(); f.mu.Lock(); f.nativeDone = true; f.mu.Unlock() }()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		f.mu.Lock()
		f.fields["state"] = "connected"
		f.mu.Unlock()
		close(connected)
		request := make([]byte, len(lastRelayRequest))
		n, err := io.ReadFull(connection, request)
		f.mu.Lock()
		f.fields["request_bytes"] = strconv.Itoa(n)
		response := append([]byte(nil), f.response...)
		delay, entered, release := f.responseDelay, f.enteredRead, f.releaseResponse
		f.mu.Unlock()
		if err != nil {
			return
		}
		if string(request) != lastRelayRequest {
			f.t.Error("probe changed its fixed relay-local request")
			return
		}
		if entered != nil {
			close(entered)
		}
		if release != nil {
			<-release
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		n, err = connection.Write(response)
		f.mu.Lock()
		f.fields["response_bytes"] = strconv.Itoa(n)
		f.fields["state"], f.fields["reason"], f.fields["end_reason"] = "ended", "relay-end", "6"
		f.mu.Unlock()
		_ = err
	}()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return connection, err
	}
	select {
	case <-connected:
		return connection, nil
	case <-ctx.Done():
		return connection, ctx.Err()
	}
}

func lastRelayNewProbe(t *testing.T, f *lastRelayProbeFixture) *LastRelayProbe {
	t.Helper()
	p, err := NewLastRelayProbe(t.Context(), f.wire.control, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if p.Close(ctx) != nil {
			f.mu.Lock()
			f.joined = true
			f.mu.Unlock()
			_ = p.Close(ctx)
		}
	})
	return p
}

func TestLastRelayProbeMeasuresFreshHTTPBytesAndExcludesAdmissionControlAndCleanup(t *testing.T) {
	f := newLastRelayProbeFixture(t)
	f.captureDelay = 90 * time.Millisecond
	f.dialDelay = 80 * time.Millisecond
	f.responseDelay = 20 * time.Millisecond
	p := lastRelayNewProbe(t, f)
	started := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	elapsed, err := p.Run(ctx)
	total := time.Since(started)
	f.mu.Lock()
	setup, holds, releases, dials, closes := f.setupElapsed, f.holds, f.releases, f.dials, f.closes
	first := f.addresses[0]
	f.mu.Unlock()
	if err != nil || elapsed < 20*time.Millisecond || elapsed+setup > total || holds != 0 || releases != 1 || dials != 1 || closes < 1 {
		t.Fatal("measurement lost actual response or counted admission time", elapsed, total, setup, holds, releases, dials, closes, err)
	}
	if elapsed, err := p.Run(ctx); err == nil || elapsed != 0 {
		t.Fatal("completed probe reused a cached measurement")
	}
	if _, err := f.wire.control.LastRelayInfo(ctx); err != nil {
		t.Fatal("normal probe drain retired its reusable native controller", err)
	}
	f.mu.Lock()
	f.captureDelay = 0
	f.dialDelay = 0
	f.responseDelay = 35 * time.Millisecond
	f.mu.Unlock()
	next := lastRelayNewProbe(t, f)
	elapsed, err = next.Run(ctx)
	f.mu.Lock()
	second := f.addresses[1]
	f.mu.Unlock()
	if err != nil || elapsed < 35*time.Millisecond || first == second {
		t.Fatal("next probe reused a nonce, native generation or cached latency", elapsed, err)
	}
}

func TestLastRelayProbeRejectsWrongHTTPActualENDCountersAndNativeSource(t *testing.T) {
	for _, fault := range []string{"status", "body", "short-body", "gzip", "trailing", "oversized", "end-reason", "counter", "circuit", "exit", "path", "stream", "proof-source"} {
		t.Run(fault, func(t *testing.T) {
			f := newLastRelayProbeFixture(t)
			switch fault {
			case "status":
				f.response = []byte("HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")
			case "body":
				f.response = []byte(fmt.Sprintf("HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(lastRelayRobots), strings.Repeat("x", len(lastRelayRobots))))
			case "short-body":
				f.response = f.response[:len(f.response)-1]
			case "gzip":
				f.response = []byte(strings.Replace(string(f.response), "Content-Length:", "Content-Encoding: gzip\r\nContent-Length:", 1))
			case "trailing":
				f.response = append(f.response, 'x')
			case "oversized":
				f.response = append(f.response, []byte(strings.Repeat("x", 8193))...)
			default:
				f.alter = func(command, reply string) string {
					if !strings.Contains(command, " STATUS ") {
						return reply
					}
					switch fault {
					case "end-reason":
						return strings.Replace(reply, "end_reason=6", "end_reason=14", 1)
					case "counter":
						return strings.Replace(reply, "response_bytes="+strconv.Itoa(len(f.response)), "response_bytes=1", 1)
					case "circuit":
						return strings.Replace(reply, "circuit=222", "circuit=223", 1)
					case "exit":
						return strings.Replace(reply, strings.Repeat("4", 40), strings.Repeat("6", 40), 1)
					case "path":
						return strings.Replace(reply, strings.Repeat("5", 64), strings.Repeat("6", 64), 1)
					case "stream":
						if strings.Contains(reply, "state=ended") {
							return strings.Replace(reply, "stream=333", "stream=334", 1)
						}
					case "proof-source":
						f.captureFailed = true
					}
					return reply
				}
			}
			p := lastRelayNewProbe(t, f)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			elapsed, err := p.Run(ctx)
			if err == nil || elapsed != 0 {
				t.Fatal("failed candidate acquired a latency", fault, elapsed, err)
			}
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if p.Close(cleanup) != nil {
				f.mu.Lock()
				f.joined = true
				f.mu.Unlock()
				if p.Close(cleanup) != nil {
					t.Fatal("failed source owner did not release after its exact native join")
				}
			}
		})
	}
}

func TestLastRelayProbeCancellationKeepsIssuedControlAndAnchorUntilAcknowledgedDrain(t *testing.T) {
	f := newLastRelayProbeFixture(t)
	f.enteredCapture = make(chan struct{})
	f.releaseCapture = make(chan struct{})
	p := lastRelayNewProbe(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, err := p.Run(ctx); result <- err }()
	select {
	case <-f.enteredCapture:
	case <-time.After(time.Second):
		t.Fatal("capture frame not issued")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled capture returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("Cancel waited for the native control reply")
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if p.Close(short) == nil {
		t.Fatal("unfinished capture frame falsely drained")
	}
	f.mu.Lock()
	holds, closes, dials := f.holds, f.closes, f.dials
	f.mu.Unlock()
	if holds != 1 || closes != 0 || dials != 0 {
		t.Fatal("cancelled capture released anchor or sent data before its reply", holds, closes, dials)
	}
	if replacement, err := NewLastRelayProbe(t.Context(), f.wire.control, f); err == nil || replacement != nil {
		t.Fatal("unfinished controller claim was replaced")
	}
	close(f.releaseCapture)
	finish, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := p.Close(finish); err != nil {
		t.Fatal("exact cancelled capture could not finish its acknowledged drain", err)
	}
	if _, err := f.wire.control.LastRelayInfo(finish); err != nil {
		t.Fatal("normal cancellation retired the owning control stream", err)
	}
	f.mu.Lock()
	holds, releases := f.holds, f.releases
	f.mu.Unlock()
	if holds != 0 || releases != 1 {
		t.Fatal("captured anchor reference not released exactly once")
	}
}

func TestLastRelayProbeUnknownCaptureRetainsClaimUntilExactNativeJoin(t *testing.T) {
	f := newLastRelayProbeFixture(t)
	f.alter = func(command, reply string) string {
		if strings.Contains(command, " CAPTURE ") {
			return strings.Replace(reply, "source="+f.path.SourceSHA256, "source="+strings.Repeat("9", 64), 1)
		}
		return reply
	}
	p := lastRelayNewProbe(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if duration, err := p.Run(ctx); err == nil || duration != 0 {
		t.Fatal("unknown capture returned a latency")
	}
	if p.Close(ctx) == nil {
		t.Fatal("closed control socket was mistaken for an actual native drain")
	}
	f.mu.Lock()
	holds := f.holds
	f.mu.Unlock()
	if holds != 1 {
		t.Fatal("unknown native capture discarded its anchor hold")
	}
	if next, err := NewLastRelayProbe(t.Context(), f.wire.control, f); next != nil || err == nil {
		t.Fatal("unknown native capture lost the controller claim")
	}
	other := newLastRelayProbeFixture(t)
	other.mu.Lock()
	other.joined = true
	other.mu.Unlock()
	if p.Close(ctx) == nil {
		t.Fatal("another joined native owner released this capture")
	}
	f.mu.Lock()
	f.joined = true
	f.mu.Unlock()
	if p.Close(ctx) != nil {
		t.Fatal("exact native instance join did not resolve retained cleanup")
	}
}

func TestLastRelayResponseRejectsTrailingBytesBeyondBufferedHeader(t *testing.T) {
	base := fmt.Sprintf("HTTP/1.0 200 OK\r\nContent-Length: %d\r\nX-Padding: ", len(lastRelayRobots))
	message := base + strings.Repeat("x", 4096-len(base)-4-len(lastRelayRobots)) + "\r\n\r\n" + lastRelayRobots
	if len(message) != 4096 || validateLastRelayResponse([]byte(message)) != nil {
		t.Fatal("exact bounded response fixture is invalid")
	}
	if validateLastRelayResponse([]byte(message+"x")) == nil {
		t.Fatal("unbuffered trailing response bytes were accepted")
	}
}

type lastRelayHeldRead struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
	closed           atomic.Int64
}

func (c *lastRelayHeldRead) Read([]byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return 0, io.EOF
}
func (c *lastRelayHeldRead) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (c *lastRelayHeldRead) Close() error                     { c.closed.Add(1); return nil }
func (c *lastRelayHeldRead) SetDeadline(time.Time) error      { return nil }

func TestLastRelayProbeRetainsEnteredIOAfterRawCloseAndIgnoresReplacement(t *testing.T) {
	f := newLastRelayProbeFixture(t)
	held := &lastRelayHeldRead{entered: make(chan struct{}), release: make(chan struct{})}
	var released sync.Once
	release := func() { released.Do(func() { close(held.release) }) }
	defer release()
	f.dialOverride = func(context.Context, string) (net.Conn, error) { return held, nil }
	p := lastRelayNewProbe(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, err := p.Run(ctx); result <- err }()
	select {
	case <-held.entered:
	case <-time.After(time.Second):
		t.Fatal("held actual Read was not entered")
	}
	other := newLastRelayProbeFixture(t)
	replacement := lastRelayNewProbe(t, other)
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled held Read returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("Run failed to return while retained Read was pending")
	}
	short, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if p.Close(short) == nil {
		t.Fatal("raw Close released a still-entered Read")
	}
	f.mu.Lock()
	holds, closes := f.holds, f.closes
	f.mu.Unlock()
	if holds != 1 || closes != 0 || held.closed.Load() == 0 {
		t.Fatal("pending Read failed to retain its native stream and anchor", holds, closes, held.closed.Load())
	}
	if duration, err := replacement.Run(t.Context()); err != nil || duration <= 0 {
		t.Fatal("old probe cancellation affected a replacement controller", duration, err)
	}
	// Keep the release explicit while deferring a guarded fallback for failures.
	release()
	f.mu.Lock()
	f.nativeDone = true
	f.mu.Unlock()
	finish, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if p.Close(finish) != nil {
		t.Fatal("joined Read did not release its exact retained cleanup")
	}
}

func TestLastRelayProbeCloseWaitDoesNotAbandonItsIssuedFrame(t *testing.T) {
	f := newLastRelayProbeFixture(t)
	f.enteredClose, f.releaseClose = make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(f.releaseClose) }) }
	defer release()
	p := lastRelayNewProbe(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, err := p.Run(ctx); result <- err }()
	select {
	case <-f.enteredClose:
	case <-time.After(time.Second):
		t.Fatal("native CLOSE frame was not issued")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled cleanup returned a measurement")
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation waited for the held control reply")
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if p.Close(short) == nil {
		t.Fatal("unread native CLOSE frame was discarded")
	}
	stop()
	f.mu.Lock()
	holds := f.holds
	f.mu.Unlock()
	if holds != 1 {
		t.Fatal("held native CLOSE released its anchor")
	}
	f.wire.mu.Lock()
	commands := append([]string(nil), f.wire.commands...)
	f.wire.mu.Unlock()
	count := 0
	for _, command := range commands {
		if strings.Contains(command, " CLOSE ") {
			count++
		}
	}
	if count != 1 {
		t.Fatal("retry wrote another CLOSE while the old reply remained owned", count)
	}
	release()
	finish, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if p.Close(finish) != nil {
		t.Fatal("acknowledged native CLOSE did not complete its retained owner")
	}
	if _, err := f.wire.control.LastRelayInfo(finish); err != nil {
		t.Fatal("short cleanup wait retired a valid controller", err)
	}
}

type lastRelayRetryClose struct {
	net.Conn
	fail   atomic.Bool
	closes atomic.Int64
	closed func()
}

func (c *lastRelayRetryClose) Close() error {
	c.closes.Add(1)
	if c.fail.Load() {
		return errors.New("actual socket close still pending")
	}
	err := c.Conn.Close()
	if c.closed != nil {
		c.closed()
	}
	return err
}

func TestLastRelayProbeRetainsLateErrorSocketAndFailedCloseForRetry(t *testing.T) {
	f := newLastRelayProbeFixture(t)
	raw, peer := net.Pipe()
	defer peer.Close()
	socket := &lastRelayRetryClose{Conn: raw, closed: func() { f.mu.Lock(); f.nativeDone = true; f.mu.Unlock() }}
	socket.fail.Store(true)
	entered, returned := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(returned) }) }
	defer release()
	f.dialOverride = func(context.Context, string) (net.Conn, error) {
		close(entered)
		<-returned
		return socket, errors.New("late SOCKS handshake failure with a retained raw socket")
	}
	p := lastRelayNewProbe(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, err := p.Run(ctx); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual late dial was not entered")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled late dial returned a measurement")
		}
	case <-time.After(time.Second):
		t.Fatal("late dial blocked caller cancellation")
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if p.Close(short) == nil {
		t.Fatal("pending late socket factory was forgotten")
	}
	stop()
	release()
	finish, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if p.Close(finish) == nil {
		t.Fatal("non-nil error-path socket with failed Close was dropped")
	}
	f.mu.Lock()
	holds, closes := f.holds, f.closes
	f.mu.Unlock()
	if holds != 1 || closes != 0 || socket.closes.Load() == 0 {
		t.Fatal("failed error-path close released native or anchor authority", holds, closes, socket.closes.Load())
	}
	socket.fail.Store(false)
	if p.Close(finish) != nil {
		t.Fatal("captured late socket did not drain on a successful retry")
	}
	f.mu.Lock()
	holds, releases := f.holds, f.releases
	f.mu.Unlock()
	if holds != 0 || releases != 1 {
		t.Fatal("late socket retry released wrong anchor hold")
	}
}

func TestLastRelayProbeSourceChangeCancelsBlockedIOAndCannotRevive(t *testing.T) {
	f := newLastRelayProbeFixture(t)
	held := &lastRelayHeldRead{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(held.release) }) }
	defer release()
	f.dialOverride = func(context.Context, string) (net.Conn, error) { return held, nil }
	p := lastRelayNewProbe(t, f)
	result := make(chan error, 1)
	go func() { _, err := p.Run(t.Context()); result <- err }()
	select {
	case <-held.entered:
	case <-time.After(time.Second):
		t.Fatal("source-change test never entered its actual read")
	}
	f.mu.Lock()
	f.path.SourceSHA256 = strings.Repeat("9", 64)
	f.mu.Unlock()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("changed source retained a measurement")
		}
	case <-time.After(time.Second):
		t.Fatal("source change did not cancel held I/O")
	}
	f.mu.Lock()
	f.path.SourceSHA256 = strings.Repeat("2", 64)
	f.mu.Unlock()
	if duration, err := p.Run(t.Context()); err == nil || duration != 0 {
		t.Fatal("restored source revived the cancelled operation")
	}
	release()
	f.mu.Lock()
	f.nativeDone = true
	f.mu.Unlock()
	finish, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if p.Close(finish) != nil {
		t.Fatal("retired source could not clean up its own retained stream")
	}
}

func TestLastRelayProbeRetainsConstructorErrorOwnerAndReleasesOnlyItsClaim(t *testing.T) {
	f := newLastRelayProbeFixture(t)
	f.retainFailed = true
	p, err := NewLastRelayProbe(t.Context(), f.wire.control, f)
	if p == nil || err == nil {
		t.Fatal("constructor lost its non-nil failed retention owner")
	}
	if next, err := NewLastRelayProbe(t.Context(), f.wire.control, f); next != nil || err == nil {
		t.Fatal("failed constructor silently released its claim")
	}
	if p.Close(t.Context()) != nil {
		t.Fatal("failed constructor could not release its exact retained hold")
	}
	f.mu.Lock()
	f.retainFailed = false
	f.mu.Unlock()
	next := lastRelayNewProbe(t, f)
	if p.Close(t.Context()) != nil {
		t.Fatal("old close retry unexpectedly failed")
	}
	if f.wire.control.lastRelayProbe.Load() != next {
		t.Fatal("old close released a replacement controller claim")
	}
}

func TestLastRelayNetworkRetainsEveryEnteredReadAfterRawClose(t *testing.T) {
	f := newLastRelayProbeFixture(t)
	p := lastRelayNewProbe(t, f)
	held := &lastRelayHeldRead{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(held.release) }) }
	defer release()
	network, err := NewNetwork(t.Context(), func(context.Context, string, string) (net.Conn, error) {
		return &lastRelayProbeConnection{Conn: held, probe: p}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := network.DialRetainedContext(t.Context(), "tcp", "owned-fixture:1")
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan struct{})
	go func() { _, _ = connection.Read(make([]byte, 1)); close(readDone) }()
	select {
	case <-held.entered:
	case <-time.After(time.Second):
		t.Fatal("native read did not enter")
	}
	short, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if err := network.Close(short); !errors.Is(err, context.DeadlineExceeded) {
		cancel()
		t.Fatal("Network released a still-entered last-relay read", err)
	}
	cancel()
	release()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("released read did not join")
	}
	finish, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := network.Close(finish); err != nil {
		t.Fatal("last-relay read did not release after actual completion", err)
	}
}
