package controllerbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/controllertransport"
)

type forwardFunc func(context.Context, string, string, []byte, int64) (controllertransport.Response, error)

func (f forwardFunc) Request(ctx context.Context, method, path string, body []byte, limit int64) (controllertransport.Response, error) {
	return f(ctx, method, path, body, limit)
}

// net.Pipe exercises actual blocking stream reads/writes without a listener or
// privilege boundary double. This adapter joins cancellation before returning.
type testStream struct{ net.Conn }

func (s testStream) ReadContext(ctx context.Context, body []byte) (int, error) {
	return s.operation(ctx, body, true)
}
func (s testStream) WriteContext(ctx context.Context, body []byte) (int, error) {
	return s.operation(ctx, body, false)
}
func (s testStream) operation(ctx context.Context, body []byte, read bool) (int, error) {
	deadline := s.SetWriteDeadline
	if read {
		deadline = s.SetReadDeadline
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = deadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		_ = deadline(time.Time{})
	}()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var n int
	var err error
	if read {
		n, err = s.Read(body)
	} else {
		n, err = s.Write(body)
	}
	if ctx.Err() != nil {
		return n, ctx.Err()
	}
	return n, err
}

type harness struct {
	peer   net.Conn
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func newHarness(t *testing.T, forward Forwarder) *harness {
	return newHarnessWriter(t, forward, new(sync.Mutex))
}
func newHarnessWriter(t *testing.T, forward Forwarder, writer sync.Locker) *harness {
	t.Helper()
	server, peer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{peer: peer, cancel: cancel, done: make(chan struct{})}
	go func() { h.err = serve(ctx, testStream{server}, forward, writer); close(h.done) }()
	t.Cleanup(func() {
		cancel()
		_ = peer.Close()
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Error("bridge harness failed to join its owned server")
		}
	})
	return h
}
func requestHeader(id uint64, path string, body []byte, limit uint32) Header {
	return Header{Kind: Request, Method: 2, ID: id, TimeoutMS: 30000, PathLength: uint16(len(path)), BodyLength: uint32(len(body)), ResponseLimit: limit}
}
func (h *harness) send(header Header, path string, body []byte) error {
	raw, err := header.Encode()
	if err != nil {
		return err
	}
	_ = h.peer.SetWriteDeadline(time.Now().Add(20 * time.Second))
	defer h.peer.SetWriteDeadline(time.Time{})
	for _, data := range [][]byte{raw[:], []byte(path), body} {
		for len(data) > 0 {
			n, err := h.peer.Write(data)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrNoProgress
			}
			data = data[n:]
		}
	}
	return nil
}
func (h *harness) receive() (Header, []byte, error) {
	_ = h.peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer h.peer.SetReadDeadline(time.Time{})
	var raw [HeaderSize]byte
	if _, err := io.ReadFull(h.peer, raw[:]); err != nil {
		return Header{}, nil, err
	}
	header, err := DecodeHeader(raw[:])
	if err != nil {
		return Header{}, nil, err
	}
	body := make([]byte, header.BodyLength)
	_, err = io.ReadFull(h.peer, body)
	return header, body, err
}
func mustSignal(t *testing.T, channel <-chan struct{}, why string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(3 * time.Second):
		t.Fatal(why)
	}
}
func inertForward(context.Context, string, string, []byte, int64) (controllertransport.Response, error) {
	return controllertransport.Response{Status: 200, Body: []byte(`{"ok":true}`)}, nil
}

func TestControllerBridgeIndependentHeaderEncoding(t *testing.T) {
	header := Header{Kind: Request, Method: 2, ID: 0x0102030405060708, TimeoutMS: 420000, PathLength: 19, BodyLength: 12345, ResponseLimit: 32768}
	raw, err := header.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{'R', 'V', 'B', '1', 1, 2, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 6, 0x68, 0xa0, 0, 19, 0, 0, 0, 0, 0x30, 0x39, 0, 0, 0x80, 0}
	if !bytes.Equal(raw[:], want) {
		t.Fatalf("cross-language header bytes changed: %x", raw)
	}
	actual, err := DecodeHeader(want)
	if err != nil || actual != header {
		t.Fatal("independent header did not decode", err)
	}
}

func TestControllerBridgeHeaderRejectsMalformedControls(t *testing.T) {
	good, _ := requestHeader(1, "/api/status", nil, 1024).Encode()
	for _, mutation := range []func([]byte){
		func(v []byte) { v[3] = '2' }, func(v []byte) { v[4] = 99 }, func(v []byte) { v[5] = 0 }, func(v []byte) { v[7] = 1 },
		func(v []byte) { binary.BigEndian.PutUint64(v[8:16], 0) }, func(v []byte) { binary.BigEndian.PutUint32(v[16:20], 0) },
		func(v []byte) { binary.BigEndian.PutUint32(v[16:20], MaxTimeoutMS+1) }, func(v []byte) { binary.BigEndian.PutUint16(v[20:22], 0) },
		func(v []byte) { binary.BigEndian.PutUint16(v[20:22], MaxPath+1) }, func(v []byte) { v[22] = 1 }, func(v []byte) { v[23] = 1 },
		func(v []byte) { binary.BigEndian.PutUint32(v[24:28], MaxImport+1) }, func(v []byte) { binary.BigEndian.PutUint32(v[28:32], 0) },
		func(v []byte) { binary.BigEndian.PutUint32(v[28:32], MaxBody+1) }, func(v []byte) { v[4] = Cancel },
	} {
		raw := good
		mutation(raw[:])
		if _, err := DecodeHeader(raw[:]); err == nil {
			t.Fatal("malformed frame header acquired a request reservation")
		}
	}
	for _, raw := range [][]byte{nil, good[:31], append(good[:], 0)} {
		if _, err := DecodeHeader(raw); err == nil {
			t.Fatal("truncated or extended header was admitted")
		}
	}
}

func TestControllerBridgeTargetRejectsOtherAuthorities(t *testing.T) {
	for _, target := range []string{"/api/status", "/api/nodes?sort=latency", "/api/session/events?after=12", "/api/status?name=a%20b"} {
		if err := ValidateTarget(target); err != nil {
			t.Fatal("existing local API target rejected", target, err)
		}
	}
	for _, target := range []string{"http://127.0.0.1:8788/api/status", "//127.0.0.1/api/status", "/api/../status", "/api/a/..", "/api/./status", "/api//status", "/api/status#other", "/api/status\x00", "/api/\\status", "/api/%73tatus", "/api/%2e%2e/status", "/api/status%23other", "/api/%C3%A9", "/api/status%00", "/api/status?x=%zz", "/api/controller/shutdown", "/api/controller/identity", "/api/controller", string([]byte{'/', 'a', 'p', 'i', '/', 0xff})} {
		if err := ValidateTarget(target); err == nil {
			t.Fatal("UI channel admitted a foreign, aliased or launcher-only target", target)
		}
	}
}

func TestControllerBridgeForwardsExactBytesAndHTTPStatus(t *testing.T) {
	body := []byte{0, 0xc3, 0xa9, '"', '\\', '\n', 0xff}
	h := newHarness(t, forwardFunc(func(ctx context.Context, method, target string, got []byte, limit int64) (controllertransport.Response, error) {
		if method != "POST" || target != "/api/profile/settings" || !bytes.Equal(got, body) || limit != 32768 {
			t.Error("bridge changed its captured request")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < 400*time.Second {
			t.Error("bridge clipped the captured long-running action deadline")
		}
		return controllertransport.Response{Status: 409, Body: []byte("selected node changed")}, nil
	}))
	header := requestHeader(1, "/api/profile/settings", body, 32768)
	header.TimeoutMS = 420000
	if err := h.send(header, "/api/profile/settings", body); err != nil {
		t.Fatal(err)
	}
	reply, payload, err := h.receive()
	if err != nil || reply.Kind != Response || reply.ID != 1 || reply.Status != 409 || string(payload) != "selected node changed" {
		t.Fatal("actual bridge lost non-2xx status or body", reply, err)
	}
}

func TestControllerBridgeCompleteImportAndAggregateBound(t *testing.T) {
	body := bytes.Repeat([]byte{0, 0xc3, 0xa9, '\n'}, MaxImport/4)
	want := sha256.Sum256(body)
	entered := make(chan struct{}, 3)
	h := newHarness(t, forwardFunc(func(ctx context.Context, method, target string, got []byte, limit int64) (controllertransport.Response, error) {
		if target == "/api/profile/import" && (len(got) != MaxImport || sha256.Sum256(got) != want) {
			t.Error("bridge changed complete 32 MiB import bytes")
		}
		entered <- struct{}{}
		<-ctx.Done()
		return controllertransport.Response{}, ctx.Err()
	}))
	if err := h.send(requestHeader(1, "/api/profile/import", body, MaxBody), "/api/profile/import", body); err != nil {
		t.Fatal("existing complete import failed", err)
	}
	mustSignal(t, entered, "complete import was not forwarded")
	small := body[:MaxBody]
	if err := h.send(requestHeader(2, "/api/profile/settings", small, MaxBody), "/api/profile/settings", small); err != nil {
		t.Fatal(err)
	}
	mustSignal(t, entered, "second bounded operation was not admitted")
	// First reservation is 40 MiB, second 16 MiB. A third 16 MiB operation
	// must be refused before its body allocation/read or forwarding.
	err := h.send(requestHeader(3, "/api/profile/settings", small, MaxBody), "/api/profile/settings", small)
	if err == nil {
		t.Fatal("aggregate UI request byte budget admitted an unbounded third owner")
	}
	mustSignal(t, h.done, "aggregate budget rejection did not retire the channel")
	select {
	case <-entered:
		t.Fatal("aggregate UI request byte budget reached the controller")
	default:
	}
}

func TestControllerBridgeRejectsOversizedOrdinaryBodyBeforeRead(t *testing.T) {
	var forwarded atomic.Int32
	h := newHarness(t, forwardFunc(func(context.Context, string, string, []byte, int64) (controllertransport.Response, error) {
		forwarded.Add(1)
		return controllertransport.Response{}, nil
	}))
	header := requestHeader(1, "/api/profile/settings", nil, 1024)
	header.BodyLength = MaxBody + 1
	// No body is supplied: the exact route check must reject before allocating
	// or waiting for bytes merely because the fixed header allowed an import.
	if err := h.send(header, "/api/profile/settings", nil); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	mustSignal(t, h.done, "oversized ordinary route waited for an unowned body")
	if forwarded.Load() != 0 {
		t.Fatal("ordinary route borrowed the import body allowance")
	}
}

func TestControllerBridgeCancellationRetainsJoinAndOtherRequest(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	h := newHarness(t, forwardFunc(func(ctx context.Context, _ string, target string, _ []byte, _ int64) (controllertransport.Response, error) {
		if target == "/api/first" {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-release
			return controllertransport.Response{Status: 200, Body: []byte("late-private-result")}, nil
		}
		return controllertransport.Response{Status: 200, Body: []byte("replacement")}, nil
	}))
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	if err := h.send(requestHeader(1, "/api/first", nil, 1024), "/api/first", nil); err != nil {
		t.Fatal(err)
	}
	mustSignal(t, entered, "first operation did not enter")
	if err := h.send(Header{Kind: Cancel, ID: 1}, "", nil); err != nil {
		t.Fatal(err)
	}
	mustSignal(t, cancelled, "captured request cancellation did not revoke its entered operation")
	if err := h.send(requestHeader(2, "/api/second", nil, 1024), "/api/second", nil); err != nil {
		t.Fatal(err)
	}
	reply, body, err := h.receive()
	if err != nil || reply.ID != 2 || reply.Kind != Response || string(body) != "replacement" {
		t.Fatal("cancelled request stopped an independent UI operation", err)
	}
	releaseOnce.Do(func() { close(release) })
	reply, body, err = h.receive()
	if err != nil || reply.ID != 1 || reply.Kind != Cancelled || len(body) != 0 {
		t.Fatal("cancelled late response published private bytes or lost its terminal join", err)
	}
}

func TestControllerBridgeOldCancelCannotTouchNewOwner(t *testing.T) {
	entered, release, barrier := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	h := newHarness(t, forwardFunc(func(ctx context.Context, _ string, target string, _ []byte, _ int64) (controllertransport.Response, error) {
		if target == "/api/barrier" {
			close(barrier)
			<-ctx.Done()
			return controllertransport.Response{}, ctx.Err()
		}
		if target == "/api/second" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return controllertransport.Response{}, ctx.Err()
			}
		}
		return controllertransport.Response{Status: 200, Body: []byte(target)}, nil
	}))
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	if err := h.send(requestHeader(1, "/api/first", nil, 1024), "/api/first", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.receive(); err != nil {
		t.Fatal(err)
	}
	if err := h.send(requestHeader(2, "/api/second", nil, 1024), "/api/second", nil); err != nil {
		t.Fatal(err)
	}
	mustSignal(t, entered, "replacement operation did not enter")
	if err := h.send(Header{Kind: Cancel, ID: 1}, "", nil); err != nil {
		t.Fatal(err)
	}
	// Successful stream Write alone proves that bytes were read, not that the
	// preceding cancellation was processed. Enter a later request as the real
	// read-loop barrier before releasing the replacement operation.
	if err := h.send(requestHeader(3, "/api/barrier", nil, 1), "/api/barrier", nil); err != nil {
		t.Fatal(err)
	}
	mustSignal(t, barrier, "cancellation read-loop barrier did not enter")
	once.Do(func() { close(release) })
	reply, body, err := h.receive()
	if err != nil || reply.ID != 2 || reply.Kind != Response || string(body) != "/api/second" {
		t.Fatal("old cancellation mutated a replacement owner", err)
	}
}

type observedWriteMutex struct {
	mu     sync.Mutex
	count  atomic.Int32
	first  chan struct{}
	second chan struct{}
}

func (m *observedWriteMutex) Lock() {
	count := m.count.Add(1)
	if count == 2 {
		close(m.second)
	}
	m.mu.Lock()
	if count == 1 {
		close(m.first)
	}
}
func (m *observedWriteMutex) Unlock() { m.mu.Unlock() }

func TestControllerBridgeQueuedReplyRechecksCancellation(t *testing.T) {
	writer := &observedWriteMutex{first: make(chan struct{}), second: make(chan struct{})}
	first, secondCancelled := make(chan struct{}), make(chan struct{})
	h := newHarnessWriter(t, forwardFunc(func(ctx context.Context, _ string, target string, _ []byte, _ int64) (controllertransport.Response, error) {
		if target == "/api/first" {
			close(first)
		} else {
			context.AfterFunc(ctx, func() { close(secondCancelled) })
		}
		return controllertransport.Response{Status: 200, Body: []byte("private-" + target)}, nil
	}), writer)
	if err := h.send(requestHeader(1, "/api/first", nil, 1024), "/api/first", nil); err != nil {
		t.Fatal(err)
	}
	mustSignal(t, first, "first response did not enter")
	mustSignal(t, writer.first, "first response did not acquire actual publication ownership")
	// No peer read has happened: the first actual net.Pipe write owns the
	// publication mutex until this test explicitly consumes its response.
	if err := h.send(requestHeader(2, "/api/second", nil, 1024), "/api/second", nil); err != nil {
		t.Fatal(err)
	}
	mustSignal(t, writer.second, "second response did not actually queue behind the occupied writer")
	if err := h.send(Header{Kind: Cancel, ID: 2}, "", nil); err != nil {
		t.Fatal(err)
	}
	mustSignal(t, secondCancelled, "queued response owner was not actually cancelled")
	reply, _, err := h.receive()
	if err != nil || reply.ID != 1 || reply.Kind != Response {
		t.Fatal("first response lost ownership", err)
	}
	reply, body, err := h.receive()
	if err != nil || reply.ID != 2 || reply.Kind != Cancelled || len(body) != 0 {
		t.Fatal("queued cancelled response published its previous private result", err)
	}
}

func TestControllerBridgeRejectsReplayedAndFutureIDs(t *testing.T) {
	for _, kind := range []string{"replayed-request", "future-cancel"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, forwardFunc(inertForward))
			if err := h.send(requestHeader(1, "/api/status", nil, 1024), "/api/status", nil); err != nil {
				t.Fatal(err)
			}
			if _, _, err := h.receive(); err != nil {
				t.Fatal(err)
			}
			if kind == "replayed-request" {
				_ = h.send(requestHeader(1, "/api/status", nil, 1024), "/api/status", nil)
			} else {
				_ = h.send(Header{Kind: Cancel, ID: 2}, "", nil)
			}
			if _, _, err := h.receive(); err == nil {
				t.Fatal("replayed or future request identity was admitted")
			}
			mustSignal(t, h.done, "invalid identity did not retire the entire channel")
		})
	}
}

func TestControllerBridgeBoundsSimultaneousOperations(t *testing.T) {
	entered := make(chan struct{}, MaxPending+1)
	h := newHarness(t, forwardFunc(func(ctx context.Context, _ string, _ string, _ []byte, _ int64) (controllertransport.Response, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return controllertransport.Response{}, ctx.Err()
	}))
	for id := uint64(1); id <= MaxPending; id++ {
		if err := h.send(requestHeader(id, "/api/status", nil, 1), "/api/status", nil); err != nil {
			t.Fatal(err)
		}
		mustSignal(t, entered, "bounded pending request did not enter")
	}
	if err := h.send(requestHeader(MaxPending+1, "/api/status", nil, 1), "/api/status", nil); err == nil {
		t.Fatal("UI channel exceeded its captured pending operation count")
	}
	mustSignal(t, h.done, "pending count rejection failed to join channel")
}

func TestControllerBridgeOwnerCloseJoinsEnteredForwarder(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	h := newHarness(t, forwardFunc(func(ctx context.Context, _ string, _ string, _ []byte, _ int64) (controllertransport.Response, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return controllertransport.Response{}, ctx.Err()
	}))
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	if err := h.send(requestHeader(1, "/api/status", nil, 1024), "/api/status", nil); err != nil {
		t.Fatal(err)
	}
	mustSignal(t, entered, "owned forwarder never entered")
	h.cancel()
	mustSignal(t, cancelled, "channel close did not revoke entered forwarding")
	select {
	case <-h.done:
		t.Fatal("UI channel Close abandoned an entered controller operation")
	case <-time.After(50 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	mustSignal(t, h.done, "released controller operation failed to join")
}

func TestControllerBridgeTruncatedFrameRetiresWithoutForwarding(t *testing.T) {
	for _, phase := range []string{"header", "path", "body"} {
		t.Run(phase, func(t *testing.T) {
			var calls atomic.Int32
			h := newHarness(t, forwardFunc(func(context.Context, string, string, []byte, int64) (controllertransport.Response, error) {
				calls.Add(1)
				return controllertransport.Response{}, nil
			}))
			body := []byte("private")
			raw, _ := requestHeader(1, "/api/status", body, 1024).Encode()
			value := append(append(raw[:], []byte("/api/status")...), body...)
			cut := 17
			if phase == "path" {
				cut = HeaderSize + 3
			}
			if phase == "body" {
				cut = len(value) - 1
			}
			if _, err := h.peer.Write(value[:cut]); err != nil {
				t.Fatal(err)
			}
			_ = h.peer.Close()
			mustSignal(t, h.done, "partial frame failed to revoke and join channel")
			if calls.Load() != 0 {
				t.Fatal("truncated GUI frame executed a partial private operation")
			}
		})
	}
}

func TestControllerBridgeSuppressesNativeErrorContext(t *testing.T) {
	h := newHarness(t, forwardFunc(func(context.Context, string, string, []byte, int64) (controllertransport.Response, error) {
		return controllertransport.Response{}, errors.New("captured-secret-must-not-cross-channel")
	}))
	if err := h.send(requestHeader(1, "/api/status", nil, 1024), "/api/status", nil); err != nil {
		t.Fatal(err)
	}
	reply, body, err := h.receive()
	if err != nil || reply.Kind != Failure || strings.Contains(string(body), "captured-secret") || len(body) > 4096 {
		t.Fatal("raw native transport error leaked through UI failure", err)
	}
}

func TestControllerBridgeRejectsUnboundedForwarderResponse(t *testing.T) {
	h := newHarness(t, forwardFunc(func(context.Context, string, string, []byte, int64) (controllertransport.Response, error) {
		return controllertransport.Response{Status: 200, Body: []byte("larger than one byte")}, nil
	}))
	if err := h.send(requestHeader(1, "/api/status", nil, 1), "/api/status", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.receive(); err == nil {
		t.Fatal("UI channel published bytes beyond the captured response bound")
	}
	mustSignal(t, h.done, "invalid forwarding response did not retire channel")
}
