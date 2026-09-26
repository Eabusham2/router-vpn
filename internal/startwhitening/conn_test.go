package startwhitening

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testKey(t *testing.T) [32]byte {
	t.Helper()
	key, err := Key(Method, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func within(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("owned I/O did not terminate")
	}
}
func openPipe(t *testing.T, owner *Owner, packet bool) (*Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	c, err := owner.Open(context.Background(), testKey(t), packet, func(context.Context) (net.Conn, error) { return a, nil })
	if err != nil {
		a.Close()
		b.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); b.Close() })
	return c, b
}
func TestWhiteningMatchesServerScheduleAndNeverClaimsEncryption(t *testing.T) {
	password := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	got := testKey(t)
	expected := sha256.Sum256([]byte("router-vpn-xor-whitening-v1\x00" + password))
	if got != expected {
		t.Fatal("server whitening schedule changed")
	}
	input := []byte("already authenticated ciphertext")
	saved := append([]byte(nil), input...)
	apply(input, got, 0)
	if bytes.Equal(input, saved) {
		t.Fatal("whitening not applied")
	}
	apply(input, got, 0)
	if !bytes.Equal(input, saved) {
		t.Fatal("whitening is not reversible")
	}
	for _, tc := range []struct{ method, password string }{{"none", password}, {"aes-256-gcm", password}, {Method, "short"}, {Method, "1234567890123456\x00"}, {Method, string(bytes.Repeat([]byte("x"), 4097))}} {
		if _, err := Key(tc.method, tc.password); err == nil {
			t.Fatal("unauthenticated/malformed profile accepted")
		}
	}
	t.Log("exact server-compatible whitening key digest", hex.EncodeToString(got[:]))
}
func TestTCPOffsetsAreIndependentAndCallerBuffersUnchanged(t *testing.T) {
	owner := NewOwner(context.Background())
	defer owner.Close()
	conn, peer := openPipe(t, owner, false)
	key := testKey(t)
	a := bytes.Repeat([]byte("client ciphertext/"), 4000)
	b := bytes.Repeat([]byte("server ciphertext/"), 1000)
	original := append([]byte(nil), a...)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		got := make([]byte, len(a))
		if _, err := io.ReadFull(peer, got); err != nil {
			t.Error(err)
			return
		}
		apply(got, key, 0)
		if !bytes.Equal(got, a) {
			t.Error("TCP writes lost continuous offset")
		}
		encoded := append([]byte(nil), b...)
		apply(encoded, key, 0)
		for len(encoded) > 0 {
			count := 117
			if len(encoded) < count {
				count = len(encoded)
			}
			if _, err := peer.Write(encoded[:count]); err != nil {
				t.Error(err)
				return
			}
			encoded = encoded[count:]
		}
	}()
	if _, err := conn.Write(a[:37]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(a[37:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, original) {
		t.Fatal("write mutated caller ciphertext")
	}
	got := make([]byte, len(b))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, b) {
		t.Fatal("read offset not independent", err)
	}
	within(t, serverDone)
}

type shortConn struct {
	net.Conn
	max  int
	sent bytes.Buffer
}

func (s *shortConn) Write(b []byte) (int, error) {
	n := len(b)
	if n > s.max {
		n = s.max
	}
	return s.sent.Write(b[:n])
}
func TestShortTCPWritesAdvanceOnlyTransferredBytes(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	raw := &shortConn{Conn: a, max: 7}
	owner := NewOwner(context.Background())
	defer owner.Close()
	c, err := owner.Open(context.Background(), testKey(t), false, func(context.Context) (net.Conn, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("partial authenticated ciphertext")
	off := 0
	for off < len(body) {
		n, err := c.Write(body[off:])
		if err != nil && !errors.Is(err, io.ErrShortWrite) {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("no progress")
		}
		off += n
	}
	received := append([]byte(nil), raw.sent.Bytes()...)
	apply(received, testKey(t), 0)
	if !bytes.Equal(received, body) {
		t.Fatal("partial write skipped whitening bytes")
	}
}
func TestUDPResetsEachDatagramAndSupportsJumbo(t *testing.T) {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	owner := NewOwner(context.Background())
	defer owner.Close()
	c, err := owner.Open(context.Background(), testKey(t), true, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", socket.LocalAddr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	for _, size := range []int{0, 1, 31, 32, 33, 1200, 9000, 65000} {
		original := bytes.Repeat([]byte{byte(size)}, size)
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_ = socket.SetDeadline(time.Now().Add(time.Second))
		if n, err := c.Write(original); err != nil || n != size {
			t.Fatal(size, n, err)
		}
		buf := make([]byte, 65535)
		n, peer, err := socket.ReadFromUDP(buf)
		if err != nil || n != size {
			t.Fatal(size, n, err)
		}
		got := append([]byte(nil), buf[:n]...)
		apply(got, key, 0)
		if !bytes.Equal(got, original) {
			t.Fatal("UDP offset carried between datagrams")
		}
		if _, err := socket.WriteToUDP(buf[:n], peer); err != nil {
			t.Fatal(err)
		}
		n, err = c.Read(buf)
		if err != nil || n != size || !bytes.Equal(buf[:n], original) {
			t.Fatal("UDP whitening receive mismatch", size, n, err)
		}
	}
	if _, err := c.Write(make([]byte, 65536)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("unbounded datagram accepted")
	}
}
func TestOwnerCancellationAndRealReadDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := NewOwner(ctx)
	defer owner.Close()
	c, _ := openPipe(t, owner, false)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("real read deadline not honored", err)
	}
	_ = c.SetDeadline(time.Time{})
	read := make(chan struct{})
	go func() { defer close(read); _, _ = c.Read(make([]byte, 1)) }()
	cancel()
	within(t, read)
	if _, err := c.Write([]byte("late")); err == nil {
		t.Fatal("cancelled owner allowed traffic")
	}
}
func TestResetRejectsLateDialAndAllowsNewGeneration(t *testing.T) {
	owner := NewOwner(context.Background())
	defer owner.Close()
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	a, b := net.Pipe()
	defer b.Close()
	go func() {
		defer close(finished)
		c, err := owner.Open(context.Background(), [32]byte{}, false, func(ctx context.Context) (net.Conn, error) { close(started); <-release; return a, nil })
		if err == nil || c != nil {
			t.Error("stale dial adopted after interface reset")
		}
	}()
	within(t, started)
	owner.Reset()
	close(release)
	within(t, finished)
	if _, err := a.Write([]byte("late")); err == nil {
		t.Fatal("rejected dial socket not closed")
	}
	c, peer := openPipe(t, owner, false)
	owner.Reset()
	if _, err := peer.Write([]byte("closed")); err == nil {
		t.Fatal("old established socket survived reset")
	}
	_ = c.Close()
	_, _ = openPipe(t, owner, false)
}
func TestOwnerBoundsPendingConnectionsBeforeDial(t *testing.T) {
	owner := NewOwner(context.Background())
	defer owner.Close()
	for i := 0; i < MaxConnections; i++ {
		_, _ = openPipe(t, owner, false)
	}
	var called atomic.Bool
	_, err := owner.Open(context.Background(), [32]byte{}, false, func(context.Context) (net.Conn, error) { called.Store(true); return nil, nil })
	if err == nil || called.Load() {
		t.Fatal("connection limit checked after dial")
	}
}
func TestConcurrentCloseCannotRaceCipherState(t *testing.T) {
	owner := NewOwner(context.Background())
	c, peer := openPipe(t, owner, false)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.SetDeadline(time.Now().Add(10 * time.Millisecond))
			_, _ = c.Write([]byte("payload"))
			_ = c.Close()
		}()
	}
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	_ = owner.Close()
	wg.Wait()
}

type heldCloseConn struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *heldCloseConn) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Close()
}
func TestRepeatedOwnerCloseWaitsForTeardown(t *testing.T) {
	owner := NewOwner(context.Background())
	a, b := net.Pipe()
	defer b.Close()
	raw := &heldCloseConn{Conn: a, entered: make(chan struct{}), release: make(chan struct{})}
	if _, err := owner.Open(context.Background(), [32]byte{}, false, func(context.Context) (net.Conn, error) { return raw, nil }); err != nil {
		t.Fatal(err)
	}
	first, second := make(chan struct{}), make(chan struct{})
	go func() { _ = owner.Close(); close(first) }()
	<-raw.entered
	go func() { _ = owner.Close(); close(second) }()
	select {
	case <-second:
		t.Fatal("second Close certified unfinished teardown")
	case <-time.After(10 * time.Millisecond):
	}
	close(raw.release)
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("first Close stuck")
	}
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("second Close stuck")
	}
}
