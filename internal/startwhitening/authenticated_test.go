package startwhitening

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Deliberately unsynchronized cipher state emulates a vetted engine whose
// close method must not race its direction-specific reader/writer allocation.
type statefulCipher struct {
	net.Conn
	readers, writers int
	closed           atomic.Int32
}

func (c *statefulCipher) Read(p []byte) (int, error)  { c.readers++; return c.Conn.Read(p) }
func (c *statefulCipher) Write(p []byte) (int, error) { c.writers++; return c.Conn.Write(p) }
func (c *statefulCipher) Close() error {
	_ = c.readers
	_ = c.writers
	c.closed.Add(1)
	return c.Conn.Close()
}
func TestAuthenticatedOwnerSerializesCipherCloseAgainstDuplexIO(t *testing.T) {
	for i := 0; i < 50; i++ {
		o := NewOwner(context.Background())
		a, b := net.Pipe()
		raw, err := o.Open(context.Background(), [32]byte{}, false, func(context.Context) (net.Conn, error) { return a, nil })
		if err != nil {
			t.Fatal(err)
		}
		cipher := &statefulCipher{Conn: raw}
		c, err := OwnAuthenticatedStream(raw, cipher)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = c.Read(make([]byte, 64)) }()
		go func() { defer wg.Done(); _, _ = c.Write([]byte("payload")) }()
		wg.Add(2)
		go func() { defer wg.Done(); _ = o.Close() }()
		go func() { defer wg.Done(); _ = c.Close() }()
		wg.Wait()
		b.Close()
		if cipher.closed.Load() != 1 {
			t.Fatal("cipher cleanup not exactly once")
		}
		o.mu.Lock()
		remaining := len(o.conns)
		o.mu.Unlock()
		if remaining != 0 {
			t.Fatal("owned cipher leaked")
		}
	}
}

type packetFixture struct {
	net.PacketConn
	length int
	closed atomic.Int32
}

func (p *packetFixture) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(b) < p.length+64 {
		return 0, nil, errors.New("ciphertext truncated before authentication")
	}
	copy(b, bytes.Repeat([]byte{9}, p.length))
	return p.length, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}, nil
}
func (p *packetFixture) Close() error { p.closed.Add(1); return nil }
func TestAuthenticatedPacketUsesWholeCiphertextBeforePlaintextTruncation(t *testing.T) {
	o := NewOwner(context.Background())
	defer o.Close()
	a, b := net.Pipe()
	defer b.Close()
	raw, err := o.Open(context.Background(), [32]byte{}, true, func(context.Context) (net.Conn, error) { return a, nil })
	if err != nil {
		t.Fatal(err)
	}
	fixture := &packetFixture{length: 1280}
	c, err := OwnAuthenticatedPacket(raw, fixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 20, 1280, 1500} {
		b := make([]byte, size)
		n, _, err := c.ReadFrom(b)
		if err != nil || n != min(size, 1280) {
			t.Fatal("cipher requires complete ciphertext but plaintext respects caller size", err)
		}
	}
	o.Reset()
	if fixture.closed.Load() != 1 {
		t.Fatal("reset did not close complete cipher")
	}
	if _, _, err := c.ReadFrom(make([]byte, 1280)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("old cipher survived reset")
	}
}
func TestLateCipherCannotAttachToNewPhysicalGeneration(t *testing.T) {
	o := NewOwner(context.Background())
	defer o.Close()
	a, b := net.Pipe()
	defer b.Close()
	raw, err := o.Open(context.Background(), [32]byte{}, false, func(context.Context) (net.Conn, error) { return a, nil })
	if err != nil {
		t.Fatal(err)
	}
	o.Reset()
	cipher := &statefulCipher{Conn: raw}
	if _, err := OwnAuthenticatedStream(raw, cipher); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late cipher was adopted", err)
	}
	if cipher.closed.Load() != 1 {
		t.Fatal("late cipher not released")
	}
}

type slowCipher struct {
	net.Conn
	started, release chan struct{}
	once             sync.Once
}

func (c *slowCipher) Close() error { c.once.Do(func() { close(c.started); <-c.release }); return nil }
func TestOwnerCannotFinishWhileExplicitCipherCloseStillRuns(t *testing.T) {
	o := NewOwner(context.Background())
	a, b := net.Pipe()
	defer b.Close()
	raw, err := o.Open(context.Background(), [32]byte{}, false, func(context.Context) (net.Conn, error) { return a, nil })
	if err != nil {
		t.Fatal(err)
	}
	cipher := &slowCipher{Conn: raw, started: make(chan struct{}), release: make(chan struct{})}
	c, err := OwnAuthenticatedStream(raw, cipher)
	if err != nil {
		t.Fatal(err)
	}
	direct := make(chan struct{})
	go func() { defer close(direct); _ = c.Close() }()
	<-cipher.started
	owner := make(chan struct{})
	go func() { defer close(owner); _ = o.Close() }()
	select {
	case <-owner:
		t.Fatal("owner prematurely certified active cipher teardown")
	case <-time.After(10 * time.Millisecond):
	}
	close(cipher.release)
	<-direct
	<-owner
}

var _ io.Closer = (*AuthenticatedStream)(nil)
