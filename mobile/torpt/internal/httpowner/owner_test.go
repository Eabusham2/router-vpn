package httpowner

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type brokerOwnerFixture struct {
	readEntered, writeEntered, closeEntered chan struct{}
	readRelease, writeRelease, closeRelease chan struct{}
	readOnce, writeOnce, closeOnce          sync.Once
	reads, writes, closes, deadlines        atomic.Int32
	active                                  atomic.Int32
	closeErr                                error
}

func newBrokerOwnerFixture() *brokerOwnerFixture {
	return &brokerOwnerFixture{readEntered: make(chan struct{}), writeEntered: make(chan struct{}),
		closeEntered: make(chan struct{}), readRelease: make(chan struct{})}
}
func (c *brokerOwnerFixture) Read([]byte) (int, error) {
	c.reads.Add(1)
	c.active.Add(1)
	defer c.active.Add(-1)
	c.readOnce.Do(func() { close(c.readEntered) })
	<-c.readRelease
	return 0, net.ErrClosed
}
func (c *brokerOwnerFixture) Write(b []byte) (int, error) {
	c.writes.Add(1)
	c.active.Add(1)
	defer c.active.Add(-1)
	c.writeOnce.Do(func() { close(c.writeEntered) })
	if c.writeRelease != nil {
		<-c.writeRelease
		return 0, net.ErrClosed
	}
	return len(b), nil
}
func (c *brokerOwnerFixture) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closeEntered) })
	if c.closeRelease != nil {
		<-c.closeRelease
	}
	return c.closeErr
}
func (*brokerOwnerFixture) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10101}
}
func (*brokerOwnerFixture) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
}
func (c *brokerOwnerFixture) SetDeadline(time.Time) error      { c.deadlines.Add(1); return nil }
func (c *brokerOwnerFixture) SetReadDeadline(time.Time) error  { c.deadlines.Add(1); return nil }
func (c *brokerOwnerFixture) SetWriteDeadline(time.Time) error { c.deadlines.Add(1); return nil }

func brokerAwait(t *testing.T, signal <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal(label)
	}
}
func brokerPending(t *testing.T, result <-chan error, label string) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("%s: %v", label, err)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestBrokerOwnerRetainsPendingAndLateSuccessfulDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw := newBrokerOwnerFixture()
	raw.closeRelease = make(chan struct{})
	releaseDial := make(chan struct{})
	var releaseDialOnce, releaseCloseOnce sync.Once
	defer releaseDialOnce.Do(func() { close(releaseDial) })
	defer releaseCloseOnce.Do(func() { close(raw.closeRelease) })
	entered := make(chan context.Context, 1)
	owner, err := New(ctx, func(call context.Context, _, _ string) (net.Conn, error) {
		entered <- call
		<-releaseDial
		return raw, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	dialed := make(chan error, 1)
	go func() {
		conn, err := owner.DialContext(context.Background(), "tcp", "front.example:443")
		if conn != nil {
			err = errors.New("late broker socket was published")
		}
		dialed <- err
	}()
	call := <-entered
	owner.BeginClose()
	brokerAwait(t, call.Done(), "broker shutdown did not cancel its pending dial")
	closed := make(chan error, 1)
	go func() { closed <- owner.Close() }()
	brokerPending(t, closed, "broker shutdown released a pending dial")
	releaseDialOnce.Do(func() { close(releaseDial) })
	brokerAwait(t, raw.closeEntered, "late broker socket was not closed")
	brokerPending(t, closed, "broker shutdown released a slow late-socket close")
	releaseCloseOnce.Do(func() { close(raw.closeRelease) })
	if err := <-dialed; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("retry close", err)
	}
	if raw.closes.Load() != 1 || raw.reads.Load() != 0 || raw.writes.Load() != 0 {
		t.Fatal("late broker socket escaped its sole close owner")
	}
	brokerAwait(t, owner.parentDone, "broker cancellation callback was not retired")
}

func TestBrokerOwnerJoinsIOAndRejectsLateOperations(t *testing.T) {
	raw := newBrokerOwnerFixture()
	raw.writeRelease = make(chan struct{})
	var readOnce, writeOnce sync.Once
	defer readOnce.Do(func() { close(raw.readRelease) })
	defer writeOnce.Do(func() { close(raw.writeRelease) })
	owner, err := New(context.Background(), func(context.Context, string, string) (net.Conn, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	conn, err := owner.DialContext(context.Background(), "tcp", "front.example:443")
	if err != nil {
		t.Fatal(err)
	}
	readDone, writeDone := make(chan struct{}), make(chan struct{})
	go func() { _, _ = conn.Read(make([]byte, 8)); close(readDone) }()
	go func() { _, _ = conn.Write([]byte("active")); close(writeDone) }()
	brokerAwait(t, raw.readEntered, "broker read did not start")
	brokerAwait(t, raw.writeEntered, "broker write did not start")
	owner.BeginClose()
	brokerAwait(t, raw.closeEntered, "broker socket close did not start")
	closed := make(chan error, 1)
	go func() { closed <- owner.Close() }()
	brokerPending(t, closed, "broker owner released active reads and writes")
	if _, err := conn.Read(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late read", err)
	}
	if _, err := conn.Write(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late write", err)
	}
	for _, set := range []func(time.Time) error{conn.SetDeadline, conn.SetReadDeadline, conn.SetWriteDeadline} {
		if err := set(time.Now()); !errors.Is(err, net.ErrClosed) {
			t.Fatal("late deadline", err)
		}
	}
	if _, err := owner.DialContext(context.Background(), "tcp", "after-close.example:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late dial", err)
	}
	if raw.reads.Load() != 1 || raw.writes.Load() != 1 || raw.deadlines.Load() != 0 {
		t.Fatal("late broker operation touched the lower socket")
	}
	readOnce.Do(func() { close(raw.readRelease) })
	brokerAwait(t, readDone, "broker read did not drain")
	brokerPending(t, closed, "broker owner released an active writer")
	writeOnce.Do(func() { close(raw.writeRelease) })
	brokerAwait(t, writeDone, "broker write did not drain")
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if raw.active.Load() != 0 || raw.closes.Load() != 1 {
		t.Fatal("broker operations remain active or socket closed twice")
	}
}

func TestBrokerOwnerKeepsCloseFailureCredentialFree(t *testing.T) {
	for _, failedDial := range []bool{false, true} {
		raw := newBrokerOwnerFixture()
		raw.closeErr = errors.New("private-token=must-not-be-returned")
		owner, err := New(context.Background(), func(context.Context, string, string) (net.Conn, error) {
			if failedDial {
				return raw, errors.New("private-dial-token")
			}
			return raw, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := owner.DialContext(context.Background(), "tcp", "front.example:443")
		if failedDial {
			if conn != nil || err == nil || strings.Contains(err.Error(), "token") {
				t.Fatal("failed dial credentials escaped", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := owner.Close(); !errors.Is(err, ErrClose) || strings.Contains(err.Error(), "token") {
				t.Fatal("broker close failure was cleared or exposed credentials", err)
			}
		}
		if raw.closes.Load() != 1 {
			t.Fatal("broker socket close ownership was lost")
		}
	}
}
