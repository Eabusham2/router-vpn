package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func serverFrontFixture(t *testing.T, dial DialContext) *ServerTorFront {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f, err := newServerTorFront(t.Context(), listener, netip.MustParseAddr("127.0.0.1"), strings.Repeat("a", 48), strings.Repeat("b", 48), dial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return f
}
func serverFrontConnect(t *testing.T, f *ServerTorFront, password string, command byte) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp4", f.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err = c.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var header [2]byte
	if _, err = io.ReadFull(c, header[:]); err != nil || header != [2]byte{5, 2} {
		t.Fatal("front did not require authentication", header, err)
	}
	raw := append([]byte{1, 48}, []byte(strings.Repeat("a", 48))...)
	raw = append(raw, byte(len(password)))
	raw = append(raw, password...)
	if _, err = c.Write(raw); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[1] != 0 {
		return c, header[1]
	}
	host := "example.com"
	request := append([]byte{5, command, 0, 3, byte(len(host))}, []byte(host)...)
	request = append(request, 1, 187)
	if _, err = c.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		if !f.Current() {
			return c, 255
		}
		t.Fatal(err)
	}
	return c, reply[1]
}
func TestServerTorFrontGatesExactPeerAuthenticationAndRealTraffic(t *testing.T) {
	var calls atomic.Int32
	f := serverFrontFixture(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		if network != "tcp" || address != "example.com:443" {
			t.Error("changed selected destination", network, address)
		}
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
		return a, nil
	})
	for _, test := range []struct {
		password string
		command  byte
	}{{strings.Repeat("b", 48), 1}, {strings.Repeat("c", 48), 1}, {strings.Repeat("b", 48), 3}} {
		c, code := serverFrontConnect(t, f, test.password, test.command)
		_ = c.Close()
		if code == 0 || calls.Load() != 0 {
			t.Fatal("unproved or unauthenticated traffic escaped", code, calls.Load())
		}
	}
	if err := f.Enable(); err != nil {
		t.Fatal(err)
	}
	c, code := serverFrontConnect(t, f, strings.Repeat("b", 48), 1)
	defer c.Close()
	if code != 0 {
		t.Fatal("proved front rejected its exact peer", code)
	}
	if _, err := c.Write([]byte("owned traffic")); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("owned traffic"))
	if _, err := io.ReadFull(c, received); err != nil || string(received) != "owned traffic" {
		t.Fatal("owned pumps did not transfer actual bytes", err)
	}
	other, err := (&net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).Dial("tcp4", f.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	_ = other.SetDeadline(time.Now().Add(time.Second))
	_, _ = other.Write([]byte{5, 1, 2})
	var one [1]byte
	if _, err = other.Read(one[:]); err == nil {
		t.Fatal("another peer obtained a proxy greeting")
	}
	if calls.Load() != 1 {
		t.Fatal("another peer borrowed the proved path", calls.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if f.Close(ctx) != nil || f.Enable() == nil || f.Allowed() {
		t.Fatal("retired front was revived")
	}
}
func TestServerTorFrontRetainsLateOwnedDialThroughCanceledDrain(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := serverFrontFixture(t, func(context.Context, string, string) (net.Conn, error) {
		close(entered)
		<-release
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	})
	if f.Enable() != nil {
		t.Fatal("enable failed")
	}
	done := make(chan struct{})
	go func() { defer close(done); c, _ := serverFrontConnect(t, f, strings.Repeat("b", 48), 1); _ = c.Close() }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled close fabricated a completed dial", err)
	}
	select {
	case <-f.done:
		t.Fatal("late dial escaped close barrier")
	default:
	}
	close(release)
	joined, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	if err := f.Close(joined); err != nil {
		t.Fatal(err)
	}
	<-done
}
