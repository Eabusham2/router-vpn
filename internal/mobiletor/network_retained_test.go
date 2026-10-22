package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type retainedNetworkTestConn struct {
	net.Conn
	allowClose atomic.Bool
	closes     atomic.Int32
}

func (c *retainedNetworkTestConn) Close() error {
	c.closes.Add(1)
	if !c.allowClose.Load() {
		return errors.New("private-native-socket-close-detail")
	}
	return c.Conn.Close()
}

func TestRetainedNetworkReturnsLateSocketAndWaitsForSuccessfulClose(t *testing.T) {
	for _, retire := range []string{"caller", "network", "native-error"} {
		t.Run(retire, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			raw := &retainedNetworkTestConn{Conn: client}
			defer func() { raw.allowClose.Store(true); _ = raw.Close() }()
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			network, err := NewNetwork(context.Background(), func(context.Context, string, string) (net.Conn, error) {
				close(entered)
				<-release // Native dial deliberately returns a socket after cancellation.
				if retire == "native-error" {
					return raw, errors.New("private-native-dial-detail")
				}
				return raw, nil
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type dialResult struct {
				connection net.Conn
				err        error
			}
			done := make(chan dialResult, 1)
			go func() { c, err := network.DialRetainedContext(ctx, "tcp", "1.1.1.1:53"); done <- dialResult{c, err} }()
			<-entered
			if retire == "caller" {
				cancel()
			} else if retire == "network" {
				network.beginClose()
			}
			releaseOnce.Do(func() { close(release) })
			result := <-done
			if result.connection == nil || result.err == nil || strings.Contains(result.err.Error(), "private-") {
				t.Fatal("late/error socket was discarded or its native detail escaped", result.err)
			}
			if err := result.connection.Close(); err == nil || strings.Contains(err.Error(), "private-") {
				t.Fatal("failed native close was accepted or exposed", err)
			}
			waiting, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
			if err := network.Close(waiting); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("network retired a retained socket before actual close", err)
			}
			stop()
			if raw.closes.Load() == 0 {
				t.Fatal("native Close was not attempted")
			}
			raw.allowClose.Store(true)
			var closers sync.WaitGroup
			for range 8 {
				closers.Add(1)
				go func() {
					defer closers.Done()
					if err := result.connection.Close(); err != nil {
						t.Error(err)
					}
				}()
			}
			closers.Wait()
			waiting, stop = context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := network.Close(waiting); err != nil {
				t.Fatal("successful native retry did not release its network", err)
			}
			var b [1]byte
			if _, err := peer.Read(b[:]); err != io.EOF {
				t.Fatal("native socket still open after retained drain", err)
			}
			network.mu.Lock()
			count := network.count
			network.mu.Unlock()
			if count != 0 {
				t.Fatal("retained socket ownership was released more than once", count)
			}
		})
	}
}

func TestRetainedNetworkPublicationTransfersCallerLifetime(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	var captured context.Context
	network, _ := NewNetwork(context.Background(), func(ctx context.Context, _, _ string) (net.Conn, error) { captured = ctx; return client, nil }, nil)
	ctx, cancel := context.WithCancel(context.Background())
	connection, err := network.DialRetainedContext(ctx, "tcp", "1.1.1.1:53")
	if err != nil || connection == nil {
		t.Fatal(err)
	}
	cancel()
	if captured.Err() != nil {
		t.Fatal("published stream was owned by the expired dial caller")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if captured.Err() == nil {
		t.Fatal("native stream context survived its actual socket close")
	}
	if err := network.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedNetworkNilSocketAndInvalidInputDoNotLeakOrDialFallback(t *testing.T) {
	var calls atomic.Int32
	network, _ := NewNetwork(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("private-native-failure")
	}, nil)
	for _, kind := range []string{"tcp", "udp", "ip"} {
		if c, err := network.DialRetainedContext(context.Background(), kind, "1.1.1.1:53"); c != nil || err == nil || strings.Contains(err.Error(), "private-") {
			t.Fatal("missing native socket or unsupported network was accepted", err)
		}
	}
	if c, err := network.DialRetainedContext(nil, "tcp", "1.1.1.1:53"); c != nil || err == nil {
		t.Fatal("nil context was accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("invalid network reached a native dialer", calls.Load())
	}
	if err := network.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, err := network.DialRetainedContext(context.Background(), "tcp", "1.1.1.1:53"); c != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatal("retired network reopened", err)
	}
}
