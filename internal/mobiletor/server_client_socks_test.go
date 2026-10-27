package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type serverTorPendingSocket struct {
	net.Conn
	allowClose atomic.Bool
}

func (c *serverTorPendingSocket) Close() error {
	if !c.allowClose.Load() {
		return errors.New("private captured socket close failure")
	}
	return c.Conn.Close()
}

func TestServerTorRetainedSOCKSFailureKeepsNativeSocketUntilCloseSucceeds(t *testing.T) {
	for _, failure := range []string{"native-dial", "handshake", "cancellation"} {
		t.Run(failure, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			raw := &serverTorPendingSocket{Conn: client}
			defer func() { raw.allowClose.Store(true); _ = raw.Close() }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				if failure == "native-dial" {
					return
				}
				var greeting [3]byte
				if _, err := io.ReadFull(peer, greeting[:]); err != nil {
					return
				}
				if failure == "cancellation" {
					cancel()
				}
				_, _ = peer.Write([]byte{5, 0}) // The captured front must require authentication.
			}()
			underlying := func(context.Context, string, string) (net.Conn, error) {
				if failure == "native-dial" {
					return raw, errors.New("private captured native dial detail")
				}
				return raw, nil
			}
			network, err := NewNetwork(context.Background(), func(ctx context.Context, _, address string) (net.Conn, error) {
				return dialServerTorSOCKS(ctx, "192.168.50.1:41000", strings.Repeat("a", 48), strings.Repeat("b", 48), address, underlying)
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			connection, err := network.DialRetainedContext(ctx, "tcp", "1.1.1.1:53")
			<-finished
			if connection == nil || err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("failed native SOCKS socket was discarded or exposed", err)
			}
			if err := connection.Close(); err == nil {
				t.Fatal("failed lower socket close was reported as complete")
			}
			waiting, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
			if err := network.Close(waiting); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("network retired a SOCKS socket before its actual close", err)
			}
			stop()
			raw.allowClose.Store(true)
			if err := connection.Close(); err != nil {
				t.Fatal("exact native socket cleanup could not be retried", err)
			}
			waiting, stop = context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := network.Close(waiting); err != nil {
				t.Fatal("successful native socket retry did not release its owner", err)
			}
		})
	}
}
