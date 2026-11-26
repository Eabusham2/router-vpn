package common

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func dnsProbeTestServer(t *testing.T, network, address string, reply func([]byte) []byte) (string, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			buf := make([]byte, 65536)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			calls.Add(1)
			if response := reply(buf[:n]); response != nil {
				if _, err := conn.WriteTo(response, addr); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return conn.LocalAddr().String(), &calls
}

func TestDNSUDPProbeBindsOriginalQuestionAndResponse(t *testing.T) {
	for _, tc := range []struct {
		network, address string
		qtype            uint16
		corrupt          bool
	}{
		{"udp4", "127.0.0.1:0", 1, false},
		{"udp6", "[::1]:0", 28, false},
		{"udp4", "127.0.0.1:0", 1, true},
	} {
		endpoint, calls := dnsProbeTestServer(t, tc.network, tc.address, func(q []byte) []byte {
			if binary.BigEndian.Uint16(q[len(q)-4:len(q)-2]) != tc.qtype {
				t.Error("probe changed its original question type")
			}
			q[2] |= 128
			if tc.corrupt {
				q[0]++
			}
			return q
		})
		duration, err := ProbeDNSUDP(context.Background(), endpoint, tc.qtype, time.Second)
		// Protocol validity, not an invented positive minimum RTT, decides success.
		if (!tc.corrupt && (err != nil || duration < 0)) || (tc.corrupt && (err == nil || duration != 0)) {
			t.Fatalf("original response binding lost: duration=%s err=%v", duration, err)
		}
		if calls.Load() != 1 {
			t.Fatal("probe did not use exactly one owned query")
		}
	}
}

func TestDNSUDPProbeCancellationClosesTheOwnedSocket(t *testing.T) {
	started := make(chan struct{}, 1)
	endpoint, calls := dnsProbeTestServer(t, "udp4", "127.0.0.1:0", func(q []byte) []byte {
		select {
		case started <- struct{}{}:
		default:
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := ProbeDNSUDP(ctx, endpoint, 1, 5*time.Second); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled probe retained socket until timeout")
	}
	if calls.Load() != 1 {
		t.Fatal("cancelled probe retried")
	}
	if _, err := ProbeDNSUDP(ctx, endpoint, 1, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled request=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("pre-cancelled probe issued traffic")
	}
}
