package common

import (
	"bytes"
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

func TestDNSUDPProbeValidatesTheWholeResponse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply func([]byte) []byte
		valid bool
	}{
		{"valid-a", func(b []byte) []byte { return b }, true},
		{"nxdomain-is-responsive", func(b []byte) []byte { b[3] |= 3; return b }, true},
		{"wrong-transaction", func(b []byte) []byte { b[0]++; return b }, false},
		{"query-echo", func(b []byte) []byte { b[2] &^= 128; return b }, false},
		{"wrong-question", func(b []byte) []byte { b[13] = 'z'; return b }, false},
		{"wrong-type", func(b []byte) []byte { b[len(b)-3] = 28; return b }, false},
		{"short-header", func(b []byte) []byte { return b[:11] }, false},
		{"header-only", func(b []byte) []byte { return b[:12] }, false},
		{"servfail", func(b []byte) []byte { b[3] = 2; return b }, false},
		{"truncated", func(b []byte) []byte { b[2] |= 2; return b }, false},
		{"incomplete-record", func(b []byte) []byte { b[7] = 1; return b }, false},
		{"oversized-valid-prefix", func(b []byte) []byte { return append(b, make([]byte, 5000)...) }, false},
		{"large-complete-record", func(b []byte) []byte {
			b[11] = 1
			b = append(b, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0x13, 0x88)
			return append(b, make([]byte, 5000)...)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, calls := dnsProbeTestServer(t, "udp4", "127.0.0.1:0", func(q []byte) []byte { q[2] |= 128; return tc.reply(q) })
			duration, err := ProbeDNSUDP(context.Background(), endpoint, 1, time.Second)
			// A valid loopback exchange can complete within one clock tick (as
			// observed on Windows). Protocol validation, not positive elapsed
			// time, decides success; retain the real zero rather than inventing RTT.
			if (err == nil) != tc.valid || tc.valid && duration < 0 || !tc.valid && duration != 0 {
				t.Fatalf("duration=%s err=%v valid=%t", duration, err, tc.valid)
			}
			if calls.Load() != 1 {
				t.Fatalf("expected one owned query; got %d", calls.Load())
			}
		})
	}
}

func TestDNSUDPProbeIPv6AAAA(t *testing.T) {
	endpoint, _ := dnsProbeTestServer(t, "udp6", "[::1]:0", func(q []byte) []byte {
		if binary.BigEndian.Uint16(q[len(q)-4:len(q)-2]) != 28 {
			t.Error("lost AAAA question")
		}
		q[2] |= 128
		return q
	})
	if _, err := ProbeDNSUDP(context.Background(), endpoint, 28, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestDNSUDPProbeCancellationClosesTheOwnedSocket(t *testing.T) {
	started := make(chan struct{}, 1)
	endpoint, calls := dnsProbeTestServer(t, "udp4", "127.0.0.1:0", func(q []byte) []byte { started <- struct{}{}; return nil })
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

func TestDNSUDPProbeDeadlineAndInputValidation(t *testing.T) {
	endpoint, _ := dnsProbeTestServer(t, "udp4", "127.0.0.1:0", func([]byte) []byte { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := ProbeDNSUDP(ctx, endpoint, 1, time.Second); err == nil {
		t.Fatal("nonresponsive upstream accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("ignored caller deadline")
	}
	for _, address := range []string{"localhost:53", "resolver.invalid:53", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:bad"} {
		if _, err := ProbeDNSUDP(context.Background(), address, 1, time.Second); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", address)
		}
	}
	if _, err := ProbeDNSUDP(nil, endpoint, 1, time.Second); err == nil {
		t.Fatal("nil context")
	}
	if _, err := ProbeDNSUDP(context.Background(), endpoint, 1, 0); err == nil {
		t.Fatal("unbounded probe")
	}
	if _, err := ProbeDNSUDP(context.Background(), endpoint, 15, time.Second); err == nil {
		t.Fatal("unsupported question")
	}
}

func TestDNSProbeQuestionsHaveFreshIDsAndPreserveType(t *testing.T) {
	var previous []byte
	changed := false
	for i := 0; i < 16; i++ {
		q, err := NewDNSProbeQuery(28)
		if err != nil {
			t.Fatal(err)
		}
		if len(q) != 29 || binary.BigEndian.Uint16(q[25:27]) != 28 {
			t.Fatalf("bad AAAA question: %x", q)
		}
		if previous != nil && !bytes.Equal(q[:2], previous[:2]) {
			changed = true
		}
		previous = q
	}
	if !changed {
		t.Fatal("transaction ID is fixed across probes")
	}
}
