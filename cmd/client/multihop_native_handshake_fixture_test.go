package main

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// Readiness is a real authenticated packet path, separately bounded like the
// application's node-proof phase. It never retries a wrong exit credential or
// extends the assertion deadline for the tested Naive TCP/UDP exchange.
func nativeMultihopAwaitEncryptedEntry(t *testing.T, proxy, echo int) {
	t.Helper()
	until := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(until) {
		last = nativeMultihopTrafficExchangeTo(proxy, echo, "tcp", [4]byte{10, 77, 0, 1}, 250*time.Millisecond)
		if last == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("owned encrypted entry never passed its bounded data-plane readiness exchange", last)
}

type nativeWGFirstHandshakeGate struct {
	port      int
	mu        sync.Mutex
	first     time.Time
	held      int
	forwarded int
	hold      time.Duration
}

func (g *nativeWGFirstHandshakeGate) requireObservedRetry(t *testing.T) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.first.IsZero() || g.held == 0 || g.forwarded == 0 || time.Since(g.first) < g.hold {
		t.Fatal("first-handshake regression did not hold then relay an actual owned WG response")
	}
}

// The exact pinned WireGuard peer sends response type2 in its little-endian
// datagram header. Drop only those responses during the initial controlled
// network transition; all payloads remain opaque and authenticated. This
// deterministically reproduces a startup rebind losing the first response.
// No network interface, route, production timeout or transport is modified.
func nativeMultihopDelayFirstWGHandshake(t *testing.T, target int, hold time.Duration) *nativeWGFirstHandshakeGate {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: target})
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	g := &nativeWGFirstHandshakeGate{port: front.LocalAddr().(*net.UDPAddr).Port, hold: hold}
	var peerMu sync.Mutex
	var peer *net.UDPAddr
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			peerMu.Lock()
			peer = from
			peerMu.Unlock()
			if _, err = back.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		buf := make([]byte, 65535)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			if n >= 4 && binary.LittleEndian.Uint32(buf[:4]) == 2 {
				now := time.Now()
				g.mu.Lock()
				if g.first.IsZero() {
					g.first = now
				}
				drop := now.Sub(g.first) < g.hold
				if drop {
					g.held++
				} else {
					g.forwarded++
				}
				g.mu.Unlock()
				if drop {
					continue
				}
			}
			peerMu.Lock()
			to := peer
			peerMu.Unlock()
			if to != nil {
				if _, err = front.WriteToUDP(buf[:n], to); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		front.Close()
		back.Close()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("owned handshake fixture sockets did not drain")
		}
	})
	return g
}
