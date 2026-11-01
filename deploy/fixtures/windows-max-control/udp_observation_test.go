package routervpnpq

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type maxUDPControlTestPeer struct {
	mu            sync.Mutex
	listener      *net.UDPConn
	counts        map[string]int64
	attempted     string
	silentAttempt bool
	events        []string
}

func newMAXUDPControlTestPeer(t *testing.T) *maxUDPControlTestPeer {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	peer := &maxUDPControlTestPeer{listener: listener, counts: make(map[string]int64)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		body := make([]byte, 4096)
		for {
			n, remote, err := listener.ReadFromUDP(body)
			if err != nil {
				return
			}
			value := strings.TrimPrefix(string(body[:n]), "routervpn-complete-max-owned-marker/")
			peer.mu.Lock()
			_, armed := peer.counts[value]
			if armed {
				peer.counts[value]++
			}
			silent := value == peer.attempted && peer.silentAttempt
			peer.mu.Unlock()
			if armed && !silent {
				_, _ = listener.WriteToUDP(body[:n], remote)
			}
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return peer
}

func (peer *maxUDPControlTestPeer) probe(ctx context.Context, action, nonce string) (int64, error) {
	if ctx.Err() != nil || len(nonce) != 32 {
		return 0, errors.New("test reference lost its live private nonce")
	}
	peer.mu.Lock()
	peer.events = append(peer.events, action)
	count, exists := peer.counts[nonce]
	if action == "observe" {
		peer.mu.Unlock()
		if !exists {
			return 0, errors.New("test reference observed an unarmed nonce")
		}
		return count, nil
	}
	if exists || action != "arm" && action != "positive" {
		peer.mu.Unlock()
		return 0, errors.New("test reference reused a nonce or changed its command")
	}
	peer.counts[nonce] = 0
	if action == "arm" {
		peer.attempted = nonce
	}
	peer.mu.Unlock()
	if action == "arm" {
		return 0, nil
	}
	connection, err := net.DialUDP("udp4", nil, peer.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return 0, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return 0, err
	}
	marker := []byte("routervpn-complete-max-owned-marker/" + nonce)
	if _, err := connection.Write(marker); err != nil {
		return 0, err
	}
	answer := make([]byte, len(marker)+1)
	n, err := connection.Read(answer)
	if err != nil || !bytes.Equal(answer[:n], marker) {
		return 0, errors.Join(err, errors.New("test reference did not receive its independent positive"))
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	return peer.counts[nonce], nil
}

// Only the intentional drop/denial cases model socket blocking. Delivery and
// no-echo delivery are real UDP loopback traffic. This test does not establish
// native WFP protection, which remains the separately executed Windows gate.
type maxUDPControlTestConn struct {
	net.Conn
	mode      string
	deadlines []time.Time
	writes    int
}

func (connection *maxUDPControlTestConn) Write(body []byte) (int, error) {
	connection.writes++
	switch connection.mode {
	case "drop", "reset-error", "late-receipt":
		return len(body), nil
	case "denied":
		return 0, syscall.Errno(10013)
	case "short":
		return len(body) - 1, nil
	case "write-error":
		return 0, errors.New("unrelated write failure")
	}
	return connection.Conn.Write(body)
}

func (connection *maxUDPControlTestConn) SetDeadline(deadline time.Time) error {
	connection.deadlines = append(connection.deadlines, deadline)
	if connection.mode == "deadline-error" && !deadline.IsZero() || connection.mode == "reset-error" && deadline.IsZero() {
		return errors.New("test deadline operation refused")
	}
	return connection.Conn.SetDeadline(deadline)
}

func TestWindowsMAXUDPObservation(t *testing.T) {
	for _, mode := range []string{"drop", "denied", "delivered", "delivered-without-echo", "deadline-error", "reset-error", "short", "write-error", "late-receipt", "positive-error", "foreign-local", "foreign-remote", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			peer := newMAXUDPControlTestPeer(t)
			peer.mu.Lock()
			peer.silentAttempt = mode == "delivered-without-echo"
			peer.mu.Unlock()
			actual, err := net.DialUDP("udp4", nil, peer.listener.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer actual.Close()
			connection := &maxUDPControlTestConn{Conn: actual, mode: mode}
			local := actual.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
			remote := actual.RemoteAddr().(*net.UDPAddr).AddrPort()
			if mode == "foreign-local" {
				local = netip.MustParseAddr("192.0.2.99")
			}
			if mode == "foreign-remote" {
				remote = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.99"), remote.Port())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			positives := 0
			probe := func(ctx context.Context, action, nonce string) (int64, error) {
				if mode == "positive-error" && action == "positive" {
					return 0, errors.New("independent reference unavailable")
				}
				count, err := peer.probe(ctx, action, nonce)
				if action == "positive" {
					positives++
					if mode == "late-receipt" && positives == 2 {
						peer.mu.Lock()
						peer.counts[peer.attempted]++
						peer.mu.Unlock()
					}
				}
				return count, err
			}
			err = nodeMAXWFPObserveOrdinaryUDP(ctx, connection, local, remote, probe)
			wantSuccess := mode == "drop" || mode == "denied"
			if (err == nil) != wantSuccess {
				t.Fatalf("ordinary UDP observation verdict: mode=%s error=%v", mode, err)
			}
			if len(connection.deadlines) != 0 && !connection.deadlines[len(connection.deadlines)-1].IsZero() {
				t.Fatal("observer left its temporary deadline on the actual connection")
			}
			if mode == "foreign-local" || mode == "foreign-remote" || mode == "cancelled" {
				peer.mu.Lock()
				events := len(peer.events)
				peer.mu.Unlock()
				if events != 0 || connection.writes != 0 || len(connection.deadlines) != 0 {
					t.Fatal("observer touched a cancelled or differently owned socket")
				}
			}
			if wantSuccess {
				peer.mu.Lock()
				events := strings.Join(peer.events, ",")
				peer.mu.Unlock()
				if connection.writes != 1 || events != "positive,arm,observe,positive,observe" {
					t.Fatal("observer omitted the actual attempted nonce or repeated independent proof", events)
				}
			}
		})
	}
}
