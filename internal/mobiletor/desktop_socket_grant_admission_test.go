package mobiletor

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type desktopUnsubmittedGrantFixture struct {
	*desktopSocketPolicyFixture
	control desktopSocketControlMutex
	mode    string
	revoked chan DesktopSocketGrant
}

func (p *desktopUnsubmittedGrantFixture) grantSocketAdmitted(ctx context.Context, g DesktopSocketGrant) (DesktopSocketReceipt, error) {
	err := p.control.lockContext(ctx)
	if err == nil {
		p.control.Unlock()
		return DesktopSocketReceipt{}, errors.New("fixture unexpectedly admitted queued grant")
	}
	switch p.mode {
	case "cancel", "deadline":
		return DesktopSocketReceipt{}, desktopSocketUnsubmittedGrant(g, err)
	case "unknown":
		return DesktopSocketReceipt{}, err
	case "different-request":
		g.SocketID = strings.Repeat("f", 32)
		return DesktopSocketReceipt{}, desktopSocketUnsubmittedGrant(g, err)
	case "nonempty-receipt":
		return DesktopSocketReceipt{Grant: g}, desktopSocketUnsubmittedGrant(g, err)
	}
	panic("unknown fixture")
}
func (p *desktopUnsubmittedGrantFixture) revokeSocketAdmitted(_ context.Context, g DesktopSocketGrant) error {
	p.revoked <- g
	return nil
}

func TestDesktopSocketGrantUnsubmittedPreservesJoinedRetirement(t *testing.T) {
	for _, initial := range []uint64{0, 1} {
		for _, mode := range []string{"cancel", "deadline", "unknown", "different-request", "nonempty-receipt"} {
			t.Run(mode+"/"+string(rune('0'+initial)), func(t *testing.T) {
				p := &desktopUnsubmittedGrantFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy(), mode: mode, revoked: make(chan DesktopSocketGrant, 2)}
				p.control.Lock()
				defer p.control.Unlock()
				ctx, cancel := context.WithCancel(context.Background())
				if mode == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 40*time.Millisecond)
				}
				defer cancel()
				b := &DesktopSocketBroker{ctx: context.Background(), capture: desktopSocketFixtureCapture(), owner: p.owner, policy: p, current: func() bool { return true }, sockets: make(map[*desktopSocket]struct{})}
				remote := netip.MustParseAddrPort("192.0.2.1:443")
				original := DesktopSocketGrant{Capture: b.capture, Binding: DesktopSocketBinding{Owner: p.owner, InterfaceName: "owned", InterfaceIndex: 2, LocalAddress: netip.MustParseAddr("192.0.2.2")}, SocketID: strings.Repeat("a", 32), Network: "tcp", Local: netip.MustParseAddrPort("192.0.2.2:40000"), Remote: remote, Sequence: initial}
				peer := &desktopSocketPeer{request: original}
				s := &desktopSocket{ctx: ctx, cancel: cancel, broker: b, id: original.SocketID, network: "tcp", remote: remote, binding: original.Binding, local: original.Local, peers: map[netip.AddrPort]*desktopSocketPeer{remote: peer}, operation: make(chan struct{}), done: make(chan struct{})}
				b.sockets[s] = struct{}{}
				applied := make(chan error, 1)
				go func() { applied <- s.apply(ctx, peer) }()
				desktopSocketAwaitControlQueue(t, &p.control, 1)
				if mode != "deadline" {
					cancel()
				}
				failure := desktopSocketAwait(t, applied)
				cause := context.Canceled
				if mode == "deadline" {
					cause = context.DeadlineExceeded
				}
				if !errors.Is(failure, cause) {
					t.Fatal("unsent admission lost caller cancellation", failure)
				}
				close(s.operation)
				desktopSocketAwait(t, s.done)
				expected := original
				if mode != "cancel" && mode != "deadline" {
					expected.Sequence++
				}
				peer.mu.Lock()
				retained := peer.request
				peer.mu.Unlock()
				if retained != expected {
					t.Fatal("grant submission evidence changed exact retirement identity", mode, initial, retained.Sequence, expected.Sequence)
				}
				if expected.Sequence == 0 {
					select {
					case q := <-p.revoked:
						t.Fatal("never-submitted initial grant invented native retirement", q)
					default:
					}
				} else {
					if q := desktopSocketAwait(t, p.revoked); q != expected {
						t.Fatal("joined drain revoked another operation", q, expected)
					}
				}
				b.mu.Lock()
				remaining := len(b.sockets)
				b.mu.Unlock()
				if remaining != 0 {
					t.Fatal("joined drain retained socket registry")
				}
			})
		}
	}
}
